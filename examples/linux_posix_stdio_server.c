#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "emssh/platform_posix_net.h"
#include "emssh/platform_posix_passwd_auth.h"
#include "emssh/platform_posix_runtime.h"
#include "emssh/platform_posix_term.h"
#include "emssh/platform_stdio_fs.h"
#include "emssh/sshd_config_file.h"
#include "emssh/ssh_error.h"
#include "emssh/ssh_server.h"

#if defined(EMSSH_USE_MBEDTLS)
#include "emssh/crypto_mbedtls.h"
#endif
#if defined(EMSSH_USE_OPENSSL)
#include "emssh/crypto_openssl.h"
#endif
#if defined(EMSSH_USE_WOLFSSL)
#include "emssh/crypto_wolfssl.h"
#endif

#if defined(EMSSH_LINUX_SERVER_FIXED_BACKEND_MBEDTLS)
#define EMSSH_LINUX_SERVER_ENABLE_MBEDTLS 1
#define EMSSH_LINUX_SERVER_ENABLE_OPENSSL 0
#define EMSSH_LINUX_SERVER_ENABLE_WOLFSSL 0
#elif defined(EMSSH_LINUX_SERVER_FIXED_BACKEND_OPENSSL)
#define EMSSH_LINUX_SERVER_ENABLE_MBEDTLS 0
#define EMSSH_LINUX_SERVER_ENABLE_OPENSSL 1
#define EMSSH_LINUX_SERVER_ENABLE_WOLFSSL 0
#elif defined(EMSSH_LINUX_SERVER_FIXED_BACKEND_WOLFSSL)
#define EMSSH_LINUX_SERVER_ENABLE_MBEDTLS 0
#define EMSSH_LINUX_SERVER_ENABLE_OPENSSL 0
#define EMSSH_LINUX_SERVER_ENABLE_WOLFSSL 1
#else
#if defined(EMSSH_USE_MBEDTLS)
#define EMSSH_LINUX_SERVER_ENABLE_MBEDTLS 1
#else
#define EMSSH_LINUX_SERVER_ENABLE_MBEDTLS 0
#endif
#if defined(EMSSH_USE_OPENSSL)
#define EMSSH_LINUX_SERVER_ENABLE_OPENSSL 1
#else
#define EMSSH_LINUX_SERVER_ENABLE_OPENSSL 0
#endif
#if defined(EMSSH_USE_WOLFSSL)
#define EMSSH_LINUX_SERVER_ENABLE_WOLFSSL 1
#else
#define EMSSH_LINUX_SERVER_ENABLE_WOLFSSL 0
#endif
#endif

#if !EMSSH_LINUX_SERVER_ENABLE_MBEDTLS && !EMSSH_LINUX_SERVER_ENABLE_OPENSSL && !EMSSH_LINUX_SERVER_ENABLE_WOLFSSL
#error "linux_posix_stdio_server requires at least one crypto backend enabled"
#endif

#define LINUX_SERVER_DEFAULT_PORT 2222u
#define LINUX_SERVER_DEFAULT_TIMEOUT_MS 30000u
#define LINUX_SERVER_DEFAULT_MAX_WORKERS 16u
#define LINUX_SERVER_DEFAULT_WORKER_STACK_KB 1024u
#define LINUX_SERVER_MAX_PATH 512u
#define LINUX_SERVER_MAX_MBEDTLS_HOSTKEY_PRIVATE 128u
#define LINUX_SERVER_PUTTY_REQ_SIMPLE "simple@putty.projects.tartarus.org"
#define LINUX_SERVER_PUTTY_REQ_WINADJ "winadj@putty.projects.tartarus.org"

#define LINUX_STAGE_MAIN_INIT 10
#define LINUX_STAGE_MAIN_LISTEN 20
#define LINUX_STAGE_MAIN_ACCEPT_WAIT 30
#define LINUX_STAGE_MAIN_ACCEPTED 40
#define LINUX_STAGE_WORKER_START 100
#define LINUX_STAGE_WORKER_BACKEND_INIT 110
#define LINUX_STAGE_WORKER_SERVER_INIT 120
#define LINUX_STAGE_WORKER_RUN_SFTP 130
#define LINUX_STAGE_WORKER_DONE 140
#define LINUX_STAGE_WORKER_NON_SFTP_REQUEST 150

static volatile sig_atomic_t g_linux_server_stage = 0;

static void set_linux_server_stage(sig_atomic_t stage)
{
    g_linux_server_stage = stage;
}

static void append_lit(char *buf, size_t capacity, size_t *used, const char *text)
{
    size_t i;

    if (buf == NULL || used == NULL || text == NULL || *used >= capacity) {
        return;
    }
    for (i = 0u; text[i] != '\0' && *used + 1u < capacity; ++i) {
        buf[*used] = text[i];
        *used += 1u;
    }
}

static void append_u32(char *buf, size_t capacity, size_t *used, uint32_t value)
{
    char tmp[16];
    size_t pos;
    size_t i;

    if (buf == NULL || used == NULL || *used >= capacity) {
        return;
    }

    if (value == 0u) {
        if (*used + 1u < capacity) {
            buf[*used] = '0';
            *used += 1u;
        }
        return;
    }

    pos = 0u;
    while (value != 0u && pos < sizeof(tmp)) {
        tmp[pos++] = (char)('0' + (value % 10u));
        value /= 10u;
    }

    for (i = 0u; i < pos && *used + 1u < capacity; ++i) {
        buf[*used] = tmp[pos - 1u - i];
        *used += 1u;
    }
}

static void append_hex_ptr(char *buf, size_t capacity, size_t *used, uintptr_t value)
{
    static const char hex[] = "0123456789abcdef";
    int shift;
    int started;

    if (buf == NULL || used == NULL || *used >= capacity) {
        return;
    }

    append_lit(buf, capacity, used, "0x");
    if (value == 0u) {
        append_lit(buf, capacity, used, "0");
        return;
    }

    started = 0;
    for (shift = (int)(sizeof(uintptr_t) * 8u) - 4; shift >= 0; shift -= 4) {
        unsigned nibble = (unsigned)((value >> (unsigned)shift) & 0xFu);
        if (!started && nibble == 0u) {
            continue;
        }
        started = 1;
        if (*used + 1u >= capacity) {
            break;
        }
        buf[*used] = hex[nibble];
        *used += 1u;
    }
}

static void linux_server_fatal_signal_handler(int signo, siginfo_t *info, void *ucontext)
{
    char line[192];
    size_t used;

    (void)ucontext;

    used = 0u;
    append_lit(line, sizeof(line), &used, "fatal signal ");
    append_u32(line, sizeof(line), &used, (uint32_t)signo);
    append_lit(line, sizeof(line), &used, " stage=");
    append_u32(line, sizeof(line), &used, (uint32_t)g_linux_server_stage);
    if (info != NULL) {
        append_lit(line, sizeof(line), &used, " code=");
        append_u32(line, sizeof(line), &used, (uint32_t)info->si_code);
        append_lit(line, sizeof(line), &used, " addr=");
        append_hex_ptr(line, sizeof(line), &used, (uintptr_t)info->si_addr);
    }
    append_lit(line, sizeof(line), &used, "\n");
    if (used > 0u) {
        (void)write(STDERR_FILENO, line, used);
    }
    _exit(128 + signo);
}

static int install_linux_server_fatal_handlers(void)
{
    struct sigaction sa;
    const int signals[] = {SIGSEGV, SIGBUS, SIGILL, SIGABRT, SIGFPE};
    size_t i;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = linux_server_fatal_signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);

    for (i = 0u; i < sizeof(signals) / sizeof(signals[0]); ++i) {
        if (sigaction(signals[i], &sa, NULL) != 0) {
            return SSH_ERR_PLATFORM;
        }
    }
    return SSH_OK;
}

typedef enum crypto_backend {
    CRYPTO_BACKEND_NONE = 0,
    CRYPTO_BACKEND_MBEDTLS,
    CRYPTO_BACKEND_OPENSSL,
    CRYPTO_BACKEND_WOLFSSL
} crypto_backend_t;

typedef enum session_mode {
    SESSION_MODE_SFTP = 0,
    SESSION_MODE_TERMINAL = 1
} session_mode_t;

typedef struct worker_pool {
    pthread_mutex_t lock;
    pthread_cond_t cv;
    unsigned max_workers;
    unsigned active_workers;
} worker_pool_t;

typedef struct program_options {
    const char *root_dir;
    const char *listen_address;
    const char *sshd_config_path;
    const char *passwd_path;
    const char *shadow_path;
    uint16_t port;
    uint32_t timeout_ms;
    unsigned max_workers;
    unsigned worker_stack_kb;
    session_mode_t session_mode;
    crypto_backend_t backend;
    int port_overridden;
    int listen_overridden;
    int timeout_overridden;
} program_options_t;

typedef struct app_shared {
    ssh_posix_net_platform_t net;
    ssh_posix_runtime_t runtime;
    ssh_stdio_fs_t sftp_fs;
    ssh_stdio_fs_t host_fs;
#if defined(EMSSH_BUILD_POSIX_TERM)
    ssh_posix_term_platform_t term;
#endif
    ssh_posix_passwd_auth_t passwd_auth;
    ssh_sshd_config_file_t sshd_config;
    ssh_server_config_t base_server_config;
    ssh_server_session_options_t base_session_options;
    ssh_kexinit_algorithm_set_t base_algorithms;
    uint16_t port;
    session_mode_t session_mode;
    crypto_backend_t backend;
    uint8_t mbedtls_hostkey_private[LINUX_SERVER_MAX_MBEDTLS_HOSTKEY_PRIVATE];
    size_t mbedtls_hostkey_private_len;
} app_shared_t;

typedef struct backend_instance {
    crypto_backend_t type;
    ssh_platform_t platform;
#if EMSSH_LINUX_SERVER_ENABLE_MBEDTLS
    ssh_mbedtls_crypto_t mbedtls;
#endif
#if EMSSH_LINUX_SERVER_ENABLE_OPENSSL
    ssh_openssl_crypto_t openssl;
#endif
#if EMSSH_LINUX_SERVER_ENABLE_WOLFSSL
    ssh_wolfssl_crypto_t wolfssl;
#endif
    int initialized;
} backend_instance_t;

typedef struct worker_task {
    app_shared_t *shared;
    worker_pool_t *pool;
    ssh_posix_conn_t conn;
} worker_task_t;

static void usage(const char *program)
{
    fprintf(
        stderr,
        "usage: %s [options]\n"
        "  --root-dir <path>        SFTP root (default: .)\n"
        "  --port <1-65535>         Listen port (default: 2222)\n"
        "  --listen <addr>          Listen address (default: from sshd_config or any)\n"
        "  --sshd-config <path>     OpenSSH-compatible sshd_config (read via stdio_fs rooted at /)\n"
        "  --passwd-file <path>     passwd file (default: /etc/passwd)\n"
        "  --shadow-file <path>     shadow file (default: /etc/shadow)\n"
        "  --timeout-ms <ms>        Session timeout (default: 30000)\n"
        "  --max-workers <n>        Parallel worker threads (default: 16)\n"
        "  --worker-stack-kb <n>    Worker thread stack size in KB (default: 1024)\n"
        "  --session-mode <mode>    sftp|terminal (default: sftp)\n"
        "  --backend <name>         mbedtls|openssl|wolfssl (compiled backends only)\n",
        program);
}

static int parse_port(const char *text, uint16_t *port)
{
    unsigned long value;
    char *end;

    if (text == NULL || port == NULL || text[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    value = strtoul(text, &end, 10);
    if (*end != '\0' || value == 0ul || value > 65535ul) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *port = (uint16_t)value;
    return SSH_OK;
}

static int parse_u32(const char *text, uint32_t *value_out)
{
    unsigned long value;
    char *end;

    if (text == NULL || value_out == NULL || text[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    value = strtoul(text, &end, 10);
    if (*end != '\0' || value > 0xfffffffful) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *value_out = (uint32_t)value;
    return SSH_OK;
}

static int parse_positive_unsigned(const char *text, unsigned *value_out)
{
    unsigned long value;
    char *end;

    if (text == NULL || value_out == NULL || text[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    value = strtoul(text, &end, 10);
    if (*end != '\0' || value == 0ul || value > 1000000ul) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *value_out = (unsigned)value;
    return SSH_OK;
}

static crypto_backend_t default_backend(void)
{
#if EMSSH_LINUX_SERVER_ENABLE_MBEDTLS
    return CRYPTO_BACKEND_MBEDTLS;
#elif EMSSH_LINUX_SERVER_ENABLE_OPENSSL
    return CRYPTO_BACKEND_OPENSSL;
#elif EMSSH_LINUX_SERVER_ENABLE_WOLFSSL
    return CRYPTO_BACKEND_WOLFSSL;
#else
    return CRYPTO_BACKEND_NONE;
#endif
}

static const char *backend_name(crypto_backend_t backend)
{
    switch (backend) {
    case CRYPTO_BACKEND_MBEDTLS:
        return "mbedtls";
    case CRYPTO_BACKEND_OPENSSL:
        return "openssl";
    case CRYPTO_BACKEND_WOLFSSL:
        return "wolfssl";
    default:
        return "unknown";
    }
}

static const char *session_mode_name(session_mode_t mode)
{
    return mode == SESSION_MODE_TERMINAL ? "terminal" : "sftp";
}

static int parse_session_mode(const char *text, session_mode_t *mode)
{
    if (text == NULL || mode == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (strcmp(text, "sftp") == 0) {
        *mode = SESSION_MODE_SFTP;
        return SSH_OK;
    }
    if (strcmp(text, "terminal") == 0) {
        *mode = SESSION_MODE_TERMINAL;
        return SSH_OK;
    }
    return SSH_ERR_INVALID_ARGUMENT;
}

static int parse_backend(const char *text, crypto_backend_t *backend)
{
    if (text == NULL || backend == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (strcmp(text, "mbedtls") == 0) {
#if EMSSH_LINUX_SERVER_ENABLE_MBEDTLS
        *backend = CRYPTO_BACKEND_MBEDTLS;
        return SSH_OK;
#else
        return SSH_ERR_UNSUPPORTED;
#endif
    }
    if (strcmp(text, "openssl") == 0) {
#if EMSSH_LINUX_SERVER_ENABLE_OPENSSL
        *backend = CRYPTO_BACKEND_OPENSSL;
        return SSH_OK;
#else
        return SSH_ERR_UNSUPPORTED;
#endif
    }
    if (strcmp(text, "wolfssl") == 0) {
#if EMSSH_LINUX_SERVER_ENABLE_WOLFSSL
        *backend = CRYPTO_BACKEND_WOLFSSL;
        return SSH_OK;
#else
        return SSH_ERR_UNSUPPORTED;
#endif
    }

    return SSH_ERR_INVALID_ARGUMENT;
}

static int normalize_host_fs_path(const char *input, char out[LINUX_SERVER_MAX_PATH])
{
    const char *p;
    size_t len;

    if (input == NULL || out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    p = input;
    while (*p == '/') {
        ++p;
    }
    if (*p == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    len = strlen(p);
    if (len + 1u > LINUX_SERVER_MAX_PATH) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(out, p, len + 1u);
    return SSH_OK;
}

static void options_defaults(program_options_t *opts)
{
    memset(opts, 0, sizeof(*opts));
    opts->root_dir = ".";
    opts->listen_address = NULL;
    opts->sshd_config_path = NULL;
    opts->passwd_path = "/etc/passwd";
    opts->shadow_path = "/etc/shadow";
    opts->port = LINUX_SERVER_DEFAULT_PORT;
    opts->timeout_ms = LINUX_SERVER_DEFAULT_TIMEOUT_MS;
    opts->max_workers = LINUX_SERVER_DEFAULT_MAX_WORKERS;
    opts->worker_stack_kb = LINUX_SERVER_DEFAULT_WORKER_STACK_KB;
    opts->session_mode = SESSION_MODE_SFTP;
    opts->backend = default_backend();
}

static int parse_args(int argc, char **argv, program_options_t *opts)
{
    int i;
    int status;

    if (opts == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    options_defaults(opts);
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--root-dir") == 0) {
            if (i + 1 >= argc) {
                return SSH_ERR_INVALID_ARGUMENT;
            }
            opts->root_dir = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--port") == 0) {
            if (i + 1 >= argc) {
                return SSH_ERR_INVALID_ARGUMENT;
            }
            status = parse_port(argv[++i], &opts->port);
            if (status != SSH_OK) {
                return status;
            }
            opts->port_overridden = 1;
            continue;
        }
        if (strcmp(argv[i], "--listen") == 0) {
            if (i + 1 >= argc) {
                return SSH_ERR_INVALID_ARGUMENT;
            }
            opts->listen_address = argv[++i];
            opts->listen_overridden = 1;
            continue;
        }
        if (strcmp(argv[i], "--sshd-config") == 0) {
            if (i + 1 >= argc) {
                return SSH_ERR_INVALID_ARGUMENT;
            }
            opts->sshd_config_path = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--passwd-file") == 0) {
            if (i + 1 >= argc) {
                return SSH_ERR_INVALID_ARGUMENT;
            }
            opts->passwd_path = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--shadow-file") == 0) {
            if (i + 1 >= argc) {
                return SSH_ERR_INVALID_ARGUMENT;
            }
            opts->shadow_path = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--timeout-ms") == 0) {
            if (i + 1 >= argc) {
                return SSH_ERR_INVALID_ARGUMENT;
            }
            status = parse_u32(argv[++i], &opts->timeout_ms);
            if (status != SSH_OK) {
                return status;
            }
            opts->timeout_overridden = 1;
            continue;
        }
        if (strcmp(argv[i], "--max-workers") == 0) {
            status = (i + 1 < argc) ? SSH_OK : SSH_ERR_INVALID_ARGUMENT;
            if (status != SSH_OK) {
                return status;
            }
            status = parse_positive_unsigned(argv[++i], &opts->max_workers);
            if (status != SSH_OK) {
                return status;
            }
            continue;
        }
        if (strcmp(argv[i], "--worker-stack-kb") == 0) {
            status = (i + 1 < argc) ? SSH_OK : SSH_ERR_INVALID_ARGUMENT;
            if (status != SSH_OK) {
                return status;
            }
            status = parse_positive_unsigned(argv[++i], &opts->worker_stack_kb);
            if (status != SSH_OK) {
                return status;
            }
            continue;
        }
        if (strcmp(argv[i], "--backend") == 0) {
            if (i + 1 >= argc) {
                return SSH_ERR_INVALID_ARGUMENT;
            }
            status = parse_backend(argv[++i], &opts->backend);
            if (status != SSH_OK) {
                return status;
            }
            continue;
        }
        if (strcmp(argv[i], "--session-mode") == 0) {
            if (i + 1 >= argc) {
                return SSH_ERR_INVALID_ARGUMENT;
            }
            status = parse_session_mode(argv[++i], &opts->session_mode);
            if (status != SSH_OK) {
                return status;
            }
            continue;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            return SSH_ERR_UNSUPPORTED;
        }
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (opts->backend == CRYPTO_BACKEND_NONE) {
        return SSH_ERR_UNSUPPORTED;
    }
    return SSH_OK;
}

static int worker_pool_init(worker_pool_t *pool, unsigned max_workers)
{
    if (pool == NULL || max_workers == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(pool, 0, sizeof(*pool));
    pool->max_workers = max_workers;
    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        return SSH_ERR_PLATFORM;
    }
    if (pthread_cond_init(&pool->cv, NULL) != 0) {
        pthread_mutex_destroy(&pool->lock);
        return SSH_ERR_PLATFORM;
    }
    return SSH_OK;
}

static void worker_pool_deinit(worker_pool_t *pool)
{
    if (pool == NULL) {
        return;
    }

    pthread_cond_destroy(&pool->cv);
    pthread_mutex_destroy(&pool->lock);
    memset(pool, 0, sizeof(*pool));
}

static void worker_pool_reserve_slot(worker_pool_t *pool)
{
    pthread_mutex_lock(&pool->lock);
    while (pool->active_workers >= pool->max_workers) {
        pthread_cond_wait(&pool->cv, &pool->lock);
    }
    ++pool->active_workers;
    pthread_mutex_unlock(&pool->lock);
}

static void worker_pool_release_slot(worker_pool_t *pool)
{
    pthread_mutex_lock(&pool->lock);
    if (pool->active_workers > 0u) {
        --pool->active_workers;
    }
    pthread_cond_broadcast(&pool->cv);
    pthread_mutex_unlock(&pool->lock);
}

static void backend_instance_deinit(backend_instance_t *backend)
{
    if (backend == NULL || !backend->initialized) {
        return;
    }

    switch (backend->type) {
#if EMSSH_LINUX_SERVER_ENABLE_MBEDTLS
    case CRYPTO_BACKEND_MBEDTLS:
        ssh_mbedtls_crypto_free(&backend->mbedtls);
        break;
#endif
#if EMSSH_LINUX_SERVER_ENABLE_OPENSSL
    case CRYPTO_BACKEND_OPENSSL:
        ssh_openssl_crypto_free(&backend->openssl);
        break;
#endif
#if EMSSH_LINUX_SERVER_ENABLE_WOLFSSL
    case CRYPTO_BACKEND_WOLFSSL:
        ssh_wolfssl_crypto_free(&backend->wolfssl);
        break;
#endif
    default:
        break;
    }

    memset(backend, 0, sizeof(*backend));
}

static int backend_instance_init(backend_instance_t *backend, const app_shared_t *shared)
{
    int status;

    if (backend == NULL || shared == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(backend, 0, sizeof(*backend));
    backend->type = shared->backend;
    backend->platform.net = ssh_posix_net_api((ssh_posix_net_platform_t *)&shared->net);
    backend->platform.fs = ssh_stdio_fs_api((ssh_stdio_fs_t *)&shared->sftp_fs);
    backend->platform.mem = ssh_posix_mem_api((ssh_posix_runtime_t *)&shared->runtime);
    backend->platform.time = ssh_posix_time_api((ssh_posix_runtime_t *)&shared->runtime);
    backend->platform.log = ssh_posix_log_api((ssh_posix_runtime_t *)&shared->runtime);
#if defined(EMSSH_BUILD_POSIX_TERM)
    backend->platform.term = shared->session_mode == SESSION_MODE_TERMINAL ? ssh_posix_term_api((ssh_posix_term_platform_t *)&shared->term) : NULL;
#else
    backend->platform.term = NULL;
#endif

    switch (backend->type) {
#if EMSSH_LINUX_SERVER_ENABLE_MBEDTLS
    case CRYPTO_BACKEND_MBEDTLS:
        status = ssh_mbedtls_crypto_init(&backend->mbedtls);
        if (status != SSH_OK) {
            return status;
        }
        status = ssh_mbedtls_crypto_import_ecdsa_p256_hostkey(
            &backend->mbedtls,
            shared->mbedtls_hostkey_private,
            shared->mbedtls_hostkey_private_len);
        if (status != SSH_OK) {
            ssh_mbedtls_crypto_free(&backend->mbedtls);
            return status;
        }
        backend->platform.crypto = ssh_mbedtls_crypto_api(&backend->mbedtls);
        backend->platform.rng = ssh_mbedtls_rng_api(&backend->mbedtls);
        break;
#endif
#if EMSSH_LINUX_SERVER_ENABLE_OPENSSL
    case CRYPTO_BACKEND_OPENSSL:
        status = ssh_openssl_crypto_init(&backend->openssl);
        if (status != SSH_OK) {
            return status;
        }
        backend->platform.crypto = ssh_openssl_crypto_api(&backend->openssl);
        backend->platform.rng = ssh_openssl_rng_api(&backend->openssl);
        break;
#endif
#if EMSSH_LINUX_SERVER_ENABLE_WOLFSSL
    case CRYPTO_BACKEND_WOLFSSL:
        status = ssh_wolfssl_crypto_init(&backend->wolfssl);
        if (status != SSH_OK) {
            return status;
        }
        backend->platform.crypto = ssh_wolfssl_crypto_api(&backend->wolfssl);
        backend->platform.rng = ssh_wolfssl_rng_api(&backend->wolfssl);
        break;
#endif
    default:
        return SSH_ERR_UNSUPPORTED;
    }

    backend->initialized = 1;
    return SSH_OK;
}

static int prepare_mbedtls_hostkey_if_needed(app_shared_t *shared)
{
#if EMSSH_LINUX_SERVER_ENABLE_MBEDTLS
    ssh_mbedtls_crypto_t bootstrap;
    int status;

    if (shared->backend != CRYPTO_BACKEND_MBEDTLS) {
        return SSH_OK;
    }

    memset(&bootstrap, 0, sizeof(bootstrap));
    status = ssh_mbedtls_crypto_init(&bootstrap);
    if (status != SSH_OK) {
        return status;
    }
    status = ssh_mbedtls_crypto_generate_ecdsa_p256_hostkey(&bootstrap);
    if (status == SSH_OK) {
        status = ssh_mbedtls_crypto_export_hostkey_private(
            &bootstrap,
            shared->mbedtls_hostkey_private,
            sizeof(shared->mbedtls_hostkey_private),
            &shared->mbedtls_hostkey_private_len);
    }
    ssh_mbedtls_crypto_free(&bootstrap);
    return status;
#else
    (void)shared;
    return SSH_OK;
#endif
}

static void set_backend_kex_defaults(crypto_backend_t backend, ssh_kexinit_algorithm_set_t *algorithms)
{
    if (algorithms == NULL) {
        return;
    }

    switch (backend) {
#if EMSSH_LINUX_SERVER_ENABLE_MBEDTLS
    case CRYPTO_BACKEND_MBEDTLS:
        ssh_mbedtls_kexinit_algorithm_set_defaults(algorithms);
        return;
#endif
#if EMSSH_LINUX_SERVER_ENABLE_OPENSSL
    case CRYPTO_BACKEND_OPENSSL:
        ssh_openssl_kexinit_algorithm_set_defaults(algorithms);
        return;
#endif
#if EMSSH_LINUX_SERVER_ENABLE_WOLFSSL
    case CRYPTO_BACKEND_WOLFSSL:
        ssh_wolfssl_kexinit_algorithm_set_defaults(algorithms);
        return;
#endif
    default:
        memset(algorithms, 0, sizeof(*algorithms));
        return;
    }
}

static int initialize_server_templates(
    app_shared_t *shared,
    const program_options_t *opts,
    const char *sshd_config_path_normalized)
{
    int status;

    if (shared == NULL || opts == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_server_config_defaults(&shared->base_server_config);
    ssh_server_session_options_defaults(&shared->base_session_options);
    set_backend_kex_defaults(shared->backend, &shared->base_algorithms);
    shared->base_session_options.algorithms = &shared->base_algorithms;
    shared->base_session_options.timeout_ms = LINUX_SERVER_DEFAULT_TIMEOUT_MS;
    shared->port = LINUX_SERVER_DEFAULT_PORT;

    if (sshd_config_path_normalized != NULL) {
        ssh_sshd_config_file_defaults(&shared->sshd_config);
        status = ssh_sshd_config_file_load(
            ssh_stdio_fs_api(&shared->host_fs),
            sshd_config_path_normalized,
            &shared->sshd_config);
        if (status != SSH_OK) {
            return status;
        }
        status = ssh_sshd_config_file_apply(
            &shared->sshd_config,
            &shared->base_server_config,
            &shared->base_session_options,
            &shared->base_algorithms,
            &shared->port);
        if (status != SSH_OK) {
            return status;
        }
    }

    if (opts->port_overridden) {
        shared->port = opts->port;
    }
    if (opts->listen_overridden) {
        shared->base_server_config.listen_address = opts->listen_address;
    }
    if (opts->timeout_overridden) {
        shared->base_session_options.timeout_ms = opts->timeout_ms;
    }

    shared->base_server_config.password_auth = ssh_posix_passwd_auth_cb;
    shared->base_server_config.auth_ctx = &shared->passwd_auth;
    return SSH_OK;
}

static int request_type_is(const ssh_channel_request_t *request, const char *request_type)
{
    size_t len;

    if (request == NULL || request_type == NULL || request->request_type.data == NULL) {
        return 0;
    }
    len = strlen(request_type);
    return request->request_type.len == len &&
           memcmp(request->request_type.data, request_type, len) == 0;
}

static int view_to_printable(const ssh_string_view_t view, char *out, size_t out_capacity)
{
    size_t copy_len;

    if (out == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (view.data == NULL) {
        out[0] = '\0';
        return SSH_OK;
    }

    copy_len = view.len;
    if (copy_len + 1u > out_capacity) {
        copy_len = out_capacity - 1u;
    }
    memcpy(out, view.data, copy_len);
    out[copy_len] = '\0';
    return copy_len == view.len ? SSH_OK : SSH_ERR_BUFFER_TOO_SMALL;
}

static int log_non_sftp_channel_request_policy(void *ctx, const ssh_channel_request_t *request)
{
    const ssh_posix_conn_t *conn = (const ssh_posix_conn_t *)ctx;
    const char *peer = ssh_posix_conn_peer_address(conn);
    char request_type[64];
    int type_status;

    if (request == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    set_linux_server_stage(LINUX_STAGE_WORKER_NON_SFTP_REQUEST);

    type_status = view_to_printable(request->request_type, request_type, sizeof(request_type));
    if (request_type_is(request, LINUX_SERVER_PUTTY_REQ_SIMPLE) ||
        request_type_is(request, LINUX_SERVER_PUTTY_REQ_WINADJ)) {
        fprintf(
            stderr,
            "ignored putty channel extension from %s: type=%s%s\n",
            peer != NULL ? peer : "unknown",
            request_type[0] != '\0' ? request_type : "(empty)",
            type_status == SSH_ERR_BUFFER_TOO_SMALL ? "..." : "");
        return SSH_OK;
    }

    if (request_type_is(request, SSH_CHANNEL_REQUEST_PTY_REQ) ||
        request_type_is(request, SSH_CHANNEL_REQUEST_SHELL) ||
        request_type_is(request, SSH_CHANNEL_REQUEST_EXEC) ||
        request_type_is(request, SSH_CHANNEL_REQUEST_ENV) ||
        request_type_is(request, SSH_CHANNEL_REQUEST_WINDOW_CHANGE) ||
        request_type_is(request, SSH_CHANNEL_REQUEST_SIGNAL)) {
        fprintf(
            stderr,
            "ignored non-sftp channel request from %s: type=%s%s\n",
            peer != NULL ? peer : "unknown",
            request_type[0] != '\0' ? request_type : "(empty)",
            type_status == SSH_ERR_BUFFER_TOO_SMALL ? "..." : "");

        if (request_type_is(request, SSH_CHANNEL_REQUEST_EXEC)) {
            char command[128];
            int status = view_to_printable(request->command, command, sizeof(command));
            fprintf(
                stderr,
                "  exec=%s%s\n",
                command[0] != '\0' ? command : "(empty)",
                status == SSH_ERR_BUFFER_TOO_SMALL ? "..." : "");
        } else if (request_type_is(request, SSH_CHANNEL_REQUEST_ENV)) {
            char env_name[64];
            int name_status = view_to_printable(request->env_name, env_name, sizeof(env_name));
            fprintf(
                stderr,
                "  env=%s%s value_len=%lu\n",
                env_name[0] != '\0' ? env_name : "(empty)",
                name_status == SSH_ERR_BUFFER_TOO_SMALL ? "..." : "",
                (unsigned long)request->env_value.len);
        } else if (request_type_is(request, SSH_CHANNEL_REQUEST_PTY_REQ)) {
            char term_type[64];
            int status = view_to_printable(request->term_type, term_type, sizeof(term_type));
            fprintf(
                stderr,
                "  pty term=%s%s cols=%lu rows=%lu width_px=%lu height_px=%lu\n",
                term_type[0] != '\0' ? term_type : "(empty)",
                status == SSH_ERR_BUFFER_TOO_SMALL ? "..." : "",
                (unsigned long)request->cols,
                (unsigned long)request->rows,
                (unsigned long)request->width_px,
                (unsigned long)request->height_px);
        } else if (request_type_is(request, SSH_CHANNEL_REQUEST_WINDOW_CHANGE)) {
            fprintf(
                stderr,
                "  window-change cols=%lu rows=%lu width_px=%lu height_px=%lu\n",
                (unsigned long)request->cols,
                (unsigned long)request->rows,
                (unsigned long)request->width_px,
                (unsigned long)request->height_px);
        } else if (request_type_is(request, SSH_CHANNEL_REQUEST_SIGNAL)) {
            char signal_name[64];
            int status = view_to_printable(request->signal_name, signal_name, sizeof(signal_name));
            fprintf(
                stderr,
                "  signal=%s%s\n",
                signal_name[0] != '\0' ? signal_name : "(empty)",
                status == SSH_ERR_BUFFER_TOO_SMALL ? "..." : "");
        }
        return SSH_OK;
    }

    fprintf(
        stderr,
        "unsupported channel request from %s: type=%s%s\n",
        peer != NULL ? peer : "unknown",
        request_type[0] != '\0' ? request_type : "(empty)",
        type_status == SSH_ERR_BUFFER_TOO_SMALL ? "..." : "");

    if (request_type_is(request, SSH_CHANNEL_REQUEST_SUBSYSTEM)) {
        char subsystem[64];
        int status = view_to_printable(request->subsystem_name, subsystem, sizeof(subsystem));
        fprintf(
            stderr,
            "  subsystem=%s%s\n",
            subsystem[0] != '\0' ? subsystem : "(empty)",
            status == SSH_ERR_BUFFER_TOO_SMALL ? "..." : "");
    }

    return SSH_ERR_UNSUPPORTED;
}

static int run_worker_session(app_shared_t *shared, ssh_posix_conn_t *conn)
{
    backend_instance_t backend;
    ssh_server_t server;
    ssh_server_config_t config;
    ssh_server_session_options_t options;
    int status;
    int initialized_server;

    if (shared == NULL || conn == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    set_linux_server_stage(LINUX_STAGE_WORKER_START);

    memset(&backend, 0, sizeof(backend));
    memset(&server, 0, sizeof(server));
    initialized_server = 0;

    status = backend_instance_init(&backend, shared);
    if (status != SSH_OK) {
        return status;
    }
    set_linux_server_stage(LINUX_STAGE_WORKER_BACKEND_INIT);

    config = shared->base_server_config;
    options = shared->base_session_options;
    if (shared->session_mode == SESSION_MODE_SFTP) {
        options.non_sftp_channel_request_policy = log_non_sftp_channel_request_policy;
        options.non_sftp_channel_request_policy_ctx = conn;
    }
    status = ssh_server_init(&server, &backend.platform, &config);
    if (status != SSH_OK) {
        backend_instance_deinit(&backend);
        return status;
    }
    set_linux_server_stage(LINUX_STAGE_WORKER_SERVER_INIT);
    initialized_server = 1;

    set_linux_server_stage(LINUX_STAGE_WORKER_RUN_SFTP);
    if (shared->session_mode == SESSION_MODE_TERMINAL) {
        status = ssh_server_run_terminal_session(&server, conn, &options);
    } else {
        status = ssh_server_run_sftp_session(&server, conn, &options);
    }
    if (status != SSH_OK) {
        const char *peer = ssh_posix_conn_peer_address(conn);
        fprintf(stderr, "session %s ended: %s\n", peer != NULL ? peer : "unknown", ssh_status_string(status));
        if (status == SSH_ERR_UNSUPPORTED && shared->session_mode == SESSION_MODE_SFTP) {
            fprintf(stderr, "hint: this example serves SFTP subsystem only; use an SFTP client/session.\n");
        } else if (status == SSH_ERR_UNSUPPORTED && shared->session_mode == SESSION_MODE_TERMINAL) {
            fprintf(stderr, "hint: terminal mode expects shell/exec channel requests.\n");
        }
    }

    if (initialized_server) {
        ssh_server_deinit(&server);
    }
    backend_instance_deinit(&backend);
    set_linux_server_stage(LINUX_STAGE_WORKER_DONE);
    return status;
}

static void *worker_main(void *arg)
{
    worker_task_t *task = (worker_task_t *)arg;

    if (task != NULL) {
        (void)run_worker_session(task->shared, &task->conn);
        (void)ssh_posix_conn_close(&task->shared->net, &task->conn);
        worker_pool_release_slot(task->pool);
        free(task);
    }

    return NULL;
}

int main(int argc, char **argv)
{
    program_options_t opts;
    app_shared_t shared;
    worker_pool_t pool;
    ssh_posix_listener_t listener;
    char passwd_path_normalized[LINUX_SERVER_MAX_PATH];
    char shadow_path_normalized[LINUX_SERVER_MAX_PATH];
    char sshd_config_path_normalized[LINUX_SERVER_MAX_PATH];
    const char *sshd_config_effective_path;
    int status;
    int initialized_runtime;
    int initialized_net;
    int initialized_sftp_fs;
    int initialized_host_fs;
    int initialized_term;
    int initialized_passwd_auth;
    int initialized_pool;
    size_t worker_stack_size_bytes;

    status = parse_args(argc, argv, &opts);
    if (status == SSH_ERR_UNSUPPORTED) {
        usage(argv[0]);
        return 0;
    }
    if (status != SSH_OK) {
        usage(argv[0]);
        return 2;
    }
    status = install_linux_server_fatal_handlers();
    if (status != SSH_OK) {
        fprintf(stderr, "fatal handler install failed: %s\n", ssh_status_string(status));
        return 2;
    }
    fprintf(stderr, "diag: fatal signal handlers installed\n");
    set_linux_server_stage(LINUX_STAGE_MAIN_INIT);
    if (getenv("EMSSH_DIAG_CRASH") != NULL) {
        volatile int *crash = (volatile int *)0;
        *crash = 1;
    }

    memset(&shared, 0, sizeof(shared));
    memset(&pool, 0, sizeof(pool));
    memset(&listener, 0, sizeof(listener));
    initialized_runtime = 0;
    initialized_net = 0;
    initialized_sftp_fs = 0;
    initialized_host_fs = 0;
    initialized_term = 0;
    initialized_passwd_auth = 0;
    initialized_pool = 0;
    shared.backend = opts.backend;
    shared.session_mode = opts.session_mode;
    if (opts.worker_stack_kb > (unsigned)(SIZE_MAX / 1024u)) {
        fprintf(stderr, "invalid --worker-stack-kb value: overflow\n");
        return 2;
    }
    worker_stack_size_bytes = (size_t)opts.worker_stack_kb * 1024u;
#if defined(PTHREAD_STACK_MIN)
    if (worker_stack_size_bytes < (size_t)PTHREAD_STACK_MIN) {
        worker_stack_size_bytes = (size_t)PTHREAD_STACK_MIN;
        fprintf(
            stderr,
            "note: worker stack adjusted to pthread minimum: %lu bytes\n",
            (unsigned long)worker_stack_size_bytes);
    }
#endif

    status = normalize_host_fs_path(opts.passwd_path, passwd_path_normalized);
    if (status != SSH_OK) {
        fprintf(stderr, "invalid --passwd-file path: %s\n", opts.passwd_path);
        goto cleanup;
    }
    status = normalize_host_fs_path(opts.shadow_path, shadow_path_normalized);
    if (status != SSH_OK) {
        fprintf(stderr, "invalid --shadow-file path: %s\n", opts.shadow_path);
        goto cleanup;
    }
    sshd_config_effective_path = NULL;
    if (opts.sshd_config_path != NULL) {
        status = normalize_host_fs_path(opts.sshd_config_path, sshd_config_path_normalized);
        if (status != SSH_OK) {
            fprintf(stderr, "invalid --sshd-config path: %s\n", opts.sshd_config_path);
            goto cleanup;
        }
        sshd_config_effective_path = sshd_config_path_normalized;
    }

    status = ssh_posix_runtime_init(&shared.runtime, NULL, NULL);
    if (status != SSH_OK) {
        fprintf(stderr, "posix runtime init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_runtime = 1;

    status = ssh_posix_net_platform_init(&shared.net);
    if (status != SSH_OK) {
        fprintf(stderr, "posix net init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_net = 1;

    status = ssh_stdio_fs_init(&shared.sftp_fs, opts.root_dir);
    if (status != SSH_OK) {
        fprintf(stderr, "stdio fs (sftp root) init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_sftp_fs = 1;

    status = ssh_stdio_fs_init(&shared.host_fs, "/");
    if (status != SSH_OK) {
        fprintf(stderr, "stdio fs (host root) init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_host_fs = 1;

    if (opts.session_mode == SESSION_MODE_TERMINAL) {
#if defined(EMSSH_BUILD_POSIX_TERM)
        status = ssh_posix_term_platform_init(&shared.term);
        if (status != SSH_OK) {
            fprintf(stderr, "posix term init failed: %s\n", ssh_status_string(status));
            goto cleanup;
        }
        initialized_term = 1;
#else
        fprintf(stderr, "terminal mode not compiled: enable EMSSH_BUILD_POSIX_TERM=ON\n");
        status = SSH_ERR_UNSUPPORTED;
        goto cleanup;
#endif
    }

    status = ssh_posix_passwd_auth_init(
        &shared.passwd_auth,
        ssh_stdio_fs_api(&shared.host_fs),
        passwd_path_normalized,
        shadow_path_normalized);
    if (status != SSH_OK) {
        fprintf(stderr, "posix passwd auth init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_passwd_auth = 1;

    status = initialize_server_templates(&shared, &opts, sshd_config_effective_path);
    if (status != SSH_OK) {
        fprintf(stderr, "server template init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }

    status = prepare_mbedtls_hostkey_if_needed(&shared);
    if (status != SSH_OK) {
        fprintf(stderr, "backend hostkey prepare failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }

    status = worker_pool_init(&pool, opts.max_workers);
    if (status != SSH_OK) {
        fprintf(stderr, "worker pool init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_pool = 1;

    status = ssh_posix_listen(
        &shared.net,
        shared.base_server_config.listen_address,
        shared.port,
        (int)opts.max_workers,
        &listener);
    if (status != SSH_OK) {
        fprintf(stderr, "listen failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }

    printf(
        "linux posix+stdio server listening on %s:%u, backend=%s, mode=%s, max-workers=%u, worker-stack=%luKB\n",
        shared.base_server_config.listen_address != NULL ? shared.base_server_config.listen_address : "0.0.0.0",
        (unsigned)shared.port,
        backend_name(shared.backend),
        session_mode_name(shared.session_mode),
        opts.max_workers,
        (unsigned long)(worker_stack_size_bytes / 1024u));
    printf("note: command line overrides sshd_config for overlapping parameters.\n");
    fflush(stdout);
    set_linux_server_stage(LINUX_STAGE_MAIN_LISTEN);

    for (;;) {
        ssh_posix_conn_t conn;
        worker_task_t *task;
        pthread_attr_t thread_attr;
        pthread_t thread;
        int attr_status;
        int create_status;

        memset(&conn, 0, sizeof(conn));
        worker_pool_reserve_slot(&pool);
        set_linux_server_stage(LINUX_STAGE_MAIN_ACCEPT_WAIT);
        status = ssh_posix_accept(&shared.net, &listener, &conn, 0u);
        if (status != SSH_OK) {
            worker_pool_release_slot(&pool);
            fprintf(stderr, "accept failed: %s\n", ssh_status_string(status));
            continue;
        }
        set_linux_server_stage(LINUX_STAGE_MAIN_ACCEPTED);

        task = (worker_task_t *)malloc(sizeof(*task));
        if (task == NULL) {
            (void)ssh_posix_conn_close(&shared.net, &conn);
            worker_pool_release_slot(&pool);
            fprintf(stderr, "worker alloc failed\n");
            continue;
        }

        memset(task, 0, sizeof(*task));
        task->shared = &shared;
        task->pool = &pool;
        task->conn = conn;

        attr_status = pthread_attr_init(&thread_attr);
        if (attr_status != 0) {
            (void)ssh_posix_conn_close(&shared.net, &task->conn);
            worker_pool_release_slot(&pool);
            free(task);
            fprintf(stderr, "pthread_attr_init failed\n");
            continue;
        }

        attr_status = pthread_attr_setstacksize(&thread_attr, worker_stack_size_bytes);
        if (attr_status != 0) {
            (void)pthread_attr_destroy(&thread_attr);
            (void)ssh_posix_conn_close(&shared.net, &task->conn);
            worker_pool_release_slot(&pool);
            free(task);
            fprintf(stderr, "pthread_attr_setstacksize failed (size=%lu bytes)\n", (unsigned long)worker_stack_size_bytes);
            continue;
        }

        create_status = pthread_create(&thread, &thread_attr, worker_main, task);
        (void)pthread_attr_destroy(&thread_attr);
        if (create_status != 0) {
            (void)ssh_posix_conn_close(&shared.net, &task->conn);
            worker_pool_release_slot(&pool);
            free(task);
            fprintf(stderr, "pthread_create failed\n");
            continue;
        }

        (void)pthread_detach(thread);
    }

cleanup:
    (void)ssh_posix_listener_close(&shared.net, &listener);
    if (initialized_pool) {
        worker_pool_deinit(&pool);
    }
    if (initialized_passwd_auth) {
        ssh_posix_passwd_auth_deinit(&shared.passwd_auth);
    }
    if (initialized_host_fs) {
        ssh_stdio_fs_deinit(&shared.host_fs);
    }
    if (initialized_term) {
#if defined(EMSSH_BUILD_POSIX_TERM)
        ssh_posix_term_platform_deinit(&shared.term);
#endif
    }
    if (initialized_sftp_fs) {
        ssh_stdio_fs_deinit(&shared.sftp_fs);
    }
    if (initialized_net) {
        ssh_posix_net_platform_deinit(&shared.net);
    }
    if (initialized_runtime) {
        ssh_posix_runtime_deinit(&shared.runtime);
    }

    return status == SSH_OK ? 0 : 1;
}
