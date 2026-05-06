#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "emssh/platform_posix_net.h"
#include "emssh/platform_posix_passwd_auth.h"
#include "emssh/platform_posix_runtime.h"
#include "emssh/platform_stdio_fs.h"
#include "emssh/sshd_config_file.h"
#include "emssh/ssh_error.h"
#include "emssh/ssh_server.h"

#if defined(EMSSH_USE_MBEDTLS)
#include "emssh/crypto_mbedtls.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#if !defined(_WIN32)
#include <sys/random.h>
#endif
#include <unistd.h>
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

#if defined(EMSSH_USE_MBEDTLS)
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    size_t total;
    int fd;

    (void)data;

    if (output == NULL || olen == NULL) {
        return -1;
    }

    *olen = 0u;
    if (len == 0u) {
        return 0;
    }

    total = 0u;

#if !defined(_WIN32)
    /* Prefer getrandom() when available. */
    while (total < len) {
        ssize_t n = getrandom(output + total, len - total, 0u);
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == ENOSYS || errno == EAGAIN)) {
            break;
        }
        if (n <= 0) {
            break;
        }
    }
    if (total == len) {
        *olen = total;
        return 0;
    }
#endif

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        fd = open("/dev/random", O_RDONLY);
        if (fd < 0) {
            *olen = total;
            return -1;
        }
    }

    while (total < len) {
        ssize_t n = read(fd, output + total, len - total);
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        if (n == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        (void)close(fd);
        *olen = total;
        return -1;
    }

    (void)close(fd);
    *olen = total;
    return total == len ? 0 : -1;
}
#endif

#define LINUX_SERVER_DEFAULT_PORT 2222u
#define LINUX_SERVER_DEFAULT_TIMEOUT_MS 30000u
#define LINUX_SERVER_DEFAULT_MAX_WORKERS 16u
#define LINUX_SERVER_MAX_PATH 512u
#define LINUX_SERVER_MAX_MBEDTLS_HOSTKEY_PRIVATE 128u

typedef enum crypto_backend {
    CRYPTO_BACKEND_NONE = 0,
    CRYPTO_BACKEND_MBEDTLS,
    CRYPTO_BACKEND_OPENSSL,
    CRYPTO_BACKEND_WOLFSSL
} crypto_backend_t;

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
    ssh_posix_passwd_auth_t passwd_auth;
    ssh_sshd_config_file_t sshd_config;
    ssh_server_config_t base_server_config;
    ssh_server_session_options_t base_session_options;
    ssh_kexinit_algorithm_set_t base_algorithms;
    uint16_t port;
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
    backend->platform.term = NULL;

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

    memset(&backend, 0, sizeof(backend));
    memset(&server, 0, sizeof(server));
    initialized_server = 0;

    status = backend_instance_init(&backend, shared);
    if (status != SSH_OK) {
        return status;
    }

    config = shared->base_server_config;
    options = shared->base_session_options;
    status = ssh_server_init(&server, &backend.platform, &config);
    if (status != SSH_OK) {
        backend_instance_deinit(&backend);
        return status;
    }
    initialized_server = 1;

    status = ssh_server_run_sftp_session(&server, conn, &options);
    if (status != SSH_OK) {
        const char *peer = ssh_posix_conn_peer_address(conn);
        fprintf(stderr, "session %s ended: %s\n", peer != NULL ? peer : "unknown", ssh_status_string(status));
    }

    if (initialized_server) {
        ssh_server_deinit(&server);
    }
    backend_instance_deinit(&backend);
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
    int initialized_passwd_auth;
    int initialized_pool;

    status = parse_args(argc, argv, &opts);
    if (status == SSH_ERR_UNSUPPORTED) {
        usage(argv[0]);
        return 0;
    }
    if (status != SSH_OK) {
        usage(argv[0]);
        return 2;
    }

    memset(&shared, 0, sizeof(shared));
    memset(&pool, 0, sizeof(pool));
    memset(&listener, 0, sizeof(listener));
    initialized_runtime = 0;
    initialized_net = 0;
    initialized_sftp_fs = 0;
    initialized_host_fs = 0;
    initialized_passwd_auth = 0;
    initialized_pool = 0;
    shared.backend = opts.backend;

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
        "linux posix+stdio sftp server listening on %s:%u, backend=%s, max-workers=%u\n",
        shared.base_server_config.listen_address != NULL ? shared.base_server_config.listen_address : "0.0.0.0",
        (unsigned)shared.port,
        backend_name(shared.backend),
        opts.max_workers);
    printf("note: command line overrides sshd_config for overlapping parameters.\n");
    fflush(stdout);

    for (;;) {
        ssh_posix_conn_t conn;
        worker_task_t *task;
        pthread_t thread;
        int create_status;

        memset(&conn, 0, sizeof(conn));
        worker_pool_reserve_slot(&pool);
        status = ssh_posix_accept(&shared.net, &listener, &conn, 0u);
        if (status != SSH_OK) {
            worker_pool_release_slot(&pool);
            fprintf(stderr, "accept failed: %s\n", ssh_status_string(status));
            continue;
        }

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

        create_status = pthread_create(&thread, NULL, worker_main, task);
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
