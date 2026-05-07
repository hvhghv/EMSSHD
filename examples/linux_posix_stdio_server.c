#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "emssh/platform_posix_net.h"
#include "emssh/platform_posix_passwd_auth.h"
#include "emssh/platform_posix_runtime.h"
#include "emssh/platform_posix_term.h"
#include "emssh/platform_stdio_fs.h"
#include "emssh/sftp.h"
#include "emssh/sshd_config_file.h"
#include "emssh/ssh_error.h"
#include "emssh/ssh_server.h"

#if !defined(EMSSH_USE_MBEDTLS)
#error "linux_posix_stdio_server requires mbedtls legacy backend"
#endif
#include "emssh/crypto_mbedtls.h"

#define LINUX_SERVER_DEFAULT_PORT 22u
#define LINUX_SERVER_DEFAULT_TIMEOUT_MS 30000u
#define LINUX_SERVER_DEFAULT_MAX_WORKERS 16u
#define LINUX_SERVER_DEFAULT_WORKER_STACK_KB 1024u
#define LINUX_SERVER_MAX_PATH 512u
#define LINUX_SERVER_MAX_USERNAME 128u
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
    CRYPTO_BACKEND_MBEDTLS
} crypto_backend_t;

typedef enum session_mode {
    SESSION_MODE_AUTO = 0,
    SESSION_MODE_SFTP = 1,
    SESSION_MODE_TERMINAL = 2
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
    int root_overridden;
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
    char sshd_config_path[LINUX_SERVER_MAX_PATH];
    int has_sshd_config_path;
    const char *chroot_dir_from_config;
    const char *hostkey_path_from_config;
    uint16_t port;
    session_mode_t session_mode;
    crypto_backend_t backend;
    int sftp_trace_enabled;
    uint8_t mbedtls_hostkey_private[LINUX_SERVER_MAX_MBEDTLS_HOSTKEY_PRIVATE];
    size_t mbedtls_hostkey_private_len;
} app_shared_t;

typedef struct auth_runtime_context {
    app_shared_t *shared;
    const ssh_posix_conn_t *conn;
    const ssh_server_config_t *session_server_config;
} auth_runtime_context_t;

typedef struct backend_instance {
    crypto_backend_t type;
    ssh_platform_t platform;
    ssh_mbedtls_crypto_t mbedtls;
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
        "  --port <1-65535>         Listen port (default: 22)\n"
        "  --listen <addr>          Listen address (default: from sshd_config or any)\n"
        "  --sshd-config <path>     OpenSSH-compatible sshd_config (read via stdio_fs rooted at /)\n"
        "  --passwd-file <path>     passwd file (default: /etc/passwd)\n"
        "  --shadow-file <path>     shadow file (default: /etc/shadow)\n"
        "  --timeout-ms <ms>        Session timeout (default: 30000)\n"
        "  --max-workers <n>        Parallel worker threads (default: 16)\n"
        "  --worker-stack-kb <n>    Worker thread stack size in KB (default: 1024)\n"
        "  --session-mode <mode>    auto|sftp|terminal (default: auto)\n"
        "  --backend <name>         mbedtls|mbedtls-legacy (fixed)\n"
        "env:\n"
        "  EMSSH_SFTP_TRACE=1       Enable SFTP trace logs (packet type/id/len and result)\n",
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
    return CRYPTO_BACKEND_MBEDTLS;
}

static const char *backend_name(crypto_backend_t backend)
{
    switch (backend) {
    case CRYPTO_BACKEND_MBEDTLS:
        return "mbedtls-legacy";
    default:
        return "unknown";
    }
}

static const char *session_mode_name(session_mode_t mode)
{
    if (mode == SESSION_MODE_TERMINAL) {
        return "terminal";
    }
    if (mode == SESSION_MODE_SFTP) {
        return "sftp";
    }
    return "auto";
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
    if (strcmp(text, "auto") == 0) {
        *mode = SESSION_MODE_AUTO;
        return SSH_OK;
    }
    return SSH_ERR_INVALID_ARGUMENT;
}

static int parse_backend(const char *text, crypto_backend_t *backend)
{
    if (text == NULL || backend == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (strcmp(text, "mbedtls") == 0 || strcmp(text, "mbedtls-legacy") == 0) {
        *backend = CRYPTO_BACKEND_MBEDTLS;
        return SSH_OK;
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

static int is_space_char_local(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

static int base64_value_local(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    if (c == '=') {
        return -2;
    }
    return -1;
}

static int decode_base64_token_local(
    const char *text,
    size_t text_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    uint32_t acc;
    unsigned bits;
    size_t i;
    size_t written;
    int saw_padding;

    if (text == NULL || out == NULL || out_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    acc = 0u;
    bits = 0u;
    written = 0u;
    saw_padding = 0;
    for (i = 0u; i < text_len; ++i) {
        int value = base64_value_local(text[i]);
        if (value < 0) {
            if (value == -2) {
                saw_padding = 1;
                continue;
            }
            return SSH_ERR_MALFORMED_PACKET;
        }
        if (saw_padding) {
            return SSH_ERR_MALFORMED_PACKET;
        }
        acc = (acc << 6) | (uint32_t)value;
        bits += 6u;
        if (bits >= 8u) {
            bits -= 8u;
            if (written >= out_capacity) {
                return SSH_ERR_BUFFER_TOO_SMALL;
            }
            out[written++] = (uint8_t)((acc >> bits) & 0xffu);
        }
    }

    *out_len = written;
    return written != 0u ? SSH_OK : SSH_ERR_MALFORMED_PACKET;
}

static int is_authorized_key_algorithm_token(const char *token, size_t token_len)
{
    return (token_len == strlen("ssh-ed25519") && memcmp(token, "ssh-ed25519", token_len) == 0) ||
           (token_len == strlen("ssh-rsa") && memcmp(token, "ssh-rsa", token_len) == 0) ||
           (token_len == strlen("ecdsa-sha2-nistp256") && memcmp(token, "ecdsa-sha2-nistp256", token_len) == 0);
}

static int username_is_safe_for_path(const char *username)
{
    size_t i;

    if (username == NULL || username[0] == '\0') {
        return 0;
    }

    for (i = 0u; username[i] != '\0'; ++i) {
        char ch = username[i];
        int ok = (ch >= 'a' && ch <= 'z') ||
                 (ch >= 'A' && ch <= 'Z') ||
                 (ch >= '0' && ch <= '9') ||
                 ch == '_' || ch == '-' || ch == '.';
        if (!ok) {
            return 0;
        }
    }

    return 1;
}

static int build_home_path_for_user(const char *username, char out[LINUX_SERVER_MAX_PATH])
{
    int written;

    if (username == NULL || out == NULL || !username_is_safe_for_path(username)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (strcmp(username, "root") == 0) {
        written = snprintf(out, LINUX_SERVER_MAX_PATH, "/root");
    } else {
        written = snprintf(out, LINUX_SERVER_MAX_PATH, "/home/%s", username);
    }
    if (written < 0 || (size_t)written >= LINUX_SERVER_MAX_PATH) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    return SSH_OK;
}

static int expand_authorized_keys_template(
    const char *template_path,
    const char *username,
    char out[LINUX_SERVER_MAX_PATH])
{
    char home[LINUX_SERVER_MAX_PATH];
    const char *src;
    size_t out_len;
    size_t i;

    if (out == NULL || username == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    src = template_path != NULL && template_path[0] != '\0' ? template_path : ".ssh/authorized_keys";
    if (!username_is_safe_for_path(username)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (build_home_path_for_user(username, home) != SSH_OK) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    out_len = 0u;
    for (i = 0u; src[i] != '\0'; ++i) {
        if (src[i] == '%') {
            const char *rep = NULL;
            ++i;
            if (src[i] == '\0') {
                return SSH_ERR_INVALID_ARGUMENT;
            }
            if (src[i] == 'u') {
                rep = username;
            } else if (src[i] == 'h') {
                rep = home;
            } else if (src[i] == '%') {
                rep = "%";
            } else {
                return SSH_ERR_INVALID_ARGUMENT;
            }

            while (*rep != '\0') {
                if (out_len + 1u >= LINUX_SERVER_MAX_PATH) {
                    return SSH_ERR_BUFFER_TOO_SMALL;
                }
                out[out_len++] = *rep++;
            }
            continue;
        }

        if (out_len + 1u >= LINUX_SERVER_MAX_PATH) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        out[out_len++] = src[i];
    }
    out[out_len] = '\0';

    if (out[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (out[0] != '/') {
        char absolute[LINUX_SERVER_MAX_PATH];
        int written = snprintf(absolute, sizeof(absolute), "%s/%s", home, out);
        if (written < 0 || (size_t)written >= sizeof(absolute)) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(out, absolute, (size_t)written + 1u);
    }

    return normalize_host_fs_path(out, out);
}

static int line_publickey_blob_matches_request(
    char *line,
    const ssh_publickey_auth_request_t *request,
    int *matched)
{
    char *p;
    char *token_start;
    size_t token_len;
    char *algorithm_token;
    char *blob_token;
    size_t blob_token_len;
    uint8_t blob[EMSSH_MAX_HOST_KEY_BLOB];
    size_t blob_len;
    int status;

    if (line == NULL || request == NULL || matched == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *matched = 0;
    p = line;
    while (*p != '\0' && is_space_char_local(*p)) {
        ++p;
    }
    if (*p == '\0' || *p == '#') {
        return SSH_OK;
    }

    algorithm_token = NULL;
    blob_token = NULL;
    while (*p != '\0') {
        while (*p != '\0' && is_space_char_local(*p)) {
            ++p;
        }
        if (*p == '\0' || *p == '#') {
            break;
        }

        token_start = p;
        while (*p != '\0' && !is_space_char_local(*p)) {
            ++p;
        }
        token_len = (size_t)(p - token_start);
        if (token_len == 0u) {
            continue;
        }

        if (algorithm_token == NULL) {
            if (is_authorized_key_algorithm_token(token_start, token_len)) {
                algorithm_token = token_start;
            }
            continue;
        }
        blob_token = token_start;
        blob_token_len = token_len;
        break;
    }

    if (algorithm_token == NULL || blob_token == NULL || blob_token_len == 0u) {
        return SSH_OK;
    }

    status = decode_base64_token_local(blob_token, blob_token_len, blob, sizeof(blob), &blob_len);
    if (status != SSH_OK) {
        return SSH_OK;
    }
    if (blob_len == request->publickey_blob_len &&
        memcmp(blob, request->publickey_blob, blob_len) == 0) {
        *matched = 1;
    }
    return SSH_OK;
}

static int authorized_keys_file_contains_key(
    const ssh_fs_api_t *fs,
    const char *path,
    const ssh_publickey_auth_request_t *request,
    int *contains)
{
    void *handle;
    char chunk[512];
    char line[1024];
    size_t line_len;
    size_t read_len;
    size_t i;
    int status;

    if (fs == NULL || fs->open == NULL || fs->read == NULL || fs->close == NULL ||
        path == NULL || request == NULL || contains == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *contains = 0;
    handle = NULL;
    line_len = 0u;
    status = fs->open(fs->ctx, path, SSH_FXF_READ, &handle);
    if (status != SSH_OK) {
        return status;
    }

    for (;;) {
        read_len = 0u;
        status = fs->read(fs->ctx, handle, (uint8_t *)chunk, sizeof(chunk), &read_len);
        if (status != SSH_OK) {
            (void)fs->close(fs->ctx, handle);
            return status;
        }
        if (read_len == 0u) {
            break;
        }

        for (i = 0u; i < read_len; ++i) {
            if (chunk[i] == '\n') {
                int matched = 0;
                if (line_len != 0u && line[line_len - 1u] == '\r') {
                    --line_len;
                }
                line[line_len] = '\0';
                status = line_publickey_blob_matches_request(line, request, &matched);
                if (status != SSH_OK) {
                    (void)fs->close(fs->ctx, handle);
                    return status;
                }
                if (matched) {
                    (void)fs->close(fs->ctx, handle);
                    *contains = 1;
                    return SSH_OK;
                }
                line_len = 0u;
                continue;
            }
            if (line_len + 1u >= sizeof(line)) {
                (void)fs->close(fs->ctx, handle);
                return SSH_ERR_BUFFER_TOO_SMALL;
            }
            line[line_len++] = chunk[i];
        }
    }

    if (line_len != 0u) {
        int matched = 0;
        if (line[line_len - 1u] == '\r') {
            --line_len;
        }
        line[line_len] = '\0';
        status = line_publickey_blob_matches_request(line, request, &matched);
        if (status != SSH_OK) {
            (void)fs->close(fs->ctx, handle);
            return status;
        }
        if (matched) {
            *contains = 1;
        }
    }

    (void)fs->close(fs->ctx, handle);
    return SSH_OK;
}

static int username_pattern_matches_local(
    const char *pattern,
    size_t pattern_len,
    const char *username,
    size_t username_len)
{
    size_t p;
    size_t u;
    size_t star_p;
    size_t star_u;

    if (pattern == NULL || username == NULL) {
        return 0;
    }

    p = 0u;
    u = 0u;
    star_p = (size_t)-1;
    star_u = 0u;
    while (u < username_len) {
        if (p < pattern_len && (pattern[p] == '?' || pattern[p] == username[u])) {
            ++p;
            ++u;
            continue;
        }
        if (p < pattern_len && pattern[p] == '*') {
            star_p = ++p;
            star_u = u;
            continue;
        }
        if (star_p != (size_t)-1) {
            p = star_p;
            ++star_u;
            u = star_u;
            continue;
        }
        return 0;
    }

    while (p < pattern_len && pattern[p] == '*') {
        ++p;
    }
    return p == pattern_len;
}

static int username_allowed_by_allow_users_local(const char *allow_users, const char *username, size_t username_len)
{
    const char *p;

    if (allow_users == NULL || allow_users[0] == '\0') {
        return 1;
    }
    if (username == NULL || username_len == 0u) {
        return 0;
    }

    p = allow_users;
    while (*p != '\0') {
        const char *start;
        const char *end;
        const char *at;
        size_t token_len;

        while (*p == ' ' || *p == '\t' || *p == ',') {
            ++p;
        }
        if (*p == '\0') {
            break;
        }

        start = p;
        while (*p != '\0' && *p != ' ' && *p != '\t' && *p != ',') {
            ++p;
        }
        end = p;
        token_len = (size_t)(end - start);
        if (token_len == 0u) {
            continue;
        }

        at = start;
        while (at < end && *at != '@') {
            ++at;
        }
        if (at < end) {
            end = at;
            token_len = (size_t)(end - start);
            if (token_len == 0u) {
                continue;
            }
        }

        if (username_pattern_matches_local(start, token_len, username, username_len)) {
            return 1;
        }
    }

    return 0;
}

static int username_is_root_local(const char *username, size_t username_len)
{
    return username != NULL && username_len == 4u && memcmp(username, "root", 4u) == 0;
}

static int root_login_allows_method_local(int permit_root_login, const char *username, size_t username_len, int is_password_method)
{
    int mode;

    if (!username_is_root_local(username, username_len)) {
        return 1;
    }

    mode = permit_root_login;
    if (mode == EMSSH_PERMIT_ROOT_LOGIN_DEFAULT) {
        mode = EMSSH_PERMIT_ROOT_LOGIN_PROHIBIT_PASSWORD;
    }
    if (mode == EMSSH_PERMIT_ROOT_LOGIN_NO) {
        return 0;
    }
    if (mode == EMSSH_PERMIT_ROOT_LOGIN_PROHIBIT_PASSWORD && is_password_method) {
        return 0;
    }
    return 1;
}

static int copy_username_request_local(
    const char *username,
    size_t username_len,
    char username_out[LINUX_SERVER_MAX_USERNAME])
{
    if (username == NULL || username_out == NULL || username_len == 0u || username_len + 1u > LINUX_SERVER_MAX_USERNAME) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memcpy(username_out, username, username_len);
    username_out[username_len] = '\0';
    return SSH_OK;
}

static int fill_match_context_local(
    const app_shared_t *shared,
    const ssh_posix_conn_t *conn,
    const char *username,
    ssh_sshd_match_context_t *ctx,
    char local_addr_buf[64])
{
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;
    uint16_t local_port;
    int have_local_addr;

    if (shared == NULL || conn == NULL || ctx == NULL || local_addr_buf == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(ctx, 0, sizeof(*ctx));
    local_addr_buf[0] = '\0';
    if (username != NULL && username[0] != '\0') {
        ctx->user = username;
    }
    ctx->host = ssh_posix_conn_peer_address(conn);
    ctx->address = ctx->host;

    have_local_addr = 0;
    local_port = 0u;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr_len = (socklen_t)sizeof(local_addr);
    if (getsockname(conn->socket_fd, (struct sockaddr *)&local_addr, &local_addr_len) == 0) {
        if (local_addr.ss_family == AF_INET) {
            const struct sockaddr_in *in = (const struct sockaddr_in *)&local_addr;
            if (inet_ntop(AF_INET, &in->sin_addr, local_addr_buf, 64u) != NULL) {
                have_local_addr = 1;
            }
            local_port = ntohs(in->sin_port);
        } else if (local_addr.ss_family == AF_INET6) {
            const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)&local_addr;
            if (inet_ntop(AF_INET6, &in6->sin6_addr, local_addr_buf, 64u) != NULL) {
                have_local_addr = 1;
            }
            local_port = ntohs(in6->sin6_port);
        }
    }

    if (have_local_addr) {
        ctx->local_address = local_addr_buf;
    } else {
        ctx->local_address = shared->base_server_config.listen_address;
    }
    ctx->local_port = local_port != 0u ? local_port : shared->port;
    return SSH_OK;
}

static int load_runtime_policy_for_user(
    const auth_runtime_context_t *auth_ctx,
    const char *username,
    ssh_sshd_config_file_t *matched_config_out,
    ssh_server_config_t *policy_out)
{
    ssh_sshd_match_context_t match_ctx;
    char local_addr_buf[64];
    int status;

    if (auth_ctx == NULL || auth_ctx->shared == NULL || auth_ctx->conn == NULL ||
        auth_ctx->session_server_config == NULL || matched_config_out == NULL || policy_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *policy_out = *auth_ctx->session_server_config;
    ssh_sshd_config_file_defaults(matched_config_out);
    if (!auth_ctx->shared->has_sshd_config_path) {
        return SSH_OK;
    }

    status = fill_match_context_local(auth_ctx->shared, auth_ctx->conn, username, &match_ctx, local_addr_buf);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_sshd_config_file_load_with_match_context(
        ssh_stdio_fs_api(&auth_ctx->shared->host_fs),
        auth_ctx->shared->sshd_config_path,
        &match_ctx,
        matched_config_out);
    if (status != SSH_OK) {
        return status;
    }

    return ssh_sshd_config_file_apply(
        matched_config_out,
        policy_out,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
}

static int publickey_authorized_by_path_list(
    app_shared_t *shared,
    const ssh_publickey_auth_request_t *request,
    const char *username,
    const char *path_list)
{
    const ssh_fs_api_t *fs;
    const char *p;

    if (shared == NULL || request == NULL || username == NULL) {
        return 0;
    }

    fs = ssh_stdio_fs_api(&shared->host_fs);
    if (fs == NULL) {
        return 0;
    }

    p = (path_list != NULL && path_list[0] != '\0') ? path_list : ".ssh/authorized_keys .ssh/authorized_keys2";
    while (*p != '\0') {
        const char *start;
        const char *end;
        char token[LINUX_SERVER_MAX_PATH];
        char resolved[LINUX_SERVER_MAX_PATH];
        int status;
        int contains;
        size_t len;

        while (*p != '\0' && is_space_char_local(*p)) {
            ++p;
        }
        if (*p == '\0') {
            break;
        }
        start = p;
        while (*p != '\0' && !is_space_char_local(*p)) {
            ++p;
        }
        end = p;
        len = (size_t)(end - start);
        if (len == 0u || len >= sizeof(token)) {
            continue;
        }

        memcpy(token, start, len);
        token[len] = '\0';
        status = expand_authorized_keys_template(token, username, resolved);
        if (status != SSH_OK) {
            continue;
        }

        contains = 0;
        status = authorized_keys_file_contains_key(fs, resolved, request, &contains);
        if (status == SSH_OK && contains) {
            return 1;
        }
    }

    return 0;
}

static int linux_password_auth_cb(void *ctx, const ssh_password_auth_request_t *request)
{
    auth_runtime_context_t *auth_ctx = (auth_runtime_context_t *)ctx;
    ssh_sshd_config_file_t matched_config;
    ssh_server_config_t policy;
    char username[LINUX_SERVER_MAX_USERNAME];
    int status;
    size_t username_len;

    if (auth_ctx == NULL || auth_ctx->shared == NULL || request == NULL || request->username == NULL) {
        return 0;
    }

    status = copy_username_request_local(request->username, request->username_len, username);
    if (status != SSH_OK) {
        return 0;
    }
    username_len = request->username_len;

    status = load_runtime_policy_for_user(auth_ctx, username, &matched_config, &policy);
    if (status != SSH_OK || policy.password_auth == NULL) {
        return 0;
    }
    if (!username_allowed_by_allow_users_local(policy.allow_users, username, username_len)) {
        return 0;
    }
    if (!root_login_allows_method_local(policy.permit_root_login, username, username_len, 1)) {
        return 0;
    }

    return ssh_posix_passwd_auth_cb(&auth_ctx->shared->passwd_auth, request);
}

static int linux_publickey_auth_cb(void *ctx, const ssh_publickey_auth_request_t *request)
{
    auth_runtime_context_t *auth_ctx = (auth_runtime_context_t *)ctx;
    ssh_sshd_config_file_t matched_config;
    ssh_server_config_t policy;
    char username[LINUX_SERVER_MAX_USERNAME];
    int status;
    size_t username_len;

    if (auth_ctx == NULL || auth_ctx->shared == NULL || request == NULL ||
        request->username == NULL || request->publickey_blob == NULL || request->publickey_blob_len == 0u) {
        return 0;
    }

    status = copy_username_request_local(request->username, request->username_len, username);
    if (status != SSH_OK) {
        return 0;
    }
    username_len = request->username_len;
    if (!username_is_safe_for_path(username)) {
        return 0;
    }

    status = load_runtime_policy_for_user(auth_ctx, username, &matched_config, &policy);
    if (status != SSH_OK || policy.publickey_auth == NULL) {
        return 0;
    }
    if (!username_allowed_by_allow_users_local(policy.allow_users, username, username_len)) {
        return 0;
    }
    if (!root_login_allows_method_local(policy.permit_root_login, username, username_len, 0)) {
        return 0;
    }

    return publickey_authorized_by_path_list(
        auth_ctx->shared,
        request,
        username,
        policy.authorized_keys_file);
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
    opts->session_mode = SESSION_MODE_AUTO;
    opts->backend = default_backend();
}

static int env_flag_enabled(const char *name)
{
    const char *value;

    if (name == NULL || name[0] == '\0') {
        return 0;
    }
    value = getenv(name);
    if (value == NULL || value[0] == '\0') {
        return 0;
    }

    return strcmp(value, "1") == 0 ||
           strcmp(value, "true") == 0 ||
           strcmp(value, "yes") == 0 ||
           strcmp(value, "on") == 0;
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
            opts->root_overridden = 1;
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
    case CRYPTO_BACKEND_MBEDTLS:
        ssh_mbedtls_crypto_free(&backend->mbedtls);
        break;
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
    backend->platform.term = shared->session_mode == SESSION_MODE_SFTP ? NULL : ssh_posix_term_api((ssh_posix_term_platform_t *)&shared->term);
#else
    backend->platform.term = NULL;
#endif

    switch (backend->type) {
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
    default:
        return SSH_ERR_UNSUPPORTED;
    }

    backend->initialized = 1;
    return SSH_OK;
}

static int prepare_mbedtls_hostkey_if_needed(app_shared_t *shared)
{
    ssh_mbedtls_crypto_t bootstrap;
    const ssh_fs_api_t *host_fs_api;
    void *handle;
    size_t read_len;
    int status;

    if (shared->backend != CRYPTO_BACKEND_MBEDTLS) {
        return SSH_OK;
    }

    if (shared->hostkey_path_from_config != NULL) {
        host_fs_api = ssh_stdio_fs_api(&shared->host_fs);
        if (host_fs_api == NULL || host_fs_api->open == NULL || host_fs_api->read == NULL || host_fs_api->close == NULL) {
            return SSH_ERR_PLATFORM;
        }

        shared->mbedtls_hostkey_private_len = 0u;
        handle = NULL;
        status = host_fs_api->open(host_fs_api->ctx, shared->hostkey_path_from_config, SSH_FXF_READ, &handle);
        if (status != SSH_OK) {
            return status;
        }

        for (;;) {
            read_len = 0u;
            status = host_fs_api->read(
                host_fs_api->ctx,
                handle,
                shared->mbedtls_hostkey_private + shared->mbedtls_hostkey_private_len,
                sizeof(shared->mbedtls_hostkey_private) - shared->mbedtls_hostkey_private_len,
                &read_len);
            if (status != SSH_OK) {
                (void)host_fs_api->close(host_fs_api->ctx, handle);
                return status;
            }
            if (read_len == 0u) {
                break;
            }
            shared->mbedtls_hostkey_private_len += read_len;
            if (shared->mbedtls_hostkey_private_len == sizeof(shared->mbedtls_hostkey_private)) {
                size_t probe_len = 0u;
                int probe_status = host_fs_api->read(
                    host_fs_api->ctx,
                    handle,
                    shared->mbedtls_hostkey_private,
                    1u,
                    &probe_len);
                if (probe_status != SSH_OK) {
                    (void)host_fs_api->close(host_fs_api->ctx, handle);
                    return probe_status;
                }
                if (probe_len != 0u) {
                    (void)host_fs_api->close(host_fs_api->ctx, handle);
                    return SSH_ERR_BUFFER_TOO_SMALL;
                }
                break;
            }
        }
        (void)host_fs_api->close(host_fs_api->ctx, handle);
        if (shared->mbedtls_hostkey_private_len == 0u) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
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
}

static void set_backend_kex_defaults(crypto_backend_t backend, ssh_kexinit_algorithm_set_t *algorithms)
{
    if (algorithms == NULL) {
        return;
    }

    switch (backend) {
    case CRYPTO_BACKEND_MBEDTLS:
        ssh_mbedtls_kexinit_algorithm_set_defaults(algorithms);
        return;
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
    shared->has_sshd_config_path = 0;
    shared->sshd_config_path[0] = '\0';

    if (sshd_config_path_normalized != NULL) {
        size_t config_path_len = strlen(sshd_config_path_normalized);
        if (config_path_len + 1u > sizeof(shared->sshd_config_path)) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(shared->sshd_config_path, sshd_config_path_normalized, config_path_len + 1u);
        shared->has_sshd_config_path = 1;
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
            &shared->port,
            &shared->chroot_dir_from_config,
            &shared->hostkey_path_from_config);
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
    shared->base_session_options.sftp_trace_enabled = shared->sftp_trace_enabled;

    if (!shared->sshd_config.has_password_authentication || shared->sshd_config.password_authentication) {
        shared->base_server_config.password_auth = linux_password_auth_cb;
    }
    if (!shared->sshd_config.has_pubkey_authentication || shared->sshd_config.pubkey_authentication) {
        shared->base_server_config.publickey_auth = linux_publickey_auth_cb;
    }
    shared->base_server_config.auth_ctx = NULL;
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
        return SSH_ERR_UNSUPPORTED;
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
        return SSH_ERR_UNSUPPORTED;
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
    ssh_kexinit_algorithm_set_t algorithms;
    ssh_sshd_config_file_t matched_config;
    ssh_sshd_match_context_t match_ctx;
    auth_runtime_context_t auth_ctx;
    char local_addr_buf[64];
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
    algorithms = shared->base_algorithms;
    options.algorithms = &algorithms;
    ssh_sshd_config_file_defaults(&matched_config);

    if (shared->has_sshd_config_path) {
        status = fill_match_context_local(shared, conn, NULL, &match_ctx, local_addr_buf);
        if (status != SSH_OK) {
            backend_instance_deinit(&backend);
            return status;
        }

        status = ssh_sshd_config_file_load_with_match_context(
            ssh_stdio_fs_api(&shared->host_fs),
            shared->sshd_config_path,
            &match_ctx,
            &matched_config);
        if (status != SSH_OK) {
            backend_instance_deinit(&backend);
            return status;
        }

        status = ssh_sshd_config_file_apply(
            &matched_config,
            &config,
            &options,
            &algorithms,
            NULL,
            NULL,
            NULL);
        if (status != SSH_OK) {
            backend_instance_deinit(&backend);
            return status;
        }
    }

    auth_ctx.shared = shared;
    auth_ctx.conn = conn;
    auth_ctx.session_server_config = &config;
    config.auth_ctx = &auth_ctx;

    if (shared->session_mode == SESSION_MODE_SFTP || shared->session_mode == SESSION_MODE_AUTO) {
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
    } else if (shared->session_mode == SESSION_MODE_AUTO) {
        status = ssh_server_run_auto_session(&server, conn, &options);
    } else {
        status = ssh_server_run_sftp_session(&server, conn, &options);
    }
    if (status != SSH_OK) {
        const char *peer = ssh_posix_conn_peer_address(conn);
        fprintf(stderr, "session %s ended: %s\n", peer != NULL ? peer : "unknown", ssh_status_string(status));
        if (server.diag_last_received_message_id_valid) {
            fprintf(
                stderr,
                "diag: last received ssh msg id=%u (0x%02x)\n",
                (unsigned)server.diag_last_received_message_id,
                (unsigned)server.diag_last_received_message_id);
        }
        if (status == SSH_ERR_UNSUPPORTED && server.diag_last_channel_request_type_valid) {
            fprintf(
                stderr,
                "diag: unsupported channel request type=%s want-reply=%d\n",
                server.diag_last_channel_request_type,
                server.diag_last_channel_request_want_reply != 0 ? 1 : 0);
        }
        if (status == SSH_ERR_UNSUPPORTED && shared->session_mode == SESSION_MODE_SFTP) {
            fprintf(stderr, "hint: this example serves SFTP subsystem only; use an SFTP client/session.\n");
        } else if (status == SSH_ERR_UNSUPPORTED && shared->session_mode == SESSION_MODE_TERMINAL) {
            fprintf(stderr, "hint: terminal mode expects shell/exec channel requests.\n");
        } else if (status == SSH_ERR_UNSUPPORTED && shared->session_mode == SESSION_MODE_AUTO) {
            fprintf(stderr, "hint: auto mode supports both subsystem sftp and terminal requests.\n");
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
    shared.sftp_trace_enabled = env_flag_enabled("EMSSH_SFTP_TRACE");
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

    status = ssh_stdio_fs_init(&shared.host_fs, "/");
    if (status != SSH_OK) {
        fprintf(stderr, "stdio fs (host root) init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_host_fs = 1;

    if (opts.session_mode != SESSION_MODE_SFTP) {
#if defined(EMSSH_BUILD_POSIX_TERM)
        status = ssh_posix_term_platform_init(&shared.term);
        if (status != SSH_OK) {
            fprintf(stderr, "posix term init failed: %s\n", ssh_status_string(status));
            goto cleanup;
        }
        initialized_term = 1;
#else
        fprintf(stderr, "session mode '%s' needs terminal adapter; enable EMSSH_BUILD_POSIX_TERM=ON\n", session_mode_name(opts.session_mode));
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

    {
        const char *effective_sftp_root = opts.root_dir;
        if (!opts.root_overridden && shared.chroot_dir_from_config != NULL && shared.chroot_dir_from_config[0] != '\0') {
            effective_sftp_root = shared.chroot_dir_from_config;
        }
        status = ssh_stdio_fs_init(&shared.sftp_fs, effective_sftp_root);
        if (status != SSH_OK) {
            fprintf(stderr, "stdio fs (sftp root) init failed: %s\n", ssh_status_string(status));
            goto cleanup;
        }
        initialized_sftp_fs = 1;
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
    if (shared.sftp_trace_enabled) {
        printf("note: EMSSH_SFTP_TRACE enabled (SFTP request/response trace is on).\n");
    }
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
