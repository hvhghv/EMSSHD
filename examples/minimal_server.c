#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "emssh/platform_stdio_fs.h"
#include "emssh/platform_tcp.h"
#include "emssh/sftp.h"
#include "emssh/ssh_buffer.h"
#include "emssh/ssh_crypto.h"
#include "emssh/ssh_error.h"
#include "emssh/ssh_server.h"

#if defined(EMSSH_USE_MBEDTLS)
#include "emssh/crypto_mbedtls.h"
#if defined(EMSSH_MBEDTLS_USE_PSA)
typedef ssh_crypto_context_mbedtls_t minimal_crypto_context_t;
#else
typedef ssh_crypto_context_mbedtls_legacy_t minimal_crypto_context_t;
#endif
#elif defined(EMSSH_USE_OPENSSL)
#include "emssh/crypto_openssl.h"
typedef ssh_crypto_context_openssl_t minimal_crypto_context_t;
#elif defined(EMSSH_USE_WOLFSSL)
#include "emssh/crypto_wolfssl.h"
typedef ssh_crypto_context_wolfssl_t minimal_crypto_context_t;
#else
#error "minimal_server requires one crypto backend"
#endif

#define MINIMAL_CTX_PTR(ctx) ((ssh_crypto_context_t *)(ctx))
#define MINIMAL_CTX_CONST_PTR(ctx) ((const ssh_crypto_context_t *)(ctx))

#define MINIMAL_SERVER_MAX_AUTHORIZED_KEYS 8u
#define MINIMAL_SERVER_MAX_FROM_PATTERNS 128u
#define MINIMAL_SERVER_MAX_PATH_PREFIX EMSSH_SFTP_MAX_PATH

typedef struct authorized_publickey {
    char algorithm[64];
    char from_patterns[MINIMAL_SERVER_MAX_FROM_PATTERNS];
    char path_prefix[MINIMAL_SERVER_MAX_PATH_PREFIX];
    uint8_t publickey[EMSSH_MAX_HOST_KEY_BLOB];
    size_t publickey_len;
    uint64_t max_read_end;
    uint64_t max_write_end;
    int restrict_from;
    int restrict_path_prefix;
    int restrict_max_read_end;
    int restrict_max_write_end;
    int deny_non_sftp_channel_request;
    int deny_rename;
    int deny_delete;
    int deny_setstat;
    int deny_create;
    int deny_hardlink;
    int deny_remove;
    int deny_rmdir;
    int deny_mkdir;
    int deny_open_create;
    int deny_open_trunc;
    int deny_open_append;
    int deny_open_write;
    int deny_open_read;
    int deny_read;
    int deny_realpath;
    int deny_stat;
    int deny_fstat;
    int deny_fsetstat;
    int deny_fsync;
    int deny_statvfs;
    int deny_fstatvfs;
    int deny_opendir;
    int deny_readdir;
    int deny_write;
    int read_only;
} authorized_publickey_t;

typedef struct authorized_session_policy {
    int read_only;
    int restrict_path_prefix;
    int restrict_max_read_end;
    int restrict_max_write_end;
    int deny_non_sftp_channel_request;
    int deny_rename;
    int deny_delete;
    int deny_setstat;
    int deny_create;
    int deny_hardlink;
    int deny_remove;
    int deny_rmdir;
    int deny_mkdir;
    int deny_open_create;
    int deny_open_trunc;
    int deny_open_append;
    int deny_open_write;
    int deny_open_read;
    int deny_read;
    int deny_realpath;
    int deny_stat;
    int deny_fstat;
    int deny_fsetstat;
    int deny_fsync;
    int deny_statvfs;
    int deny_fstatvfs;
    int deny_opendir;
    int deny_readdir;
    int deny_write;
    uint64_t max_read_end;
    uint64_t max_write_end;
    char path_prefix[MINIMAL_SERVER_MAX_PATH_PREFIX];
} authorized_session_policy_t;

typedef struct password_auth_ctx {
    const char *username;
    const char *password;
    const char *peer_address;
    authorized_publickey_t authorized_keys[MINIMAL_SERVER_MAX_AUTHORIZED_KEYS];
    size_t authorized_key_count;
    int ed25519_publickey_supported;
    authorized_session_policy_t active_policy;
} password_auth_ctx_t;

typedef enum hostkey_algorithm {
    HOSTKEY_ALGORITHM_ECDSA_P256 = 0,
    HOSTKEY_ALGORITHM_ED25519 = 1
} hostkey_algorithm_t;

typedef enum ed25519_probe_mode {
    ED25519_PROBE_MODE_NONE = 0,
    ED25519_PROBE_MODE_PUBLICKEY = 1,
    ED25519_PROBE_MODE_HOSTKEY = 2
} ed25519_probe_mode_t;

static ssh_string_view_t sv(const char *value)
{
    ssh_string_view_t view;

    view.data = (const uint8_t *)value;
    view.len = value != NULL ? strlen(value) : 0u;
    return view;
}

static ssh_string_view_t hostkey_algorithm_view(hostkey_algorithm_t algorithm)
{
    static const char k_alg_ecdsa[] = "ecdsa-sha2-nistp256";
    static const char k_alg_ed25519[] = "ssh-ed25519";
    if (algorithm == HOSTKEY_ALGORITHM_ED25519) {
        return sv(k_alg_ed25519);
    }
    return sv(k_alg_ecdsa);
}

static int string_view_matches(const char *expected, const char *actual, size_t actual_len)
{
    size_t expected_len;

    if (expected == NULL || actual == NULL) {
        return 0;
    }

    expected_len = strlen(expected);
    return expected_len == actual_len && memcmp(expected, actual, actual_len) == 0;
}

static int authorized_options_allow_peer(
    const authorized_publickey_t *authorized,
    const password_auth_ctx_t *auth);

static int is_rsa_signature_algorithm(const char *actual, size_t actual_len)
{
    return string_view_matches("rsa-sha2-256", actual, actual_len) ||
           string_view_matches("rsa-sha2-512", actual, actual_len);
}

static int authorized_algorithm_matches(const char *authorized, const char *actual, size_t actual_len)
{
    if (string_view_matches(authorized, actual, actual_len)) {
        return 1;
    }

    return strcmp(authorized, "ssh-rsa") == 0 && is_rsa_signature_algorithm(actual, actual_len);
}

static int view_is_rsa_algorithm(ssh_string_view_t algorithm)
{
    return string_view_matches("ssh-rsa", (const char *)algorithm.data, algorithm.len) ||
           string_view_matches("rsa-sha2-256", (const char *)algorithm.data, algorithm.len) ||
           string_view_matches("rsa-sha2-512", (const char *)algorithm.data, algorithm.len);
}

static int mpint_same_positive_value(ssh_string_view_t a, ssh_string_view_t b)
{
    while (a.len > 0u && a.data[0] == 0u) {
        ++a.data;
        --a.len;
    }
    while (b.len > 0u && b.data[0] == 0u) {
        ++b.data;
        --b.len;
    }

    return a.len == b.len && a.data != NULL && b.data != NULL && memcmp(a.data, b.data, a.len) == 0;
}

static int decode_rsa_key_blob(
    const uint8_t *blob,
    size_t blob_len,
    ssh_string_view_t *e,
    ssh_string_view_t *n)
{
    ssh_buffer_t buffer;
    ssh_string_view_t algorithm;
    int status;

    if (blob == NULL || e == NULL || n == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(&algorithm, 0, sizeof(algorithm));
    memset(e, 0, sizeof(*e));
    memset(n, 0, sizeof(*n));

    ssh_buffer_wrap(&buffer, (uint8_t *)blob, blob_len);
    status = ssh_buffer_get_string_view(&buffer, &algorithm);
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&buffer, e);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&buffer, n);
    }
    if (status != SSH_OK) {
        return status;
    }

    if (!view_is_rsa_algorithm(algorithm) || e->len == 0u || n->len == 0u || ssh_buffer_remaining_read(&buffer) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return SSH_OK;
}

static int publickey_blob_matches(
    const authorized_publickey_t *authorized,
    const ssh_publickey_auth_request_t *request)
{
    ssh_string_view_t authorized_e;
    ssh_string_view_t authorized_n;
    ssh_string_view_t request_e;
    ssh_string_view_t request_n;

    if (authorized == NULL || request == NULL) {
        return 0;
    }

    if (request->publickey_blob_len == authorized->publickey_len &&
        memcmp(request->publickey_blob, authorized->publickey, authorized->publickey_len) == 0) {
        return 1;
    }

    if (strcmp(authorized->algorithm, "ssh-rsa") != 0 || !is_rsa_signature_algorithm(request->algorithm, request->algorithm_len)) {
        return 0;
    }

    if (decode_rsa_key_blob(authorized->publickey, authorized->publickey_len, &authorized_e, &authorized_n) != SSH_OK ||
        decode_rsa_key_blob(request->publickey_blob, request->publickey_blob_len, &request_e, &request_n) != SSH_OK) {
        return 0;
    }

    return mpint_same_positive_value(authorized_e, request_e) && mpint_same_positive_value(authorized_n, request_n);
}

static int password_auth(void *ctx, const ssh_password_auth_request_t *request)
{
    password_auth_ctx_t *auth = (password_auth_ctx_t *)ctx;

    if (auth == NULL || request == NULL) {
        return 0;
    }

    if (!string_view_matches(auth->username, request->username, request->username_len) ||
        !string_view_matches(auth->password, request->password, request->password_len)) {
        return 0;
    }

    memset(&auth->active_policy, 0, sizeof(auth->active_policy));
    return 1;
}

static int publickey_auth(void *ctx, const ssh_publickey_auth_request_t *request)
{
    password_auth_ctx_t *auth = (password_auth_ctx_t *)ctx;
    size_t i;

    if (auth == NULL || request == NULL || auth->authorized_key_count == 0u) {
        return 0;
    }

    if (!string_view_matches(auth->username, request->username, request->username_len)) {
        return 0;
    }
    if (!auth->ed25519_publickey_supported &&
        string_view_matches("ssh-ed25519", request->algorithm, request->algorithm_len)) {
        return 0;
    }

    for (i = 0u; i < auth->authorized_key_count; ++i) {
        const authorized_publickey_t *authorized = &auth->authorized_keys[i];
        if (authorized_options_allow_peer(authorized, auth) &&
            authorized_algorithm_matches(authorized->algorithm, request->algorithm, request->algorithm_len) &&
            publickey_blob_matches(authorized, request)) {
            memset(&auth->active_policy, 0, sizeof(auth->active_policy));
            auth->active_policy.read_only = authorized->read_only;
            auth->active_policy.restrict_path_prefix = authorized->restrict_path_prefix;
            auth->active_policy.restrict_max_read_end = authorized->restrict_max_read_end;
            auth->active_policy.restrict_max_write_end = authorized->restrict_max_write_end;
            auth->active_policy.deny_non_sftp_channel_request = authorized->deny_non_sftp_channel_request;
            auth->active_policy.deny_rename = authorized->deny_rename;
            auth->active_policy.deny_delete = authorized->deny_delete;
            auth->active_policy.deny_setstat = authorized->deny_setstat;
            auth->active_policy.deny_create = authorized->deny_create;
            auth->active_policy.deny_hardlink = authorized->deny_hardlink;
            auth->active_policy.deny_remove = authorized->deny_remove;
            auth->active_policy.deny_rmdir = authorized->deny_rmdir;
            auth->active_policy.deny_mkdir = authorized->deny_mkdir;
            auth->active_policy.deny_open_create = authorized->deny_open_create;
            auth->active_policy.deny_open_trunc = authorized->deny_open_trunc;
            auth->active_policy.deny_open_append = authorized->deny_open_append;
            auth->active_policy.deny_open_write = authorized->deny_open_write;
            auth->active_policy.deny_open_read = authorized->deny_open_read;
            auth->active_policy.deny_read = authorized->deny_read;
            auth->active_policy.deny_realpath = authorized->deny_realpath;
            auth->active_policy.deny_stat = authorized->deny_stat;
            auth->active_policy.deny_fstat = authorized->deny_fstat;
            auth->active_policy.deny_fsetstat = authorized->deny_fsetstat;
            auth->active_policy.deny_fsync = authorized->deny_fsync;
            auth->active_policy.deny_statvfs = authorized->deny_statvfs;
            auth->active_policy.deny_fstatvfs = authorized->deny_fstatvfs;
            auth->active_policy.deny_opendir = authorized->deny_opendir;
            auth->active_policy.deny_readdir = authorized->deny_readdir;
            auth->active_policy.deny_write = authorized->deny_write;
            auth->active_policy.max_read_end = authorized->max_read_end;
            auth->active_policy.max_write_end = authorized->max_write_end;
            if (authorized->restrict_path_prefix) {
                memcpy(
                    auth->active_policy.path_prefix,
                    authorized->path_prefix,
                    sizeof(auth->active_policy.path_prefix));
            }
            return 1;
        }
    }

    return 0;
}

static uint16_t parse_port(const char *text)
{
    unsigned long value;
    char *end;

    if (text == NULL || text[0] == '\0') {
        return 0u;
    }

    value = strtoul(text, &end, 10);
    if (*end != '\0' || value == 0ul || value > 65535ul) {
        return 0u;
    }

    return (uint16_t)value;
}

static unsigned parse_positive_unsigned(const char *text)
{
    unsigned long value;
    char *end;

    if (text == NULL || text[0] == '\0') {
        return 0u;
    }

    value = strtoul(text, &end, 10);
    if (*end != '\0' || value == 0ul || value > 1000000ul) {
        return 0u;
    }

    return (unsigned)value;
}

static int parse_hostkey_algorithm(const char *text, hostkey_algorithm_t *algorithm)
{
    if (text == NULL || algorithm == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (strcmp(text, "ecdsa-p256") == 0 ||
        strcmp(text, "ecdsa-sha2-nistp256") == 0) {
        *algorithm = HOSTKEY_ALGORITHM_ECDSA_P256;
        return SSH_OK;
    }
    if (strcmp(text, "ed25519") == 0 ||
        strcmp(text, "ssh-ed25519") == 0) {
        *algorithm = HOSTKEY_ALGORITHM_ED25519;
        return SSH_OK;
    }

    return SSH_ERR_MALFORMED_PACKET;
}

static int parse_ed25519_probe_mode(const char *text, ed25519_probe_mode_t *mode)
{
    if (text == NULL || mode == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (strcmp(text, "publickey") == 0) {
        *mode = ED25519_PROBE_MODE_PUBLICKEY;
        return SSH_OK;
    }
    if (strcmp(text, "hostkey") == 0) {
        *mode = ED25519_PROBE_MODE_HOSTKEY;
        return SSH_OK;
    }

    return SSH_ERR_MALFORMED_PACKET;
}

static void usage(const char *program)
{
    fprintf(
        stderr,
        "usage: %s <port> <root-dir> <username> <password> [hostkey-file] [authorized-pubkey-file] [--max-connections N] [--hostkey-algorithm ecdsa-p256|ed25519]\n"
        "       %s --probe-ed25519 publickey|hostkey\n",
        program,
        program);
}

static int load_file(const char *path, uint8_t *data, size_t data_capacity, size_t *data_len)
{
    FILE *file;
    size_t len;

    if (path == NULL || data == NULL || data_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        return errno == ENOENT ? SSH_ERR_NOT_FOUND : SSH_ERR_PLATFORM;
    }

    len = fread(data, 1u, data_capacity, file);
    if (ferror(file)) {
        (void)fclose(file);
        return SSH_ERR_PLATFORM;
    }
    if (!feof(file)) {
        (void)fclose(file);
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    if (fclose(file) != 0) {
        return SSH_ERR_PLATFORM;
    }

    *data_len = len;
    return len != 0u ? SSH_OK : SSH_ERR_MALFORMED_PACKET;
}

static int save_file(const char *path, const uint8_t *data, size_t data_len)
{
    FILE *file;

    if (path == NULL || data == NULL || data_len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    file = fopen(path, "wb");
    if (file == NULL) {
        return SSH_ERR_PLATFORM;
    }
    if (fwrite(data, 1u, data_len, file) != data_len) {
        (void)fclose(file);
        return SSH_ERR_PLATFORM;
    }
    return fclose(file) == 0 ? SSH_OK : SSH_ERR_PLATFORM;
}

static int is_space_char(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static int base64_value(char c)
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

static int decode_base64_token(const char *text, size_t text_len, uint8_t *out, size_t out_capacity, size_t *out_len)
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
        int value = base64_value(text[i]);
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

static int token_matches(const char *token, size_t token_len, const char *expected)
{
    size_t expected_len;

    if (token == NULL || expected == NULL) {
        return 0;
    }

    expected_len = strlen(expected);
    return token_len == expected_len && memcmp(token, expected, expected_len) == 0;
}

static int copy_authorized_option_value(
    const char *value,
    size_t value_len,
    char *out,
    size_t out_capacity)
{
    size_t i;
    size_t written;
    int quoted;
    int escaped;

    if (value == NULL || out == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    quoted = value_len >= 2u && value[0] == '"' && value[value_len - 1u] == '"';
    if (!quoted && value_len >= out_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    if (!quoted) {
        memcpy(out, value, value_len);
        out[value_len] = '\0';
        return SSH_OK;
    }

    written = 0u;
    escaped = 0;
    for (i = 1u; i + 1u < value_len; ++i) {
        char ch = value[i];
        if (escaped) {
            escaped = 0;
        } else if (ch == '\\') {
            escaped = 1;
            continue;
        } else if (ch == '"') {
            return SSH_ERR_MALFORMED_PACKET;
        }
        if (written + 1u >= out_capacity) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        out[written++] = ch;
    }
    if (escaped) {
        return SSH_ERR_MALFORMED_PACKET;
    }
    out[written] = '\0';
    return SSH_OK;
}

static int path_prefix_is_valid(const char *value)
{
    const char *p;
    int segment_start;

    if (value == NULL || value[0] == '\0') {
        return 0;
    }

    segment_start = 1;
    for (p = value; *p != '\0'; ++p) {
        char ch = *p;
        if (ch == '\\' || ch == ':') {
            return 0;
        }
        if (segment_start &&
            ch == '.' &&
            p[1] == '.' &&
            (p[2] == '\0' || p[2] == '/')) {
            return 0;
        }
        segment_start = ch == '/';
    }

    return 1;
}

static int normalize_path_prefix_list(char *value)
{
    char normalized[MINIMAL_SERVER_MAX_PATH_PREFIX];
    size_t out_len;
    char *cursor;
    int saw_any;

    if (value == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    out_len = 0u;
    cursor = value;
    saw_any = 0;
    while (*cursor != '\0') {
        char *segment_start = cursor;
        char *segment_end;
        size_t segment_len;

        while (*segment_start == ' ' || *segment_start == '\t') {
            ++segment_start;
        }
        segment_end = segment_start;
        while (*segment_end != '\0' && *segment_end != ',') {
            ++segment_end;
        }

        while (segment_end > segment_start &&
               (segment_end[-1] == ' ' || segment_end[-1] == '\t')) {
            --segment_end;
        }
        while (segment_start < segment_end && *segment_start == '/') {
            ++segment_start;
        }

        segment_len = (size_t)(segment_end - segment_start);
        if (segment_len == 0u) {
            return SSH_ERR_MALFORMED_PACKET;
        }

        {
            char segment[MINIMAL_SERVER_MAX_PATH_PREFIX];
            memcpy(segment, segment_start, segment_len);
            segment[segment_len] = '\0';
            if (!path_prefix_is_valid(segment)) {
                return SSH_ERR_MALFORMED_PACKET;
            }
        }

        if (saw_any) {
            if (out_len + 1u >= sizeof(normalized)) {
                return SSH_ERR_BUFFER_TOO_SMALL;
            }
            normalized[out_len++] = ',';
        }
        if (out_len + segment_len >= sizeof(normalized)) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(normalized + out_len, segment_start, segment_len);
        out_len += segment_len;
        saw_any = 1;

        cursor = *segment_end == ',' ? segment_end + 1 : segment_end;
    }

    if (!saw_any) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    normalized[out_len] = '\0';
    memcpy(value, normalized, out_len + 1u);
    return SSH_OK;
}

static int parse_authorized_key_options(
    const char *options,
    size_t options_len,
    authorized_publickey_t *authorized)
{
    size_t token_start;
    size_t i;
    int quoted;
    int escaped;

    if (options == NULL || authorized == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    token_start = 0u;
    quoted = 0;
    escaped = 0;
    for (i = 0u; i <= options_len; ++i) {
        char ch = i < options_len ? options[i] : ',';
        int at_end = i == options_len;

        if (!at_end) {
            if (escaped) {
                escaped = 0;
                continue;
            }
            if (quoted && ch == '\\') {
                escaped = 1;
                continue;
            }
            if (ch == '"') {
                quoted = !quoted;
                continue;
            }
            if (quoted || ch != ',') {
                continue;
            }
        }

        if (i > token_start) {
            const char *token = options + token_start;
            size_t token_len = i - token_start;
            if (token_len > 5u && memcmp(token, "from=", 5u) == 0) {
                int status = copy_authorized_option_value(
                    token + 5u,
                    token_len - 5u,
                    authorized->from_patterns,
                    sizeof(authorized->from_patterns));
                if (status != SSH_OK) {
                    return status;
                }
                authorized->restrict_from = 1;
            } else if (token_len > 18u && memcmp(token, "emssh-path-prefix=", 18u) == 0) {
                int status = copy_authorized_option_value(
                    token + 18u,
                    token_len - 18u,
                    authorized->path_prefix,
                    sizeof(authorized->path_prefix));
                if (status != SSH_OK) {
                    return status;
                }
                status = normalize_path_prefix_list(authorized->path_prefix);
                if (status != SSH_OK) {
                    return status;
                }
                authorized->restrict_path_prefix = 1;
            } else if (token_len > 20u && memcmp(token, "emssh-max-write-end=", 20u) == 0) {
                unsigned long long value_u64;
                char *end = NULL;
                char value_text[32];
                int status = copy_authorized_option_value(
                    token + 20u,
                    token_len - 20u,
                    value_text,
                    sizeof(value_text));
                if (status != SSH_OK) {
                    return status;
                }
                if (value_text[0] == '\0') {
                    return SSH_ERR_MALFORMED_PACKET;
                }
                errno = 0;
                value_u64 = strtoull(value_text, &end, 10);
                if (errno != 0 || end == NULL || *end != '\0') {
                    return SSH_ERR_MALFORMED_PACKET;
                }
                authorized->max_write_end = (uint64_t)value_u64;
                authorized->restrict_max_write_end = 1;
            } else if (token_len > 19u && memcmp(token, "emssh-max-read-end=", 19u) == 0) {
                unsigned long long value_u64;
                char *end = NULL;
                char value_text[32];
                int status = copy_authorized_option_value(
                    token + 19u,
                    token_len - 19u,
                    value_text,
                    sizeof(value_text));
                if (status != SSH_OK) {
                    return status;
                }
                if (value_text[0] == '\0') {
                    return SSH_ERR_MALFORMED_PACKET;
                }
                errno = 0;
                value_u64 = strtoull(value_text, &end, 10);
                if (errno != 0 || end == NULL || *end != '\0') {
                    return SSH_ERR_MALFORMED_PACKET;
                }
                authorized->max_read_end = (uint64_t)value_u64;
                authorized->restrict_max_read_end = 1;
            } else if (token_matches(token, token_len, "emssh-deny-non-sftp-channel")) {
                authorized->deny_non_sftp_channel_request = 1;
            } else if (token_matches(token, token_len, "emssh-deny-rename")) {
                authorized->deny_rename = 1;
            } else if (token_matches(token, token_len, "emssh-deny-delete")) {
                authorized->deny_delete = 1;
            } else if (token_matches(token, token_len, "emssh-deny-setstat")) {
                authorized->deny_setstat = 1;
            } else if (token_matches(token, token_len, "emssh-deny-create")) {
                authorized->deny_create = 1;
            } else if (token_matches(token, token_len, "emssh-deny-hardlink")) {
                authorized->deny_hardlink = 1;
            } else if (token_matches(token, token_len, "emssh-deny-remove")) {
                authorized->deny_remove = 1;
            } else if (token_matches(token, token_len, "emssh-deny-rmdir")) {
                authorized->deny_rmdir = 1;
            } else if (token_matches(token, token_len, "emssh-deny-mkdir")) {
                authorized->deny_mkdir = 1;
            } else if (token_matches(token, token_len, "emssh-deny-open-create")) {
                authorized->deny_open_create = 1;
            } else if (token_matches(token, token_len, "emssh-deny-open-trunc")) {
                authorized->deny_open_trunc = 1;
            } else if (token_matches(token, token_len, "emssh-deny-open-append")) {
                authorized->deny_open_append = 1;
            } else if (token_matches(token, token_len, "emssh-deny-open-write")) {
                authorized->deny_open_write = 1;
            } else if (token_matches(token, token_len, "emssh-deny-open-read")) {
                authorized->deny_open_read = 1;
            } else if (token_matches(token, token_len, "emssh-deny-read")) {
                authorized->deny_read = 1;
            } else if (token_matches(token, token_len, "emssh-deny-realpath")) {
                authorized->deny_realpath = 1;
            } else if (token_matches(token, token_len, "emssh-deny-stat")) {
                authorized->deny_stat = 1;
            } else if (token_matches(token, token_len, "emssh-deny-fstat")) {
                authorized->deny_fstat = 1;
            } else if (token_matches(token, token_len, "emssh-deny-fsetstat")) {
                authorized->deny_fsetstat = 1;
            } else if (token_matches(token, token_len, "emssh-deny-fsync")) {
                authorized->deny_fsync = 1;
            } else if (token_matches(token, token_len, "emssh-deny-statvfs")) {
                authorized->deny_statvfs = 1;
            } else if (token_matches(token, token_len, "emssh-deny-fstatvfs")) {
                authorized->deny_fstatvfs = 1;
            } else if (token_matches(token, token_len, "emssh-deny-opendir")) {
                authorized->deny_opendir = 1;
            } else if (token_matches(token, token_len, "emssh-deny-readdir")) {
                authorized->deny_readdir = 1;
            } else if (token_matches(token, token_len, "emssh-deny-write")) {
                authorized->deny_write = 1;
            } else if (token_matches(token, token_len, "emssh-readonly")) {
                authorized->read_only = 1;
            }
        }

        token_start = i + 1u;
    }

    return quoted || escaped ? SSH_ERR_MALFORMED_PACKET : SSH_OK;
}

static int from_pattern_char_matches(char pattern, char value)
{
    return pattern == '?' || pattern == value;
}

static int from_pattern_matches_one(
    const char *pattern,
    size_t pattern_len,
    const char *value)
{
    size_t value_len;
    size_t pi;
    size_t vi;
    size_t star_pi;
    size_t star_vi;

    if (pattern == NULL || value == NULL) {
        return 0;
    }

    value_len = strlen(value);
    pi = 0u;
    vi = 0u;
    star_pi = (size_t)-1;
    star_vi = 0u;

    while (vi < value_len) {
        if (pi < pattern_len && from_pattern_char_matches(pattern[pi], value[vi])) {
            ++pi;
            ++vi;
        } else if (pi < pattern_len && pattern[pi] == '*') {
            star_pi = pi++;
            star_vi = vi;
        } else if (star_pi != (size_t)-1) {
            pi = star_pi + 1u;
            vi = ++star_vi;
        } else {
            return 0;
        }
    }

    while (pi < pattern_len && pattern[pi] == '*') {
        ++pi;
    }

    return pi == pattern_len;
}

static int from_patterns_match(const char *patterns, const char *peer_address)
{
    const char *start;
    const char *p;
    int matched;

    if (patterns == NULL || peer_address == NULL || peer_address[0] == '\0') {
        return 0;
    }

    start = patterns;
    matched = 0;
    for (p = patterns; ; ++p) {
        if (*p == ',' || *p == '\0') {
            size_t len = (size_t)(p - start);
            int negated = len > 0u && start[0] == '!';
            const char *pattern = negated ? start + 1 : start;
            size_t pattern_len = negated ? len - 1u : len;
            if (pattern_len > 0u && from_pattern_matches_one(pattern, pattern_len, peer_address)) {
                if (negated) {
                    return 0;
                }
                matched = 1;
            }
            if (*p == '\0') {
                break;
            }
            start = p + 1;
        }
    }

    return matched;
}

static int authorized_options_allow_peer(
    const authorized_publickey_t *authorized,
    const password_auth_ctx_t *auth)
{
    if (authorized == NULL || auth == NULL) {
        return 0;
    }
    if (!authorized->restrict_from) {
        return 1;
    }

    return from_patterns_match(authorized->from_patterns, auth->peer_address);
}

static int path_matches_prefix(const char *path, const char *prefix)
{
    const char *p;
    size_t prefix_len;

    if (path == NULL || prefix == NULL || prefix[0] == '\0') {
        return 0;
    }

    p = path;
    while (*p == '/') {
        ++p;
    }
    while (p[0] == '.' && p[1] == '/') {
        p += 2;
    }

    prefix_len = strlen(prefix);
    while (prefix_len > 0u && prefix[prefix_len - 1u] == '/') {
        --prefix_len;
    }
    if (prefix_len == 0u) {
        return 0;
    }
    if (strncmp(p, prefix, prefix_len) != 0) {
        return 0;
    }

    return p[prefix_len] == '\0' || p[prefix_len] == '/';
}

static int path_matches_prefix_list(const char *path, const char *prefixes)
{
    const char *start;
    const char *p;

    if (path == NULL || prefixes == NULL || prefixes[0] == '\0') {
        return 0;
    }

    start = prefixes;
    for (p = prefixes; ; ++p) {
        if (*p == ',' || *p == '\0') {
            size_t prefix_len = (size_t)(p - start);
            if (prefix_len > 0u) {
                char prefix[MINIMAL_SERVER_MAX_PATH_PREFIX];
                if (prefix_len >= sizeof(prefix)) {
                    return 0;
                }
                memcpy(prefix, start, prefix_len);
                prefix[prefix_len] = '\0';
                if (path_matches_prefix(path, prefix)) {
                    return 1;
                }
            }
            if (*p == '\0') {
                break;
            }
            start = p + 1;
        }
    }

    return 0;
}

static int path_is_dot_or_root(const char *path)
{
    return path != NULL &&
           (strcmp(path, ".") == 0 || strcmp(path, "/") == 0);
}

static int active_non_sftp_channel_request_policy(void *ctx, const ssh_channel_request_t *request)
{
    const password_auth_ctx_t *auth = (const password_auth_ctx_t *)ctx;

    if (auth == NULL || request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (auth->active_policy.deny_non_sftp_channel_request) {
        return SSH_ERR_SECURITY;
    }

    return SSH_OK;
}

static int is_authorized_key_algorithm(const char *token, size_t token_len)
{
    return token_matches(token, token_len, "ecdsa-sha2-nistp256") ||
           token_matches(token, token_len, "ssh-ed25519") ||
           token_matches(token, token_len, "ssh-rsa");
}

static int active_policy_is_readonly_denied_operation(const sftp_policy_request_t *request)
{
    if (request == NULL) {
        return 0;
    }

    switch (request->operation) {
    case SFTP_POLICY_OPEN:
        return (request->pflags & SSH_FXF_WRITE) != 0u ||
               (request->pflags & SSH_FXF_APPEND) != 0u ||
               (request->pflags & SSH_FXF_CREAT) != 0u ||
               (request->pflags & SSH_FXF_TRUNC) != 0u ||
               (request->pflags & SSH_FXF_EXCL) != 0u;
    case SFTP_POLICY_WRITE:
    case SFTP_POLICY_SETSTAT:
    case SFTP_POLICY_REMOVE:
    case SFTP_POLICY_MKDIR:
    case SFTP_POLICY_RMDIR:
    case SFTP_POLICY_RENAME:
    case SFTP_POLICY_FSETSTAT:
    case SFTP_POLICY_FSYNC:
    case SFTP_POLICY_HARDLINK:
        return 1;
    default:
        return 0;
    }
}

static int active_sftp_policy(void *ctx, const sftp_policy_request_t *request)
{
    const password_auth_ctx_t *auth = (const password_auth_ctx_t *)ctx;

    if (auth == NULL || request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (auth->active_policy.deny_rename &&
        request->operation == SFTP_POLICY_RENAME) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_delete &&
        (request->operation == SFTP_POLICY_REMOVE ||
         request->operation == SFTP_POLICY_RMDIR)) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_setstat &&
        (request->operation == SFTP_POLICY_SETSTAT ||
         request->operation == SFTP_POLICY_FSETSTAT)) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_create &&
        ((request->operation == SFTP_POLICY_OPEN &&
          (request->pflags & SSH_FXF_CREAT) != 0u) ||
         request->operation == SFTP_POLICY_MKDIR)) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_hardlink &&
        request->operation == SFTP_POLICY_HARDLINK) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_remove &&
        request->operation == SFTP_POLICY_REMOVE) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_rmdir &&
        request->operation == SFTP_POLICY_RMDIR) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_mkdir &&
        request->operation == SFTP_POLICY_MKDIR) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_open_create &&
        request->operation == SFTP_POLICY_OPEN &&
        (request->pflags & SSH_FXF_CREAT) != 0u) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_open_trunc &&
        request->operation == SFTP_POLICY_OPEN &&
        (request->pflags & SSH_FXF_TRUNC) != 0u) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_open_append &&
        request->operation == SFTP_POLICY_OPEN &&
        (request->pflags & SSH_FXF_APPEND) != 0u) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_open_write &&
        request->operation == SFTP_POLICY_OPEN &&
        (request->pflags & SSH_FXF_WRITE) != 0u) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_open_read &&
        request->operation == SFTP_POLICY_OPEN &&
        (request->pflags & SSH_FXF_READ) != 0u) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_read &&
        request->operation == SFTP_POLICY_READ) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_realpath &&
        request->operation == SFTP_POLICY_REALPATH) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_stat &&
        request->operation == SFTP_POLICY_STAT) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_fstat &&
        request->operation == SFTP_POLICY_FSTAT) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_fsetstat &&
        request->operation == SFTP_POLICY_FSETSTAT) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_fsync &&
        request->operation == SFTP_POLICY_FSYNC) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_statvfs &&
        request->operation == SFTP_POLICY_STATVFS) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_fstatvfs &&
        request->operation == SFTP_POLICY_FSTATVFS) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_opendir &&
        request->operation == SFTP_POLICY_OPENDIR) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_readdir &&
        request->operation == SFTP_POLICY_READDIR) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.deny_write &&
        request->operation == SFTP_POLICY_WRITE) {
        return SSH_ERR_SECURITY;
    }
    if (auth->active_policy.restrict_path_prefix) {
        if (request->path != NULL &&
            !(request->operation == SFTP_POLICY_REALPATH && path_is_dot_or_root(request->path)) &&
            !path_matches_prefix_list(request->path, auth->active_policy.path_prefix)) {
            return SSH_ERR_SECURITY;
        }
        if (request->new_path != NULL &&
            !path_matches_prefix_list(request->new_path, auth->active_policy.path_prefix)) {
            return SSH_ERR_SECURITY;
        }
    }
    if (auth->active_policy.read_only &&
        active_policy_is_readonly_denied_operation(request)) {
        return SSH_ERR_READ_ONLY;
    }
    if (auth->active_policy.restrict_max_read_end &&
        request->operation == SFTP_POLICY_READ) {
        if (request->length > UINT64_MAX - request->offset ||
            request->offset + (uint64_t)request->length > auth->active_policy.max_read_end) {
            return SSH_ERR_SECURITY;
        }
    }
    if (auth->active_policy.restrict_max_write_end &&
        request->operation == SFTP_POLICY_WRITE) {
        if (request->length > UINT64_MAX - request->offset ||
            request->offset + (uint64_t)request->length > auth->active_policy.max_write_end) {
            return SSH_ERR_SECURITY;
        }
    }

    return SSH_OK;
}

static char *skip_authorized_keys_field(char *p)
{
    int quoted;
    int escaped;

    if (p == NULL) {
        return NULL;
    }

    quoted = 0;
    escaped = 0;
    while (*p != '\0') {
        if (escaped) {
            escaped = 0;
        } else if (*p == '\\' && quoted) {
            escaped = 1;
        } else if (*p == '"') {
            quoted = !quoted;
        } else if (!quoted && is_space_char(*p)) {
            break;
        }
        ++p;
    }

    return quoted || escaped ? NULL : p;
}

static int parse_authorized_pubkey_line(char *line, authorized_publickey_t *authorized)
{
    char *algorithm;
    char *encoded;
    char *p;
    char *field_end;
    size_t algorithm_len;
    size_t encoded_len;
    int has_options;
    int status;

    if (line == NULL || authorized == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    p = line;
    while (*p != '\0' && is_space_char(*p)) {
        ++p;
    }
    if (*p == '\0' || *p == '#') {
        return SSH_ERR_NOT_FOUND;
    }

    algorithm = p;
    field_end = skip_authorized_keys_field(algorithm);
    if (field_end == NULL) {
        return SSH_ERR_MALFORMED_PACKET;
    }
    algorithm_len = (size_t)(field_end - algorithm);
    has_options = 0;
    if (!is_authorized_key_algorithm(algorithm, algorithm_len)) {
        status = parse_authorized_key_options(algorithm, algorithm_len, authorized);
        if (status != SSH_OK) {
            return status;
        }
        has_options = 1;
        p = field_end;
        while (*p != '\0' && is_space_char(*p)) {
            *p++ = '\0';
        }
        algorithm = p;
        field_end = skip_authorized_keys_field(algorithm);
        if (field_end == NULL) {
            return SSH_ERR_MALFORMED_PACKET;
        }
        algorithm_len = (size_t)(field_end - algorithm);
    }
    if (*field_end == '\0') {
        return SSH_ERR_MALFORMED_PACKET;
    }
    if (!is_authorized_key_algorithm(algorithm, algorithm_len)) {
        return SSH_ERR_MALFORMED_PACKET;
    }
    if (!has_options) {
        authorized->restrict_from = 0;
        authorized->from_patterns[0] = '\0';
        authorized->restrict_path_prefix = 0;
        authorized->path_prefix[0] = '\0';
        authorized->restrict_max_read_end = 0;
        authorized->max_read_end = 0u;
        authorized->restrict_max_write_end = 0;
        authorized->max_write_end = 0u;
        authorized->deny_non_sftp_channel_request = 0;
        authorized->deny_rename = 0;
        authorized->deny_delete = 0;
        authorized->deny_setstat = 0;
        authorized->deny_create = 0;
        authorized->deny_hardlink = 0;
        authorized->deny_remove = 0;
        authorized->deny_rmdir = 0;
        authorized->deny_mkdir = 0;
        authorized->deny_open_create = 0;
        authorized->deny_open_trunc = 0;
        authorized->deny_open_append = 0;
        authorized->deny_open_write = 0;
        authorized->deny_open_read = 0;
        authorized->deny_read = 0;
        authorized->deny_realpath = 0;
        authorized->deny_stat = 0;
        authorized->deny_fstat = 0;
        authorized->deny_fsetstat = 0;
        authorized->deny_fsync = 0;
        authorized->deny_statvfs = 0;
        authorized->deny_fstatvfs = 0;
        authorized->deny_opendir = 0;
        authorized->deny_readdir = 0;
        authorized->deny_write = 0;
        authorized->read_only = 0;
    }
    p = field_end;
    while (*p != '\0' && is_space_char(*p)) {
        *p++ = '\0';
    }
    encoded = p;
    while (*p != '\0' && !is_space_char(*p)) {
        ++p;
    }
    encoded_len = (size_t)(p - encoded);
    if (algorithm_len == 0u || algorithm_len >= sizeof(authorized->algorithm) || encoded_len == 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    memcpy(authorized->algorithm, algorithm, algorithm_len);
    authorized->algorithm[algorithm_len] = '\0';
    status = decode_base64_token(
        encoded,
        encoded_len,
        authorized->publickey,
        sizeof(authorized->publickey),
        &authorized->publickey_len);
    if (status != SSH_OK) {
        memset(authorized, 0, sizeof(*authorized));
    }
    return status;
}

static int load_authorized_pubkeys(const char *path, password_auth_ctx_t *auth)
{
    char line[1024];
    FILE *file;
    int status;

    if (path == NULL || auth == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        return SSH_ERR_PLATFORM;
    }

    auth->authorized_key_count = 0u;
    while (fgets(line, sizeof(line), file) != NULL) {
        size_t len = strlen(line);
        authorized_publickey_t parsed;

        if (len == sizeof(line) - 1u && line[len - 1u] != '\n') {
            (void)fclose(file);
            return SSH_ERR_BUFFER_TOO_SMALL;
        }

        memset(&parsed, 0, sizeof(parsed));
        status = parse_authorized_pubkey_line(line, &parsed);
        if (status == SSH_ERR_NOT_FOUND) {
            continue;
        }
        if (status != SSH_OK) {
            (void)fclose(file);
            return status;
        }
        if (auth->authorized_key_count >= MINIMAL_SERVER_MAX_AUTHORIZED_KEYS) {
            (void)fclose(file);
            return SSH_ERR_BUFFER_TOO_SMALL;
        }

        auth->authorized_keys[auth->authorized_key_count] = parsed;
        ++auth->authorized_key_count;
    }

    if (ferror(file)) {
        (void)fclose(file);
        return SSH_ERR_PLATFORM;
    }
    if (fclose(file) != 0) {
        return SSH_ERR_PLATFORM;
    }

    return auth->authorized_key_count != 0u ? SSH_OK : SSH_ERR_MALFORMED_PACKET;
}

static int configure_hostkey(
    ssh_crypto_context_t *crypto_ctx,
    const char *hostkey_path,
    hostkey_algorithm_t hostkey_algorithm)
{
    const ssh_crypto_api_t *crypto;
    ssh_string_view_t hostkey_alg;
    uint8_t private_key[128];
    size_t private_key_len;
    int status;

    if (crypto_ctx == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    crypto = ssh_crypto_api(crypto_ctx);
    if (crypto == NULL) {
        return SSH_ERR_PLATFORM;
    }
    hostkey_alg = hostkey_algorithm_view(hostkey_algorithm);

    if (hostkey_path != NULL) {
        status = load_file(hostkey_path, private_key, sizeof(private_key), &private_key_len);
        if (status == SSH_OK) {
            if (crypto->hostkey_import_private_auto == NULL) {
                memset(private_key, 0, sizeof(private_key));
                return SSH_ERR_UNSUPPORTED;
            }
            status = crypto->hostkey_import_private_auto(
                crypto->ctx,
                hostkey_alg,
                private_key,
                private_key_len);
            memset(private_key, 0, sizeof(private_key));
            return status;
        }
        if (status != SSH_ERR_NOT_FOUND) {
            return status;
        }
    }

    if (crypto->hostkey_generate == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    status = crypto->hostkey_generate(crypto->ctx, hostkey_alg);
    if (status != SSH_OK || hostkey_path == NULL) {
        return status;
    }

    if (crypto->hostkey_export_private == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    status = crypto->hostkey_export_private(
        crypto->ctx,
        hostkey_alg,
        private_key,
        sizeof(private_key),
        &private_key_len);
    if (status == SSH_OK) {
        status = save_file(hostkey_path, private_key, private_key_len);
    }
    memset(private_key, 0, sizeof(private_key));
    return status;
}

static int has_authorized_ed25519_key(const password_auth_ctx_t *auth)
{
    size_t i;

    if (auth == NULL) {
        return 0;
    }

    for (i = 0u; i < auth->authorized_key_count; ++i) {
        if (strcmp(auth->authorized_keys[i].algorithm, "ssh-ed25519") == 0) {
            return 1;
        }
    }

    return 0;
}

static int detect_ed25519_hostkey_support(void)
{
    minimal_crypto_context_t crypto_ctx;
    const ssh_crypto_api_t *crypto;
    int status;

    memset(&crypto_ctx, 0, sizeof(crypto_ctx));
    status = ssh_crypto_open(MINIMAL_CTX_PTR(&crypto_ctx));
    if (status != SSH_OK) {
        return 0;
    }
    crypto = ssh_crypto_api(MINIMAL_CTX_CONST_PTR(&crypto_ctx));
    if (crypto == NULL || crypto->hostkey_generate == NULL) {
        ssh_crypto_close(MINIMAL_CTX_PTR(&crypto_ctx));
        return 0;
    }
    status = crypto->hostkey_generate(
        crypto->ctx,
        hostkey_algorithm_view(HOSTKEY_ALGORITHM_ED25519));
    ssh_crypto_close(MINIMAL_CTX_PTR(&crypto_ctx));
    return status == SSH_OK;
}

static int detect_ed25519_publickey_verify_support(void)
{
    minimal_crypto_context_t crypto_ctx;
    const ssh_crypto_api_t *crypto;
    ssh_string_view_t algorithm;
    uint8_t hostkey_blob[EMSSH_MAX_HOST_KEY_BLOB];
    uint8_t exchange_hash[32];
    uint8_t signature[EMSSH_MAX_SIGNATURE];
    size_t hostkey_blob_len;
    size_t signature_len;
    int status;

    memset(&crypto_ctx, 0, sizeof(crypto_ctx));
    status = ssh_crypto_open(MINIMAL_CTX_PTR(&crypto_ctx));
    if (status != SSH_OK) {
        return 0;
    }
    crypto = ssh_crypto_api(MINIMAL_CTX_CONST_PTR(&crypto_ctx));
    if (crypto == NULL || crypto->hostkey_generate == NULL || crypto->hostkey_public == NULL ||
        crypto->hostkey_sign == NULL || crypto->publickey_verify == NULL) {
        ssh_crypto_close(MINIMAL_CTX_PTR(&crypto_ctx));
        return 0;
    }
    algorithm = hostkey_algorithm_view(HOSTKEY_ALGORITHM_ED25519);
    status = crypto->hostkey_generate(crypto->ctx, algorithm);
    if (status != SSH_OK) {
        ssh_crypto_close(MINIMAL_CTX_PTR(&crypto_ctx));
        return 0;
    }

    memset(exchange_hash, 0xA5, sizeof(exchange_hash));
    hostkey_blob_len = 0u;
    signature_len = 0u;
    status = crypto->hostkey_public(
        crypto->ctx,
        algorithm,
        hostkey_blob,
        sizeof(hostkey_blob),
        &hostkey_blob_len);
    if (status == SSH_OK) {
        status = crypto->hostkey_sign(
            crypto->ctx,
            algorithm,
            exchange_hash,
            sizeof(exchange_hash),
            signature,
            sizeof(signature),
            &signature_len);
    }
    if (status == SSH_OK) {
        status = crypto->publickey_verify(
            crypto->ctx,
            algorithm,
            hostkey_blob,
            hostkey_blob_len,
            exchange_hash,
            sizeof(exchange_hash),
            signature,
            signature_len);
    }
    ssh_crypto_close(MINIMAL_CTX_PTR(&crypto_ctx));
    return status == SSH_OK;
}

int main(int argc, char **argv)
{
    uint16_t port;
    const char *hostkey_path;
    const char *authorized_keys_path;
    unsigned max_connections;
    unsigned connection_count;
    int positional_argc;
    hostkey_algorithm_t hostkey_algorithm;
    minimal_crypto_context_t crypto_ctx;
    ssh_tcp_platform_t tcp;
    ssh_tcp_listener_t listener;
    ssh_tcp_conn_t conn;
    ssh_stdio_fs_t fs;
    ssh_platform_t platform;
    ssh_server_config_t config;
    ssh_server_session_options_t options;
    ssh_server_t server;
    password_auth_ctx_t auth;
    int status;
    int initialized_crypto;
    int initialized_tcp;
    int initialized_fs;
    int initialized_server;
    ed25519_probe_mode_t probe_mode;

    max_connections = 1u;
    hostkey_algorithm = HOSTKEY_ALGORITHM_ECDSA_P256;
    probe_mode = ED25519_PROBE_MODE_NONE;

    if (argc == 3 && strcmp(argv[1], "--probe-ed25519") == 0) {
        if (parse_ed25519_probe_mode(argv[2], &probe_mode) != SSH_OK) {
            usage(argv[0]);
            return 2;
        }
        if (probe_mode == ED25519_PROBE_MODE_PUBLICKEY) {
            if (detect_ed25519_publickey_verify_support()) {
                printf("ed25519 publickey verify supported\n");
                return 0;
            }
            printf("ed25519 publickey verify unsupported\n");
            return 1;
        }
        if (probe_mode == ED25519_PROBE_MODE_HOSTKEY) {
            if (detect_ed25519_hostkey_support()) {
                printf("ed25519 hostkey supported\n");
                return 0;
            }
            printf("ed25519 hostkey unsupported\n");
            return 1;
        }
        return 2;
    }

    positional_argc = argc;
    while (positional_argc >= 3) {
        if (strcmp(argv[positional_argc - 2], "--max-connections") == 0) {
            max_connections = parse_positive_unsigned(argv[positional_argc - 1]);
            if (max_connections == 0u) {
                usage(argv[0]);
                return 2;
            }
            positional_argc -= 2;
            continue;
        }
        if (strcmp(argv[positional_argc - 2], "--hostkey-algorithm") == 0) {
            if (parse_hostkey_algorithm(argv[positional_argc - 1], &hostkey_algorithm) != SSH_OK) {
                usage(argv[0]);
                return 2;
            }
            positional_argc -= 2;
            continue;
        }
        break;
    }

    if (positional_argc < 5 || positional_argc > 7) {
        usage(argv[0]);
        return 2;
    }

    port = parse_port(argv[1]);
    if (port == 0u) {
        usage(argv[0]);
        return 2;
    }
    hostkey_path = positional_argc >= 6 ? argv[5] : NULL;
    authorized_keys_path = positional_argc >= 7 ? argv[6] : NULL;

    memset(&crypto_ctx, 0, sizeof(crypto_ctx));
    memset(&tcp, 0, sizeof(tcp));
    memset(&listener, 0, sizeof(listener));
    memset(&conn, 0, sizeof(conn));
    memset(&fs, 0, sizeof(fs));
    memset(&platform, 0, sizeof(platform));
    memset(&server, 0, sizeof(server));
    initialized_crypto = 0;
    initialized_tcp = 0;
    initialized_fs = 0;
    initialized_server = 0;

    status = ssh_crypto_open(MINIMAL_CTX_PTR(&crypto_ctx));
    if (status != SSH_OK) {
        fprintf(stderr, "crypto init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_crypto = 1;

    status = configure_hostkey(MINIMAL_CTX_PTR(&crypto_ctx), hostkey_path, hostkey_algorithm);
    if (status != SSH_OK) {
        fprintf(stderr, "hostkey setup failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }

    status = ssh_tcp_platform_init(&tcp);
    if (status != SSH_OK) {
        fprintf(stderr, "tcp init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_tcp = 1;

    status = ssh_stdio_fs_init(&fs, argv[2]);
    if (status != SSH_OK) {
        fprintf(stderr, "filesystem init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_fs = 1;

    auth.username = argv[3];
    auth.password = argv[4];
    auth.peer_address = NULL;
    memset(auth.authorized_keys, 0, sizeof(auth.authorized_keys));
    auth.authorized_key_count = 0u;
    auth.ed25519_publickey_supported = 1;
    memset(&auth.active_policy, 0, sizeof(auth.active_policy));
    if (authorized_keys_path != NULL) {
        status = load_authorized_pubkeys(authorized_keys_path, &auth);
        if (status != SSH_OK) {
            fprintf(stderr, "authorized public key setup failed: %s\n", ssh_status_string(status));
            goto cleanup;
        }
        if (has_authorized_ed25519_key(&auth)) {
            auth.ed25519_publickey_supported = detect_ed25519_publickey_verify_support();
            if (!auth.ed25519_publickey_supported) {
                fprintf(stderr, "ed25519 publickey verify unsupported on this crypto context\n");
            }
        }
    }

    platform.net = ssh_tcp_net_api(&tcp);
    platform.fs = ssh_stdio_fs_api(&fs);
    platform.crypto = ssh_crypto_api(MINIMAL_CTX_CONST_PTR(&crypto_ctx));
    platform.rng = ssh_crypto_rng_api(MINIMAL_CTX_CONST_PTR(&crypto_ctx));

    ssh_server_config_defaults(&config);
    config.password_auth = password_auth;
    config.publickey_auth = authorized_keys_path != NULL ? publickey_auth : NULL;
    config.auth_ctx = &auth;

    status = ssh_server_init(&server, &platform, &config);
    if (status != SSH_OK) {
        fprintf(stderr, "server init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_server = 1;

    status = ssh_tcp_listen(&tcp, NULL, port, 1, &listener);
    if (status != SSH_OK) {
        fprintf(stderr, "listen failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }

    printf(
        "listening on 0.0.0.0:%u, root=%s, user=%s, max_connections=%u\n",
        (unsigned)port,
        argv[2],
        argv[3],
        max_connections);
    fflush(stdout);

    ssh_server_session_options_defaults(&options);
    options.timeout_ms = 30000u;
    options.max_sftp_packets = 0u;
    options.sftp_policy = active_sftp_policy;
    options.sftp_policy_ctx = &auth;
    options.non_sftp_channel_request_policy = active_non_sftp_channel_request_policy;
    options.non_sftp_channel_request_policy_ctx = &auth;

    status = SSH_OK;
    for (connection_count = 0u; connection_count < max_connections; ++connection_count) {
        int session_status;

        memset(&conn, 0, sizeof(conn));
        memset(&auth.active_policy, 0, sizeof(auth.active_policy));
        session_status = ssh_tcp_accept(&tcp, &listener, &conn, 0u);
        if (session_status != SSH_OK) {
            fprintf(stderr, "accept failed: %s\n", ssh_status_string(session_status));
            status = session_status;
            goto cleanup;
        }
        auth.peer_address = ssh_tcp_conn_peer_address(&conn);

        session_status = ssh_server_run_sftp_session(&server, &conn, &options);
        if (session_status != SSH_OK) {
            fprintf(stderr, "session ended: %s\n", ssh_status_string(session_status));
            status = session_status;
        }
        (void)ssh_tcp_conn_close(&tcp, &conn);
    }

cleanup:
    (void)ssh_tcp_conn_close(&tcp, &conn);
    (void)ssh_tcp_listener_close(&tcp, &listener);
    if (initialized_server) {
        ssh_server_deinit(&server);
    }
    if (initialized_fs) {
        ssh_stdio_fs_deinit(&fs);
    }
    if (initialized_tcp) {
        ssh_tcp_platform_deinit(&tcp);
    }
    if (initialized_crypto) {
        ssh_crypto_close(MINIMAL_CTX_PTR(&crypto_ctx));
    }

    return status == SSH_OK ? 0 : 1;
}
