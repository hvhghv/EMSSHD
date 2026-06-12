#include "emtask_internal.h"

#include "emssh/crypto_mbedtls.h"
#include "emssh/ssh_crypto.h"
#include "emssh/ssh_transport.h"
#include "mbedtls/md.h"


#include <time.h>

typedef ssh_crypto_context_mbedtls_legacy_t emtask_crypto_context_t;
#define EMTASK_CTX_PTR(ctx) ((ssh_crypto_context_t *)(ctx))
#define EMTASK_CTX_CONST_PTR(ctx) ((const ssh_crypto_context_t *)(ctx))

#define EMTASK_PANEL_TOKEN_RANDOM_BYTES 24u
#define EMTASK_PANEL_OTP_RANDOM_BYTES 20u
#define EMTASK_QR_VERSION 10u
#define EMTASK_QR_SIZE (17u + (4u * EMTASK_QR_VERSION))
#define EMTASK_QR_DATA_CODEWORDS 274u
#define EMTASK_QR_TOTAL_CODEWORDS 346u
#define EMTASK_QR_ECC_CODEWORDS 18u
#define EMTASK_QR_BLOCK_COUNT 4u
#define EMTASK_QR_PAYLOAD_MAX 512u
#define EMTASK_TERMINAL_RESTART_GRACE_MS 5000u

static int emtask_net_read(void *ctx, void *conn, uint8_t *buf, size_t len, uint32_t timeout_ms);
static int emtask_net_write(void *ctx, void *conn, const uint8_t *buf, size_t len, uint32_t timeout_ms);
static int emtask_net_close(void *ctx, void *conn);
static int emtask_panel_decode_base32_secret(const char *text, uint8_t *out, size_t out_capacity, size_t *out_len);
static int emtask_panel_materialize_auth(emtask_config_t *config);
static int emtask_panel_materialize_qr(const emtask_config_t *config);
static int emtask_panel_tasks_db_check_runtime(const emtask_global_config_t *global);
static int emtask_panel_tasks_db_load(emtask_config_t *config);
static int emtask_panel_tasks_db_insert(const emtask_global_config_t *global, const emtask_task_config_t *task);
static int emtask_panel_tasks_db_update(const emtask_global_config_t *global, const char *old_task_name, const emtask_task_config_t *task);
static int emtask_panel_tasks_db_delete(const emtask_global_config_t *global, const char *task_name);
static int emtask_panel_create_task_from_json(emtask_app_t *app, const char *json, char *out, size_t out_capacity);
static int emtask_panel_update_task_from_json(emtask_app_t *app, const char *task_name, const char *json, char *out, size_t out_capacity);
static int emtask_panel_delete_task_by_name(emtask_app_t *app, const char *task_name, char *out, size_t out_capacity);
static int emtask_panel_restart_task_by_name(emtask_app_t *app, const char *task_name, char *out, size_t out_capacity);
static int emtask_task_init(emtask_app_t *app, emtask_task_t *task, const emtask_task_config_t *config);
static void emtask_task_deinit(emtask_app_t *app, emtask_task_t *task);
static int emtask_term_restart_manual(emtask_term_t *term);

static const ssh_net_api_t g_emtask_net_api = {
    emtask_net_read,
    emtask_net_write,
    emtask_net_close,
    NULL
};

static void emtask_screen_feed_locked(emtask_term_t *term, const uint8_t *buf, size_t len);
static void emtask_term_replay_append_locked(emtask_term_t *term, const uint8_t *buf, size_t len);

void emtask_logf(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    (void)fprintf(stderr, "[emtask] ");
    (void)vfprintf(stderr, fmt, args);
    (void)fprintf(stderr, "\n");
    va_end(args);
}

static void emtask_term_clear_last_error_locked(emtask_term_t *term)
{
    if (term == NULL) {
        return;
    }
    term->last_error[0] = '\0';
    term->last_error_status = 0u;
    term->last_error_ms = 0u;
}

static void emtask_term_set_last_error_locked(emtask_term_t *term, int status, const char *fmt, ...)
{
    va_list args;

    if (term == NULL || fmt == NULL) {
        return;
    }
    va_start(args, fmt);
    (void)vsnprintf(term->last_error, sizeof(term->last_error), fmt, args);
    va_end(args);
    term->last_error[sizeof(term->last_error) - 1u] = '\0';
    term->last_error_status = status;
    term->last_error_ms = emtask_platform_monotonic_ms();
}

static int emtask_copy_text(char *dst, size_t dst_capacity, const char *src)
{
    size_t len;

    if (dst == NULL || src == NULL || dst_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    len = strlen(src);
    if (len + 1u > dst_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(dst, src, len + 1u);
    return SSH_OK;
}

static size_t emtask_min_size(size_t a, size_t b)
{
    return a < b ? a : b;
}

static char *emtask_trim(char *text)
{
    char *end;

    if (text == NULL) {
        return NULL;
    }

    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') {
        ++text;
    }

    end = text + strlen(text);
    while (end > text && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) {
        --end;
    }
    *end = '\0';
    return text;
}

static void emtask_unquote(char *text)
{
    size_t len;

    if (text == NULL) {
        return;
    }
    len = strlen(text);
    if (len >= 2u && ((text[0] == '"' && text[len - 1u] == '"') || (text[0] == '\'' && text[len - 1u] == '\''))) {
        memmove(text, text + 1, len - 2u);
        text[len - 2u] = '\0';
    }
}

static int emtask_key_equals(const char *lhs, const char *rhs)
{
    return emtask_platform_key_equals(lhs, rhs);
}

static int emtask_parse_port(const char *text, uint16_t *port_out)
{
    unsigned long value;
    char *end;

    if (text == NULL || port_out == NULL || text[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    value = strtoul(text, &end, 10);
    if (*end != '\0' || value == 0ul || value > 65535ul) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *port_out = (uint16_t)value;
    return SSH_OK;
}

static int emtask_parse_u32(const char *text, uint32_t *value_out)
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

static int emtask_parse_unsigned(const char *text, unsigned *value_out)
{
    unsigned long value;
    char *end;

    if (text == NULL || value_out == NULL || text[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    value = strtoul(text, &end, 10);
    if (*end != '\0' || value > 1000000ul) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *value_out = (unsigned)value;
    return SSH_OK;
}

static int emtask_parse_bool(const char *text, int *value_out)
{
    if (text == NULL || value_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (emtask_key_equals(text, "1") ||
        emtask_key_equals(text, "true") ||
        emtask_key_equals(text, "yes") ||
        emtask_key_equals(text, "on")) {
        *value_out = 1;
        return SSH_OK;
    }
    if (emtask_key_equals(text, "0") ||
        emtask_key_equals(text, "false") ||
        emtask_key_equals(text, "no") ||
        emtask_key_equals(text, "off")) {
        *value_out = 0;
        return SSH_OK;
    }
    return SSH_ERR_INVALID_ARGUMENT;
}

static int emtask_path_is_absolute(const char *path)
{
    return emtask_platform_path_is_absolute(path);
}

static void emtask_task_config_defaults(emtask_task_config_t *task)
{
    if (task == NULL) {
        return;
    }

    memset(task, 0, sizeof(*task));
    task->port = EMTASK_DEFAULT_PORT;
    task->restart_limit = EMTASK_DEFAULT_RESTART_LIMIT;
    task->restart_window_sec = EMTASK_DEFAULT_RESTART_WINDOW_SEC;
    task->replay_buffer_bytes = EMTASK_DEFAULT_REPLAY_BUFFER_BYTES;
    task->use_conpty = emtask_platform_default_use_conpty();
    task->replay_on_attach = 1;
    task->repaint_on_attach = 1;
    task->screen_snapshot = EMTASK_DEFAULT_SCREEN_SNAPSHOT;
    task->use_sftp = 1;
}

static void emtask_config_defaults(emtask_config_t *config)
{
    if (config == NULL) {
        return;
    }

    memset(config, 0, sizeof(*config));
    config->global.timeout_ms = EMTASK_DEFAULT_TIMEOUT_MS;
    config->global.max_workers = EMTASK_DEFAULT_MAX_WORKERS;
    config->global.use_conpty = emtask_platform_default_use_conpty();
    config->global.auth_backend = EMTASK_AUTH_BACKEND_INTERNAL;
    config->global.panel_enabled = 1;
    config->global.panel_port = (uint16_t)EMTASK_DEFAULT_PANEL_PORT;
    config->global.panel_auth = EMTASK_PANEL_AUTH_TOKEN | EMTASK_PANEL_AUTH_OTP;
    (void)emtask_copy_text(config->global.hostkey_file, sizeof(config->global.hostkey_file), "emtask_hostkey_p256.raw");
    (void)emtask_copy_text(
        config->global.panel_listen_address,
        sizeof(config->global.panel_listen_address),
        EMTASK_DEFAULT_PANEL_LISTEN_ADDRESS);
    (void)emtask_copy_text(
        config->global.panel_auth_file,
        sizeof(config->global.panel_auth_file),
        EMTASK_DEFAULT_PANEL_AUTH_FILE);
    (void)emtask_copy_text(
        config->global.panel_qr_file,
        sizeof(config->global.panel_qr_file),
        EMTASK_DEFAULT_PANEL_QR_FILE);
    (void)emtask_copy_text(
        config->global.panel_tasks_db_file,
        sizeof(config->global.panel_tasks_db_file),
        EMTASK_DEFAULT_PANEL_TASKS_DB_FILE);
    (void)emtask_copy_text(
        config->global.panel_qr_host,
        sizeof(config->global.panel_qr_host),
        EMTASK_DEFAULT_PANEL_QR_HOST);
    config->global.panel_qr_mode = EMTASK_PANEL_QR_ALWAYS;
    config->global.panel_qr_include_username = 0;
    config->global.panel_qr_include_password = 0;
    config->global.panel_otp_digits = EMTASK_DEFAULT_PANEL_OTP_DIGITS;
    config->global.panel_otp_step_sec = EMTASK_DEFAULT_PANEL_OTP_STEP_SEC;
    config->global.panel_otp_window = EMTASK_DEFAULT_PANEL_OTP_WINDOW;
    config->global.bind_retry_enabled = 1;
    config->global.bind_retry_max_sec = EMTASK_DEFAULT_BIND_RETRY_MAX_SEC;
}

static void emtask_extract_dirname(const char *path, char out[EMTASK_MAX_PATH])
{
    const char *last_slash;
    const char *last_backslash;
    const char *cut;
    size_t len;

    if (out == NULL) {
        return;
    }

    out[0] = '.';
    out[1] = '\0';
    if (path == NULL || path[0] == '\0') {
        return;
    }

    last_slash = strrchr(path, '/');
    last_backslash = strrchr(path, '\\');
    cut = last_slash;
    if (last_backslash != NULL && (cut == NULL || last_backslash > cut)) {
        cut = last_backslash;
    }
    if (cut == NULL) {
        return;
    }

    len = (size_t)(cut - path);
    if (len == 0u) {
        len = 1u;
    }
    if (len >= EMTASK_MAX_PATH) {
        len = EMTASK_MAX_PATH - 1u;
    }
    memcpy(out, path, len);
    out[len] = '\0';
}

static int emtask_resolve_path(
    const char *base_dir,
    const char *value,
    char out[EMTASK_MAX_PATH])
{
    char value_copy[EMTASK_MAX_PATH];
    int written;

    if (value == NULL || out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (value == out) {
        int status = emtask_copy_text(value_copy, sizeof(value_copy), value);
        if (status != SSH_OK) {
            return status;
        }
        value = value_copy;
    }
    if (value[0] == '\0') {
        out[0] = '\0';
        return SSH_OK;
    }
    if (emtask_path_is_absolute(value) || base_dir == NULL || base_dir[0] == '\0') {
        return emtask_copy_text(out, EMTASK_MAX_PATH, value);
    }
    written = 0;
    (void)written;
    return emtask_platform_join_path(base_dir, value, out);
}

static int emtask_parse_auth_backend(const char *value, emtask_auth_backend_t *backend_out)
{
    if (value == NULL || backend_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (emtask_key_equals(value, "internal")) {
        *backend_out = EMTASK_AUTH_BACKEND_INTERNAL;
        return SSH_OK;
    }
    if (emtask_key_equals(value, "passwd") || emtask_key_equals(value, "etc_passwd")) {
        *backend_out = EMTASK_AUTH_BACKEND_PASSWD;
        return SSH_OK;
    }
    return SSH_ERR_INVALID_ARGUMENT;
}

static int emtask_parse_panel_auth(const char *value, unsigned *auth_out)
{
    if (value == NULL || auth_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (emtask_key_equals(value, "none") ||
        emtask_key_equals(value, "off") ||
        emtask_key_equals(value, "no") ||
        emtask_key_equals(value, "false") ||
        emtask_key_equals(value, "0")) {
        *auth_out = 0u;
        return SSH_OK;
    }
    if (emtask_key_equals(value, "token")) {
        *auth_out = EMTASK_PANEL_AUTH_TOKEN;
        return SSH_OK;
    }
    if (emtask_key_equals(value, "otp") || emtask_key_equals(value, "totp")) {
        *auth_out = EMTASK_PANEL_AUTH_OTP;
        return SSH_OK;
    }
    if (emtask_key_equals(value, "both") ||
        emtask_key_equals(value, "all") ||
        emtask_key_equals(value, "token+otp") ||
        emtask_key_equals(value, "otp+token") ||
        emtask_key_equals(value, "token,otp") ||
        emtask_key_equals(value, "otp,token")) {
        *auth_out = EMTASK_PANEL_AUTH_TOKEN | EMTASK_PANEL_AUTH_OTP;
        return SSH_OK;
    }
    return SSH_ERR_INVALID_ARGUMENT;
}

static int emtask_parse_panel_qr_mode(const char *value, emtask_panel_qr_mode_t *mode_out)
{
    if (value == NULL || mode_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (emtask_key_equals(value, "none") ||
        emtask_key_equals(value, "off") ||
        emtask_key_equals(value, "no") ||
        emtask_key_equals(value, "false") ||
        emtask_key_equals(value, "0") ||
        emtask_key_equals(value, "never") ||
        emtask_key_equals(value, "disabled")) {
        *mode_out = EMTASK_PANEL_QR_DISABLED;
        return SSH_OK;
    }
    if (emtask_key_equals(value, "missing") ||
        emtask_key_equals(value, "if_missing") ||
        emtask_key_equals(value, "if-missing") ||
        emtask_key_equals(value, "create_if_missing") ||
        emtask_key_equals(value, "create-if-missing") ||
        emtask_key_equals(value, "no_overwrite") ||
        emtask_key_equals(value, "no-overwrite") ||
        emtask_key_equals(value, "preserve")) {
        *mode_out = EMTASK_PANEL_QR_IF_MISSING;
        return SSH_OK;
    }
    if (emtask_key_equals(value, "always") ||
        emtask_key_equals(value, "overwrite") ||
        emtask_key_equals(value, "replace") ||
        emtask_key_equals(value, "regenerate") ||
        emtask_key_equals(value, "true") ||
        emtask_key_equals(value, "1")) {
        *mode_out = EMTASK_PANEL_QR_ALWAYS;
        return SSH_OK;
    }
    return SSH_ERR_INVALID_ARGUMENT;
}

static int emtask_apply_global_config_pair(
    emtask_global_config_t *global,
    const char *key,
    char *value)
{
    uint32_t u32;
    unsigned u;
    int flag;
    int status;
    emtask_auth_backend_t backend;
    unsigned panel_auth;
    emtask_panel_qr_mode_t panel_qr_mode;

    if (global == NULL || key == NULL || value == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    value = emtask_trim(value);
    emtask_unquote(value);

    if (emtask_key_equals(key, "username")) {
        return emtask_copy_text(global->username, sizeof(global->username), value);
    }
    if (emtask_key_equals(key, "password")) {
        return emtask_copy_text(global->password, sizeof(global->password), value);
    }
    if (emtask_key_equals(key, "hostkey_file")) {
        return emtask_copy_text(global->hostkey_file, sizeof(global->hostkey_file), value);
    }
    if (emtask_key_equals(key, "authorized_keys_file")) {
        return emtask_copy_text(global->authorized_keys_file, sizeof(global->authorized_keys_file), value);
    }
    if (emtask_key_equals(key, "panel_enabled")) {
        status = emtask_parse_bool(value, &flag);
        if (status == SSH_OK) {
            global->panel_enabled = flag;
        }
        return status;
    }
    if (emtask_key_equals(key, "panel_listen_address")) {
        return emtask_copy_text(global->panel_listen_address, sizeof(global->panel_listen_address), value);
    }
    if (emtask_key_equals(key, "panel_port")) {
        uint16_t panel_port;

        status = emtask_parse_port(value, &panel_port);
        if (status == SSH_OK) {
            global->panel_port = panel_port;
        }
        return status;
    }
    if (emtask_key_equals(key, "panel_auth")) {
        status = emtask_parse_panel_auth(value, &panel_auth);
        if (status == SSH_OK) {
            global->panel_auth = panel_auth;
        }
        return status;
    }
    if (emtask_key_equals(key, "panel_auth_file") || emtask_key_equals(key, "panel_auth_key_file")) {
        return emtask_copy_text(global->panel_auth_file, sizeof(global->panel_auth_file), value);
    }
    if (emtask_key_equals(key, "panel_name") ||
        emtask_key_equals(key, "panel_display_name") ||
        emtask_key_equals(key, "panel_qr_name")) {
        return emtask_copy_text(global->panel_name, sizeof(global->panel_name), value);
    }
    if (emtask_key_equals(key, "panel_qr_file") ||
        emtask_key_equals(key, "panel_qrcode_file") ||
        emtask_key_equals(key, "panel_qr_code_file")) {
        return emtask_copy_text(global->panel_qr_file, sizeof(global->panel_qr_file), value);
    }
    if (emtask_key_equals(key, "panel_tasks_db_file") ||
        emtask_key_equals(key, "panel_task_db_file") ||
        emtask_key_equals(key, "panel_sqlite_file") ||
        emtask_key_equals(key, "tasks_db_file")) {
        return emtask_copy_text(global->panel_tasks_db_file, sizeof(global->panel_tasks_db_file), value);
    }
    if (emtask_key_equals(key, "panel_qr_host") || emtask_key_equals(key, "panel_qrcode_host")) {
        return emtask_copy_text(global->panel_qr_host, sizeof(global->panel_qr_host), value);
    }
    if (emtask_key_equals(key, "panel_qr_include_username") ||
        emtask_key_equals(key, "panel_qrcode_include_username") ||
        emtask_key_equals(key, "panel_qr_embed_username") ||
        emtask_key_equals(key, "panel_qrcode_embed_username")) {
        status = emtask_parse_bool(value, &flag);
        if (status == SSH_OK) {
            global->panel_qr_include_username = flag;
        }
        return status;
    }
    if (emtask_key_equals(key, "panel_qr_include_password") ||
        emtask_key_equals(key, "panel_qrcode_include_password") ||
        emtask_key_equals(key, "panel_qr_embed_password") ||
        emtask_key_equals(key, "panel_qrcode_embed_password")) {
        status = emtask_parse_bool(value, &flag);
        if (status == SSH_OK) {
            global->panel_qr_include_password = flag;
        }
        return status;
    }
    if (emtask_key_equals(key, "panel_qr_mode") ||
        emtask_key_equals(key, "panel_qr_policy") ||
        emtask_key_equals(key, "panel_qr_generate") ||
        emtask_key_equals(key, "panel_qrcode_mode")) {
        status = emtask_parse_panel_qr_mode(value, &panel_qr_mode);
        if (status == SSH_OK) {
            global->panel_qr_mode = panel_qr_mode;
        }
        return status;
    }
    if (emtask_key_equals(key, "panel_otp_digits")) {
        status = emtask_parse_unsigned(value, &u);
        if (status == SSH_OK && (u == 6u || u == 7u || u == 8u)) {
            global->panel_otp_digits = u;
            return SSH_OK;
        }
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (emtask_key_equals(key, "panel_otp_step_sec")) {
        status = emtask_parse_unsigned(value, &u);
        if (status == SSH_OK && u != 0u && u <= 3600u) {
            global->panel_otp_step_sec = u;
            return SSH_OK;
        }
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (emtask_key_equals(key, "panel_otp_window")) {
        status = emtask_parse_unsigned(value, &u);
        if (status == SSH_OK && u <= 10u) {
            global->panel_otp_window = u;
            return SSH_OK;
        }
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (emtask_key_equals(key, "bind_retry") ||
        emtask_key_equals(key, "bind_retry_enabled") ||
        emtask_key_equals(key, "listen_retry") ||
        emtask_key_equals(key, "listen_retry_enabled") ||
        emtask_key_equals(key, "listener_retry_enabled")) {
        status = emtask_parse_bool(value, &flag);
        if (status == SSH_OK) {
            global->bind_retry_enabled = flag;
        }
        return status;
    }
    if (emtask_key_equals(key, "bind_retry_max_sec") ||
        emtask_key_equals(key, "bind_retry_max_seconds") ||
        emtask_key_equals(key, "bind_retry_max_interval_sec") ||
        emtask_key_equals(key, "listen_retry_max_sec") ||
        emtask_key_equals(key, "listener_retry_max_sec")) {
        status = emtask_parse_unsigned(value, &u);
        if (status == SSH_OK && u != 0u && u <= 86400u) {
            global->bind_retry_max_sec = u;
            return SSH_OK;
        }
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (emtask_key_equals(key, "timeout_ms")) {
        status = emtask_parse_u32(value, &u32);
        if (status == SSH_OK) {
            global->timeout_ms = u32;
        }
        return status;
    }
    if (emtask_key_equals(key, "max_workers")) {
        status = emtask_parse_unsigned(value, &u);
        if (status == SSH_OK && u != 0u) {
            global->max_workers = u;
            return SSH_OK;
        }
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (emtask_key_equals(key, "use_conpty")) {
        status = emtask_parse_bool(value, &flag);
        if (status == SSH_OK) {
            global->use_conpty = flag;
        }
        return status;
    }
    if (emtask_key_equals(key, "auth_backend")) {
        status = emtask_parse_auth_backend(value, &backend);
        if (status == SSH_OK) {
            global->auth_backend = backend;
        }
        return status;
    }

    return SSH_ERR_UNSUPPORTED;
}

static int emtask_apply_task_config_pair(
    emtask_task_config_t *task,
    const char *key,
    char *value)
{
    uint16_t port;
    unsigned u;
    int flag;
    int status;

    if (task == NULL || key == NULL || value == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    value = emtask_trim(value);
    emtask_unquote(value);

    if (emtask_key_equals(key, "name")) {
        return emtask_copy_text(task->name, sizeof(task->name), value);
    }
    if (emtask_key_equals(key, "listen_address")) {
        return emtask_copy_text(task->listen_address, sizeof(task->listen_address), value);
    }
    if (emtask_key_equals(key, "port")) {
        status = emtask_parse_port(value, &port);
        if (status == SSH_OK) {
            task->port = port;
        }
        return status;
    }
    if (emtask_key_equals(key, "command")) {
        return emtask_copy_text(task->command, sizeof(task->command), value);
    }
    if (emtask_key_equals(key, "working_dir") || emtask_key_equals(key, "workdir") || emtask_key_equals(key, "cwd")) {
        return emtask_copy_text(task->working_dir, sizeof(task->working_dir), value);
    }
    if (emtask_key_equals(key, "restart_limit")) {
        status = emtask_parse_unsigned(value, &u);
        if (status == SSH_OK) {
            task->restart_limit = u;
        }
        return status;
    }
    if (emtask_key_equals(key, "restart_window_sec")) {
        status = emtask_parse_unsigned(value, &u);
        if (status == SSH_OK) {
            task->restart_window_sec = u;
        }
        return status;
    }
    if (emtask_key_equals(key, "replay_buffer_bytes")) {
        status = emtask_parse_unsigned(value, &u);
        if (status == SSH_OK) {
            task->replay_buffer_bytes = (size_t)u;
        }
        return status;
    }
    if (emtask_key_equals(key, "use_conpty")) {
        status = emtask_parse_bool(value, &flag);
        if (status == SSH_OK) {
            task->use_conpty = flag;
        }
        return status;
    }
    if (emtask_key_equals(key, "use_sftp")) {
        status = emtask_parse_bool(value, &flag);
        if (status == SSH_OK) {
            task->use_sftp = flag;
        }
        return status;
    }
    if (emtask_key_equals(key, "replay_on_attach")) {
        status = emtask_parse_bool(value, &flag);
        if (status == SSH_OK) {
            task->replay_on_attach = flag;
        }
        return status;
    }
    if (emtask_key_equals(key, "repaint_on_attach")) {
        status = emtask_parse_bool(value, &flag);
        if (status == SSH_OK) {
            task->repaint_on_attach = flag;
        }
        return status;
    }
    if (emtask_key_equals(key, "screen_snapshot")) {
        status = emtask_parse_bool(value, &flag);
        if (status == SSH_OK) {
            task->screen_snapshot = flag;
        }
        return status;
    }

    return SSH_ERR_UNSUPPORTED;
}

static int emtask_start_task_section(emtask_config_t *config, const char *section_text, emtask_task_config_t **task_out)
{
    const char *p;
    const char *end;
    size_t len;
    emtask_task_config_t *task;

    if (config == NULL || section_text == NULL || task_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (config->task_count >= EMTASK_MAX_TASKS) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    task = &config->tasks[config->task_count++];
    emtask_task_config_defaults(task);
    task->use_conpty = config->global.use_conpty;

    p = section_text;
    while (*p == ' ' || *p == '\t') {
        ++p;
    }
    if (strncmp(p, "task", 4) == 0 && (p[4] == '\0' || p[4] == ' ' || p[4] == '\t')) {
        p += 4;
        while (*p == ' ' || *p == '\t') {
            ++p;
        }
    }
    end = p + strlen(p);
    while (end > p && (end[-1] == ' ' || end[-1] == '\t')) {
        --end;
    }
    len = (size_t)(end - p);
    if (len != 0u) {
        if (len >= sizeof(task->name)) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(task->name, p, len);
        task->name[len] = '\0';
    } else {
        int written = snprintf(task->name, sizeof(task->name), "task%u", (unsigned)config->task_count);
        if (written < 0 || (size_t)written >= sizeof(task->name)) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
    }

    *task_out = task;
    return SSH_OK;
}

static int emtask_load_config(const char *path, emtask_config_t *config)
{
    FILE *file;
    char line[2048];
    unsigned line_no;
    int status;

    if (path == NULL || config == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    emtask_task_config_t *current_task;

    emtask_config_defaults(config);
    current_task = NULL;
    status = emtask_copy_text(config->global.config_path, sizeof(config->global.config_path), path);
    if (status != SSH_OK) {
        return status;
    }
    emtask_extract_dirname(path, config->global.config_dir);

    file = fopen(path, "rb");
    if (file == NULL) {
        return errno == ENOENT ? SSH_ERR_NOT_FOUND : SSH_ERR_PLATFORM;
    }

    line_no = 0u;
    while (fgets(line, (int)sizeof(line), file) != NULL) {
        char *trimmed;
        char *sep;
        char *key;
        char *value;

        ++line_no;
        trimmed = emtask_trim(line);
        if (trimmed[0] == '\0' || trimmed[0] == '#') {
            continue;
        }

        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (end == NULL) {
                status = SSH_ERR_MALFORMED_PACKET;
                break;
            }
            *end = '\0';
            status = emtask_start_task_section(config, trimmed + 1, &current_task);
            if (status != SSH_OK) {
                emtask_logf("invalid task section at line %u", line_no);
                break;
            }
            continue;
        }

        sep = strchr(trimmed, '=');
        if (sep == NULL) {
            status = SSH_ERR_MALFORMED_PACKET;
            break;
        }
        *sep = '\0';
        key = emtask_trim(trimmed);
        value = sep + 1;
        if (current_task != NULL) {
            status = emtask_apply_task_config_pair(current_task, key, value);
        } else {
            status = emtask_apply_global_config_pair(&config->global, key, value);
            if (status == SSH_ERR_UNSUPPORTED &&
                (emtask_key_equals(key, "listen_address") ||
                 emtask_key_equals(key, "port") ||
                 emtask_key_equals(key, "command") ||
                 emtask_key_equals(key, "working_dir") ||
                 emtask_key_equals(key, "workdir") ||
                 emtask_key_equals(key, "cwd") ||
                 emtask_key_equals(key, "restart_limit") ||
                 emtask_key_equals(key, "restart_window_sec") ||
                 emtask_key_equals(key, "replay_buffer_bytes") ||
                 emtask_key_equals(key, "use_sftp") ||
                 emtask_key_equals(key, "replay_on_attach") ||
                 emtask_key_equals(key, "repaint_on_attach") ||
                 emtask_key_equals(key, "screen_snapshot"))) {
                status = emtask_start_task_section(config, "default", &current_task);
                if (status == SSH_OK) {
                    status = emtask_apply_task_config_pair(current_task, key, value);
                }
            }
        }
        if (status == SSH_ERR_UNSUPPORTED) {
            emtask_logf("ignoring unknown config key at line %u: %s", line_no, key);
            status = SSH_OK;
        }
        if (status != SSH_OK) {
            emtask_logf("invalid config at line %u: %s", line_no, key);
            break;
        }
    }

    if (ferror(file) != 0) {
        status = SSH_ERR_PLATFORM;
    }
    (void)fclose(file);
    if (status != SSH_OK) {
        return status;
    }

    status = emtask_resolve_path(config->global.config_dir, config->global.hostkey_file, config->global.hostkey_file);
    if (status != SSH_OK) {
        return status;
    }
    status = emtask_resolve_path(
        config->global.config_dir,
        config->global.authorized_keys_file,
        config->global.authorized_keys_file);
    if (status != SSH_OK) {
        return status;
    }
    status = emtask_resolve_path(config->global.config_dir, config->global.panel_auth_file, config->global.panel_auth_file);
    if (status != SSH_OK) {
        return status;
    }
    status = emtask_resolve_path(config->global.config_dir, config->global.panel_qr_file, config->global.panel_qr_file);
    if (status != SSH_OK) {
        return status;
    }
    status = emtask_resolve_path(config->global.config_dir, config->global.panel_tasks_db_file, config->global.panel_tasks_db_file);
    if (status != SSH_OK) {
        return status;
    }
    status = emtask_panel_tasks_db_check_runtime(&config->global);
    if (status != SSH_OK) {
        return status;
    }
    status = emtask_panel_tasks_db_load(config);
    if (status != SSH_OK) {
        return status;
    }
    for (size_t i = 0u; i < config->task_count; ++i) {
        status = emtask_resolve_path(config->global.config_dir, config->tasks[i].working_dir, config->tasks[i].working_dir);
        if (status != SSH_OK) {
            return status;
        }
    }

    status = emtask_panel_materialize_auth(config);
    if (status != SSH_OK) {
        return status;
    }

    if (config->global.auth_backend == EMTASK_AUTH_BACKEND_INTERNAL && config->global.username[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (config->global.auth_backend == EMTASK_AUTH_BACKEND_INTERNAL &&
        config->global.password[0] == '\0' &&
        config->global.authorized_keys_file[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (config->global.max_workers == 0u || (config->task_count == 0u && !config->global.panel_enabled)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (config->global.panel_enabled && config->global.panel_port == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (config->global.panel_enabled) {
        if ((config->global.panel_auth & ~(EMTASK_PANEL_AUTH_TOKEN | EMTASK_PANEL_AUTH_OTP)) != 0u) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        if ((config->global.panel_auth & EMTASK_PANEL_AUTH_TOKEN) != 0u && config->global.panel_token[0] == '\0') {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        if ((config->global.panel_auth & EMTASK_PANEL_AUTH_OTP) != 0u) {
            uint8_t otp_secret[128];
            size_t otp_secret_len;

            if (config->global.panel_otp_secret[0] == '\0' ||
                emtask_panel_decode_base32_secret(
                    config->global.panel_otp_secret,
                    otp_secret,
                    sizeof(otp_secret),
                    &otp_secret_len) != SSH_OK) {
                memset(otp_secret, 0, sizeof(otp_secret));
                return SSH_ERR_INVALID_ARGUMENT;
            }
            memset(otp_secret, 0, sizeof(otp_secret));
        }
    }
    for (size_t i = 0u; i < config->task_count; ++i) {
        if (config->tasks[i].name[0] == '\0' || config->tasks[i].command[0] == '\0' || config->tasks[i].port == 0u) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        for (size_t j = i + 1u; j < config->task_count; ++j) {
            if (emtask_key_equals(config->tasks[i].name, config->tasks[j].name) ||
                config->tasks[i].port == config->tasks[j].port) {
                return SSH_ERR_ALREADY_EXISTS;
            }
        }
        if (config->global.panel_enabled && config->tasks[i].port == config->global.panel_port) {
            const char *task_addr = config->tasks[i].listen_address[0] != '\0' ? config->tasks[i].listen_address : "0.0.0.0";
            const char *panel_addr = config->global.panel_listen_address[0] != '\0'
                                         ? config->global.panel_listen_address
                                         : EMTASK_DEFAULT_PANEL_LISTEN_ADDRESS;

            if (emtask_key_equals(task_addr, panel_addr) ||
                emtask_key_equals(task_addr, "0.0.0.0") ||
                emtask_key_equals(panel_addr, "0.0.0.0") ||
                emtask_key_equals(task_addr, "::") ||
                emtask_key_equals(panel_addr, "::")) {
                return SSH_ERR_INVALID_ARGUMENT;
            }
        }
    }
    status = emtask_panel_materialize_qr(config);
    if (status != SSH_OK) {
        return status;
    }
    return SSH_OK;
}

static ssh_string_view_t emtask_hostkey_algorithm_view(void)
{
    static const char k_alg[] = "ecdsa-sha2-nistp256";
    ssh_string_view_t view;

    view.data = (const uint8_t *)k_alg;
    view.len = sizeof(k_alg) - 1u;
    return view;
}

static int emtask_load_file(const char *path, uint8_t *data, size_t data_capacity, size_t *data_len)
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
    if (ferror(file) != 0) {
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

static int emtask_save_file(const char *path, const uint8_t *data, size_t data_len)
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

static int emtask_text_appendf(char *out, size_t out_capacity, size_t *out_len, const char *fmt, ...)
{
    va_list args;
    int written;

    if (out == NULL || out_len == NULL || fmt == NULL || *out_len >= out_capacity) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    va_start(args, fmt);
    written = vsnprintf(out + *out_len, out_capacity - *out_len, fmt, args);
    va_end(args);
    if (written < 0) {
        return SSH_ERR_PLATFORM;
    }
    if ((size_t)written >= out_capacity - *out_len) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    *out_len += (size_t)written;
    return SSH_OK;
}

static int emtask_panel_file_exists(const char *path, int *exists_out)
{
    FILE *file;

    if (path == NULL || exists_out == NULL || path[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        if (errno == ENOENT) {
            *exists_out = 0;
            return SSH_OK;
        }
        return SSH_ERR_PLATFORM;
    }
    (void)fclose(file);
    *exists_out = 1;
    return SSH_OK;
}

typedef struct emtask_sqlite3 emtask_sqlite3_t;
typedef struct emtask_sqlite3_stmt emtask_sqlite3_stmt_t;

#define EMTASK_SQLITE_OK 0
#define EMTASK_SQLITE_ROW 100
#define EMTASK_SQLITE_DONE 101
#define EMTASK_SQLITE_OPEN_READWRITE 0x00000002
#define EMTASK_SQLITE_OPEN_CREATE 0x00000004
#define EMTASK_SQLITE_TRANSIENT ((void (*)(void *))-1)

typedef struct emtask_sqlite_api {
    void *library;
    int (*open_v2)(const char *, emtask_sqlite3_t **, int, const char *);
    int (*close)(emtask_sqlite3_t *);
    int (*exec)(emtask_sqlite3_t *, const char *, int (*)(void *, int, char **, char **), void *, char **);
    void (*free_mem)(void *);
    const char *(*errmsg)(emtask_sqlite3_t *);
    int (*prepare_v2)(emtask_sqlite3_t *, const char *, int, emtask_sqlite3_stmt_t **, const char **);
    int (*bind_text)(emtask_sqlite3_stmt_t *, int, const char *, int, void (*)(void *));
    int (*bind_int)(emtask_sqlite3_stmt_t *, int, int);
    int (*step)(emtask_sqlite3_stmt_t *);
    int (*finalize)(emtask_sqlite3_stmt_t *);
    const unsigned char *(*column_text)(emtask_sqlite3_stmt_t *, int);
    int (*column_int)(emtask_sqlite3_stmt_t *, int);
    int (*changes)(emtask_sqlite3_t *);
} emtask_sqlite_api_t;

static void emtask_sqlite_close_library(emtask_sqlite_api_t *api)
{
    if (api == NULL || api->library == NULL) {
        return;
    }
    emtask_platform_library_close(api->library);
    memset(api, 0, sizeof(*api));
}

static void *emtask_sqlite_symbol(emtask_sqlite_api_t *api, const char *name)
{
    if (api == NULL || api->library == NULL || name == NULL) {
        return NULL;
    }
    return emtask_platform_library_symbol(api->library, name);
}

static int emtask_sqlite_load_library(emtask_sqlite_api_t *api)
{
    int status;
    int using_system_sqlite;

    if (api == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    memset(api, 0, sizeof(*api));
    using_system_sqlite = 0;
    status = emtask_platform_sqlite_library_open(&api->library, &using_system_sqlite);
    if (status != SSH_OK) {
        emtask_logf("sqlite runtime not found; place sqlite3.dll/libsqlite3.so in the current directory or install SQLite system-wide");
        return status;
    }
    if (using_system_sqlite) {
        emtask_logf("warning: using system SQLite runtime; place sqlite3.dll/libsqlite3.so in the current directory to use the bundled runtime");
    }

    api->open_v2 = (int (*)(const char *, emtask_sqlite3_t **, int, const char *))emtask_sqlite_symbol(api, "sqlite3_open_v2");
    api->close = (int (*)(emtask_sqlite3_t *))emtask_sqlite_symbol(api, "sqlite3_close");
    api->exec = (int (*)(emtask_sqlite3_t *, const char *, int (*)(void *, int, char **, char **), void *, char **))emtask_sqlite_symbol(api, "sqlite3_exec");
    api->free_mem = (void (*)(void *))emtask_sqlite_symbol(api, "sqlite3_free");
    api->errmsg = (const char *(*)(emtask_sqlite3_t *))emtask_sqlite_symbol(api, "sqlite3_errmsg");
    api->prepare_v2 = (int (*)(emtask_sqlite3_t *, const char *, int, emtask_sqlite3_stmt_t **, const char **))emtask_sqlite_symbol(api, "sqlite3_prepare_v2");
    api->bind_text = (int (*)(emtask_sqlite3_stmt_t *, int, const char *, int, void (*)(void *)))emtask_sqlite_symbol(api, "sqlite3_bind_text");
    api->bind_int = (int (*)(emtask_sqlite3_stmt_t *, int, int))emtask_sqlite_symbol(api, "sqlite3_bind_int");
    api->step = (int (*)(emtask_sqlite3_stmt_t *))emtask_sqlite_symbol(api, "sqlite3_step");
    api->finalize = (int (*)(emtask_sqlite3_stmt_t *))emtask_sqlite_symbol(api, "sqlite3_finalize");
    api->column_text = (const unsigned char *(*)(emtask_sqlite3_stmt_t *, int))emtask_sqlite_symbol(api, "sqlite3_column_text");
    api->column_int = (int (*)(emtask_sqlite3_stmt_t *, int))emtask_sqlite_symbol(api, "sqlite3_column_int");
    api->changes = (int (*)(emtask_sqlite3_t *))emtask_sqlite_symbol(api, "sqlite3_changes");

    if (api->open_v2 == NULL || api->close == NULL || api->exec == NULL ||
        api->free_mem == NULL || api->errmsg == NULL || api->prepare_v2 == NULL ||
        api->bind_text == NULL || api->bind_int == NULL || api->step == NULL ||
        api->finalize == NULL || api->column_text == NULL || api->column_int == NULL ||
        api->changes == NULL) {
        emtask_logf("sqlite runtime missing required sqlite3 symbols");
        emtask_sqlite_close_library(api);
        return SSH_ERR_UNSUPPORTED;
    }
    return SSH_OK;
}

static int emtask_sqlite_open_database(const char *path, emtask_sqlite_api_t *api, emtask_sqlite3_t **db_out)
{
    int status;

    if (path == NULL || path[0] == '\0' || api == NULL || db_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    *db_out = NULL;
    status = emtask_sqlite_load_library(api);
    if (status != SSH_OK) {
        return status;
    }
    if (api->open_v2(path, db_out, EMTASK_SQLITE_OPEN_READWRITE | EMTASK_SQLITE_OPEN_CREATE, NULL) != EMTASK_SQLITE_OK) {
        const char *msg = *db_out != NULL ? api->errmsg(*db_out) : "open failed";
        emtask_logf("sqlite open %s failed: %s", path, msg != NULL ? msg : "unknown");
        if (*db_out != NULL) {
            (void)api->close(*db_out);
            *db_out = NULL;
        }
        emtask_sqlite_close_library(api);
        return SSH_ERR_PLATFORM;
    }
    return SSH_OK;
}

static void emtask_sqlite_close_database(emtask_sqlite_api_t *api, emtask_sqlite3_t *db)
{
    if (api != NULL && db != NULL && api->close != NULL) {
        (void)api->close(db);
    }
    emtask_sqlite_close_library(api);
}

static int emtask_panel_tasks_db_init(emtask_sqlite_api_t *api, emtask_sqlite3_t *db)
{
    static const char k_schema[] =
        "CREATE TABLE IF NOT EXISTS tasks ("
        "name TEXT PRIMARY KEY NOT NULL,"
        "listen_address TEXT NOT NULL DEFAULT '',"
        "port INTEGER NOT NULL UNIQUE,"
        "command TEXT NOT NULL,"
        "working_dir TEXT NOT NULL DEFAULT '.',"
        "use_sftp INTEGER NOT NULL DEFAULT 1,"
        "use_conpty INTEGER NOT NULL DEFAULT 1,"
        "restart_limit INTEGER NOT NULL DEFAULT 8,"
        "restart_window_sec INTEGER NOT NULL DEFAULT 60,"
        "replay_buffer_bytes INTEGER NOT NULL DEFAULT 1048576,"
        "replay_on_attach INTEGER NOT NULL DEFAULT 1,"
        "repaint_on_attach INTEGER NOT NULL DEFAULT 1,"
        "screen_snapshot INTEGER NOT NULL DEFAULT 1,"
        "created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),"
        "updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))"
        ");";
    char *error = NULL;
    int rc;

    if (api == NULL || db == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    rc = api->exec(db, k_schema, NULL, NULL, &error);
    if (rc != EMTASK_SQLITE_OK) {
        emtask_logf("sqlite schema init failed: %s", error != NULL ? error : api->errmsg(db));
        if (error != NULL) {
            api->free_mem(error);
        }
        return SSH_ERR_PLATFORM;
    }
    return SSH_OK;
}

static const char *emtask_sqlite_column_string(emtask_sqlite_api_t *api, emtask_sqlite3_stmt_t *stmt, int column)
{
    const unsigned char *text;

    if (api == NULL || stmt == NULL) {
        return "";
    }
    text = api->column_text(stmt, column);
    return text != NULL ? (const char *)text : "";
}

static int emtask_panel_tasks_db_check_runtime(const emtask_global_config_t *global)
{
    emtask_sqlite_api_t api;
    int status;

    if (global == NULL || !global->panel_enabled || global->panel_tasks_db_file[0] == '\0') {
        return SSH_OK;
    }
    memset(&api, 0, sizeof(api));
    status = emtask_sqlite_load_library(&api);
    if (status != SSH_OK) {
        emtask_logf("sqlite runtime required at startup because panel dynamic tasks use %s", global->panel_tasks_db_file);
        return status == SSH_ERR_NOT_FOUND ? SSH_ERR_PLATFORM : status;
    }
    emtask_sqlite_close_library(&api);
    return SSH_OK;
}

static int emtask_panel_tasks_db_load(emtask_config_t *config)
{
    static const char k_select[] =
        "SELECT name, listen_address, port, command, working_dir, use_sftp, use_conpty, "
        "restart_limit, restart_window_sec, replay_buffer_bytes, replay_on_attach, repaint_on_attach, screen_snapshot "
        "FROM tasks ORDER BY name";
    emtask_sqlite_api_t api;
    emtask_sqlite3_t *db;
    emtask_sqlite3_stmt_t *stmt;
    int exists;
    int status;
    int rc;

    if (config == NULL || !config->global.panel_enabled || config->global.panel_tasks_db_file[0] == '\0') {
        return SSH_OK;
    }
    status = emtask_panel_file_exists(config->global.panel_tasks_db_file, &exists);
    if (status != SSH_OK || !exists) {
        return status;
    }

    memset(&api, 0, sizeof(api));
    db = NULL;
    status = emtask_sqlite_open_database(config->global.panel_tasks_db_file, &api, &db);
    if (status != SSH_OK) {
        return status;
    }
    status = emtask_panel_tasks_db_init(&api, db);
    if (status != SSH_OK) {
        emtask_sqlite_close_database(&api, db);
        return status;
    }

    stmt = NULL;
    rc = api.prepare_v2(db, k_select, -1, &stmt, NULL);
    if (rc != EMTASK_SQLITE_OK) {
        emtask_logf("sqlite select tasks failed: %s", api.errmsg(db));
        emtask_sqlite_close_database(&api, db);
        return SSH_ERR_PLATFORM;
    }

    while ((rc = api.step(stmt)) == EMTASK_SQLITE_ROW) {
        emtask_task_config_t *task;

        if (config->task_count >= EMTASK_MAX_TASKS) {
            (void)api.finalize(stmt);
            emtask_sqlite_close_database(&api, db);
            return SSH_ERR_BUFFER_TOO_SMALL;
        }

        task = &config->tasks[config->task_count];
        emtask_task_config_defaults(task);
        task->use_conpty = config->global.use_conpty;
        status = emtask_copy_text(task->name, sizeof(task->name), emtask_sqlite_column_string(&api, stmt, 0));
        if (status == SSH_OK) {
            status = emtask_copy_text(task->listen_address, sizeof(task->listen_address), emtask_sqlite_column_string(&api, stmt, 1));
        }
        if (status == SSH_OK) {
            int port = api.column_int(stmt, 2);
            if (port <= 0 || port > 65535) {
                status = SSH_ERR_INVALID_ARGUMENT;
            } else {
                task->port = (uint16_t)port;
            }
        }
        if (status == SSH_OK) {
            status = emtask_copy_text(task->command, sizeof(task->command), emtask_sqlite_column_string(&api, stmt, 3));
        }
        if (status == SSH_OK) {
            status = emtask_copy_text(task->working_dir, sizeof(task->working_dir), emtask_sqlite_column_string(&api, stmt, 4));
        }
        if (status == SSH_OK) {
            task->use_sftp = api.column_int(stmt, 5) != 0;
            task->use_conpty = api.column_int(stmt, 6) != 0;
            task->restart_limit = (unsigned)api.column_int(stmt, 7);
            task->restart_window_sec = (unsigned)api.column_int(stmt, 8);
            task->replay_buffer_bytes = (size_t)api.column_int(stmt, 9);
            task->replay_on_attach = api.column_int(stmt, 10) != 0;
            task->repaint_on_attach = api.column_int(stmt, 11) != 0;
            task->screen_snapshot = api.column_int(stmt, 12) != 0;
        }
        if (status != SSH_OK) {
            (void)api.finalize(stmt);
            emtask_sqlite_close_database(&api, db);
            return status;
        }
        config->task_count += 1u;
    }
    status = rc == EMTASK_SQLITE_DONE ? SSH_OK : SSH_ERR_PLATFORM;
    (void)api.finalize(stmt);
    emtask_sqlite_close_database(&api, db);
    return status;
}

static int emtask_panel_tasks_db_insert(const emtask_global_config_t *global, const emtask_task_config_t *task)
{
    static const char k_insert[] =
        "INSERT INTO tasks (name, listen_address, port, command, working_dir, use_sftp, use_conpty, "
        "restart_limit, restart_window_sec, replay_buffer_bytes, replay_on_attach, repaint_on_attach, screen_snapshot, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%s','now'))";
    emtask_sqlite_api_t api;
    emtask_sqlite3_t *db;
    emtask_sqlite3_stmt_t *stmt;
    int status;
    int rc;

    if (global == NULL || task == NULL || global->panel_tasks_db_file[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    memset(&api, 0, sizeof(api));
    db = NULL;
    status = emtask_sqlite_open_database(global->panel_tasks_db_file, &api, &db);
    if (status != SSH_OK) {
        return status;
    }
    status = emtask_panel_tasks_db_init(&api, db);
    if (status != SSH_OK) {
        emtask_sqlite_close_database(&api, db);
        return status;
    }

    stmt = NULL;
    rc = api.prepare_v2(db, k_insert, -1, &stmt, NULL);
    if (rc != EMTASK_SQLITE_OK) {
        emtask_sqlite_close_database(&api, db);
        return SSH_ERR_PLATFORM;
    }
    rc = api.bind_text(stmt, 1, task->name, -1, EMTASK_SQLITE_TRANSIENT);
    rc = rc == EMTASK_SQLITE_OK ? api.bind_text(stmt, 2, task->listen_address, -1, EMTASK_SQLITE_TRANSIENT) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 3, (int)task->port) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_text(stmt, 4, task->command, -1, EMTASK_SQLITE_TRANSIENT) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_text(stmt, 5, task->working_dir, -1, EMTASK_SQLITE_TRANSIENT) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 6, task->use_sftp != 0) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 7, task->use_conpty != 0) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 8, (int)task->restart_limit) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 9, (int)task->restart_window_sec) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 10, (int)task->replay_buffer_bytes) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 11, task->replay_on_attach != 0) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 12, task->repaint_on_attach != 0) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 13, task->screen_snapshot != 0) : rc;
    if (rc == EMTASK_SQLITE_OK) {
        rc = api.step(stmt);
    }
    status = rc == EMTASK_SQLITE_DONE ? SSH_OK : SSH_ERR_PLATFORM;
    if (status != SSH_OK) {
        emtask_logf("sqlite insert task %s failed: %s", task->name, api.errmsg(db));
    }
    (void)api.finalize(stmt);
    emtask_sqlite_close_database(&api, db);
    return status;
}

static int emtask_panel_tasks_db_update(const emtask_global_config_t *global, const char *old_task_name, const emtask_task_config_t *task)
{
    static const char k_update[] =
        "UPDATE tasks SET name = ?, listen_address = ?, port = ?, command = ?, working_dir = ?, "
        "use_sftp = ?, use_conpty = ?, restart_limit = ?, restart_window_sec = ?, replay_buffer_bytes = ?, "
        "replay_on_attach = ?, repaint_on_attach = ?, screen_snapshot = ?, updated_at = strftime('%s','now') "
        "WHERE name = ?";
    emtask_sqlite_api_t api;
    emtask_sqlite3_t *db;
    emtask_sqlite3_stmt_t *stmt;
    int status;
    int rc;

    if (global == NULL || old_task_name == NULL || old_task_name[0] == '\0' || task == NULL || global->panel_tasks_db_file[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    memset(&api, 0, sizeof(api));
    db = NULL;
    status = emtask_sqlite_open_database(global->panel_tasks_db_file, &api, &db);
    if (status != SSH_OK) {
        return status;
    }
    status = emtask_panel_tasks_db_init(&api, db);
    if (status != SSH_OK) {
        emtask_sqlite_close_database(&api, db);
        return status;
    }

    stmt = NULL;
    rc = api.prepare_v2(db, k_update, -1, &stmt, NULL);
    if (rc == EMTASK_SQLITE_OK) {
        rc = api.bind_text(stmt, 1, task->name, -1, EMTASK_SQLITE_TRANSIENT);
    }
    rc = rc == EMTASK_SQLITE_OK ? api.bind_text(stmt, 2, task->listen_address, -1, EMTASK_SQLITE_TRANSIENT) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 3, (int)task->port) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_text(stmt, 4, task->command, -1, EMTASK_SQLITE_TRANSIENT) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_text(stmt, 5, task->working_dir, -1, EMTASK_SQLITE_TRANSIENT) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 6, task->use_sftp != 0) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 7, task->use_conpty != 0) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 8, (int)task->restart_limit) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 9, (int)task->restart_window_sec) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 10, (int)task->replay_buffer_bytes) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 11, task->replay_on_attach != 0) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 12, task->repaint_on_attach != 0) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_int(stmt, 13, task->screen_snapshot != 0) : rc;
    rc = rc == EMTASK_SQLITE_OK ? api.bind_text(stmt, 14, old_task_name, -1, EMTASK_SQLITE_TRANSIENT) : rc;
    if (rc == EMTASK_SQLITE_OK) {
        rc = api.step(stmt);
    }
    if (rc == EMTASK_SQLITE_DONE) {
        status = api.changes(db) > 0 ? SSH_OK : SSH_ERR_NOT_FOUND;
    } else {
        status = SSH_ERR_PLATFORM;
    }
    if (status != SSH_OK) {
        emtask_logf("sqlite update task %s failed: %s", old_task_name, api.errmsg(db));
    }
    if (stmt != NULL) {
        (void)api.finalize(stmt);
    }
    emtask_sqlite_close_database(&api, db);
    return status;
}

static int emtask_panel_tasks_db_delete(const emtask_global_config_t *global, const char *task_name)
{
    static const char k_delete[] = "DELETE FROM tasks WHERE name = ?";
    emtask_sqlite_api_t api;
    emtask_sqlite3_t *db;
    emtask_sqlite3_stmt_t *stmt;
    int status;
    int rc;

    if (global == NULL || task_name == NULL || task_name[0] == '\0' || global->panel_tasks_db_file[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    memset(&api, 0, sizeof(api));
    db = NULL;
    status = emtask_sqlite_open_database(global->panel_tasks_db_file, &api, &db);
    if (status != SSH_OK) {
        return status;
    }
    stmt = NULL;
    rc = api.prepare_v2(db, k_delete, -1, &stmt, NULL);
    if (rc == EMTASK_SQLITE_OK) {
        rc = api.bind_text(stmt, 1, task_name, -1, EMTASK_SQLITE_TRANSIENT);
    }
    if (rc == EMTASK_SQLITE_OK) {
        rc = api.step(stmt);
    }
    if (rc == EMTASK_SQLITE_DONE) {
        status = api.changes(db) > 0 ? SSH_OK : SSH_ERR_NOT_FOUND;
    } else {
        status = SSH_ERR_PLATFORM;
    }
    if (stmt != NULL) {
        (void)api.finalize(stmt);
    }
    emtask_sqlite_close_database(&api, db);
    return status;
}

static int emtask_panel_fill_random(uint8_t *data, size_t data_len)
{
    emtask_crypto_context_t crypto_ctx;
    const ssh_rng_api_t *rng;
    int status;

    if (data == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (data_len == 0u) {
        return SSH_OK;
    }

    memset(&crypto_ctx, 0, sizeof(crypto_ctx));
    status = ssh_crypto_open(EMTASK_CTX_PTR(&crypto_ctx));
    if (status != SSH_OK) {
        return status;
    }
    rng = ssh_crypto_rng_api(EMTASK_CTX_CONST_PTR(&crypto_ctx));
    if (rng == NULL || rng->fill == NULL) {
        ssh_crypto_close(EMTASK_CTX_PTR(&crypto_ctx));
        return SSH_ERR_UNSUPPORTED;
    }
    status = rng->fill(rng->ctx, data, data_len);
    ssh_crypto_close(EMTASK_CTX_PTR(&crypto_ctx));
    return status;
}

static int emtask_panel_base64url_encode(const uint8_t *data, size_t data_len, char *out, size_t out_capacity)
{
    static const char k_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t i;
    size_t j;

    if (data == NULL || out == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    j = 0u;
    for (i = 0u; i < data_len; i += 3u) {
        size_t remaining = data_len - i;
        size_t chars = remaining >= 3u ? 4u : remaining + 1u;
        uint32_t value = ((uint32_t)data[i] << 16) |
                         (remaining > 1u ? ((uint32_t)data[i + 1u] << 8) : 0u) |
                         (remaining > 2u ? (uint32_t)data[i + 2u] : 0u);
        size_t k;

        if (j + chars + 1u > out_capacity) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        for (k = 0u; k < chars; ++k) {
            out[j++] = k_table[(value >> (18u - (6u * k))) & 0x3fu];
        }
    }
    out[j] = '\0';
    return SSH_OK;
}

static int emtask_panel_base32_encode(const uint8_t *data, size_t data_len, char *out, size_t out_capacity)
{
    static const char k_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    uint32_t buffer;
    unsigned bits;
    size_t i;
    size_t j;

    if (data == NULL || out == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    buffer = 0u;
    bits = 0u;
    j = 0u;
    for (i = 0u; i < data_len; ++i) {
        buffer = (buffer << 8) | data[i];
        bits += 8u;
        while (bits >= 5u) {
            if (j + 2u > out_capacity) {
                return SSH_ERR_BUFFER_TOO_SMALL;
            }
            out[j++] = k_table[(buffer >> (bits - 5u)) & 0x1fu];
            bits -= 5u;
        }
    }
    if (bits != 0u) {
        if (j + 2u > out_capacity) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        out[j++] = k_table[(buffer << (5u - bits)) & 0x1fu];
    }
    out[j] = '\0';
    return SSH_OK;
}

static int emtask_panel_generate_token(char out[EMTASK_MAX_TEXT])
{
    uint8_t random_bytes[EMTASK_PANEL_TOKEN_RANDOM_BYTES];
    int status;

    if (out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    memset(random_bytes, 0, sizeof(random_bytes));
    status = emtask_panel_fill_random(random_bytes, sizeof(random_bytes));
    if (status == SSH_OK) {
        status = emtask_panel_base64url_encode(random_bytes, sizeof(random_bytes), out, EMTASK_MAX_TEXT);
    }
    memset(random_bytes, 0, sizeof(random_bytes));
    return status;
}

static int emtask_panel_generate_otp_secret(char out[EMTASK_MAX_TEXT])
{
    uint8_t random_bytes[EMTASK_PANEL_OTP_RANDOM_BYTES];
    int status;

    if (out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    memset(random_bytes, 0, sizeof(random_bytes));
    status = emtask_panel_fill_random(random_bytes, sizeof(random_bytes));
    if (status == SSH_OK) {
        status = emtask_panel_base32_encode(random_bytes, sizeof(random_bytes), out, EMTASK_MAX_TEXT);
    }
    memset(random_bytes, 0, sizeof(random_bytes));
    return status;
}

static int emtask_panel_apply_auth_file_pair(emtask_global_config_t *global, const char *key, char *value)
{
    if (global == NULL || key == NULL || value == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    value = emtask_trim(value);
    emtask_unquote(value);
    if (emtask_key_equals(key, "panel_token") || emtask_key_equals(key, "token")) {
        if (global->panel_token[0] == '\0') {
            return emtask_copy_text(global->panel_token, sizeof(global->panel_token), value);
        }
        return SSH_OK;
    }
    if (emtask_key_equals(key, "panel_otp_secret") ||
        emtask_key_equals(key, "otp_secret") ||
        emtask_key_equals(key, "totp_secret")) {
        if (global->panel_otp_secret[0] == '\0') {
            return emtask_copy_text(global->panel_otp_secret, sizeof(global->panel_otp_secret), value);
        }
        return SSH_OK;
    }
    return SSH_OK;
}

static int emtask_panel_load_auth_file(emtask_global_config_t *global, int *exists_out)
{
    uint8_t data[4096];
    size_t data_len;
    char *cursor;
    int exists;
    int status;

    if (global == NULL || exists_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = emtask_panel_file_exists(global->panel_auth_file, &exists);
    if (status != SSH_OK || !exists) {
        *exists_out = 0;
        return status;
    }
    *exists_out = 1;

    memset(data, 0, sizeof(data));
    status = emtask_load_file(global->panel_auth_file, data, sizeof(data) - 1u, &data_len);
    if (status == SSH_ERR_MALFORMED_PACKET) {
        return SSH_OK;
    }
    if (status != SSH_OK) {
        return status;
    }
    data[data_len] = '\0';

    cursor = (char *)data;
    while (cursor != NULL && *cursor != '\0') {
        char *line;
        char *end;
        char *sep;
        char *key;

        line = cursor;
        end = strpbrk(cursor, "\r\n");
        if (end != NULL) {
            char newline = *end;

            *end = '\0';
            cursor = end + 1;
            if (newline == '\r' && *cursor == '\n') {
                ++cursor;
            }
        } else {
            cursor = NULL;
        }

        line = emtask_trim(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        sep = strchr(line, '=');
        if (sep == NULL) {
            continue;
        }
        *sep = '\0';
        key = emtask_trim(line);
        status = emtask_panel_apply_auth_file_pair(global, key, sep + 1);
        if (status != SSH_OK) {
            memset(data, 0, sizeof(data));
            return status;
        }
    }

    memset(data, 0, sizeof(data));
    return SSH_OK;
}

static const char *emtask_panel_auth_config_name(unsigned auth)
{
    if ((auth & (EMTASK_PANEL_AUTH_TOKEN | EMTASK_PANEL_AUTH_OTP)) ==
        (EMTASK_PANEL_AUTH_TOKEN | EMTASK_PANEL_AUTH_OTP)) {
        return "token+otp";
    }
    if ((auth & EMTASK_PANEL_AUTH_TOKEN) != 0u) {
        return "token";
    }
    if ((auth & EMTASK_PANEL_AUTH_OTP) != 0u) {
        return "otp";
    }
    return "none";
}

static int emtask_panel_save_auth_file(const emtask_global_config_t *global)
{
    char text[4096];
    size_t len;
    int status;

    if (global == NULL || global->panel_auth_file[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    len = 0u;
    status = emtask_text_appendf(
        text,
        sizeof(text),
        &len,
        "# Generated by emtask. Keep this file private.\n"
        "# It contains panel authentication secrets.\n"
        "panel_auth = %s\n",
        emtask_panel_auth_config_name(global->panel_auth));
    if (status != SSH_OK) {
        return status;
    }
    if ((global->panel_auth & EMTASK_PANEL_AUTH_TOKEN) != 0u) {
        status = emtask_text_appendf(text, sizeof(text), &len, "panel_token = %s\n", global->panel_token);
        if (status != SSH_OK) {
            return status;
        }
    }
    if ((global->panel_auth & EMTASK_PANEL_AUTH_OTP) != 0u) {
        status = emtask_text_appendf(text, sizeof(text), &len, "panel_otp_secret = %s\n", global->panel_otp_secret);
        if (status != SSH_OK) {
            return status;
        }
    }
    status = emtask_save_file(global->panel_auth_file, (const uint8_t *)text, len);
    memset(text, 0, sizeof(text));
    return status;
}

static int emtask_panel_materialize_auth(emtask_config_t *config)
{
    emtask_global_config_t *global;
    int auth_file_exists;
    int need_save;
    int status;

    if (config == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    global = &config->global;
    if (!global->panel_enabled || global->panel_auth == 0u) {
        return SSH_OK;
    }
    if (global->panel_auth_file[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    auth_file_exists = 0;
    need_save = 0;
    status = emtask_panel_load_auth_file(global, &auth_file_exists);
    if (status != SSH_OK) {
        return status;
    }
    if (!auth_file_exists) {
        need_save = 1;
    }

    if ((global->panel_auth & EMTASK_PANEL_AUTH_TOKEN) != 0u && global->panel_token[0] == '\0') {
        status = emtask_panel_generate_token(global->panel_token);
        if (status != SSH_OK) {
            return status;
        }
        need_save = 1;
    }
    if ((global->panel_auth & EMTASK_PANEL_AUTH_OTP) != 0u && global->panel_otp_secret[0] == '\0') {
        status = emtask_panel_generate_otp_secret(global->panel_otp_secret);
        if (status != SSH_OK) {
            return status;
        }
        need_save = 1;
    }
    if (need_save) {
        status = emtask_panel_save_auth_file(global);
        if (status != SSH_OK) {
            return status;
        }
        emtask_logf("panel auth material written to %s", global->panel_auth_file);
    }
    return SSH_OK;
}

static int emtask_panel_payload_append_literal(char *out, size_t out_capacity, size_t *out_len, const char *text)
{
    size_t len;

    if (out == NULL || out_len == NULL || text == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    len = strlen(text);
    if (*out_len + len + 1u > out_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(out + *out_len, text, len);
    *out_len += len;
    out[*out_len] = '\0';
    return SSH_OK;
}

static int emtask_panel_payload_append_escaped(
    char *out,
    size_t out_capacity,
    size_t *out_len,
    const char *text,
    size_t raw_limit)
{
    static const char k_hex[] = "0123456789ABCDEF";
    size_t i;

    if (out == NULL || out_len == NULL || text == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    for (i = 0u; text[i] != '\0' && (raw_limit == 0u || i < raw_limit); ++i) {
        unsigned char ch = (unsigned char)text[i];
        int safe = (ch >= 'A' && ch <= 'Z') ||
                   (ch >= 'a' && ch <= 'z') ||
                   (ch >= '0' && ch <= '9') ||
                   ch == '-' || ch == '_' || ch == '.' || ch == '~' || ch == ':';

        if (safe) {
            if (*out_len + 2u > out_capacity) {
                return SSH_ERR_BUFFER_TOO_SMALL;
            }
            out[(*out_len)++] = (char)ch;
        } else {
            if (*out_len + 4u > out_capacity) {
                return SSH_ERR_BUFFER_TOO_SMALL;
            }
            out[(*out_len)++] = '%';
            out[(*out_len)++] = k_hex[(ch >> 4) & 0x0fu];
            out[(*out_len)++] = k_hex[ch & 0x0fu];
        }
        out[*out_len] = '\0';
    }
    return SSH_OK;
}

static int emtask_panel_payload_append_field(
    char *out,
    size_t out_capacity,
    size_t *out_len,
    const char *key,
    const char *value,
    size_t raw_limit)
{
    int status;

    if (value == NULL || value[0] == '\0') {
        return SSH_OK;
    }
    status = emtask_panel_payload_append_literal(out, out_capacity, out_len, "|");
    if (status == SSH_OK) {
        status = emtask_panel_payload_append_literal(out, out_capacity, out_len, key);
    }
    if (status == SSH_OK) {
        status = emtask_panel_payload_append_literal(out, out_capacity, out_len, "=");
    }
    if (status == SSH_OK) {
        status = emtask_panel_payload_append_escaped(out, out_capacity, out_len, value, raw_limit);
    }
    return status;
}

static const char *emtask_panel_qr_host(const emtask_global_config_t *global)
{
    const char *host;

    if (global == NULL) {
        return "127.0.0.1";
    }
    host = global->panel_qr_host[0] != '\0' ? global->panel_qr_host : global->panel_listen_address;
    if (host[0] == '\0' ||
        emtask_key_equals(host, "0.0.0.0") ||
        emtask_key_equals(host, "::") ||
        emtask_key_equals(host, "[::]")) {
        return "127.0.0.1";
    }
    return host;
}

static int emtask_panel_build_qr_payload(const emtask_config_t *config, char *out, size_t out_capacity)
{
    const emtask_global_config_t *global;
    const emtask_task_config_t *first_task;
    char value[64];
    size_t len;
    int status;

    if (config == NULL || out == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    global = &config->global;
    first_task = config->task_count != 0u ? &config->tasks[0] : NULL;
    len = 0u;
    out[0] = '\0';

    status = emtask_panel_payload_append_literal(out, out_capacity, &len, "emtask1");
    if (status != SSH_OK) {
        return status;
    }
    if (global->panel_name[0] != '\0') {
        status = emtask_panel_payload_append_field(out, out_capacity, &len, "pn", global->panel_name, 96u);
        if (status != SSH_OK) {
            return status;
        }
    }
    status = emtask_panel_payload_append_field(out, out_capacity, &len, "h", emtask_panel_qr_host(global), 0u);
    if (status != SSH_OK) {
        return status;
    }
    (void)snprintf(value, sizeof(value), "%u", (unsigned)global->panel_port);
    status = emtask_panel_payload_append_field(out, out_capacity, &len, "pp", value, 0u);
    if (status != SSH_OK) {
        return status;
    }
    if (first_task != NULL) {
        (void)snprintf(value, sizeof(value), "%u", (unsigned)first_task->port);
        status = emtask_panel_payload_append_field(out, out_capacity, &len, "sp", value, 0u);
        if (status != SSH_OK) {
            return status;
        }
        status = emtask_panel_payload_append_field(out, out_capacity, &len, "sn", first_task->name, 48u);
        if (status != SSH_OK) {
            return status;
        }
        (void)snprintf(value, sizeof(value), "%u", (unsigned)(first_task->use_sftp != 0));
        status = emtask_panel_payload_append_field(out, out_capacity, &len, "sf", value, 0u);
        if (status != SSH_OK) {
            return status;
        }
    }
    (void)snprintf(value, sizeof(value), "%u", global->panel_auth & (EMTASK_PANEL_AUTH_TOKEN | EMTASK_PANEL_AUTH_OTP));
    status = emtask_panel_payload_append_field(out, out_capacity, &len, "a", value, 0u);
    if (status != SSH_OK) {
        return status;
    }
    if ((global->panel_auth & EMTASK_PANEL_AUTH_TOKEN) != 0u) {
        status = emtask_panel_payload_append_field(out, out_capacity, &len, "t", global->panel_token, 0u);
        if (status != SSH_OK) {
            return status;
        }
    }
    if ((global->panel_auth & EMTASK_PANEL_AUTH_OTP) != 0u) {
        status = emtask_panel_payload_append_field(out, out_capacity, &len, "o", global->panel_otp_secret, 0u);
        if (status != SSH_OK) {
            return status;
        }
        (void)snprintf(value, sizeof(value), "%u", global->panel_otp_digits);
        status = emtask_panel_payload_append_field(out, out_capacity, &len, "d", value, 0u);
        if (status != SSH_OK) {
            return status;
        }
        (void)snprintf(value, sizeof(value), "%u", global->panel_otp_step_sec);
        status = emtask_panel_payload_append_field(out, out_capacity, &len, "i", value, 0u);
        if (status != SSH_OK) {
            return status;
        }
        (void)snprintf(value, sizeof(value), "%u", global->panel_otp_window);
        status = emtask_panel_payload_append_field(out, out_capacity, &len, "w", value, 0u);
        if (status != SSH_OK) {
            return status;
        }
    }
    if (global->panel_qr_include_username != 0 && global->username[0] != '\0') {
        status = emtask_panel_payload_append_field(out, out_capacity, &len, "u", global->username, 0u);
        if (status != SSH_OK) {
            return status;
        }
    }
    if (global->panel_qr_include_password != 0 && global->password[0] != '\0') {
        status = emtask_panel_payload_append_field(out, out_capacity, &len, "p", global->password, 0u);
        if (status != SSH_OK) {
            return status;
        }
    }
    return SSH_OK;
}

typedef struct emtask_qr_matrix {
    uint8_t modules[EMTASK_QR_SIZE * EMTASK_QR_SIZE];
    uint8_t is_function[EMTASK_QR_SIZE * EMTASK_QR_SIZE];
} emtask_qr_matrix_t;

typedef struct emtask_qr_bit_buffer {
    uint8_t data[EMTASK_QR_DATA_CODEWORDS];
    size_t bit_len;
} emtask_qr_bit_buffer_t;

static size_t emtask_qr_index(unsigned row, unsigned col)
{
    return ((size_t)row * EMTASK_QR_SIZE) + col;
}

static void emtask_qr_set(emtask_qr_matrix_t *qr, unsigned row, unsigned col, int black, int is_function)
{
    size_t index;

    if (qr == NULL || row >= EMTASK_QR_SIZE || col >= EMTASK_QR_SIZE) {
        return;
    }
    index = emtask_qr_index(row, col);
    qr->modules[index] = black ? 1u : 0u;
    if (is_function) {
        qr->is_function[index] = 1u;
    }
}

static uint32_t emtask_qr_bch_remainder(uint32_t value, uint32_t generator, unsigned degree)
{
    int bit;

    value <<= degree;
    for (bit = 31; bit >= (int)degree; --bit) {
        if ((value & (1u << (unsigned)bit)) != 0u) {
            value ^= generator << (unsigned)(bit - (int)degree);
        }
    }
    return value & ((1u << degree) - 1u);
}

static void emtask_qr_draw_finder(emtask_qr_matrix_t *qr, unsigned row, unsigned col)
{
    int dy;
    int dx;

    for (dy = -1; dy <= 7; ++dy) {
        for (dx = -1; dx <= 7; ++dx) {
            int r = (int)row + dy;
            int c = (int)col + dx;
            int black;

            if (r < 0 || c < 0 || r >= (int)EMTASK_QR_SIZE || c >= (int)EMTASK_QR_SIZE) {
                continue;
            }
            black = dx >= 0 && dx <= 6 && dy >= 0 && dy <= 6 &&
                    (dx == 0 || dx == 6 || dy == 0 || dy == 6 ||
                     (dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4));
            emtask_qr_set(qr, (unsigned)r, (unsigned)c, black, 1);
        }
    }
}

static void emtask_qr_draw_alignment(emtask_qr_matrix_t *qr, unsigned row, unsigned col)
{
    int dy;
    int dx;

    for (dy = -2; dy <= 2; ++dy) {
        for (dx = -2; dx <= 2; ++dx) {
            unsigned abs_dx = (unsigned)(dx < 0 ? -dx : dx);
            unsigned abs_dy = (unsigned)(dy < 0 ? -dy : dy);
            unsigned dist = abs_dx > abs_dy ? abs_dx : abs_dy;
            int black = dist == 0u || dist == 2u;

            emtask_qr_set(qr, (unsigned)((int)row + dy), (unsigned)((int)col + dx), black, 1);
        }
    }
}

static void emtask_qr_write_format_bits(emtask_qr_matrix_t *qr, unsigned mask)
{
    uint32_t data = (1u << 3) | (mask & 7u);
    uint32_t bits = ((data << 10) | emtask_qr_bch_remainder(data, 0x537u, 10u)) ^ 0x5412u;
    unsigned i;

    for (i = 0u; i <= 5u; ++i) {
        emtask_qr_set(qr, i, 8u, (bits >> i) & 1u, 1);
    }
    emtask_qr_set(qr, 7u, 8u, (bits >> 6) & 1u, 1);
    emtask_qr_set(qr, 8u, 8u, (bits >> 7) & 1u, 1);
    emtask_qr_set(qr, 8u, 7u, (bits >> 8) & 1u, 1);
    for (i = 9u; i < 15u; ++i) {
        emtask_qr_set(qr, 8u, 14u - i, (bits >> i) & 1u, 1);
    }
    for (i = 0u; i < 8u; ++i) {
        emtask_qr_set(qr, 8u, EMTASK_QR_SIZE - 1u - i, (bits >> i) & 1u, 1);
    }
    for (i = 8u; i < 15u; ++i) {
        emtask_qr_set(qr, EMTASK_QR_SIZE - 15u + i, 8u, (bits >> i) & 1u, 1);
    }
}

static void emtask_qr_write_version_bits(emtask_qr_matrix_t *qr)
{
    uint32_t bits = (EMTASK_QR_VERSION << 12) |
                    emtask_qr_bch_remainder(EMTASK_QR_VERSION, 0x1f25u, 12u);
    unsigned i;

    for (i = 0u; i < 18u; ++i) {
        unsigned a = EMTASK_QR_SIZE - 11u + (i % 3u);
        unsigned b = i / 3u;
        int black = (bits >> i) & 1u;

        emtask_qr_set(qr, b, a, black, 1);
        emtask_qr_set(qr, a, b, black, 1);
    }
}

static void emtask_qr_draw_function_patterns(emtask_qr_matrix_t *qr)
{
    static const unsigned k_alignment[] = {6u, 28u, 50u};
    unsigned i;
    unsigned j;

    memset(qr, 0, sizeof(*qr));
    emtask_qr_draw_finder(qr, 0u, 0u);
    emtask_qr_draw_finder(qr, 0u, EMTASK_QR_SIZE - 7u);
    emtask_qr_draw_finder(qr, EMTASK_QR_SIZE - 7u, 0u);

    for (i = 0u; i < EMTASK_QR_SIZE; ++i) {
        if (qr->is_function[emtask_qr_index(6u, i)] == 0u) {
            emtask_qr_set(qr, 6u, i, (i % 2u) == 0u, 1);
        }
        if (qr->is_function[emtask_qr_index(i, 6u)] == 0u) {
            emtask_qr_set(qr, i, 6u, (i % 2u) == 0u, 1);
        }
    }

    for (i = 0u; i < sizeof(k_alignment) / sizeof(k_alignment[0]); ++i) {
        for (j = 0u; j < sizeof(k_alignment) / sizeof(k_alignment[0]); ++j) {
            if ((i == 0u && j == 0u) ||
                (i == 0u && j + 1u == sizeof(k_alignment) / sizeof(k_alignment[0])) ||
                (i + 1u == sizeof(k_alignment) / sizeof(k_alignment[0]) && j == 0u)) {
                continue;
            }
            emtask_qr_draw_alignment(qr, k_alignment[i], k_alignment[j]);
        }
    }

    for (i = 0u; i <= 8u; ++i) {
        if (i != 6u) {
            emtask_qr_set(qr, 8u, i, 0, 1);
            emtask_qr_set(qr, i, 8u, 0, 1);
        }
    }
    for (i = EMTASK_QR_SIZE - 8u; i < EMTASK_QR_SIZE; ++i) {
        emtask_qr_set(qr, 8u, i, 0, 1);
    }
    for (i = EMTASK_QR_SIZE - 7u; i < EMTASK_QR_SIZE; ++i) {
        emtask_qr_set(qr, i, 8u, 0, 1);
    }

    emtask_qr_set(qr, EMTASK_QR_SIZE - 8u, 8u, 1, 1);
    emtask_qr_write_version_bits(qr);
}

static int emtask_qr_bit_buffer_append(emtask_qr_bit_buffer_t *bits, uint32_t value, unsigned bit_count)
{
    unsigned i;

    if (bits == NULL || bit_count > 24u || bits->bit_len + bit_count > EMTASK_QR_DATA_CODEWORDS * 8u) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    for (i = 0u; i < bit_count; ++i) {
        unsigned shift = bit_count - 1u - i;
        if (((value >> shift) & 1u) != 0u) {
            bits->data[bits->bit_len >> 3] |= (uint8_t)(0x80u >> (bits->bit_len & 7u));
        }
        ++bits->bit_len;
    }
    return SSH_OK;
}

static int emtask_qr_build_data_codewords(const char *payload, uint8_t data_codewords[EMTASK_QR_DATA_CODEWORDS])
{
    emtask_qr_bit_buffer_t bits;
    size_t payload_len;
    size_t codeword_len;
    size_t i;
    int status;

    if (payload == NULL || data_codewords == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    payload_len = strlen(payload);
    if (payload_len > 271u) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memset(&bits, 0, sizeof(bits));
    status = emtask_qr_bit_buffer_append(&bits, 0x4u, 4u);
    if (status == SSH_OK) {
        status = emtask_qr_bit_buffer_append(&bits, (uint32_t)payload_len, 16u);
    }
    for (i = 0u; status == SSH_OK && i < payload_len; ++i) {
        status = emtask_qr_bit_buffer_append(&bits, (uint8_t)payload[i], 8u);
    }
    if (status != SSH_OK) {
        return status;
    }

    if (bits.bit_len < EMTASK_QR_DATA_CODEWORDS * 8u) {
        size_t remaining = (EMTASK_QR_DATA_CODEWORDS * 8u) - bits.bit_len;
        size_t terminator = remaining < 4u ? remaining : 4u;

        bits.bit_len += terminator;
    }
    while ((bits.bit_len & 7u) != 0u) {
        ++bits.bit_len;
    }
    codeword_len = bits.bit_len >> 3;
    for (i = codeword_len; i < EMTASK_QR_DATA_CODEWORDS; ++i) {
        bits.data[i] = (uint8_t)(((i - codeword_len) & 1u) == 0u ? 0xecu : 0x11u);
    }

    memcpy(data_codewords, bits.data, EMTASK_QR_DATA_CODEWORDS);
    return SSH_OK;
}

static void emtask_qr_gf_init(uint8_t exp_table[512], uint8_t log_table[256])
{
    unsigned value;
    unsigned i;

    memset(log_table, 0, 256u);
    value = 1u;
    for (i = 0u; i < 255u; ++i) {
        exp_table[i] = (uint8_t)value;
        log_table[value] = (uint8_t)i;
        value <<= 1;
        if ((value & 0x100u) != 0u) {
            value ^= 0x11du;
        }
    }
    for (i = 255u; i < 512u; ++i) {
        exp_table[i] = exp_table[i - 255u];
    }
}

static uint8_t emtask_qr_gf_mul(const uint8_t exp_table[512], const uint8_t log_table[256], uint8_t a, uint8_t b)
{
    if (a == 0u || b == 0u) {
        return 0u;
    }
    return exp_table[(unsigned)log_table[a] + (unsigned)log_table[b]];
}

static void emtask_qr_compute_generator(
    const uint8_t exp_table[512],
    const uint8_t log_table[256],
    uint8_t generator[EMTASK_QR_ECC_CODEWORDS])
{
    unsigned i;

    memset(generator, 0, EMTASK_QR_ECC_CODEWORDS);
    generator[EMTASK_QR_ECC_CODEWORDS - 1u] = 1u;
    for (i = 0u; i < EMTASK_QR_ECC_CODEWORDS; ++i) {
        unsigned j;
        uint8_t root = exp_table[i];

        for (j = 0u; j < EMTASK_QR_ECC_CODEWORDS; ++j) {
            generator[j] = emtask_qr_gf_mul(exp_table, log_table, generator[j], root);
            if (j + 1u < EMTASK_QR_ECC_CODEWORDS) {
                generator[j] ^= generator[j + 1u];
            }
        }
    }
}

static void emtask_qr_compute_ecc(
    const uint8_t exp_table[512],
    const uint8_t log_table[256],
    const uint8_t generator[EMTASK_QR_ECC_CODEWORDS],
    const uint8_t *data,
    size_t data_len,
    uint8_t ecc[EMTASK_QR_ECC_CODEWORDS])
{
    size_t i;

    memset(ecc, 0, EMTASK_QR_ECC_CODEWORDS);
    for (i = 0u; i < data_len; ++i) {
        unsigned j;
        uint8_t factor = data[i] ^ ecc[0];

        memmove(ecc, ecc + 1u, EMTASK_QR_ECC_CODEWORDS - 1u);
        ecc[EMTASK_QR_ECC_CODEWORDS - 1u] = 0u;
        for (j = 0u; j < EMTASK_QR_ECC_CODEWORDS; ++j) {
            ecc[j] ^= emtask_qr_gf_mul(exp_table, log_table, generator[j], factor);
        }
    }
}

static int emtask_qr_interleave_codewords(
    const uint8_t data_codewords[EMTASK_QR_DATA_CODEWORDS],
    uint8_t out[EMTASK_QR_TOTAL_CODEWORDS])
{
    static const size_t k_block_data_len[EMTASK_QR_BLOCK_COUNT] = {68u, 68u, 69u, 69u};
    uint8_t exp_table[512];
    uint8_t log_table[256];
    uint8_t generator[EMTASK_QR_ECC_CODEWORDS];
    uint8_t block_data[EMTASK_QR_BLOCK_COUNT][69];
    uint8_t block_ecc[EMTASK_QR_BLOCK_COUNT][EMTASK_QR_ECC_CODEWORDS];
    size_t offset;
    size_t out_len;
    unsigned block;
    size_t i;

    if (data_codewords == NULL || out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    emtask_qr_gf_init(exp_table, log_table);
    emtask_qr_compute_generator(exp_table, log_table, generator);

    offset = 0u;
    for (block = 0u; block < EMTASK_QR_BLOCK_COUNT; ++block) {
        memcpy(block_data[block], data_codewords + offset, k_block_data_len[block]);
        emtask_qr_compute_ecc(
            exp_table,
            log_table,
            generator,
            block_data[block],
            k_block_data_len[block],
            block_ecc[block]);
        offset += k_block_data_len[block];
    }

    out_len = 0u;
    for (i = 0u; i < 69u; ++i) {
        for (block = 0u; block < EMTASK_QR_BLOCK_COUNT; ++block) {
            if (i < k_block_data_len[block]) {
                out[out_len++] = block_data[block][i];
            }
        }
    }
    for (i = 0u; i < EMTASK_QR_ECC_CODEWORDS; ++i) {
        for (block = 0u; block < EMTASK_QR_BLOCK_COUNT; ++block) {
            out[out_len++] = block_ecc[block][i];
        }
    }
    return out_len == EMTASK_QR_TOTAL_CODEWORDS ? SSH_OK : SSH_ERR_PLATFORM;
}

static void emtask_qr_place_data(emtask_qr_matrix_t *qr, const uint8_t codewords[EMTASK_QR_TOTAL_CODEWORDS])
{
    size_t bit_index;
    int right;

    bit_index = 0u;
    for (right = (int)EMTASK_QR_SIZE - 1; right >= 1; right -= 2) {
        int upward;
        int i;

        if (right == 6) {
            --right;
        }
        upward = ((((int)EMTASK_QR_SIZE - 1 - right) / 2) & 1) == 0;
        for (i = 0; i < (int)EMTASK_QR_SIZE; ++i) {
            int row = upward ? ((int)EMTASK_QR_SIZE - 1 - i) : i;
            int j;

            for (j = 0; j < 2; ++j) {
                int col = right - j;
                int black;

                if (qr->is_function[emtask_qr_index((unsigned)row, (unsigned)col)] != 0u) {
                    continue;
                }
                black = 0;
                if (bit_index < EMTASK_QR_TOTAL_CODEWORDS * 8u) {
                    black = (codewords[bit_index >> 3] >> (7u - (bit_index & 7u))) & 1u;
                    ++bit_index;
                }
                if ((((unsigned)row + (unsigned)col) & 1u) == 0u) {
                    black = !black;
                }
                emtask_qr_set(qr, (unsigned)row, (unsigned)col, black, 0);
            }
        }
    }
}

static int emtask_qr_build_matrix(const char *payload, emtask_qr_matrix_t *qr)
{
    uint8_t data_codewords[EMTASK_QR_DATA_CODEWORDS];
    uint8_t all_codewords[EMTASK_QR_TOTAL_CODEWORDS];
    int status;

    if (payload == NULL || qr == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = emtask_qr_build_data_codewords(payload, data_codewords);
    if (status != SSH_OK) {
        return status;
    }
    status = emtask_qr_interleave_codewords(data_codewords, all_codewords);
    if (status != SSH_OK) {
        memset(data_codewords, 0, sizeof(data_codewords));
        memset(all_codewords, 0, sizeof(all_codewords));
        return status;
    }

    emtask_qr_draw_function_patterns(qr);
    emtask_qr_place_data(qr, all_codewords);
    emtask_qr_write_format_bits(qr, 0u);
    emtask_qr_set(qr, EMTASK_QR_SIZE - 8u, 8u, 1, 1);

    memset(data_codewords, 0, sizeof(data_codewords));
    memset(all_codewords, 0, sizeof(all_codewords));
    return SSH_OK;
}

static void emtask_qr_write_xml_escaped(FILE *file, const char *text)
{
    const char *p;

    if (file == NULL || text == NULL) {
        return;
    }
    for (p = text; *p != '\0'; ++p) {
        switch (*p) {
        case '&':
            (void)fputs("&amp;", file);
            break;
        case '<':
            (void)fputs("&lt;", file);
            break;
        case '>':
            (void)fputs("&gt;", file);
            break;
        case '"':
            (void)fputs("&quot;", file);
            break;
        default:
            (void)fputc(*p, file);
            break;
        }
    }
}

static int emtask_qr_write_svg(const char *path, const char *payload, const emtask_qr_matrix_t *qr)
{
    enum { k_quiet = 4, k_module = 8 };
    unsigned image_size;
    FILE *file;
    unsigned row;
    unsigned col;

    if (path == NULL || payload == NULL || qr == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    file = fopen(path, "wb");
    if (file == NULL) {
        return SSH_ERR_PLATFORM;
    }

    image_size = (EMTASK_QR_SIZE + (2u * k_quiet)) * k_module;
    if (fprintf(
            file,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%u\" height=\"%u\" viewBox=\"0 0 %u %u\" shape-rendering=\"crispEdges\">\n"
            "<title>emtask server import QR</title>\n<desc>",
            image_size,
            image_size,
            image_size,
            image_size) < 0) {
        (void)fclose(file);
        return SSH_ERR_PLATFORM;
    }
    emtask_qr_write_xml_escaped(file, payload);
    if (fprintf(file, "</desc>\n<rect width=\"100%%\" height=\"100%%\" fill=\"#fff\"/>\n") < 0) {
        (void)fclose(file);
        return SSH_ERR_PLATFORM;
    }
    for (row = 0u; row < EMTASK_QR_SIZE; ++row) {
        for (col = 0u; col < EMTASK_QR_SIZE; ++col) {
            if (qr->modules[emtask_qr_index(row, col)] == 0u) {
                continue;
            }
            if (fprintf(
                    file,
                    "<rect x=\"%u\" y=\"%u\" width=\"%u\" height=\"%u\" fill=\"#000\"/>\n",
                    (col + k_quiet) * k_module,
                    (row + k_quiet) * k_module,
                    k_module,
                    k_module) < 0) {
                (void)fclose(file);
                return SSH_ERR_PLATFORM;
            }
        }
    }
    if (fprintf(file, "</svg>\n") < 0) {
        (void)fclose(file);
        return SSH_ERR_PLATFORM;
    }
    return fclose(file) == 0 ? SSH_OK : SSH_ERR_PLATFORM;
}

static int emtask_panel_materialize_qr(const emtask_config_t *config)
{
    emtask_qr_matrix_t qr;
    char payload[EMTASK_QR_PAYLOAD_MAX];
    int exists;
    int status;

    if (config == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (!config->global.panel_enabled ||
        config->global.panel_auth == 0u ||
        config->global.panel_qr_file[0] == '\0' ||
        config->global.panel_qr_mode == EMTASK_PANEL_QR_DISABLED) {
        return SSH_OK;
    }

    if (config->global.panel_qr_mode == EMTASK_PANEL_QR_IF_MISSING) {
        status = emtask_panel_file_exists(config->global.panel_qr_file, &exists);
        if (status != SSH_OK || exists) {
            return status;
        }
    }

    status = emtask_panel_build_qr_payload(config, payload, sizeof(payload));
    if (status != SSH_OK) {
        memset(payload, 0, sizeof(payload));
        return status;
    }
    status = emtask_qr_build_matrix(payload, &qr);
    if (status == SSH_OK) {
        status = emtask_qr_write_svg(config->global.panel_qr_file, payload, &qr);
    }
    if (status == SSH_OK) {
        emtask_logf("panel QR code written to %s", config->global.panel_qr_file);
    }
    memset(payload, 0, sizeof(payload));
    memset(&qr, 0, sizeof(qr));
    return status;
}

static int emtask_prepare_hostkey(emtask_app_t *app)
{
    emtask_crypto_context_t crypto_ctx;
    const ssh_crypto_api_t *crypto;
    uint8_t private_key[EMTASK_MAX_HOSTKEY_PRIVATE];
    size_t private_key_len;
    int status;

    if (app == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(&crypto_ctx, 0, sizeof(crypto_ctx));
    memset(private_key, 0, sizeof(private_key));

    status = ssh_crypto_open(EMTASK_CTX_PTR(&crypto_ctx));
    if (status != SSH_OK) {
        return status;
    }

    crypto = ssh_crypto_api(EMTASK_CTX_CONST_PTR(&crypto_ctx));
    if (crypto == NULL) {
        ssh_crypto_close(EMTASK_CTX_PTR(&crypto_ctx));
        return SSH_ERR_PLATFORM;
    }

    status = emtask_load_file(app->config.global.hostkey_file, private_key, sizeof(private_key), &private_key_len);
    if (status == SSH_OK) {
        if (crypto->hostkey_import_private_auto == NULL) {
            ssh_crypto_close(EMTASK_CTX_PTR(&crypto_ctx));
            memset(private_key, 0, sizeof(private_key));
            return SSH_ERR_UNSUPPORTED;
        }
        status = crypto->hostkey_import_private_auto(
            crypto->ctx,
            emtask_hostkey_algorithm_view(),
            private_key,
            private_key_len);
        if (status != SSH_OK) {
            ssh_crypto_close(EMTASK_CTX_PTR(&crypto_ctx));
            memset(private_key, 0, sizeof(private_key));
            return status;
        }
    } else if (status == SSH_ERR_NOT_FOUND) {
        if (crypto->hostkey_generate == NULL || crypto->hostkey_export_private == NULL) {
            ssh_crypto_close(EMTASK_CTX_PTR(&crypto_ctx));
            return SSH_ERR_UNSUPPORTED;
        }
        status = crypto->hostkey_generate(crypto->ctx, emtask_hostkey_algorithm_view());
        if (status == SSH_OK) {
            status = crypto->hostkey_export_private(
                crypto->ctx,
                emtask_hostkey_algorithm_view(),
                private_key,
                sizeof(private_key),
                &private_key_len);
        }
        if (status == SSH_OK) {
            status = emtask_save_file(app->config.global.hostkey_file, private_key, private_key_len);
        }
        if (status != SSH_OK) {
            ssh_crypto_close(EMTASK_CTX_PTR(&crypto_ctx));
            memset(private_key, 0, sizeof(private_key));
            return status;
        }
    } else {
        ssh_crypto_close(EMTASK_CTX_PTR(&crypto_ctx));
        memset(private_key, 0, sizeof(private_key));
        return status;
    }

    if (crypto->hostkey_export_private == NULL) {
        ssh_crypto_close(EMTASK_CTX_PTR(&crypto_ctx));
        memset(private_key, 0, sizeof(private_key));
        return SSH_ERR_UNSUPPORTED;
    }
    status = crypto->hostkey_export_private(
        crypto->ctx,
        emtask_hostkey_algorithm_view(),
        app->hostkey_private,
        sizeof(app->hostkey_private),
        &app->hostkey_private_len);
    ssh_crypto_close(EMTASK_CTX_PTR(&crypto_ctx));
    memset(private_key, 0, sizeof(private_key));
    return status;
}

static int emtask_username_matches(const emtask_global_config_t *config, const char *username, size_t username_len)
{
    size_t expected_len;

    if (config == NULL || username == NULL) {
        return 0;
    }
    expected_len = strlen(config->username);
    return expected_len == username_len && memcmp(config->username, username, username_len) == 0;
}

static int emtask_password_auth(void *ctx, const ssh_password_auth_request_t *request)
{
    const emtask_global_config_t *config = (const emtask_global_config_t *)ctx;
    size_t password_len;

    if (config == NULL || request == NULL || config->auth_backend != EMTASK_AUTH_BACKEND_INTERNAL || config->password[0] == '\0') {
        return 0;
    }
    if (!emtask_username_matches(config, request->username, request->username_len)) {
        return 0;
    }
    password_len = strlen(config->password);
    return password_len == request->password_len &&
           memcmp(config->password, request->password, password_len) == 0;
}

static int emtask_password_auth_dispatch(void *ctx, const ssh_password_auth_request_t *request)
{
    emtask_app_t *app = (emtask_app_t *)ctx;

    if (app == NULL || request == NULL) {
        return 0;
    }
    if (app->config.global.auth_backend == EMTASK_AUTH_BACKEND_INTERNAL) {
        return emtask_password_auth(&app->config.global, request);
    }
#if defined(EMSSH_BUILD_POSIX_PASSWD_AUTH)
    if (app->config.global.auth_backend == EMTASK_AUTH_BACKEND_PASSWD) {
        return ssh_posix_passwd_auth_cb(&app->passwd_auth, request);
    }
#endif
    return 0;
}

#if defined(EMSSH_BUILD_POSIX_PASSWD_AUTH)
static int emtask_passwd_auth_init(emtask_app_t *app)
{
    int status;

    if (app == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (app->config.global.auth_backend != EMTASK_AUTH_BACKEND_PASSWD) {
        return SSH_OK;
    }

    status = ssh_stdio_fs_init(&app->passwd_fs, "/");
    if (status != SSH_OK) {
        return status;
    }
    status = ssh_posix_passwd_auth_init(
        &app->passwd_auth,
        ssh_stdio_fs_api(&app->passwd_fs),
        "etc/passwd",
        "etc/shadow");
    if (status != SSH_OK) {
        ssh_stdio_fs_deinit(&app->passwd_fs);
        return status;
    }
    app->passwd_auth_initialized = 1;
    return SSH_OK;
}

static void emtask_passwd_auth_deinit(emtask_app_t *app)
{
    if (app == NULL || !app->passwd_auth_initialized) {
        return;
    }
    ssh_posix_passwd_auth_deinit(&app->passwd_auth);
    ssh_stdio_fs_deinit(&app->passwd_fs);
    app->passwd_auth_initialized = 0;
}
#else
static int emtask_passwd_auth_init(emtask_app_t *app)
{
    if (app == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (app->config.global.auth_backend == EMTASK_AUTH_BACKEND_PASSWD) {
        return SSH_ERR_UNSUPPORTED;
    }
    return SSH_OK;
}

static void emtask_passwd_auth_deinit(emtask_app_t *app)
{
    (void)app;
}
#endif

static int emtask_is_space_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

static int emtask_base64_value(char c)
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

static int emtask_decode_base64_token(
    const char *text,
    size_t text_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    uint32_t acc;
    unsigned bits;
    size_t written;
    size_t i;
    int saw_padding;

    if (text == NULL || out == NULL || out_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    acc = 0u;
    bits = 0u;
    written = 0u;
    saw_padding = 0;
    for (i = 0u; i < text_len; ++i) {
        int value = emtask_base64_value(text[i]);
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

static int emtask_authorized_key_algorithm(const char *token, size_t token_len)
{
    return (token_len == strlen("ssh-ed25519") && memcmp(token, "ssh-ed25519", token_len) == 0) ||
           (token_len == strlen("ssh-rsa") && memcmp(token, "ssh-rsa", token_len) == 0) ||
           (token_len == strlen("ecdsa-sha2-nistp256") && memcmp(token, "ecdsa-sha2-nistp256", token_len) == 0);
}

static int emtask_line_publickey_matches(char *line, const ssh_publickey_auth_request_t *request, int *matched)
{
    char *p;
    char *token_start;
    char *algorithm_token;
    char *blob_token;
    size_t token_len;
    size_t blob_token_len;
    uint8_t blob[EMSSH_MAX_HOST_KEY_BLOB];
    size_t blob_len;
    int status;

    if (line == NULL || request == NULL || matched == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *matched = 0;
    p = line;
    while (*p != '\0' && emtask_is_space_char(*p)) {
        ++p;
    }
    if (*p == '\0' || *p == '#') {
        return SSH_OK;
    }

    algorithm_token = NULL;
    blob_token = NULL;
    blob_token_len = 0u;
    while (*p != '\0') {
        while (*p != '\0' && emtask_is_space_char(*p)) {
            ++p;
        }
        if (*p == '\0' || *p == '#') {
            break;
        }

        token_start = p;
        while (*p != '\0' && !emtask_is_space_char(*p)) {
            ++p;
        }
        token_len = (size_t)(p - token_start);
        if (token_len == 0u) {
            continue;
        }

        if (algorithm_token == NULL) {
            if (emtask_authorized_key_algorithm(token_start, token_len)) {
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

    status = emtask_decode_base64_token(blob_token, blob_token_len, blob, sizeof(blob), &blob_len);
    if (status != SSH_OK) {
        return SSH_OK;
    }
    if (blob_len == request->publickey_blob_len &&
        memcmp(blob, request->publickey_blob, blob_len) == 0) {
        *matched = 1;
    }
    return SSH_OK;
}

static int emtask_authorized_keys_contains(const char *path, const ssh_publickey_auth_request_t *request, int *matched)
{
    FILE *file;
    char line[1024];

    if (path == NULL || request == NULL || matched == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *matched = 0;
    file = fopen(path, "rb");
    if (file == NULL) {
        return errno == ENOENT ? SSH_ERR_NOT_FOUND : SSH_ERR_PLATFORM;
    }

    while (fgets(line, (int)sizeof(line), file) != NULL) {
        int line_match = 0;
        int status = emtask_line_publickey_matches(line, request, &line_match);
        if (status != SSH_OK) {
            (void)fclose(file);
            return status;
        }
        if (line_match) {
            *matched = 1;
            break;
        }
    }

    if (ferror(file) != 0) {
        (void)fclose(file);
        return SSH_ERR_PLATFORM;
    }
    (void)fclose(file);
    return SSH_OK;
}

static int emtask_publickey_blob_algorithm_matches(
    const uint8_t *blob,
    size_t blob_len,
    const char *algorithm,
    size_t algorithm_len)
{
    uint32_t encoded_len;

    if (blob == NULL || algorithm == NULL || blob_len < 4u) {
        return 0;
    }
    encoded_len = ((uint32_t)blob[0] << 24) |
                  ((uint32_t)blob[1] << 16) |
                  ((uint32_t)blob[2] << 8) |
                  (uint32_t)blob[3];
    if (encoded_len != algorithm_len || 4u + (size_t)encoded_len > blob_len) {
        return 0;
    }
    return memcmp(blob + 4u, algorithm, algorithm_len) == 0;
}

static int emtask_parse_authorized_key_line(
    char *line,
    uint8_t *blob,
    size_t blob_capacity,
    size_t *blob_len)
{
    char *p;
    char *algorithm_token;
    char *blob_token;
    size_t algorithm_len;
    size_t blob_token_len;
    int status;

    if (line == NULL || blob == NULL || blob_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (strchr(line, '\r') != NULL || strchr(line, '\n') != NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    p = emtask_trim(line);
    if (*p == '\0' || *p == '#') {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    algorithm_token = p;
    while (*p != '\0' && !emtask_is_space_char(*p)) {
        ++p;
    }
    algorithm_len = (size_t)(p - algorithm_token);
    if (!emtask_authorized_key_algorithm(algorithm_token, algorithm_len)) {
        return SSH_ERR_UNSUPPORTED;
    }
    if (*p == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    while (*p != '\0' && emtask_is_space_char(*p)) {
        ++p;
    }
    blob_token = p;
    while (*p != '\0' && !emtask_is_space_char(*p)) {
        ++p;
    }
    blob_token_len = (size_t)(p - blob_token);
    if (blob_token_len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = emtask_decode_base64_token(blob_token, blob_token_len, blob, blob_capacity, blob_len);
    if (status != SSH_OK) {
        return status;
    }
    if (!emtask_publickey_blob_algorithm_matches(blob, *blob_len, algorithm_token, algorithm_len)) {
        return SSH_ERR_MALFORMED_PACKET;
    }
    return SSH_OK;
}

static int emtask_authorized_keys_has_blob(const char *path, const uint8_t *blob, size_t blob_len, int *matched)
{
    ssh_publickey_auth_request_t request;
    int status;

    if (path == NULL || blob == NULL || matched == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    memset(&request, 0, sizeof(request));
    request.publickey_blob = blob;
    request.publickey_blob_len = blob_len;
    status = emtask_authorized_keys_contains(path, &request, matched);
    if (status == SSH_ERR_NOT_FOUND) {
        *matched = 0;
        return SSH_OK;
    }
    return status;
}

static int emtask_authorized_keys_needs_separator(const char *path, int *needs_separator)
{
    FILE *file;
    long size;
    int ch;

    if (path == NULL || needs_separator == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    *needs_separator = 0;
    file = fopen(path, "rb");
    if (file == NULL) {
        return errno == ENOENT ? SSH_OK : SSH_ERR_PLATFORM;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        (void)fclose(file);
        return SSH_ERR_PLATFORM;
    }
    size = ftell(file);
    if (size < 0) {
        (void)fclose(file);
        return SSH_ERR_PLATFORM;
    }
    if (size == 0) {
        (void)fclose(file);
        return SSH_OK;
    }
    if (fseek(file, -1, SEEK_END) != 0) {
        (void)fclose(file);
        return SSH_ERR_PLATFORM;
    }
    ch = fgetc(file);
    if (ch == EOF && ferror(file) != 0) {
        (void)fclose(file);
        return SSH_ERR_PLATFORM;
    }
    *needs_separator = ch != '\n' && ch != '\r';
    (void)fclose(file);
    return SSH_OK;
}

static int emtask_authorized_keys_append_line(const char *path, const char *line)
{
    FILE *file;
    size_t line_len;
    int needs_separator;
    int status;

    if (path == NULL || path[0] == '\0' || line == NULL || line[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    status = emtask_authorized_keys_needs_separator(path, &needs_separator);
    if (status != SSH_OK) {
        return status;
    }
    file = fopen(path, "ab");
    if (file == NULL) {
        return SSH_ERR_PLATFORM;
    }
    if (needs_separator && fwrite("\n", 1u, 1u, file) != 1u) {
        (void)fclose(file);
        return SSH_ERR_PLATFORM;
    }
    line_len = strlen(line);
    if (fwrite(line, 1u, line_len, file) != line_len || fwrite("\n", 1u, 1u, file) != 1u) {
        (void)fclose(file);
        return SSH_ERR_PLATFORM;
    }
    if (fclose(file) != 0) {
        return SSH_ERR_PLATFORM;
    }
    return SSH_OK;
}

static int emtask_publickey_auth(void *ctx, const ssh_publickey_auth_request_t *request)
{
    const emtask_global_config_t *config = (const emtask_global_config_t *)ctx;
    int matched;
    int status;

    if (config == NULL || request == NULL || config->authorized_keys_file[0] == '\0') {
        return 0;
    }
    if (!emtask_username_matches(config, request->username, request->username_len)) {
        return 0;
    }

    matched = 0;
    status = emtask_authorized_keys_contains(config->authorized_keys_file, request, &matched);
    if (status != SSH_OK) {
        return 0;
    }
    return matched;
}

static int emtask_publickey_auth_dispatch(void *ctx, const ssh_publickey_auth_request_t *request)
{
    emtask_app_t *app = (emtask_app_t *)ctx;

    if (app == NULL) {
        return 0;
    }
    return emtask_publickey_auth(&app->config.global, request);
}

static int emtask_worker_pool_init(emtask_worker_pool_t *pool, unsigned max_workers)
{
    int status;

    if (pool == NULL || max_workers == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(pool, 0, sizeof(*pool));
    status = emtask_mutex_init(&pool->lock);
    if (status != SSH_OK) {
        return status;
    }
    status = emtask_cond_init(&pool->cv);
    if (status != SSH_OK) {
        emtask_mutex_deinit(&pool->lock);
        return status;
    }
    pool->max_workers = max_workers;
    pool->initialized = 1;
    return SSH_OK;
}

static void emtask_worker_pool_deinit(emtask_worker_pool_t *pool)
{
    if (pool == NULL || !pool->initialized) {
        return;
    }
    emtask_cond_deinit(&pool->cv);
    emtask_mutex_deinit(&pool->lock);
    memset(pool, 0, sizeof(*pool));
}

static void emtask_worker_pool_reserve(emtask_worker_pool_t *pool)
{
    if (pool == NULL) {
        return;
    }
    emtask_mutex_lock(&pool->lock);
    while (pool->active_workers >= pool->max_workers) {
        emtask_cond_wait(&pool->cv, &pool->lock);
    }
    ++pool->active_workers;
    emtask_mutex_unlock(&pool->lock);
}

static void emtask_worker_pool_release(emtask_worker_pool_t *pool)
{
    if (pool == NULL) {
        return;
    }
    emtask_mutex_lock(&pool->lock);
    if (pool->active_workers > 0u) {
        --pool->active_workers;
    }
    emtask_cond_broadcast(&pool->cv);
    emtask_mutex_unlock(&pool->lock);
}

static int emtask_session_manager_init(emtask_session_manager_t *manager)
{
    int status;

    if (manager == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(manager, 0, sizeof(*manager));
    status = emtask_mutex_init(&manager->lock);
    if (status != SSH_OK) {
        return status;
    }
    status = emtask_cond_init(&manager->cv);
    if (status != SSH_OK) {
        emtask_mutex_deinit(&manager->lock);
        return status;
    }
    manager->initialized = 1;
    return SSH_OK;
}

static void emtask_session_manager_deinit(emtask_session_manager_t *manager)
{
    if (manager == NULL || !manager->initialized) {
        return;
    }
    emtask_cond_deinit(&manager->cv);
    emtask_mutex_deinit(&manager->lock);
    memset(manager, 0, sizeof(*manager));
}

static int emtask_is_peer_closed_error(void)
{
    return emtask_platform_net_is_peer_closed_error();
}

static int emtask_wait_for_socket(uintptr_t socket_handle, int for_write, uint32_t timeout_ms)
{
    return emtask_platform_net_wait(socket_handle, for_write, timeout_ms);
}

static void emtask_endpoint_init(emtask_endpoint_t *endpoint, const ssh_tcp_conn_t *conn)
{
    if (endpoint == NULL || conn == NULL) {
        return;
    }
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->socket_handle = conn->socket_handle;
    endpoint->open = conn->open;
    if (conn->peer_address[0] != '\0') {
        (void)emtask_copy_text(endpoint->peer_address, sizeof(endpoint->peer_address), conn->peer_address);
    }
}

static const char *emtask_endpoint_peer(const emtask_endpoint_t *endpoint)
{
    if (endpoint == NULL || endpoint->peer_address[0] == '\0') {
        return "unknown";
    }
    return endpoint->peer_address;
}

static void emtask_endpoint_request_shutdown(emtask_endpoint_t *endpoint)
{
    if (endpoint == NULL || !endpoint->open || endpoint->shutdown_requested) {
        return;
    }

    endpoint->shutdown_requested = 1;
    (void)emtask_platform_net_shutdown(endpoint->socket_handle);
}

static int emtask_endpoint_close(emtask_endpoint_t *endpoint)
{
    uintptr_t socket_handle;

    if (endpoint == NULL || !endpoint->open) {
        return SSH_OK;
    }

    socket_handle = endpoint->socket_handle;
    endpoint->open = 0;
    endpoint->shutdown_requested = 1;
    endpoint->socket_handle = 0u;
    return emtask_platform_net_close(socket_handle) == 0 ? SSH_OK : SSH_ERR_PLATFORM;
}

static int emtask_net_read(void *ctx, void *conn, uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    emtask_endpoint_t *endpoint = (emtask_endpoint_t *)conn;
    int n;

    (void)ctx;

    if (endpoint == NULL || buf == NULL || len == 0u) {
        return -1;
    }
    if (!endpoint->open) {
        return 0;
    }

    switch (emtask_wait_for_socket(endpoint->socket_handle, 0, timeout_ms)) {
    case 0:
        return EMTASK_NET_IO_TIMEOUT;
    case -1:
        return endpoint->shutdown_requested ? 0 : -1;
    default:
        break;
    }

    n = emtask_platform_net_recv(endpoint->socket_handle, buf, len);
    if (n < 0) {
        if (endpoint->shutdown_requested || emtask_is_peer_closed_error()) {
            return 0;
        }
    }
    return n;
}

static int emtask_net_write(void *ctx, void *conn, const uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    emtask_endpoint_t *endpoint = (emtask_endpoint_t *)conn;
    int n;

    (void)ctx;

    if (endpoint == NULL || (buf == NULL && len != 0u)) {
        return -1;
    }
    if (!endpoint->open) {
        return 0;
    }
    if (len == 0u) {
        return 0;
    }

    switch (emtask_wait_for_socket(endpoint->socket_handle, 1, timeout_ms)) {
    case 0:
        return EMTASK_NET_IO_TIMEOUT;
    case -1:
        return endpoint->shutdown_requested ? 0 : -1;
    default:
        break;
    }

    n = emtask_platform_net_send(endpoint->socket_handle, buf, len);
    if (n < 0) {
        if (endpoint->shutdown_requested || emtask_is_peer_closed_error()) {
            return 0;
        }
    }
    return n;
}

static int emtask_net_close(void *ctx, void *conn)
{
    (void)ctx;
    return emtask_endpoint_close((emtask_endpoint_t *)conn);
}

typedef struct emtask_panel_buffer {
    char *data;
    size_t len;
    size_t capacity;
    int truncated;
} emtask_panel_buffer_t;

static void emtask_panel_buffer_init(emtask_panel_buffer_t *buf, char *data, size_t capacity)
{
    if (buf == NULL) {
        return;
    }
    buf->data = data;
    buf->len = 0u;
    buf->capacity = capacity;
    buf->truncated = 0;
    if (data != NULL && capacity != 0u) {
        data[0] = '\0';
    }
}

static void emtask_panel_appendf(emtask_panel_buffer_t *buf, const char *fmt, ...)
{
    va_list args;
    int written;
    size_t available;

    if (buf == NULL || buf->data == NULL || buf->capacity == 0u || fmt == NULL || buf->truncated) {
        return;
    }
    if (buf->len >= buf->capacity) {
        buf->truncated = 1;
        return;
    }

    available = buf->capacity - buf->len;
    va_start(args, fmt);
    written = vsnprintf(buf->data + buf->len, available, fmt, args);
    va_end(args);
    if (written < 0) {
        buf->truncated = 1;
        return;
    }
    if ((size_t)written >= available) {
        buf->len = buf->capacity - 1u;
        buf->data[buf->len] = '\0';
        buf->truncated = 1;
        return;
    }
    buf->len += (size_t)written;
}

static void emtask_panel_append_json_string(emtask_panel_buffer_t *buf, const char *text)
{
    const unsigned char *p;

    emtask_panel_appendf(buf, "\"");
    if (text != NULL) {
        for (p = (const unsigned char *)text; *p != '\0'; ++p) {
            switch (*p) {
            case '\\':
                emtask_panel_appendf(buf, "\\\\");
                break;
            case '"':
                emtask_panel_appendf(buf, "\\\"");
                break;
            case '\b':
                emtask_panel_appendf(buf, "\\b");
                break;
            case '\f':
                emtask_panel_appendf(buf, "\\f");
                break;
            case '\n':
                emtask_panel_appendf(buf, "\\n");
                break;
            case '\r':
                emtask_panel_appendf(buf, "\\r");
                break;
            case '\t':
                emtask_panel_appendf(buf, "\\t");
                break;
            default:
                if (*p < 0x20u) {
                    emtask_panel_appendf(buf, "\\u%04x", (unsigned)*p);
                } else {
                    emtask_panel_appendf(buf, "%c", (char)*p);
                }
                break;
            }
        }
    }
    emtask_panel_appendf(buf, "\"");
}

static int emtask_panel_constant_time_equal(const char *lhs, const char *rhs)
{
    size_t lhs_len;
    size_t rhs_len;
    size_t max_len;
    unsigned diff;

    if (lhs == NULL || rhs == NULL) {
        return 0;
    }
    lhs_len = strlen(lhs);
    rhs_len = strlen(rhs);
    max_len = lhs_len > rhs_len ? lhs_len : rhs_len;
    diff = (unsigned)(lhs_len ^ rhs_len);
    for (size_t i = 0u; i < max_len; ++i) {
        unsigned lc = i < lhs_len ? (unsigned char)lhs[i] : 0u;
        unsigned rc = i < rhs_len ? (unsigned char)rhs[i] : 0u;
        diff |= lc ^ rc;
    }
    return diff == 0u;
}

static int emtask_panel_char_to_lower(int ch)
{
    return ch >= 'A' && ch <= 'Z' ? ch - 'A' + 'a' : ch;
}

static int emtask_panel_prefix_equals_nocase(const char *text, const char *prefix)
{
    if (text == NULL || prefix == NULL) {
        return 0;
    }
    while (*prefix != '\0') {
        if (emtask_panel_char_to_lower((unsigned char)*text) != emtask_panel_char_to_lower((unsigned char)*prefix)) {
            return 0;
        }
        ++text;
        ++prefix;
    }
    return 1;
}

static int emtask_panel_hex_value(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

static int emtask_panel_url_decode(const char *src, size_t src_len, char *out, size_t out_capacity)
{
    size_t written;

    if (src == NULL || out == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    written = 0u;
    for (size_t i = 0u; i < src_len; ++i) {
        char ch = src[i];

        if (written + 1u >= out_capacity) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        if (ch == '%' && i + 2u < src_len) {
            int hi = emtask_panel_hex_value(src[i + 1u]);
            int lo = emtask_panel_hex_value(src[i + 2u]);
            if (hi >= 0 && lo >= 0) {
                out[written++] = (char)((hi << 4) | lo);
                i += 2u;
                continue;
            }
        }
        out[written++] = ch == '+' ? ' ' : ch;
    }
    out[written] = '\0';
    return SSH_OK;
}

static int emtask_panel_query_value(const char *query, const char *key, char *out, size_t out_capacity)
{
    size_t key_len;
    const char *p;

    if (query == NULL || key == NULL || out == NULL || out_capacity == 0u) {
        return 0;
    }
    out[0] = '\0';
    key_len = strlen(key);
    p = query;
    while (*p != '\0') {
        const char *name = p;
        const char *eq;
        const char *end;

        end = strchr(p, '&');
        if (end == NULL) {
            end = p + strlen(p);
        }
        eq = memchr(name, '=', (size_t)(end - name));
        if (eq != NULL && (size_t)(eq - name) == key_len && memcmp(name, key, key_len) == 0) {
            return emtask_panel_url_decode(eq + 1, (size_t)(end - eq - 1), out, out_capacity) == SSH_OK;
        }
        p = *end == '&' ? end + 1 : end;
    }
    return 0;
}

static void emtask_panel_trim_ascii(char *text)
{
    char *trimmed;
    char *end;

    if (text == NULL) {
        return;
    }
    trimmed = text;
    while (*trimmed == ' ' || *trimmed == '\t' || *trimmed == '\r' || *trimmed == '\n') {
        ++trimmed;
    }
    if (trimmed != text) {
        memmove(text, trimmed, strlen(trimmed) + 1u);
    }
    end = text + strlen(text);
    while (end > text && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) {
        --end;
    }
    *end = '\0';
}

static int emtask_panel_header_value(const char *request, const char *name, char *out, size_t out_capacity)
{
    size_t name_len;
    const char *p;

    if (request == NULL || name == NULL || out == NULL || out_capacity == 0u) {
        return 0;
    }
    out[0] = '\0';
    name_len = strlen(name);
    p = strchr(request, '\n');
    if (p == NULL) {
        return 0;
    }
    ++p;
    while (*p != '\0') {
        const char *line_end;
        const char *colon;
        size_t line_len;

        line_end = strchr(p, '\n');
        if (line_end == NULL) {
            line_end = p + strlen(p);
        }
        line_len = (size_t)(line_end - p);
        if (line_len != 0u && p[line_len - 1u] == '\r') {
            --line_len;
        }
        if (line_len == 0u) {
            return 0;
        }
        colon = memchr(p, ':', line_len);
        if (colon != NULL && (size_t)(colon - p) == name_len) {
            int match = 1;
            for (size_t i = 0u; i < name_len; ++i) {
                if (emtask_panel_char_to_lower((unsigned char)p[i]) != emtask_panel_char_to_lower((unsigned char)name[i])) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                size_t value_len = line_len - (size_t)(colon - p) - 1u;
                if (value_len + 1u > out_capacity) {
                    value_len = out_capacity - 1u;
                }
                memcpy(out, colon + 1, value_len);
                out[value_len] = '\0';
                emtask_panel_trim_ascii(out);
                return 1;
            }
        }
        p = *line_end == '\n' ? line_end + 1 : line_end;
    }
    return 0;
}

static int emtask_panel_base32_value(char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A';
    }
    if (ch >= 'a' && ch <= 'z') {
        return ch - 'a';
    }
    if (ch >= '2' && ch <= '7') {
        return ch - '2' + 26;
    }
    return -1;
}

static int emtask_panel_decode_base32_secret(const char *text, uint8_t *out, size_t out_capacity, size_t *out_len)
{
    uint32_t acc;
    unsigned bits;
    size_t written;

    if (text == NULL || out == NULL || out_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    acc = 0u;
    bits = 0u;
    written = 0u;
    for (const char *p = text; *p != '\0'; ++p) {
        int value;

        if (*p == '=' || *p == ' ' || *p == '\t' || *p == '-' || *p == ':') {
            continue;
        }
        value = emtask_panel_base32_value(*p);
        if (value < 0) {
            return SSH_ERR_MALFORMED_PACKET;
        }
        acc = (acc << 5) | (uint32_t)value;
        bits += 5u;
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

static int emtask_panel_totp_code(
    const uint8_t *secret,
    size_t secret_len,
    uint64_t counter,
    unsigned digits,
    char out[16])
{
    const mbedtls_md_info_t *info;
    uint8_t msg[8];
    uint8_t hmac[20];
    uint32_t bin_code;
    uint32_t divisor;
    uint32_t code;
    unsigned offset;
    int written;

    if (secret == NULL || secret_len == 0u || out == NULL || digits < 6u || digits > 8u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (info == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    for (unsigned i = 0u; i < 8u; ++i) {
        msg[7u - i] = (uint8_t)(counter & 0xffu);
        counter >>= 8;
    }
    if (mbedtls_md_hmac(info, secret, secret_len, msg, sizeof(msg), hmac) != 0) {
        memset(hmac, 0, sizeof(hmac));
        return SSH_ERR_PLATFORM;
    }
    offset = hmac[19] & 0x0fu;
    bin_code = (((uint32_t)hmac[offset] & 0x7fu) << 24) |
               ((uint32_t)hmac[offset + 1u] << 16) |
               ((uint32_t)hmac[offset + 2u] << 8) |
               (uint32_t)hmac[offset + 3u];
    divisor = 1u;
    for (unsigned i = 0u; i < digits; ++i) {
        divisor *= 10u;
    }
    code = bin_code % divisor;
    written = snprintf(out, 16u, "%0*u", (int)digits, (unsigned)code);
    memset(hmac, 0, sizeof(hmac));
    return written == (int)digits ? SSH_OK : SSH_ERR_BUFFER_TOO_SMALL;
}

static int emtask_panel_verify_otp(const emtask_global_config_t *global, const char *otp)
{
    uint8_t secret[128];
    size_t secret_len;
    time_t now;
    uint64_t counter;
    int status;

    if (global == NULL || otp == NULL || otp[0] == '\0') {
        return 0;
    }
    for (const char *p = otp; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
    }
    if (strlen(otp) != global->panel_otp_digits) {
        return 0;
    }
    status = emtask_panel_decode_base32_secret(global->panel_otp_secret, secret, sizeof(secret), &secret_len);
    if (status != SSH_OK) {
        memset(secret, 0, sizeof(secret));
        return 0;
    }
    now = time(NULL);
    if (now < 0 || global->panel_otp_step_sec == 0u) {
        memset(secret, 0, sizeof(secret));
        return 0;
    }
    counter = (uint64_t)now / (uint64_t)global->panel_otp_step_sec;
    for (int delta = -(int)global->panel_otp_window; delta <= (int)global->panel_otp_window; ++delta) {
        char expected[16];
        uint64_t candidate;

        if (delta < 0 && counter < (uint64_t)(-delta)) {
            continue;
        }
        candidate = delta < 0 ? counter - (uint64_t)(-delta) : counter + (uint64_t)delta;
        if (emtask_panel_totp_code(secret, secret_len, candidate, global->panel_otp_digits, expected) == SSH_OK &&
            emtask_panel_constant_time_equal(expected, otp)) {
            memset(secret, 0, sizeof(secret));
            return 1;
        }
    }
    memset(secret, 0, sizeof(secret));
    return 0;
}

static int emtask_panel_verify_request_auth(const emtask_global_config_t *global, const char *request, const char *query)
{
    char token[EMTASK_MAX_TEXT];
    char otp[64];
    char header[EMTASK_MAX_TEXT];
    int token_ok;
    int otp_ok;

    if (global == NULL) {
        return 0;
    }
    if (global->panel_auth == 0u) {
        return 1;
    }

    token_ok = (global->panel_auth & EMTASK_PANEL_AUTH_TOKEN) == 0u;
    otp_ok = (global->panel_auth & EMTASK_PANEL_AUTH_OTP) == 0u;
    token[0] = '\0';
    otp[0] = '\0';
    header[0] = '\0';

    if (!token_ok) {
        if (emtask_panel_header_value(request, "Authorization", header, sizeof(header))) {
            if (emtask_panel_prefix_equals_nocase(header, "Bearer ")) {
                (void)emtask_copy_text(token, sizeof(token), header + strlen("Bearer "));
                emtask_panel_trim_ascii(token);
            }
        }
        if (token[0] == '\0') {
            (void)emtask_panel_header_value(request, "X-Panel-Token", token, sizeof(token));
        }
        if (token[0] == '\0') {
            (void)emtask_panel_query_value(query, "token", token, sizeof(token));
        }
        token_ok = emtask_panel_constant_time_equal(global->panel_token, token);
    }

    if (!otp_ok) {
        if (!emtask_panel_header_value(request, "X-Panel-OTP", otp, sizeof(otp))) {
            (void)emtask_panel_header_value(request, "X-OTP", otp, sizeof(otp));
        }
        if (otp[0] == '\0') {
            (void)emtask_panel_query_value(query, "otp", otp, sizeof(otp));
        }
        otp_ok = emtask_panel_verify_otp(global, otp);
    }

    memset(token, 0, sizeof(token));
    memset(otp, 0, sizeof(otp));
    memset(header, 0, sizeof(header));
    return token_ok && otp_ok;
}

static int emtask_panel_send_all(uintptr_t socket_handle, const char *data, size_t len)
{
    size_t offset;

    if (data == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    offset = 0u;
    while (offset < len) {
        size_t chunk = len - offset;
        int n;

        if (chunk > 16384u) {
            chunk = 16384u;
        }
        switch (emtask_wait_for_socket(socket_handle, 1, 5000u)) {
        case 0:
            return SSH_ERR_PLATFORM;
        case -1:
            return SSH_ERR_PLATFORM;
        default:
            break;
        }
        n = emtask_platform_net_send(socket_handle, (const uint8_t *)data + offset, chunk);
        if (n <= 0) {
            return SSH_ERR_PLATFORM;
        }
        offset += (size_t)n;
    }
    return SSH_OK;
}

static int emtask_panel_send_response(
    uintptr_t socket_handle,
    int code,
    const char *status_text,
    const char *content_type,
    const char *body)
{
    char header[512];
    size_t body_len;
    int written;
    int status;

    if (status_text == NULL || content_type == NULL || body == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    body_len = strlen(body);
    written = snprintf(
        header,
        sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %u\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-store\r\n"
        "\r\n",
        code,
        status_text,
        content_type,
        (unsigned)body_len);
    if (written < 0 || (size_t)written >= sizeof(header)) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    status = emtask_panel_send_all(socket_handle, header, (size_t)written);
    if (status != SSH_OK) {
        return status;
    }
    return emtask_panel_send_all(socket_handle, body, body_len);
}

static char *emtask_panel_find_header_end(char *request, size_t request_len, size_t *header_bytes_out)
{
    char *end;

    if (request == NULL || header_bytes_out == NULL) {
        return NULL;
    }
    end = strstr(request, "\r\n\r\n");
    if (end != NULL) {
        *header_bytes_out = (size_t)(end - request) + 4u;
        return request + *header_bytes_out;
    }
    end = strstr(request, "\n\n");
    if (end != NULL) {
        *header_bytes_out = (size_t)(end - request) + 2u;
        return request + *header_bytes_out;
    }
    (void)request_len;
    return NULL;
}

static int emtask_panel_content_length(const char *request, size_t *length_out)
{
    char header[64];
    unsigned length;

    if (request == NULL || length_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    *length_out = 0u;
    if (!emtask_panel_header_value(request, "Content-Length", header, sizeof(header))) {
        return SSH_OK;
    }
    if (emtask_parse_unsigned(header, &length) != SSH_OK) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    *length_out = (size_t)length;
    return SSH_OK;
}

static int emtask_panel_read_http_request(
    uintptr_t socket_handle,
    char *request,
    size_t request_capacity,
    char **body_out,
    size_t *body_len_out)
{
    size_t request_len;
    size_t header_bytes;
    size_t content_length;
    char *body;
    int status;

    if (request == NULL || request_capacity < 2u || body_out == NULL || body_len_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    request_len = 0u;
    header_bytes = 0u;
    content_length = 0u;
    body = NULL;
    request[0] = '\0';
    *body_out = NULL;
    *body_len_out = 0u;

    for (;;) {
        int n;

        switch (emtask_wait_for_socket(socket_handle, 0, 5000u)) {
        case 0:
            return SSH_ERR_PLATFORM;
        case -1:
            return SSH_ERR_PLATFORM;
        default:
            break;
        }
        if (request_len + 1u >= request_capacity) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        n = emtask_platform_net_recv(socket_handle, (uint8_t *)request + request_len, request_capacity - request_len - 1u);
        if (n <= 0) {
            return SSH_ERR_PLATFORM;
        }
        request_len += (size_t)n;
        request[request_len] = '\0';

        body = emtask_panel_find_header_end(request, request_len, &header_bytes);
        if (body == NULL) {
            continue;
        }
        status = emtask_panel_content_length(request, &content_length);
        if (status != SSH_OK) {
            return status;
        }
        if (content_length > 32768u) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        if (request_len >= header_bytes + content_length) {
            body[content_length] = '\0';
            *body_out = body;
            *body_len_out = content_length;
            return SSH_OK;
        }
    }
}

static void emtask_panel_append_task_json(emtask_panel_buffer_t *json, emtask_task_t *task)
{
    int session_active;
    int term_initialized;
    int term_running;
    int term_attached;
    int term_faulted;
    int term_exited;
    int term_started_once;
    uint32_t last_exit_status;
    int last_error_status;
    uint32_t cols;
    uint32_t rows;
    uint32_t screen_cols;
    uint32_t screen_rows;
    size_t replay_len;
    size_t replay_capacity;
    uint64_t last_error_ms;
    char last_error[EMTASK_MAX_TEXT];
    const char *task_status;
    const char *task_status_message;

    if (json == NULL || task == NULL) {
        return;
    }

    session_active = 0;
    emtask_mutex_lock(&task->session_manager.lock);
    session_active = task->session_manager.active_worker != NULL;
    emtask_mutex_unlock(&task->session_manager.lock);

    term_initialized = 0;
    term_running = 0;
    term_attached = 0;
    term_faulted = 0;
    term_exited = 0;
    term_started_once = 0;
    last_exit_status = 0u;
    last_error_status = 0u;
    cols = 0u;
    rows = 0u;
    screen_cols = 0u;
    screen_rows = 0u;
    replay_len = 0u;
    replay_capacity = 0u;
    last_error_ms = 0u;
    last_error[0] = '\0';
    emtask_mutex_lock(&task->term.lock);
    term_initialized = task->term.initialized;
    term_running = task->term.running;
    term_attached = task->term.attached;
    term_faulted = task->term.faulted;
    term_exited = task->term.exited;
    term_started_once = task->term.started_once;
    last_exit_status = task->term.last_exit_status;
    last_error_status = task->term.last_error_status;
    last_error_ms = task->term.last_error_ms;
    (void)snprintf(last_error, sizeof(last_error), "%s", task->term.last_error);
    cols = task->term.cols;
    rows = task->term.rows;
    screen_cols = task->term.screen_cols;
    screen_rows = task->term.screen_rows;
    replay_len = task->term.replay_len;
    replay_capacity = task->term.replay_capacity;
    emtask_mutex_unlock(&task->term.lock);

    if (term_faulted) {
        task_status = "failed";
        task_status_message = "task command failed; rerun is required";
    } else if (term_running) {
        task_status = "running";
        task_status_message = "task command is running";
    } else if (term_exited) {
        task_status = "exited";
        task_status_message = "task command exited";
    } else if (term_initialized && !term_started_once) {
        task_status = "pending";
        task_status_message = "task command has not started yet";
    } else {
        task_status = "stopped";
        task_status_message = "task command is stopped";
    }

    emtask_panel_appendf(json, "{");
    emtask_panel_appendf(json, "\"name\":");
    emtask_panel_append_json_string(json, task->config.name);
    emtask_panel_appendf(json, ",\"listen_address\":");
    emtask_panel_append_json_string(json, task->config.listen_address[0] != '\0' ? task->config.listen_address : "0.0.0.0");
    emtask_panel_appendf(json, ",\"port\":%u", (unsigned)task->config.port);
    emtask_panel_appendf(json, ",\"command\":");
    emtask_panel_append_json_string(json, task->config.command);
    emtask_panel_appendf(json, ",\"working_dir\":");
    emtask_panel_append_json_string(json, task->config.working_dir);
    emtask_panel_appendf(json, ",\"use_sftp\":%s", task->config.use_sftp ? "true" : "false");
    emtask_panel_appendf(json, ",\"use_conpty\":%s", task->config.use_conpty ? "true" : "false");
    emtask_panel_appendf(json, ",\"restart_limit\":%u", task->config.restart_limit);
    emtask_panel_appendf(json, ",\"restart_window_sec\":%u", task->config.restart_window_sec);
    emtask_panel_appendf(json, ",\"listener_open\":%s", task->listener_open ? "true" : "false");
    emtask_panel_appendf(json, ",\"status\":");
    emtask_panel_append_json_string(json, task_status);
    emtask_panel_appendf(json, ",\"status_message\":");
    emtask_panel_append_json_string(json, task_status_message);
    emtask_panel_appendf(json, ",\"session\":{\"terminal_active\":%s}", session_active ? "true" : "false");
    emtask_panel_appendf(
        json,
        ",\"terminal\":{\"initialized\":%s,\"running\":%s,\"attached\":%s,\"faulted\":%s,\"exited\":%s,\"started_once\":%s,\"last_exit_status\":%u,\"last_error_status\":%d,\"last_error_ms\":%llu,\"cols\":%u,\"rows\":%u,\"screen_cols\":%u,\"screen_rows\":%u,\"replay_len\":%u,\"replay_capacity\":%u,\"last_error\":",
        term_initialized ? "true" : "false",
        term_running ? "true" : "false",
        term_attached ? "true" : "false",
        term_faulted ? "true" : "false",
        term_exited ? "true" : "false",
        term_started_once ? "true" : "false",
        (unsigned)last_exit_status,
        last_error_status,
        (unsigned long long)last_error_ms,
        (unsigned)cols,
        (unsigned)rows,
        (unsigned)screen_cols,
        (unsigned)screen_rows,
        (unsigned)replay_len,
        (unsigned)replay_capacity);
    emtask_panel_append_json_string(json, last_error);
    emtask_panel_appendf(json, "}");
    emtask_panel_appendf(json, "}");
}

static const char *emtask_json_skip_ws(const char *p)
{
    while (p != NULL && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) {
        ++p;
    }
    return p;
}

static const char *emtask_json_find_member_value(const char *json, const char *key)
{
    size_t key_len;
    const char *p;

    if (json == NULL || key == NULL || key[0] == '\0') {
        return NULL;
    }
    key_len = strlen(key);
    p = json;
    while ((p = strchr(p, '"')) != NULL) {
        if (strncmp(p + 1, key, key_len) == 0 && p[1 + key_len] == '"') {
            const char *q = emtask_json_skip_ws(p + 2 + key_len);
            if (q != NULL && *q == ':') {
                return emtask_json_skip_ws(q + 1);
            }
        }
        ++p;
    }
    return NULL;
}

static int emtask_json_read_string_value(const char *value, char *out, size_t out_capacity)
{
    size_t out_len;
    const char *p;

    if (value == NULL || out == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    p = emtask_json_skip_ws(value);
    if (p == NULL || *p != '"') {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    ++p;
    out_len = 0u;
    while (*p != '\0' && *p != '"') {
        unsigned char ch = (unsigned char)*p++;
        if (ch == '\\') {
            ch = (unsigned char)*p++;
            switch (ch) {
            case '"':
            case '\\':
            case '/':
                break;
            case 'b':
                ch = '\b';
                break;
            case 'f':
                ch = '\f';
                break;
            case 'n':
                ch = '\n';
                break;
            case 'r':
                ch = '\r';
                break;
            case 't':
                ch = '\t';
                break;
            default:
                return SSH_ERR_INVALID_ARGUMENT;
            }
        }
        if (out_len + 1u >= out_capacity) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        out[out_len++] = (char)ch;
    }
    if (*p != '"') {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    out[out_len] = '\0';
    return SSH_OK;
}

static int emtask_json_get_string(const char *json, const char *key, char *out, size_t out_capacity, int required)
{
    const char *value;

    if (out != NULL && out_capacity != 0u) {
        out[0] = '\0';
    }
    value = emtask_json_find_member_value(json, key);
    if (value == NULL) {
        return required ? SSH_ERR_INVALID_ARGUMENT : SSH_OK;
    }
    return emtask_json_read_string_value(value, out, out_capacity);
}

static int emtask_json_get_uint(const char *json, const char *key, unsigned *out, int required)
{
    const char *value;
    char text[64];
    char *end;
    unsigned long parsed;

    if (out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    value = emtask_json_find_member_value(json, key);
    if (value == NULL) {
        return required ? SSH_ERR_INVALID_ARGUMENT : SSH_OK;
    }
    value = emtask_json_skip_ws(value);
    if (value == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (*value == '"') {
        int status = emtask_json_read_string_value(value, text, sizeof(text));
        if (status != SSH_OK) {
            return status;
        }
        value = text;
    }
    parsed = strtoul(value, &end, 10);
    if (end == value || parsed > 100000000ul) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    *out = (unsigned)parsed;
    return SSH_OK;
}

static int emtask_json_get_bool(const char *json, const char *key, int *out, int required)
{
    const char *value;
    char text[16];

    if (out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    value = emtask_json_find_member_value(json, key);
    if (value == NULL) {
        return required ? SSH_ERR_INVALID_ARGUMENT : SSH_OK;
    }
    value = emtask_json_skip_ws(value);
    if (value == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (*value == '"') {
        int status = emtask_json_read_string_value(value, text, sizeof(text));
        if (status != SSH_OK) {
            return status;
        }
        return emtask_parse_bool(text, out);
    }
    if (strncmp(value, "true", 4u) == 0) {
        *out = 1;
        return SSH_OK;
    }
    if (strncmp(value, "false", 5u) == 0) {
        *out = 0;
        return SSH_OK;
    }
    if (*value == '1' || *value == '0') {
        *out = *value == '1';
        return SSH_OK;
    }
    return SSH_ERR_INVALID_ARGUMENT;
}

static int emtask_json_has_member(const char *json, const char *key)
{
    return emtask_json_find_member_value(json, key) != NULL;
}

static int emtask_json_parse_task(const emtask_app_t *app, const char *json, emtask_task_config_t *task)
{
    unsigned value;
    int flag;
    int status;

    if (app == NULL || json == NULL || task == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    emtask_task_config_defaults(task);
    task->use_conpty = app->config.global.use_conpty;
    status = emtask_json_get_string(json, "name", task->name, sizeof(task->name), 1);
    if (status != SSH_OK) {
        return status;
    }
    status = emtask_json_get_string(json, "command", task->command, sizeof(task->command), 1);
    if (status != SSH_OK) {
        return status;
    }
    status = emtask_json_get_uint(json, "port", &value, 1);
    if (status != SSH_OK || value == 0u || value > 65535u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    task->port = (uint16_t)value;
    status = emtask_json_get_string(json, "listen_address", task->listen_address, sizeof(task->listen_address), 0);
    if (status != SSH_OK) {
        return status;
    }
    status = emtask_json_get_string(json, "working_dir", task->working_dir, sizeof(task->working_dir), 0);
    if (status != SSH_OK) {
        return status;
    }
    if (task->working_dir[0] == '\0') {
        status = emtask_copy_text(task->working_dir, sizeof(task->working_dir), ".");
        if (status != SSH_OK) {
            return status;
        }
    }
    flag = task->use_sftp;
    status = emtask_json_get_bool(json, "use_sftp", &flag, 0);
    if (status != SSH_OK) {
        return status;
    }
    task->use_sftp = flag;
    flag = task->use_conpty;
    status = emtask_json_get_bool(json, "use_conpty", &flag, 0);
    if (status != SSH_OK) {
        return status;
    }
    task->use_conpty = flag;

    value = task->restart_limit;
    status = emtask_json_get_uint(json, "restart_limit", &value, 0);
    if (status != SSH_OK) {
        return status;
    }
    task->restart_limit = value;
    value = task->restart_window_sec;
    status = emtask_json_get_uint(json, "restart_window_sec", &value, 0);
    if (status != SSH_OK) {
        return status;
    }
    task->restart_window_sec = value;
    value = (unsigned)task->replay_buffer_bytes;
    status = emtask_json_get_uint(json, "replay_buffer_bytes", &value, 0);
    if (status != SSH_OK) {
        return status;
    }
    task->replay_buffer_bytes = (size_t)value;

    flag = task->replay_on_attach;
    status = emtask_json_get_bool(json, "replay_on_attach", &flag, 0);
    if (status != SSH_OK) {
        return status;
    }
    task->replay_on_attach = flag;
    flag = task->repaint_on_attach;
    status = emtask_json_get_bool(json, "repaint_on_attach", &flag, 0);
    if (status != SSH_OK) {
        return status;
    }
    task->repaint_on_attach = flag;
    flag = task->screen_snapshot;
    status = emtask_json_get_bool(json, "screen_snapshot", &flag, 0);
    if (status != SSH_OK) {
        return status;
    }
    task->screen_snapshot = flag;
    return SSH_OK;
}

static int emtask_json_patch_task(const emtask_app_t *app, const char *json, const emtask_task_config_t *base, emtask_task_config_t *task)
{
    unsigned value;
    int flag;
    int changed;
    int status;

    if (app == NULL || json == NULL || base == NULL || task == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    *task = *base;
    changed = 0;

    if (emtask_json_has_member(json, "name")) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (emtask_json_has_member(json, "command")) {
        status = emtask_json_get_string(json, "command", task->command, sizeof(task->command), 1);
        if (status != SSH_OK || task->command[0] == '\0') {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        changed = 1;
    }
    if (emtask_json_has_member(json, "port")) {
        status = emtask_json_get_uint(json, "port", &value, 1);
        if (status != SSH_OK || value == 0u || value > 65535u) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        task->port = (uint16_t)value;
        changed = 1;
    }
    if (emtask_json_has_member(json, "listen_address")) {
        status = emtask_json_get_string(json, "listen_address", task->listen_address, sizeof(task->listen_address), 0);
        if (status != SSH_OK) {
            return status;
        }
        changed = 1;
    }
    if (emtask_json_has_member(json, "working_dir")) {
        status = emtask_json_get_string(json, "working_dir", task->working_dir, sizeof(task->working_dir), 0);
        if (status != SSH_OK) {
            return status;
        }
        if (task->working_dir[0] == '\0') {
            status = emtask_copy_text(task->working_dir, sizeof(task->working_dir), ".");
            if (status != SSH_OK) {
                return status;
            }
        }
        changed = 1;
    }
    if (emtask_json_has_member(json, "use_sftp")) {
        flag = task->use_sftp;
        status = emtask_json_get_bool(json, "use_sftp", &flag, 0);
        if (status != SSH_OK) {
            return status;
        }
        task->use_sftp = flag;
        changed = 1;
    }
    if (emtask_json_has_member(json, "use_conpty")) {
        flag = task->use_conpty;
        status = emtask_json_get_bool(json, "use_conpty", &flag, 0);
        if (status != SSH_OK) {
            return status;
        }
        task->use_conpty = flag;
        changed = 1;
    }
    return changed ? SSH_OK : SSH_ERR_INVALID_ARGUMENT;
}

static int emtask_task_conflicts_with_panel(const emtask_global_config_t *global, const emtask_task_config_t *task)
{
    const char *task_addr;
    const char *panel_addr;

    if (global == NULL || task == NULL || !global->panel_enabled || task->port != global->panel_port) {
        return 0;
    }
    task_addr = task->listen_address[0] != '\0' ? task->listen_address : "0.0.0.0";
    panel_addr = global->panel_listen_address[0] != '\0' ? global->panel_listen_address : EMTASK_DEFAULT_PANEL_LISTEN_ADDRESS;
    return emtask_key_equals(task_addr, panel_addr) ||
           emtask_key_equals(task_addr, "0.0.0.0") ||
           emtask_key_equals(panel_addr, "0.0.0.0") ||
           emtask_key_equals(task_addr, "::") ||
           emtask_key_equals(panel_addr, "::");
}

static int emtask_validate_new_task_locked(const emtask_app_t *app, const emtask_task_config_t *task)
{
    size_t free_index;
    size_t i;

    if (app == NULL || task == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (task->name[0] == '\0' || task->command[0] == '\0' || task->port == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    free_index = EMTASK_MAX_TASKS;
    for (i = 0u; i < app->task_capacity && i < EMTASK_MAX_TASKS; ++i) {
        if (!app->tasks[i].initialized && !app->tasks[i].listener_thread_running) {
            free_index = i;
            break;
        }
    }
    if (free_index == EMTASK_MAX_TASKS) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    if (emtask_task_conflicts_with_panel(&app->config.global, task)) {
        return SSH_ERR_ALREADY_EXISTS;
    }
    for (i = 0u; i < app->task_count; ++i) {
        if (!app->tasks[i].initialized || app->tasks[i].deleted) {
            continue;
        }
        if (emtask_key_equals(app->tasks[i].config.name, task->name) || app->tasks[i].config.port == task->port) {
            return SSH_ERR_ALREADY_EXISTS;
        }
    }
    return SSH_OK;
}

static int emtask_validate_updated_task_locked(const emtask_app_t *app, const emtask_task_config_t *task, size_t current_index)
{
    size_t i;

    if (app == NULL || task == NULL || current_index >= app->task_count) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (task->name[0] == '\0' || task->command[0] == '\0' || task->port == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (emtask_task_conflicts_with_panel(&app->config.global, task)) {
        return SSH_ERR_ALREADY_EXISTS;
    }
    for (i = 0u; i < app->task_count; ++i) {
        if (i == current_index || !app->tasks[i].initialized || app->tasks[i].deleted) {
            continue;
        }
        if (emtask_key_equals(app->tasks[i].config.name, task->name) || app->tasks[i].config.port == task->port) {
            return SSH_ERR_ALREADY_EXISTS;
        }
    }
    return SSH_OK;
}

static void emtask_panel_write_error_json(char *out, size_t out_capacity, const char *error, const char *message, const char *db_file)
{
    emtask_panel_buffer_t response;

    if (out == NULL || out_capacity == 0u || error == NULL) {
        return;
    }
    emtask_panel_buffer_init(&response, out, out_capacity);
    emtask_panel_appendf(&response, "{\"error\":");
    emtask_panel_append_json_string(&response, error);
    if (message != NULL && message[0] != '\0') {
        emtask_panel_appendf(&response, ",\"message\":");
        emtask_panel_append_json_string(&response, message);
    }
    if (db_file != NULL && db_file[0] != '\0') {
        emtask_panel_appendf(&response, ",\"db_file\":");
        emtask_panel_append_json_string(&response, db_file);
    }
    emtask_panel_appendf(&response, "}\n");
}

static int emtask_panel_register_authorized_key_from_json(emtask_app_t *app, const char *json, char *out, size_t out_capacity)
{
    emtask_panel_buffer_t response;
    char public_key_line[1024];
    uint8_t blob[EMSSH_MAX_HOST_KEY_BLOB];
    size_t blob_len;
    int matched;
    int status;

    if (app == NULL || json == NULL || out == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    out[0] = '\0';
    if (app->config.global.username[0] == '\0') {
        return SSH_ERR_UNSUPPORTED;
    }
    if (app->config.global.authorized_keys_file[0] == '\0') {
        return SSH_ERR_READ_ONLY;
    }
    status = emtask_json_get_string(json, "public_key", public_key_line, sizeof(public_key_line), 1);
    if (status != SSH_OK) {
        return status;
    }
    (void)emtask_trim(public_key_line);
    status = emtask_parse_authorized_key_line(public_key_line, blob, sizeof(blob), &blob_len);
    if (status != SSH_OK) {
        return status;
    }
    matched = 0;
    status = emtask_authorized_keys_has_blob(app->config.global.authorized_keys_file, blob, blob_len, &matched);
    if (status != SSH_OK) {
        return status;
    }
    if (!matched) {
        status = emtask_authorized_keys_append_line(app->config.global.authorized_keys_file, public_key_line);
        if (status != SSH_OK) {
            return status;
        }
    }

    emtask_panel_buffer_init(&response, out, out_capacity);
    emtask_panel_appendf(
        &response,
        "{\"registered\":%s,\"already_present\":%s,\"username\":",
        matched ? "false" : "true",
        matched ? "true" : "false");
    emtask_panel_append_json_string(&response, app->config.global.username);
    emtask_panel_appendf(&response, ",\"authorized_keys_file\":");
    emtask_panel_append_json_string(&response, app->config.global.authorized_keys_file);
    emtask_panel_appendf(&response, "}\n");
    return response.truncated ? SSH_ERR_BUFFER_TOO_SMALL : SSH_OK;
}

static int emtask_panel_create_task_from_json(emtask_app_t *app, const char *json, char *out, size_t out_capacity)
{
    emtask_panel_buffer_t response;
    emtask_task_config_t config;
    emtask_task_config_t runtime_config;
    emtask_task_t *task;
    emtask_task_t *new_task;
    size_t index;
    size_t free_index;
    size_t i;
    int status;

    if (app == NULL || json == NULL || out == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    status = emtask_json_parse_task(app, json, &config);
    if (status != SSH_OK) {
        return status;
    }
    runtime_config = config;
    status = emtask_resolve_path(app->config.global.config_dir, runtime_config.working_dir, runtime_config.working_dir);
    if (status != SSH_OK) {
        return status;
    }

    if (!app->task_lock_initialized) {
        return SSH_ERR_PLATFORM;
    }
    emtask_mutex_lock(&app->task_lock);
    status = emtask_validate_new_task_locked(app, &runtime_config);
    if (status != SSH_OK) {
        emtask_mutex_unlock(&app->task_lock);
        return status;
    }
    status = emtask_panel_tasks_db_insert(&app->config.global, &config);
    if (status != SSH_OK) {
        const char *error = "task_store_unavailable";
        const char *message = "SQLite task database could not be opened or written; check panel_tasks_db_file and directory permissions.";
        if (status == SSH_ERR_NOT_FOUND) {
            error = "sqlite_runtime_missing";
            message = "SQLite runtime not found; place sqlite3.dll/libsqlite3.so in the emtask current directory or install SQLite system-wide.";
        } else if (status == SSH_ERR_UNSUPPORTED) {
            error = "sqlite_runtime_incompatible";
            message = "SQLite runtime is incompatible; missing required sqlite3 symbols.";
        }
        emtask_logf("dynamic task store unavailable while adding %s: %s (db=%s)", config.name, message, app->config.global.panel_tasks_db_file);
        emtask_panel_write_error_json(out, out_capacity, error, message, app->config.global.panel_tasks_db_file);
        emtask_mutex_unlock(&app->task_lock);
        return status;
    }
    index = EMTASK_MAX_TASKS;
    for (i = 0u; i < app->task_capacity && i < EMTASK_MAX_TASKS; ++i) {
        if (!app->tasks[i].initialized && !app->tasks[i].listener_thread_running) {
            index = i;
            break;
        }
    }
    if (index == EMTASK_MAX_TASKS) {
        (void)emtask_panel_tasks_db_delete(&app->config.global, config.name);
        emtask_mutex_unlock(&app->task_lock);
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    task = &app->tasks[index];
    status = emtask_task_init(app, task, &runtime_config);
    if (status != SSH_OK) {
        (void)emtask_panel_tasks_db_delete(&app->config.global, config.name);
        emtask_mutex_unlock(&app->task_lock);
        return status;
    }
    task->listener_thread_running = 1;
    status = emtask_platform_start_listener_thread(task);
    if (status != SSH_OK) {
        task->listener_thread_running = 0;
        emtask_task_deinit(app, task);
        (void)emtask_panel_tasks_db_delete(&app->config.global, config.name);
        emtask_mutex_unlock(&app->task_lock);
        return status;
    }
    app->config.tasks[index] = runtime_config;
    if (app->config.task_count < index + 1u) {
        app->config.task_count = index + 1u;
    }
    if (app->task_count < index + 1u) {
        app->task_count = index + 1u;
    }

    emtask_panel_buffer_init(&response, out, out_capacity);
    emtask_panel_appendf(&response, "{\"task\":");
    emtask_panel_append_task_json(&response, task);
    emtask_panel_appendf(&response, "}\n");
    emtask_mutex_unlock(&app->task_lock);
    return response.truncated ? SSH_ERR_BUFFER_TOO_SMALL : SSH_OK;
}

static int emtask_panel_update_task_from_json(emtask_app_t *app, const char *task_name, const char *json, char *out, size_t out_capacity)
{
    emtask_panel_buffer_t response;
    emtask_task_config_t config;
    emtask_task_config_t runtime_config;
    emtask_task_t *task;
    emtask_task_t *new_task;
    size_t index;
    size_t free_index;
    size_t i;
    int status;

    if (app == NULL || task_name == NULL || task_name[0] == '\0' || json == NULL || out == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (!app->task_lock_initialized) {
        return SSH_ERR_PLATFORM;
    }

    emtask_mutex_lock(&app->task_lock);
    task = NULL;
    index = EMTASK_MAX_TASKS;
    free_index = EMTASK_MAX_TASKS;
    for (i = 0u; i < app->task_count; ++i) {
        if (app->tasks[i].initialized && !app->tasks[i].deleted && emtask_key_equals(app->tasks[i].config.name, task_name)) {
            task = &app->tasks[i];
            index = i;
            break;
        }
    }
    if (task == NULL) {
        emtask_mutex_unlock(&app->task_lock);
        return SSH_ERR_NOT_FOUND;
    }
    if (task->worker_count != 0u) {
        emtask_mutex_unlock(&app->task_lock);
        return SSH_ERR_READ_ONLY;
    }
    for (i = 0u; i < app->task_capacity && i < EMTASK_MAX_TASKS; ++i) {
        if (i != index && !app->tasks[i].initialized && !app->tasks[i].listener_thread_running) {
            free_index = i;
            break;
        }
    }
    if (free_index == EMTASK_MAX_TASKS) {
        emtask_mutex_unlock(&app->task_lock);
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    status = emtask_json_patch_task(app, json, &task->config, &config);
    if (status != SSH_OK) {
        emtask_mutex_unlock(&app->task_lock);
        return status;
    }
    runtime_config = config;
    status = emtask_resolve_path(app->config.global.config_dir, runtime_config.working_dir, runtime_config.working_dir);
    if (status == SSH_OK) {
        status = emtask_validate_updated_task_locked(app, &runtime_config, index);
    }
    if (status != SSH_OK) {
        emtask_mutex_unlock(&app->task_lock);
        return status;
    }
    status = emtask_panel_tasks_db_update(&app->config.global, task_name, &config);
    if (status != SSH_OK) {
        emtask_mutex_unlock(&app->task_lock);
        return status;
    }

    task->deleted = 1;
    task->stop_requested = 1;
    emtask_task_deinit(app, task);
    memset(&app->config.tasks[index], 0, sizeof(app->config.tasks[index]));

    new_task = &app->tasks[free_index];
    status = emtask_task_init(app, new_task, &runtime_config);
    if (status != SSH_OK) {
        emtask_mutex_unlock(&app->task_lock);
        return status;
    }
    new_task->listener_thread_running = 1;
    status = emtask_platform_start_listener_thread(new_task);
    if (status != SSH_OK) {
        new_task->listener_thread_running = 0;
        emtask_task_deinit(app, new_task);
        emtask_mutex_unlock(&app->task_lock);
        return status;
    }
    app->config.tasks[free_index] = runtime_config;
    if (app->config.task_count < free_index + 1u) {
        app->config.task_count = free_index + 1u;
    }
    if (app->task_count < free_index + 1u) {
        app->task_count = free_index + 1u;
    }

    emtask_panel_buffer_init(&response, out, out_capacity);
    emtask_panel_appendf(&response, "{\"task\":");
    emtask_panel_append_task_json(&response, new_task);
    emtask_panel_appendf(&response, "}\n");
    emtask_logf("dynamic task %s updated from panel store", task_name);
    emtask_mutex_unlock(&app->task_lock);
    return response.truncated ? SSH_ERR_BUFFER_TOO_SMALL : SSH_OK;
}

static size_t emtask_active_task_count_locked(const emtask_app_t *app)
{
    size_t count;
    size_t i;

    if (app == NULL) {
        return 0u;
    }
    count = 0u;
    for (i = 0u; i < app->task_count; ++i) {
        if (app->tasks[i].initialized && !app->tasks[i].deleted) {
            ++count;
        }
    }
    return count;
}

static int emtask_panel_delete_task_by_name(emtask_app_t *app, const char *task_name, char *out, size_t out_capacity)
{
    emtask_panel_buffer_t response;
    emtask_task_t *task;
    size_t index;
    size_t i;
    int status;

    if (app == NULL || task_name == NULL || task_name[0] == '\0' || out == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (!app->task_lock_initialized) {
        return SSH_ERR_PLATFORM;
    }

    emtask_mutex_lock(&app->task_lock);
    task = NULL;
    index = EMTASK_MAX_TASKS;
    for (i = 0u; i < app->task_count; ++i) {
        if (app->tasks[i].initialized && !app->tasks[i].deleted && emtask_key_equals(app->tasks[i].config.name, task_name)) {
            task = &app->tasks[i];
            index = i;
            break;
        }
    }
    if (task == NULL) {
        emtask_mutex_unlock(&app->task_lock);
        return SSH_ERR_NOT_FOUND;
    }
    if (task->worker_count != 0u) {
        emtask_mutex_unlock(&app->task_lock);
        return SSH_ERR_READ_ONLY;
    }

    status = emtask_panel_tasks_db_delete(&app->config.global, task_name);
    if (status != SSH_OK) {
        emtask_mutex_unlock(&app->task_lock);
        return status;
    }

    task->deleted = 1;
    task->stop_requested = 1;
    emtask_task_deinit(app, task);
    memset(&app->config.tasks[index], 0, sizeof(app->config.tasks[index]));

    emtask_panel_buffer_init(&response, out, out_capacity);
    emtask_panel_appendf(&response, "{\"deleted\":true,\"task\":");
    emtask_panel_append_json_string(&response, task_name);
    emtask_panel_appendf(&response, "}\n");
    emtask_logf("dynamic task %s deleted from panel store", task_name);
    emtask_mutex_unlock(&app->task_lock);
    return response.truncated ? SSH_ERR_BUFFER_TOO_SMALL : SSH_OK;
}

static int emtask_panel_restart_task_by_name(emtask_app_t *app, const char *task_name, char *out, size_t out_capacity)
{
    emtask_panel_buffer_t response;
    emtask_task_t *task;
    size_t i;
    int restart_status;

    if (app == NULL || task_name == NULL || task_name[0] == '\0' || out == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (!app->task_lock_initialized) {
        return SSH_ERR_PLATFORM;
    }

    emtask_mutex_lock(&app->task_lock);
    task = NULL;
    for (i = 0u; i < app->task_count; ++i) {
        if (app->tasks[i].initialized && !app->tasks[i].deleted && emtask_key_equals(app->tasks[i].config.name, task_name)) {
            task = &app->tasks[i];
            break;
        }
    }
    if (task == NULL) {
        emtask_mutex_unlock(&app->task_lock);
        return SSH_ERR_NOT_FOUND;
    }
    if (task->worker_count != 0u) {
        emtask_mutex_unlock(&app->task_lock);
        return SSH_ERR_READ_ONLY;
    }

    restart_status = emtask_term_restart_manual(&task->term);
    if (restart_status == SSH_OK) {
        emtask_logf("dynamic task %s rerun requested from panel", task_name);
    } else {
        emtask_logf("dynamic task %s rerun failed from panel: %s", task_name, ssh_status_string(restart_status));
    }

    emtask_panel_buffer_init(&response, out, out_capacity);
    emtask_panel_appendf(&response, "{\"rerun\":%s,\"restart_status\":", restart_status == SSH_OK ? "true" : "false");
    emtask_panel_append_json_string(&response, ssh_status_string(restart_status));
    emtask_panel_appendf(&response, ",\"task\":");
    emtask_panel_append_task_json(&response, task);
    emtask_panel_appendf(&response, "}\n");
    emtask_mutex_unlock(&app->task_lock);
    return response.truncated ? SSH_ERR_BUFFER_TOO_SMALL : SSH_OK;
}

static int emtask_panel_build_status_json(emtask_app_t *app, int tasks_only, char *out, size_t out_capacity)
{
    emtask_panel_buffer_t json;
    unsigned pool_active;
    unsigned pool_max;
    uint64_t now_ms;
    uint64_t uptime_ms;
    size_t i;
    size_t emitted_tasks;
    int task_lock_held;

    if (app == NULL || out == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    emtask_panel_buffer_init(&json, out, out_capacity);
    emtask_mutex_lock(&app->pool.lock);
    pool_active = app->pool.active_workers;
    pool_max = app->pool.max_workers;
    emtask_mutex_unlock(&app->pool.lock);
    now_ms = emtask_platform_monotonic_ms();
    uptime_ms = app->started_ms != 0u && now_ms >= app->started_ms ? now_ms - app->started_ms : 0u;
    task_lock_held = 0;
    emitted_tasks = 0u;

    if (!tasks_only) {
        emtask_panel_appendf(&json, "{");
        emtask_panel_appendf(&json, "\"software\":\"emtask\"");
        emtask_panel_appendf(&json, ",\"status\":\"ok\"");
        emtask_panel_appendf(&json, ",\"uptime_ms\":%u", (unsigned)uptime_ms);
        emtask_panel_appendf(&json, ",\"config\":{\"path\":");
        emtask_panel_append_json_string(&json, app->config.global.config_path);
        emtask_panel_appendf(&json, ",\"dir\":");
        emtask_panel_append_json_string(&json, app->config.global.config_dir);
        emtask_panel_appendf(&json, ",\"auth_backend\":");
        emtask_panel_append_json_string(
            &json,
            app->config.global.auth_backend == EMTASK_AUTH_BACKEND_PASSWD ? "passwd" : "internal");
        emtask_panel_appendf(&json, ",\"username\":");
        emtask_panel_append_json_string(
            &json,
            app->config.global.username[0] != '\0' ? app->config.global.username : "<system>");
        emtask_panel_appendf(&json, ",\"hostkey_file\":");
        emtask_panel_append_json_string(&json, app->config.global.hostkey_file);
        emtask_panel_appendf(&json, ",\"authorized_keys_file\":");
        emtask_panel_append_json_string(&json, app->config.global.authorized_keys_file);
        emtask_panel_appendf(&json, ",\"timeout_ms\":%u", (unsigned)app->config.global.timeout_ms);
        emtask_panel_appendf(&json, "}");
        emtask_panel_appendf(
            &json,
            ",\"panel\":{\"enabled\":%s,\"listen_address\":",
            app->config.global.panel_enabled ? "true" : "false");
        emtask_panel_append_json_string(
            &json,
            app->config.global.panel_listen_address[0] != '\0'
                ? app->config.global.panel_listen_address
                : EMTASK_DEFAULT_PANEL_LISTEN_ADDRESS);
        emtask_panel_appendf(
            &json,
            ",\"port\":%u,\"listener_open\":%s,\"auth\":",
            (unsigned)app->config.global.panel_port,
            app->panel_listener_open ? "true" : "false");
        if (app->config.global.panel_auth == 0u) {
            emtask_panel_append_json_string(&json, "none");
        } else if (app->config.global.panel_auth == EMTASK_PANEL_AUTH_TOKEN) {
            emtask_panel_append_json_string(&json, "token");
        } else if (app->config.global.panel_auth == EMTASK_PANEL_AUTH_OTP) {
            emtask_panel_append_json_string(&json, "otp");
        } else {
            emtask_panel_append_json_string(&json, "token+otp");
        }
        emtask_panel_appendf(&json, ",\"auth_file\":");
        emtask_panel_append_json_string(&json, app->config.global.panel_auth_file);
        emtask_panel_appendf(&json, ",\"qr_file\":");
        emtask_panel_append_json_string(&json, app->config.global.panel_qr_file);
        emtask_panel_appendf(&json, ",\"qr_mode\":");
        if (app->config.global.panel_qr_mode == EMTASK_PANEL_QR_DISABLED) {
            emtask_panel_append_json_string(&json, "disabled");
        } else if (app->config.global.panel_qr_mode == EMTASK_PANEL_QR_IF_MISSING) {
            emtask_panel_append_json_string(&json, "if_missing");
        } else {
            emtask_panel_append_json_string(&json, "always");
        }
        emtask_panel_appendf(&json, ",\"qr_host\":");
        emtask_panel_append_json_string(&json, emtask_panel_qr_host(&app->config.global));
        emtask_panel_appendf(
            &json,
            ",\"otp_digits\":%u,\"otp_step_sec\":%u,\"otp_window\":%u}",
            app->config.global.panel_otp_digits,
            app->config.global.panel_otp_step_sec,
            app->config.global.panel_otp_window);
        emtask_panel_appendf(
            &json,
            ",\"worker_pool\":{\"max_workers\":%u,\"active_workers\":%u}",
            pool_max,
            pool_active);
        if (app->task_lock_initialized) {
            emtask_mutex_lock(&app->task_lock);
            task_lock_held = 1;
        }
        emtask_panel_appendf(&json, ",\"task_count\":%u", (unsigned)emtask_active_task_count_locked(app));
        emtask_panel_appendf(&json, ",\"tasks\":[");
    } else {
        if (app->task_lock_initialized) {
            emtask_mutex_lock(&app->task_lock);
            task_lock_held = 1;
        }
        emtask_panel_appendf(&json, "{\"tasks\":[");
    }
    for (i = 0u; i < app->task_count; ++i) {
        if (!app->tasks[i].initialized || app->tasks[i].deleted) {
            continue;
        }
        if (emitted_tasks != 0u) {
            emtask_panel_appendf(&json, ",");
        }
        emtask_panel_append_task_json(&json, &app->tasks[i]);
        ++emitted_tasks;
    }
    if (task_lock_held) {
        emtask_mutex_unlock(&app->task_lock);
    }
    emtask_panel_appendf(&json, "]}\n");
    if (json.truncated) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    return SSH_OK;
}

static int emtask_panel_handle_connection(emtask_app_t *app, ssh_tcp_conn_t *conn)
{
    char request[65536];
    char method[16];
    char target[512];
    char *path;
    char *query;
    char *request_body;
    char response_body[32768];
    size_t request_body_len;
    int status;
    uintptr_t socket_handle;

    if (app == NULL || conn == NULL || !conn->open) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    socket_handle = conn->socket_handle;
    request_body = NULL;
    request_body_len = 0u;
    response_body[0] = '\0';
    status = emtask_panel_read_http_request(socket_handle, request, sizeof(request), &request_body, &request_body_len);
    if (status == SSH_ERR_BUFFER_TOO_SMALL) {
        return emtask_panel_send_response(socket_handle, 413, "Payload Too Large", "application/json", "{\"error\":\"payload_too_large\"}\n");
    }
    if (status != SSH_OK) {
        return SSH_ERR_PLATFORM;
    }
    method[0] = '\0';
    target[0] = '\0';
    if (sscanf(request, "%15s %511s", method, target) != 2) {
        return emtask_panel_send_response(socket_handle, 400, "Bad Request", "application/json", "{\"error\":\"bad_request\"}\n");
    }
    path = target;
    query = strchr(target, '?');
    if (query != NULL) {
        *query = '\0';
        ++query;
    } else {
        query = "";
    }
    if (strcmp(method, "GET") != 0 && strcmp(method, "POST") != 0 && strcmp(method, "PATCH") != 0 && strcmp(method, "DELETE") != 0) {
        return emtask_panel_send_response(
            socket_handle,
            405,
            "Method Not Allowed",
            "application/json",
            "{\"error\":\"method_not_allowed\"}\n");
    }
    if (!emtask_panel_verify_request_auth(&app->config.global, request, query)) {
        return emtask_panel_send_response(
            socket_handle,
            401,
            "Unauthorized",
            "application/json",
            "{\"error\":\"unauthorized\"}\n");
    }
    if (strcmp(method, "POST") == 0) {
        if (strcmp(path, "/auth/authorized-keys") == 0 || strcmp(path, "/auth/public-keys") == 0) {
            if (request_body == NULL || request_body_len == 0u) {
                return emtask_panel_send_response(socket_handle, 400, "Bad Request", "application/json", "{\"error\":\"empty_body\"}\n");
            }
            status = emtask_panel_register_authorized_key_from_json(app, request_body, response_body, sizeof(response_body));
            if (status == SSH_OK) {
                return emtask_panel_send_response(socket_handle, 200, "OK", "application/json", response_body);
            }
            if (status == SSH_ERR_READ_ONLY) {
                return emtask_panel_send_response(socket_handle, 409, "Conflict", "application/json", "{\"error\":\"authorized_keys_not_configured\"}\n");
            }
            if (status == SSH_ERR_UNSUPPORTED) {
                return emtask_panel_send_response(socket_handle, 409, "Conflict", "application/json", "{\"error\":\"publickey_auth_unavailable\"}\n");
            }
            if (status == SSH_ERR_INVALID_ARGUMENT || status == SSH_ERR_MALFORMED_PACKET || status == SSH_ERR_BUFFER_TOO_SMALL) {
                return emtask_panel_send_response(socket_handle, 400, "Bad Request", "application/json", "{\"error\":\"invalid_public_key\"}\n");
            }
            return emtask_panel_send_response(socket_handle, 500, "Internal Server Error", "application/json", "{\"error\":\"authorized_keys_write_failed\"}\n");
        }
        if (strcmp(path, "/tasks/restart") == 0 || strcmp(path, "/tasks/rerun") == 0) {
            char task_name[EMTASK_MAX_TASK_NAME];

            if (!emtask_panel_query_value(query, "name", task_name, sizeof(task_name)) || task_name[0] == '\0') {
                return emtask_panel_send_response(socket_handle, 400, "Bad Request", "application/json", "{\"error\":\"missing_task_name\"}\n");
            }
            status = emtask_panel_restart_task_by_name(app, task_name, response_body, sizeof(response_body));
            if (status == SSH_OK) {
                return emtask_panel_send_response(socket_handle, 200, "OK", "application/json", response_body);
            }
            if (status == SSH_ERR_NOT_FOUND) {
                return emtask_panel_send_response(socket_handle, 404, "Not Found", "application/json", "{\"error\":\"task_not_found\"}\n");
            }
            if (status == SSH_ERR_READ_ONLY) {
                return emtask_panel_send_response(socket_handle, 409, "Conflict", "application/json", "{\"error\":\"task_in_use\"}\n");
            }
            return emtask_panel_send_response(socket_handle, 500, "Internal Server Error", "application/json", "{\"error\":\"rerun_task_failed\"}\n");
        }
        if (strcmp(path, "/tasks") != 0) {
            return emtask_panel_send_response(socket_handle, 404, "Not Found", "application/json", "{\"error\":\"not_found\"}\n");
        }
        if (request_body == NULL || request_body_len == 0u) {
            return emtask_panel_send_response(socket_handle, 400, "Bad Request", "application/json", "{\"error\":\"empty_body\"}\n");
        }
        status = emtask_panel_create_task_from_json(app, request_body, response_body, sizeof(response_body));
        if (status == SSH_OK) {
            return emtask_panel_send_response(socket_handle, 201, "Created", "application/json", response_body);
        }
        if (status == SSH_ERR_ALREADY_EXISTS) {
            return emtask_panel_send_response(socket_handle, 409, "Conflict", "application/json", "{\"error\":\"task_conflict\"}\n");
        }
        if (status == SSH_ERR_BUFFER_TOO_SMALL) {
            return emtask_panel_send_response(socket_handle, 409, "Conflict", "application/json", "{\"error\":\"task_capacity_full\"}\n");
        }
        if (status == SSH_ERR_INVALID_ARGUMENT || status == SSH_ERR_MALFORMED_PACKET) {
            return emtask_panel_send_response(socket_handle, 400, "Bad Request", "application/json", "{\"error\":\"invalid_task\"}\n");
        }
        if (status == SSH_ERR_NOT_FOUND || status == SSH_ERR_UNSUPPORTED || status == SSH_ERR_PLATFORM) {
            if (response_body[0] != '\0') {
                return emtask_panel_send_response(socket_handle, 500, "Internal Server Error", "application/json", response_body);
            }
            return emtask_panel_send_response(socket_handle, 500, "Internal Server Error", "application/json", "{\"error\":\"create_task_failed\"}\n");
        }
        return emtask_panel_send_response(socket_handle, 500, "Internal Server Error", "application/json", "{\"error\":\"create_task_failed\"}\n");
    }
    if (strcmp(method, "PATCH") == 0) {
        char task_name[EMTASK_MAX_TASK_NAME];

        if (strcmp(path, "/tasks") != 0) {
            return emtask_panel_send_response(socket_handle, 404, "Not Found", "application/json", "{\"error\":\"not_found\"}\n");
        }
        if (!emtask_panel_query_value(query, "name", task_name, sizeof(task_name)) || task_name[0] == '\0') {
            return emtask_panel_send_response(socket_handle, 400, "Bad Request", "application/json", "{\"error\":\"missing_task_name\"}\n");
        }
        if (request_body == NULL || request_body_len == 0u) {
            return emtask_panel_send_response(socket_handle, 400, "Bad Request", "application/json", "{\"error\":\"empty_body\"}\n");
        }
        status = emtask_panel_update_task_from_json(app, task_name, request_body, response_body, sizeof(response_body));
        if (status == SSH_OK) {
            return emtask_panel_send_response(socket_handle, 200, "OK", "application/json", response_body);
        }
        if (status == SSH_ERR_NOT_FOUND) {
            return emtask_panel_send_response(socket_handle, 404, "Not Found", "application/json", "{\"error\":\"task_not_found\"}\n");
        }
        if (status == SSH_ERR_ALREADY_EXISTS || status == SSH_ERR_BUFFER_TOO_SMALL) {
            return emtask_panel_send_response(socket_handle, 409, "Conflict", "application/json", "{\"error\":\"task_conflict\"}\n");
        }
        if (status == SSH_ERR_READ_ONLY) {
            return emtask_panel_send_response(socket_handle, 409, "Conflict", "application/json", "{\"error\":\"task_in_use\"}\n");
        }
        if (status == SSH_ERR_INVALID_ARGUMENT || status == SSH_ERR_MALFORMED_PACKET) {
            return emtask_panel_send_response(socket_handle, 400, "Bad Request", "application/json", "{\"error\":\"invalid_task\"}\n");
        }
        return emtask_panel_send_response(socket_handle, 500, "Internal Server Error", "application/json", "{\"error\":\"update_task_failed\"}\n");
    }
    if (strcmp(method, "DELETE") == 0) {
        char task_name[EMTASK_MAX_TASK_NAME];

        if (strcmp(path, "/tasks") != 0) {
            return emtask_panel_send_response(socket_handle, 404, "Not Found", "application/json", "{\"error\":\"not_found\"}\n");
        }
        if (!emtask_panel_query_value(query, "name", task_name, sizeof(task_name)) || task_name[0] == '\0') {
            return emtask_panel_send_response(socket_handle, 400, "Bad Request", "application/json", "{\"error\":\"missing_task_name\"}\n");
        }
        status = emtask_panel_delete_task_by_name(app, task_name, response_body, sizeof(response_body));
        if (status == SSH_OK) {
            return emtask_panel_send_response(socket_handle, 200, "OK", "application/json", response_body);
        }
        if (status == SSH_ERR_NOT_FOUND) {
            return emtask_panel_send_response(socket_handle, 404, "Not Found", "application/json", "{\"error\":\"task_not_found\"}\n");
        }
        if (status == SSH_ERR_READ_ONLY) {
            return emtask_panel_send_response(socket_handle, 409, "Conflict", "application/json", "{\"error\":\"task_in_use\"}\n");
        }
        if (status == SSH_ERR_INVALID_ARGUMENT || status == SSH_ERR_MALFORMED_PACKET) {
            return emtask_panel_send_response(socket_handle, 400, "Bad Request", "application/json", "{\"error\":\"invalid_task\"}\n");
        }
        return emtask_panel_send_response(socket_handle, 500, "Internal Server Error", "application/json", "{\"error\":\"delete_task_failed\"}\n");
    }
    if (strcmp(path, "/health") == 0) {
        return emtask_panel_send_response(socket_handle, 200, "OK", "application/json", "{\"status\":\"ok\"}\n");
    }
    if (strcmp(path, "/") == 0) {
        return emtask_panel_send_response(
            socket_handle,
            200,
            "OK",
            "text/html; charset=utf-8",
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>emtask panel</title></head>"
            "<body><h1>emtask panel</h1><ul>"
            "<li><a href=\"/status\">/status</a></li>"
            "<li><a href=\"/tasks\">/tasks</a></li>"
            "<li>POST /tasks 添加动态子任务</li>"
            "<li>PATCH /tasks?name=&lt;task&gt; 修改动态子任务</li>"
            "<li>DELETE /tasks?name=&lt;task&gt; 删除动态子任务</li>"
            "<li>POST /tasks/restart?name=&lt;task&gt; 重新运行子任务命令</li>"
            "<li>POST /auth/authorized-keys 注册客户端 SSH 公钥</li>"
            "<li><a href=\"/health\">/health</a></li>"
            "</ul></body></html>\n");
    }
    if (strcmp(path, "/status") == 0 || strcmp(path, "/tasks") == 0) {
        status = emtask_panel_build_status_json(app, strcmp(path, "/tasks") == 0, response_body, sizeof(response_body));
        if (status != SSH_OK) {
            return emtask_panel_send_response(
                socket_handle,
                500,
                "Internal Server Error",
                "application/json",
                "{\"error\":\"status_too_large\"}\n");
        }
            return emtask_panel_send_response(socket_handle, 200, "OK", "application/json", response_body);
    }
    return emtask_panel_send_response(socket_handle, 404, "Not Found", "application/json", "{\"error\":\"not_found\"}\n");
}

static unsigned emtask_bind_retry_max_sec(const emtask_global_config_t *global)
{
    if (global == NULL || global->bind_retry_max_sec == 0u) {
        return 1u;
    }
    return global->bind_retry_max_sec;
}

static unsigned emtask_bind_retry_delay_sec(const emtask_global_config_t *global, unsigned attempt)
{
    unsigned max_sec;
    unsigned delay;

    max_sec = emtask_bind_retry_max_sec(global);
    delay = 1u;
    while (attempt > 0u && delay < max_sec) {
        if (delay > max_sec / 2u) {
            delay = max_sec;
            break;
        }
        delay *= 2u;
        --attempt;
    }
    return delay > max_sec ? max_sec : delay;
}

static void emtask_bind_retry_sleep(const emtask_global_config_t *global, unsigned *attempt_inout)
{
    unsigned attempt;
    unsigned delay_sec;

    attempt = attempt_inout != NULL ? *attempt_inout : 0u;
    delay_sec = emtask_bind_retry_delay_sec(global, attempt);
    if (attempt_inout != NULL) {
        *attempt_inout = attempt + 1u;
    }
    emtask_platform_sleep_ms((uint32_t)(delay_sec * 1000u));
}

static int emtask_bind_retry_enabled(const emtask_app_t *app)
{
    return app != NULL && app->config.global.bind_retry_enabled;
}

static int emtask_panel_open_listener(emtask_app_t *app)
{
    const char *listen_address;
    int status;

    if (app == NULL || !app->config.global.panel_enabled) {
        return SSH_OK;
    }
    if (app->panel_listener_open) {
        return SSH_OK;
    }

    listen_address = app->config.global.panel_listen_address[0] != '\0'
                         ? app->config.global.panel_listen_address
                         : EMTASK_DEFAULT_PANEL_LISTEN_ADDRESS;
    status = ssh_tcp_listen(
        &app->tcp,
        listen_address,
        app->config.global.panel_port,
        16,
        &app->panel_listener);
    if (status != SSH_OK) {
        emtask_logf(
            "panel listen failed on %s:%u: %s",
            listen_address,
            (unsigned)app->config.global.panel_port,
            ssh_status_string(status));
        return status;
    }
    app->panel_listener_open = 1;
    return SSH_OK;
}

void emtask_panel_thread_main(emtask_app_t *app)
{
    int status;
    unsigned bind_attempt;

    if (app == NULL) {
        return;
    }
    bind_attempt = 0u;

    for (;;) {
        ssh_tcp_conn_t accepted;

        if (!app->panel_listener_open) {
            status = emtask_panel_open_listener(app);
            if (status != SSH_OK) {
                unsigned delay_sec;

                if (!emtask_bind_retry_enabled(app)) {
                    emtask_logf("panel listener disabled after bind failure");
                    return;
                }
                delay_sec = emtask_bind_retry_delay_sec(&app->config.global, bind_attempt);
                emtask_logf(
                    "panel listen retry in %u second(s), attempt=%u, max=%us",
                    delay_sec,
                    bind_attempt + 1u,
                    emtask_bind_retry_max_sec(&app->config.global));
                emtask_bind_retry_sleep(&app->config.global, &bind_attempt);
                continue;
            }
            if (bind_attempt != 0u) {
                emtask_logf(
                    "panel listener recovered on %s:%u",
                    app->config.global.panel_listen_address[0] != '\0'
                        ? app->config.global.panel_listen_address
                        : EMTASK_DEFAULT_PANEL_LISTEN_ADDRESS,
                    (unsigned)app->config.global.panel_port);
                bind_attempt = 0u;
            }
        }

        memset(&accepted, 0, sizeof(accepted));
        status = ssh_tcp_accept(&app->tcp, &app->panel_listener, &accepted, 0u);
        if (status != SSH_OK) {
            emtask_logf("panel accept failed: %s", ssh_status_string(status));
            continue;
        }
        status = emtask_panel_handle_connection(app, &accepted);
        if (status != SSH_OK) {
            emtask_logf("panel request from %s failed: %s", ssh_tcp_conn_peer_address(&accepted), ssh_status_string(status));
        }
        (void)ssh_tcp_conn_close(&app->tcp, &accepted);
    }
}

static uint64_t emtask_monotonic_ms(void)
{
    return emtask_platform_monotonic_ms();
}

void emtask_term_default_size(emtask_term_t *term)
{
    if (term->cols == 0u) {
        term->cols = EMTASK_DEFAULT_TERM_COLS;
    }
    if (term->rows == 0u) {
        term->rows = EMTASK_DEFAULT_TERM_ROWS;
    }
}

static void emtask_term_close_handles_locked(emtask_term_t *term, int terminate_child)
{
    emtask_platform_term_close_handles_locked(term, terminate_child);
}

static void emtask_term_prune_restart_locked(emtask_term_t *term, uint64_t now_ms)
{
    size_t read_idx;
    size_t write_idx;

    if (term == NULL) {
        return;
    }

    write_idx = 0u;
    for (read_idx = 0u; read_idx < term->restart_history_len; ++read_idx) {
        uint64_t ts = term->restart_history[read_idx];
        if (term->restart_window_ms == 0u || now_ms < ts || now_ms - ts < term->restart_window_ms) {
            term->restart_history[write_idx++] = ts;
        }
    }
    term->restart_history_len = write_idx;
}

static int emtask_term_note_restart_locked(emtask_term_t *term)
{
    uint64_t now_ms;

    if (term == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (term->restart_limit == 0u || term->restart_window_ms == 0u) {
        return SSH_OK;
    }

    now_ms = emtask_monotonic_ms();
    emtask_term_prune_restart_locked(term, now_ms);
    if (term->restart_history_len >= term->restart_limit) {
        term->faulted = 1;
        emtask_term_set_last_error_locked(
            term,
            SSH_ERR_UNSUPPORTED,
            "restart limit reached for command: %u restarts within %llu ms",
            term->restart_limit,
            (unsigned long long)term->restart_window_ms);
        emtask_logf(
            "restart limit reached for command: %u restarts within %llu ms",
            term->restart_limit,
            (unsigned long long)term->restart_window_ms);
        return SSH_ERR_UNSUPPORTED;
    }
    if (term->restart_history_len < EMTASK_MAX_RESTART_HISTORY) {
        term->restart_history[term->restart_history_len++] = now_ms;
    }
    return SSH_OK;
}

static int emtask_term_spawn_locked(emtask_term_t *term, int count_as_restart)
{
    int status;

    if (term == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (term->faulted) {
        return SSH_ERR_UNSUPPORTED;
    }
    if (term->command[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (count_as_restart) {
        status = emtask_term_note_restart_locked(term);
        if (status != SSH_OK) {
            return status;
        }
    }

    status = emtask_platform_term_spawn_locked(term);
    if (status == SSH_OK) {
        term->exited = 0;
        term->interrupt_restart_deadline_ms = 0u;
        emtask_term_clear_last_error_locked(term);
        emtask_logf("started task command: %s", term->command);
    } else {
        term->faulted = 1;
        emtask_term_set_last_error_locked(
            term,
            status,
            "failed to start task command: %s (%s)",
            term->command,
            ssh_status_string(status));
        emtask_logf("failed to start task command: %s", term->command);
    }
    return status;
}

static int emtask_term_poll_exit_locked(emtask_term_t *term, int *exited, uint32_t *exit_status)
{
    int observed_exited;
    uint32_t observed_exit_status;
    int status;

    if (exited != NULL) {
        *exited = 0;
    }
    if (exit_status != NULL) {
        *exit_status = term != NULL ? term->last_exit_status : 0u;
    }
    if (term == NULL) {
        return SSH_OK;
    }

    if (!term->running) {
        if (term->exited) {
            if (exited != NULL) {
                *exited = 1;
            }
            if (exit_status != NULL) {
                *exit_status = term->last_exit_status;
            }
        }
        return SSH_OK;
    }

    observed_exited = 0;
    observed_exit_status = term->last_exit_status;
    status = emtask_platform_term_poll_exit_locked(term, &observed_exited, &observed_exit_status);
    if (status != SSH_OK) {
        return status;
    }
    if (observed_exited) {
        term->exited = 1;
        term->last_exit_status = observed_exit_status;
        if (exited != NULL) {
            *exited = 1;
        }
        if (exit_status != NULL) {
            *exit_status = observed_exit_status;
        }
    }
    return SSH_OK;
}

static int emtask_term_signal_requests_restart(const char *signal_name)
{
    if (signal_name == NULL || signal_name[0] == '\0') {
        return 0;
    }
    return emtask_key_equals(signal_name, "TERM") ||
           emtask_key_equals(signal_name, "INT") ||
           emtask_key_equals(signal_name, "KILL");
}

static int emtask_term_ensure_running_locked(emtask_term_t *term)
{
    int exited;
    uint32_t exit_status;
    int status;

    if (term == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    status = emtask_term_poll_exit_locked(term, &exited, &exit_status);
    if (status != SSH_OK) {
        return status;
    }
    if (term->running) {
        return SSH_OK;
    }
    if (term->faulted) {
        return SSH_ERR_UNSUPPORTED;
    }
    return emtask_term_spawn_locked(term, term->started_once != 0);
}

static int emtask_term_start_initial(emtask_term_t *term)
{
    int status;

    if (term == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    emtask_mutex_lock(&term->lock);
    status = emtask_term_ensure_running_locked(term);
    emtask_mutex_unlock(&term->lock);
    return status;
}

static int emtask_term_restart_manual(emtask_term_t *term)
{
    int status;

    if (term == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    emtask_mutex_lock(&term->lock);
    if (!term->initialized) {
        emtask_mutex_unlock(&term->lock);
        return SSH_ERR_INVALID_ARGUMENT;
    }
    term->faulted = 0;
    term->exited = 0;
    term->interrupt_restart_deadline_ms = 0u;
    term->restart_history_len = 0u;
    emtask_term_close_handles_locked(term, 1);
    status = emtask_term_spawn_locked(term, 0);
    emtask_mutex_unlock(&term->lock);
    return status;
}

static int emtask_term_watchdog_step_locked(emtask_term_t *term)
{
    int exited;
    uint32_t exit_status;
    int status;

    if (term == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = emtask_term_poll_exit_locked(term, &exited, &exit_status);
    if (status != SSH_OK) {
        return status;
    }
    if (!exited || term->faulted || term->attached) {
        return SSH_OK;
    }

    status = emtask_term_spawn_locked(term, 1);
    if (status == SSH_OK) {
        emtask_logf("task command restarted after exit status=%u", exit_status);
        return SSH_OK;
    }
    term->faulted = 1;
    emtask_term_set_last_error_locked(
        term,
        exit_status,
        "task command stopped after exit status=%u; restart failed: %s",
        exit_status,
        ssh_status_string(status));
    emtask_logf("task command stopped after exit status=%u", exit_status);
    return SSH_OK;
}

static int emtask_term_update_for_wait_locked(emtask_term_t *term)
{
    if (term == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    return SSH_OK;
}

static int emtask_term_capture_output_locked(emtask_term_t *term, uint8_t *buf, size_t len, size_t *read_len)
{
    int status;

    if (read_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    *read_len = 0u;
    if (term == NULL || (buf == NULL && len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (!term->running || len == 0u) {
        return SSH_OK;
    }

    status = emtask_platform_term_read_locked(term, buf, len, read_len);
    if (status == SSH_OK && *read_len != 0u) {
        emtask_screen_feed_locked(term, buf, *read_len);
        emtask_term_replay_append_locked(term, buf, *read_len);
    }
    if (status == SSH_OK && *read_len == 0u) {
        (void)emtask_term_poll_exit_locked(term, NULL, NULL);
    }
    return status;
}

static void emtask_screen_reset_locked(emtask_term_t *term)
{
    if (term == NULL || term->screen_cells == NULL) {
        return;
    }
    for (size_t i = 0u; i < term->screen_cell_count; ++i) {
        term->screen_cells[i] = (uint16_t)' ';
    }
    term->screen_cursor_col = 0u;
    term->screen_cursor_row = 0u;
    term->screen_saved_col = 0u;
    term->screen_saved_row = 0u;
    term->screen_scroll_top = 0u;
    term->screen_scroll_bottom = term->screen_rows != 0u ? term->screen_rows - 1u : 0u;
    term->screen_wrap_pending = 0;
    term->screen_esc_state = 0;
    term->screen_csi_len = 0u;
    term->screen_dirty = 1;
}

static int emtask_screen_resize_locked(emtask_term_t *term, uint32_t cols, uint32_t rows)
{
    uint16_t *cells;
    size_t count;

    if (term == NULL || !term->screen_snapshot) {
        return SSH_OK;
    }
    if (cols == 0u) {
        cols = EMTASK_DEFAULT_TERM_COLS;
    }
    if (rows == 0u) {
        rows = EMTASK_DEFAULT_TERM_ROWS;
    }
    if (cols == term->screen_cols && rows == term->screen_rows && term->screen_cells != NULL) {
        return SSH_OK;
    }
    count = (size_t)cols * (size_t)rows;
    if (count == 0u || count > 1000000u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    cells = (uint16_t *)calloc(count, sizeof(*cells));
    if (cells == NULL) {
        return SSH_ERR_PLATFORM;
    }
    free(term->screen_cells);
    term->screen_cells = cells;
    term->screen_cell_count = count;
    term->screen_cols = cols;
    term->screen_rows = rows;
    emtask_screen_reset_locked(term);
    return SSH_OK;
}

static void emtask_screen_scroll_up_locked(emtask_term_t *term)
{
    size_t line;
    size_t top;
    size_t bottom;

    if (term == NULL || term->screen_cells == NULL || term->screen_rows == 0u || term->screen_cols == 0u) {
        return;
    }
    line = (size_t)term->screen_cols;
    top = (size_t)term->screen_scroll_top;
    bottom = (size_t)term->screen_scroll_bottom;
    if (bottom >= term->screen_rows || top > bottom) {
        top = 0u;
        bottom = (size_t)term->screen_rows - 1u;
    }
    if (bottom > top) {
        memmove(
            term->screen_cells + top * line,
            term->screen_cells + (top + 1u) * line,
            line * (bottom - top) * sizeof(*term->screen_cells));
    }
    for (size_t i = bottom * line; i < (bottom + 1u) * line && i < term->screen_cell_count; ++i) {
        term->screen_cells[i] = (uint16_t)' ';
    }
    term->screen_dirty = 1;
}

static void emtask_screen_scroll_down_locked(emtask_term_t *term)
{
    size_t line;
    size_t top;
    size_t bottom;

    if (term == NULL || term->screen_cells == NULL || term->screen_rows == 0u || term->screen_cols == 0u) {
        return;
    }
    line = (size_t)term->screen_cols;
    top = (size_t)term->screen_scroll_top;
    bottom = (size_t)term->screen_scroll_bottom;
    if (bottom >= term->screen_rows || top > bottom) {
        top = 0u;
        bottom = (size_t)term->screen_rows - 1u;
    }
    if (bottom > top) {
        memmove(
            term->screen_cells + (top + 1u) * line,
            term->screen_cells + top * line,
            line * (bottom - top) * sizeof(*term->screen_cells));
    }
    for (size_t i = top * line; i < (top + 1u) * line && i < term->screen_cell_count; ++i) {
        term->screen_cells[i] = (uint16_t)' ';
    }
    term->screen_dirty = 1;
}

static void emtask_screen_newline_locked(emtask_term_t *term)
{
    if (term == NULL || term->screen_rows == 0u) {
        return;
    }
    term->screen_wrap_pending = 0;
    if (term->screen_cursor_row == term->screen_scroll_bottom) {
        emtask_screen_scroll_up_locked(term);
    } else if (term->screen_cursor_row + 1u >= term->screen_rows) {
        term->screen_cursor_row = term->screen_rows - 1u;
    } else {
        ++term->screen_cursor_row;
    }
}

static void emtask_screen_reverse_index_locked(emtask_term_t *term)
{
    if (term == NULL || term->screen_rows == 0u) {
        return;
    }
    term->screen_wrap_pending = 0;
    if (term->screen_cursor_row == term->screen_scroll_top) {
        emtask_screen_scroll_down_locked(term);
    } else if (term->screen_cursor_row != 0u) {
        --term->screen_cursor_row;
    }
}

static void emtask_screen_put_char_locked(emtask_term_t *term, uint8_t ch)
{
    size_t pos;

    if (term == NULL || term->screen_cells == NULL || term->screen_cols == 0u || term->screen_rows == 0u) {
        return;
    }
    if (term->screen_wrap_pending) {
        term->screen_cursor_col = 0u;
        emtask_screen_newline_locked(term);
    }
    pos = (size_t)term->screen_cursor_row * (size_t)term->screen_cols + (size_t)term->screen_cursor_col;
    if (pos < term->screen_cell_count) {
        term->screen_cells[pos] = (ch >= 32u && ch != 127u) ? (uint16_t)ch : (uint16_t)' ';
        term->screen_dirty = 1;
    }
    if (term->screen_cursor_col + 1u >= term->screen_cols) {
        term->screen_wrap_pending = 1;
    } else {
        ++term->screen_cursor_col;
    }
}

static int emtask_screen_csi_param(const char *text, size_t len, unsigned index, int default_value)
{
    unsigned current = 0u;
    int value = -1;

    for (size_t i = 0u; i <= len; ++i) {
        char ch = i < len ? text[i] : ';';
        if (ch >= '0' && ch <= '9') {
            if (value < 0) {
                value = 0;
            }
            value = value * 10 + (ch - '0');
            continue;
        }
        if (ch == '?' || ch == '>' || ch == ' ') {
            continue;
        }
        if (ch == ';' || i == len) {
            if (current == index) {
                return value < 0 ? default_value : value;
            }
            ++current;
            value = -1;
        }
    }
    return default_value;
}

static void emtask_screen_clear_line_locked(emtask_term_t *term, uint32_t start_col, uint32_t end_col)
{
    if (term == NULL || term->screen_cells == NULL || term->screen_cursor_row >= term->screen_rows) {
        return;
    }
    if (end_col >= term->screen_cols) {
        end_col = term->screen_cols - 1u;
    }
    for (uint32_t col = start_col; col <= end_col; ++col) {
        term->screen_cells[(size_t)term->screen_cursor_row * (size_t)term->screen_cols + col] = (uint16_t)' ';
    }
    term->screen_dirty = 1;
}

static void emtask_screen_clear_display_locked(emtask_term_t *term, int mode)
{
    if (term == NULL || term->screen_cells == NULL) {
        return;
    }
    if (mode == 2 || mode == 3) {
        for (size_t i = 0u; i < term->screen_cell_count; ++i) {
            term->screen_cells[i] = (uint16_t)' ';
        }
    } else if (mode == 0) {
        size_t start = (size_t)term->screen_cursor_row * (size_t)term->screen_cols + term->screen_cursor_col;
        for (size_t i = start; i < term->screen_cell_count; ++i) {
            term->screen_cells[i] = (uint16_t)' ';
        }
    } else if (mode == 1) {
        size_t end = (size_t)term->screen_cursor_row * (size_t)term->screen_cols + term->screen_cursor_col;
        for (size_t i = 0u; i <= end && i < term->screen_cell_count; ++i) {
            term->screen_cells[i] = (uint16_t)' ';
        }
    }
    term->screen_dirty = 1;
}

static void emtask_screen_insert_lines_locked(emtask_term_t *term, uint32_t count)
{
    size_t line;
    size_t row;
    size_t bottom;

    if (term == NULL || term->screen_cells == NULL || count == 0u || term->screen_cursor_row < term->screen_scroll_top ||
        term->screen_cursor_row > term->screen_scroll_bottom) {
        return;
    }
    line = (size_t)term->screen_cols;
    row = (size_t)term->screen_cursor_row;
    bottom = (size_t)term->screen_scroll_bottom;
    if ((size_t)count > bottom - row + 1u) {
        count = (uint32_t)(bottom - row + 1u);
    }
    memmove(
        term->screen_cells + (row + (size_t)count) * line,
        term->screen_cells + row * line,
        (bottom - row + 1u - (size_t)count) * line * sizeof(*term->screen_cells));
    for (size_t i = row * line; i < (row + (size_t)count) * line; ++i) {
        term->screen_cells[i] = (uint16_t)' ';
    }
    term->screen_dirty = 1;
}

static void emtask_screen_delete_lines_locked(emtask_term_t *term, uint32_t count)
{
    size_t line;
    size_t row;
    size_t bottom;

    if (term == NULL || term->screen_cells == NULL || count == 0u || term->screen_cursor_row < term->screen_scroll_top ||
        term->screen_cursor_row > term->screen_scroll_bottom) {
        return;
    }
    line = (size_t)term->screen_cols;
    row = (size_t)term->screen_cursor_row;
    bottom = (size_t)term->screen_scroll_bottom;
    if ((size_t)count > bottom - row + 1u) {
        count = (uint32_t)(bottom - row + 1u);
    }
    memmove(
        term->screen_cells + row * line,
        term->screen_cells + (row + (size_t)count) * line,
        (bottom - row + 1u - (size_t)count) * line * sizeof(*term->screen_cells));
    for (size_t i = (bottom + 1u - (size_t)count) * line; i < (bottom + 1u) * line; ++i) {
        term->screen_cells[i] = (uint16_t)' ';
    }
    term->screen_dirty = 1;
}

static void emtask_screen_insert_chars_locked(emtask_term_t *term, uint32_t count)
{
    size_t row;
    size_t col;
    size_t line;

    if (term == NULL || term->screen_cells == NULL || count == 0u || term->screen_cursor_col >= term->screen_cols) {
        return;
    }
    row = (size_t)term->screen_cursor_row;
    col = (size_t)term->screen_cursor_col;
    line = (size_t)term->screen_cols;
    if ((size_t)count > line - col) {
        count = (uint32_t)(line - col);
    }
    memmove(
        term->screen_cells + row * line + col + (size_t)count,
        term->screen_cells + row * line + col,
        (line - col - (size_t)count) * sizeof(*term->screen_cells));
    for (size_t i = row * line + col; i < row * line + col + (size_t)count; ++i) {
        term->screen_cells[i] = (uint16_t)' ';
    }
    term->screen_dirty = 1;
}

static void emtask_screen_delete_chars_locked(emtask_term_t *term, uint32_t count)
{
    size_t row;
    size_t col;
    size_t line;

    if (term == NULL || term->screen_cells == NULL || count == 0u || term->screen_cursor_col >= term->screen_cols) {
        return;
    }
    row = (size_t)term->screen_cursor_row;
    col = (size_t)term->screen_cursor_col;
    line = (size_t)term->screen_cols;
    if ((size_t)count > line - col) {
        count = (uint32_t)(line - col);
    }
    memmove(
        term->screen_cells + row * line + col,
        term->screen_cells + row * line + col + (size_t)count,
        (line - col - (size_t)count) * sizeof(*term->screen_cells));
    for (size_t i = row * line + line - (size_t)count; i < row * line + line; ++i) {
        term->screen_cells[i] = (uint16_t)' ';
    }
    term->screen_dirty = 1;
}

static void emtask_screen_erase_chars_locked(emtask_term_t *term, uint32_t count)
{
    size_t row;
    size_t col;
    size_t line;

    if (term == NULL || term->screen_cells == NULL || count == 0u || term->screen_cursor_col >= term->screen_cols) {
        return;
    }
    row = (size_t)term->screen_cursor_row;
    col = (size_t)term->screen_cursor_col;
    line = (size_t)term->screen_cols;
    if ((size_t)count > line - col) {
        count = (uint32_t)(line - col);
    }
    for (size_t i = row * line + col; i < row * line + col + (size_t)count; ++i) {
        term->screen_cells[i] = (uint16_t)' ';
    }
    term->screen_dirty = 1;
}

static void emtask_screen_apply_csi_locked(emtask_term_t *term, char final)
{
    int n;
    int m;

    if (term == NULL || term->screen_cols == 0u || term->screen_rows == 0u) {
        return;
    }
    n = emtask_screen_csi_param(term->screen_csi, term->screen_csi_len, 0u, 1);
    m = emtask_screen_csi_param(term->screen_csi, term->screen_csi_len, 1u, 1);
    switch (final) {
    case 'A':
        term->screen_cursor_row = (uint32_t)(n > (int)term->screen_cursor_row ? 0 : (int)term->screen_cursor_row - n);
        break;
    case 'B':
        term->screen_cursor_row = (uint32_t)emtask_min_size((size_t)term->screen_rows - 1u, (size_t)term->screen_cursor_row + (size_t)n);
        break;
    case 'C':
        term->screen_cursor_col = (uint32_t)emtask_min_size((size_t)term->screen_cols - 1u, (size_t)term->screen_cursor_col + (size_t)n);
        break;
    case 'D':
        term->screen_cursor_col = (uint32_t)(n > (int)term->screen_cursor_col ? 0 : (int)term->screen_cursor_col - n);
        break;
    case 'G':
        term->screen_cursor_col = (uint32_t)emtask_min_size((size_t)term->screen_cols - 1u, (size_t)(n > 0 ? n - 1 : 0));
        break;
    case 'H':
    case 'f':
        term->screen_cursor_row = (uint32_t)emtask_min_size((size_t)term->screen_rows - 1u, (size_t)(n > 0 ? n - 1 : 0));
        term->screen_cursor_col = (uint32_t)emtask_min_size((size_t)term->screen_cols - 1u, (size_t)(m > 0 ? m - 1 : 0));
        break;
    case 'd':
        term->screen_cursor_row = (uint32_t)emtask_min_size((size_t)term->screen_rows - 1u, (size_t)(n > 0 ? n - 1 : 0));
        break;
    case 'J':
        emtask_screen_clear_display_locked(term, emtask_screen_csi_param(term->screen_csi, term->screen_csi_len, 0u, 0));
        break;
    case 'K':
        n = emtask_screen_csi_param(term->screen_csi, term->screen_csi_len, 0u, 0);
        if (n == 1) {
            emtask_screen_clear_line_locked(term, 0u, term->screen_cursor_col);
        } else if (n == 2) {
            emtask_screen_clear_line_locked(term, 0u, term->screen_cols - 1u);
        } else {
            emtask_screen_clear_line_locked(term, term->screen_cursor_col, term->screen_cols - 1u);
        }
        break;
    case 'L':
        emtask_screen_insert_lines_locked(term, (uint32_t)n);
        break;
    case 'M':
        emtask_screen_delete_lines_locked(term, (uint32_t)n);
        break;
    case '@':
        emtask_screen_insert_chars_locked(term, (uint32_t)n);
        break;
    case 'P':
        emtask_screen_delete_chars_locked(term, (uint32_t)n);
        break;
    case 'X':
        emtask_screen_erase_chars_locked(term, (uint32_t)n);
        break;
    case 'S':
        for (int i = 0; i < n; ++i) {
            emtask_screen_scroll_up_locked(term);
        }
        break;
    case 'T':
        for (int i = 0; i < n; ++i) {
            emtask_screen_scroll_down_locked(term);
        }
        break;
    case 'r':
        if (n < 1) {
            n = 1;
        }
        if (m < 1) {
            m = (int)term->screen_rows;
        }
        if (n < m && m <= (int)term->screen_rows) {
            term->screen_scroll_top = (uint32_t)(n - 1);
            term->screen_scroll_bottom = (uint32_t)(m - 1);
            term->screen_cursor_col = 0u;
            term->screen_cursor_row = 0u;
        }
        break;
    case 's':
        term->screen_saved_col = term->screen_cursor_col;
        term->screen_saved_row = term->screen_cursor_row;
        break;
    case 'u':
        term->screen_cursor_col = term->screen_saved_col;
        term->screen_cursor_row = term->screen_saved_row;
        break;
    default:
        break;
    }
    term->screen_wrap_pending = 0;
}

static void emtask_screen_feed_locked(emtask_term_t *term, const uint8_t *buf, size_t len)
{
    if (term == NULL || !term->screen_snapshot || term->screen_cells == NULL || buf == NULL) {
        return;
    }
    for (size_t i = 0u; i < len; ++i) {
        uint8_t ch = buf[i];
        if (term->screen_esc_state == 1) {
            if (ch == '[') {
                term->screen_esc_state = 2;
                term->screen_csi_len = 0u;
            } else if (ch == '7') {
                term->screen_saved_col = term->screen_cursor_col;
                term->screen_saved_row = term->screen_cursor_row;
                term->screen_esc_state = 0;
            } else if (ch == '8') {
                term->screen_cursor_col = term->screen_saved_col;
                term->screen_cursor_row = term->screen_saved_row;
                term->screen_esc_state = 0;
            } else if (ch == 'c') {
                emtask_screen_reset_locked(term);
                term->screen_esc_state = 0;
            } else if (ch == 'D') {
                emtask_screen_newline_locked(term);
                term->screen_esc_state = 0;
            } else if (ch == 'M') {
                emtask_screen_reverse_index_locked(term);
                term->screen_esc_state = 0;
            } else if (ch == 'E') {
                term->screen_cursor_col = 0u;
                emtask_screen_newline_locked(term);
                term->screen_esc_state = 0;
            } else {
                term->screen_esc_state = 0;
            }
            continue;
        }
        if (term->screen_esc_state == 2) {
            if (ch >= 0x40u && ch <= 0x7eu) {
                emtask_screen_apply_csi_locked(term, (char)ch);
                term->screen_esc_state = 0;
                term->screen_csi_len = 0u;
            } else if (term->screen_csi_len + 1u < sizeof(term->screen_csi)) {
                term->screen_csi[term->screen_csi_len++] = (char)ch;
                term->screen_csi[term->screen_csi_len] = '\0';
            }
            continue;
        }
        if (ch == 0x1bu) {
            term->screen_esc_state = 1;
            continue;
        }
        if (ch == '\r') {
            term->screen_cursor_col = 0u;
            term->screen_wrap_pending = 0;
        } else if (ch == '\n') {
            emtask_screen_newline_locked(term);
        } else if (ch == '\b') {
            if (term->screen_cursor_col != 0u) {
                --term->screen_cursor_col;
            }
            term->screen_wrap_pending = 0;
        } else if (ch == '\t') {
            uint32_t next = (term->screen_cursor_col + 8u) & ~7u;
            while (term->screen_cursor_col < next && term->screen_cursor_col < term->screen_cols) {
                emtask_screen_put_char_locked(term, ' ');
            }
        } else if (ch >= 32u) {
            emtask_screen_put_char_locked(term, ch);
        }
    }
}

static size_t emtask_screen_snapshot_copy_locked(
    emtask_term_t *term,
    emtask_term_attachment_t *attachment,
    uint8_t *buf,
    size_t len)
{
    size_t written = 0u;

    if (term == NULL || attachment == NULL || buf == NULL || len == 0u ||
        !term->screen_snapshot || !attachment->screen_snapshot_pending || term->screen_cells == NULL) {
        return 0u;
    }
    if (attachment->screen_snapshot_phase == 0u) {
        static const uint8_t prefix[] = "\x1b[?1049h\x1b[H\x1b[2J";
        while (attachment->screen_snapshot_offset < sizeof(prefix) - 1u && written < len) {
            buf[written++] = prefix[attachment->screen_snapshot_offset++];
        }
        if (attachment->screen_snapshot_offset < sizeof(prefix) - 1u) {
            return written;
        }
        attachment->screen_snapshot_phase = 1u;
        attachment->screen_snapshot_offset = 0u;
    }
    while (attachment->screen_snapshot_phase == 1u && written < len) {
        size_t cell = attachment->screen_snapshot_offset;
        if (cell >= term->screen_cell_count) {
            attachment->screen_snapshot_phase = 2u;
            attachment->screen_snapshot_offset = 0u;
            break;
        }
        if (cell != 0u && (cell % term->screen_cols) == 0u) {
            buf[written++] = '\r';
            if (written >= len) {
                return written;
            }
            buf[written++] = '\n';
            if (written >= len) {
                return written;
            }
        }
        buf[written++] = (uint8_t)(term->screen_cells[cell] != 0u ? term->screen_cells[cell] : ' ');
        ++attachment->screen_snapshot_offset;
    }
    if (attachment->screen_snapshot_phase == 2u) {
        char suffix[64];
        int n = snprintf(suffix, sizeof(suffix), "\x1b[%u;%uH", (unsigned)term->screen_cursor_row + 1u, (unsigned)term->screen_cursor_col + 1u);
        if (n < 0) {
            attachment->screen_snapshot_pending = 0;
            return written;
        }
        while (attachment->screen_snapshot_offset < (size_t)n && written < len) {
            buf[written++] = (uint8_t)suffix[attachment->screen_snapshot_offset++];
        }
        if (attachment->screen_snapshot_offset >= (size_t)n) {
            attachment->screen_snapshot_pending = 0;
        }
    }
    return written;
}

static void emtask_term_replay_append_locked(emtask_term_t *term, const uint8_t *buf, size_t len)
{
    size_t remaining;

    if (term == NULL || term->replay_buffer == NULL || term->replay_capacity == 0u || buf == NULL || len == 0u) {
        return;
    }

    if (len >= term->replay_capacity) {
        buf += len - term->replay_capacity;
        len = term->replay_capacity;
        term->replay_start = 0u;
        memcpy(term->replay_buffer, buf, len);
        term->replay_len = len;
        return;
    }

    if (term->replay_len + len > term->replay_capacity) {
        size_t drop = term->replay_len + len - term->replay_capacity;
        term->replay_start = (term->replay_start + drop) % term->replay_capacity;
        term->replay_len -= drop;
    }

    remaining = len;
    while (remaining != 0u) {
        size_t write_pos = (term->replay_start + term->replay_len) % term->replay_capacity;
        size_t chunk = emtask_min_size(remaining, term->replay_capacity - write_pos);
        memcpy(term->replay_buffer + write_pos, buf, chunk);
        term->replay_len += chunk;
        buf += chunk;
        remaining -= chunk;
    }
}

static size_t emtask_term_replay_copy_locked(
    emtask_term_t *term,
    emtask_term_attachment_t *attachment,
    uint8_t *buf,
    size_t len)
{
    size_t pos;
    size_t chunk;

    if (term == NULL || attachment == NULL || buf == NULL || len == 0u ||
        term->replay_buffer == NULL || term->replay_capacity == 0u || attachment->replay_remaining == 0u) {
        return 0u;
    }

    if (attachment->replay_offset >= term->replay_len) {
        attachment->replay_remaining = 0u;
        return 0u;
    }

    chunk = emtask_min_size(len, attachment->replay_remaining);
    chunk = emtask_min_size(chunk, term->replay_len - attachment->replay_offset);
    pos = (term->replay_start + attachment->replay_offset) % term->replay_capacity;
    chunk = emtask_min_size(chunk, term->replay_capacity - pos);
    memcpy(buf, term->replay_buffer + pos, chunk);
    attachment->replay_offset += chunk;
    attachment->replay_remaining -= chunk;
    return chunk;
}

static int emtask_term_attach_common(
    emtask_term_t *term,
    const char *term_type,
    uint32_t cols,
    uint32_t rows,
    uint32_t width_px,
    uint32_t height_px,
    void **handle_out)
{
    emtask_term_attachment_t *attachment;
    int status;

    if (term == NULL || handle_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    emtask_mutex_lock(&term->lock);
    if (term->attached) {
        emtask_mutex_unlock(&term->lock);
        return SSH_ERR_ALREADY_EXISTS;
    }

    if (term_type != NULL && term_type[0] != '\0') {
        status = emtask_copy_text(term->term_type, sizeof(term->term_type), term_type);
        if (status != SSH_OK) {
            emtask_mutex_unlock(&term->lock);
            return status;
        }
    }
    if (cols != 0u) {
        term->cols = cols;
    }
    if (rows != 0u) {
        term->rows = rows;
    }
    term->width_px = width_px;
    term->height_px = height_px;

    status = emtask_term_ensure_running_locked(term);
    if (status != SSH_OK) {
        emtask_mutex_unlock(&term->lock);
        return status;
    }

    attachment = (emtask_term_attachment_t *)calloc(1u, sizeof(*attachment));
    if (attachment == NULL) {
        emtask_mutex_unlock(&term->lock);
        return SSH_ERR_PLATFORM;
    }
    attachment->term = term;
    attachment->active = 1;
    if (term->replay_on_attach && term->replay_len != 0u) {
        attachment->replay_offset = 0u;
        attachment->replay_remaining = term->replay_len;
    }
    if (term->screen_snapshot && term->screen_dirty) {
        attachment->screen_snapshot_pending = 1;
        attachment->screen_snapshot_phase = 0u;
        attachment->screen_snapshot_offset = 0u;
        attachment->replay_remaining = 0u;
    }
    if (term->repaint_on_attach && term->running) {
        size_t written_len = 0u;
        static const uint8_t repaint[] = { 0x0cu };
        (void)emtask_platform_term_write_locked(term, repaint, sizeof(repaint), &written_len);
    }
    term->attached = 1;
    *handle_out = attachment;
    emtask_mutex_unlock(&term->lock);
    return SSH_OK;
}

static int emtask_term_spawn_shell(
    void *ctx,
    const char *username,
    const char *term_type,
    uint32_t cols,
    uint32_t rows,
    uint32_t width_px,
    uint32_t height_px,
    void **handle)
{
    (void)username;
    return emtask_term_attach_common((emtask_term_t *)ctx, term_type, cols, rows, width_px, height_px, handle);
}

static int emtask_term_spawn_exec(
    void *ctx,
    const char *username,
    const char *command,
    const char *term_type,
    uint32_t cols,
    uint32_t rows,
    uint32_t width_px,
    uint32_t height_px,
    void **handle)
{
    (void)ctx;
    (void)username;
    (void)command;
    (void)term_type;
    (void)cols;
    (void)rows;
    (void)width_px;
    (void)height_px;
    (void)handle;
    return SSH_ERR_UNSUPPORTED;
}

static int emtask_term_write(
    void *ctx,
    void *handle_ptr,
    const uint8_t *buf,
    size_t len,
    size_t *written_len)
{
    emtask_term_attachment_t *attachment = (emtask_term_attachment_t *)handle_ptr;
    emtask_term_t *term = (emtask_term_t *)ctx;

    if (written_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    *written_len = 0u;
    if (term == NULL || attachment == NULL || !attachment->active || (buf == NULL && len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (len == 0u) {
        return SSH_OK;
    }

    emtask_mutex_lock(&term->lock);
    if (memchr(buf, 0x03, len) != NULL) {
        term->interrupt_restart_deadline_ms = emtask_monotonic_ms() + EMTASK_TERMINAL_RESTART_GRACE_MS;
    }
    (void)emtask_term_poll_exit_locked(term, NULL, NULL);
    if (!term->running) {
        emtask_mutex_unlock(&term->lock);
        return SSH_OK;
    }

    {
        int status = emtask_platform_term_write_locked(term, buf, len, written_len);
        emtask_mutex_unlock(&term->lock);
        return status;
    }

    emtask_mutex_unlock(&term->lock);
    return SSH_OK;
}

static int emtask_term_read(
    void *ctx,
    void *handle_ptr,
    uint8_t *buf,
    size_t len,
    size_t *read_len)
{
    emtask_term_attachment_t *attachment = (emtask_term_attachment_t *)handle_ptr;
    emtask_term_t *term = (emtask_term_t *)ctx;

    if (read_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    *read_len = 0u;
    if (term == NULL || attachment == NULL || !attachment->active || (buf == NULL && len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (len == 0u) {
        return SSH_OK;
    }

    emtask_mutex_lock(&term->lock);
    if (!term->running) {
        emtask_mutex_unlock(&term->lock);
        return SSH_OK;
    }

    {
        size_t screen_len = emtask_screen_snapshot_copy_locked(term, attachment, buf, len);
        if (screen_len != 0u) {
            *read_len = screen_len;
            emtask_mutex_unlock(&term->lock);
            return SSH_OK;
        }
        size_t replay_len = emtask_term_replay_copy_locked(term, attachment, buf, len);
        if (replay_len != 0u) {
            *read_len = replay_len;
            emtask_mutex_unlock(&term->lock);
            return SSH_OK;
        }
        int status = emtask_term_capture_output_locked(term, buf, len, read_len);
        emtask_mutex_unlock(&term->lock);
        return status;
    }
}

static int emtask_term_resize(
    void *ctx,
    void *handle_ptr,
    uint32_t cols,
    uint32_t rows,
    uint32_t width_px,
    uint32_t height_px)
{
    emtask_term_attachment_t *attachment = (emtask_term_attachment_t *)handle_ptr;
    emtask_term_t *term = (emtask_term_t *)ctx;

    if (term == NULL || attachment == NULL || !attachment->active) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    emtask_mutex_lock(&term->lock);
    if (cols != 0u) {
        term->cols = cols;
    }
    if (rows != 0u) {
        term->rows = rows;
    }
    term->width_px = width_px;
    term->height_px = height_px;
    (void)emtask_screen_resize_locked(term, term->cols, term->rows);

    if (term->running) {
        int status = emtask_platform_term_resize_locked(term);
        emtask_mutex_unlock(&term->lock);
        return status;
    }

    emtask_mutex_unlock(&term->lock);
    return SSH_OK;
}

static int emtask_term_signal(void *ctx, void *handle_ptr, const char *signal_name)
{
    emtask_term_attachment_t *attachment = (emtask_term_attachment_t *)handle_ptr;
    emtask_term_t *term = (emtask_term_t *)ctx;
    int restart_requested;

    if (term == NULL || attachment == NULL || !attachment->active) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    restart_requested = emtask_term_signal_requests_restart(signal_name);
    emtask_mutex_lock(&term->lock);
    if (!term->running) {
        emtask_mutex_unlock(&term->lock);
        return SSH_OK;
    }
    if (restart_requested) {
        term->interrupt_restart_deadline_ms = emtask_monotonic_ms() + EMTASK_TERMINAL_RESTART_GRACE_MS;
    }

    {
        int status = emtask_platform_term_signal_locked(term, signal_name);
        if (status == SSH_OK && restart_requested) {
            int exited = 0;
            uint32_t observed_exit_status = 0u;
            int poll_status = emtask_term_poll_exit_locked(term, &exited, &observed_exit_status);
            if (poll_status == SSH_OK && exited != 0 && !term->faulted) {
                int restart_status = emtask_term_spawn_locked(term, 1);
                if (restart_status == SSH_OK) {
                    term->interrupt_restart_deadline_ms = 0u;
                    emtask_logf(
                        "attached task command restarted after signal %s exit status=%u",
                        signal_name != NULL ? signal_name : "",
                        observed_exit_status);
                } else {
                    term->interrupt_restart_deadline_ms = 0u;
                    status = restart_status;
                    emtask_logf(
                        "attached task command failed to restart after signal %s exit status=%u",
                        signal_name != NULL ? signal_name : "",
                        observed_exit_status);
                }
            }
        }
        emtask_mutex_unlock(&term->lock);
        return status;
    }

    emtask_mutex_unlock(&term->lock);
    return SSH_OK;
}

int emtask_term_monitor_step(emtask_term_t *term)
{
    uint8_t capture_buf[4096];

    if (term == NULL) {
        return 1;
    }

    emtask_mutex_lock(&term->lock);
    if (term->stop_monitor) {
        emtask_mutex_unlock(&term->lock);
        return 1;
    }
    if (term->started_once) {
        int run_watchdog = 1;
        if (term->running && !term->attached) {
            unsigned capture_count;
            for (capture_count = 0u; capture_count < 64u; ++capture_count) {
                size_t read_len = 0u;
                int status = emtask_term_capture_output_locked(term, capture_buf, sizeof(capture_buf), &read_len);
                if (status != SSH_OK || read_len == 0u) {
                    break;
                }
            }
            if (capture_count == 64u) {
                run_watchdog = 0;
            }
        }
        if (run_watchdog) {
            (void)emtask_term_watchdog_step_locked(term);
        }
    }
    emtask_mutex_unlock(&term->lock);
    return 0;
}

static int emtask_term_wait_exit(
    void *ctx,
    void *handle_ptr,
    int *exited,
    uint32_t *exit_status)
{
    emtask_term_attachment_t *attachment = (emtask_term_attachment_t *)handle_ptr;
    emtask_term_t *term = (emtask_term_t *)ctx;
    int status;

    if (term == NULL || attachment == NULL || !attachment->active || exited == NULL || exit_status == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *exited = 0;
    *exit_status = 0u;

    emtask_mutex_lock(&term->lock);
    status = emtask_term_poll_exit_locked(term, exited, exit_status);
    if (status == SSH_OK && *exited != 0 &&
        (*exit_status != 0u ||
         (term->interrupt_restart_deadline_ms != 0u && emtask_monotonic_ms() <= term->interrupt_restart_deadline_ms)) &&
        !term->faulted) {
        uint32_t observed_exit_status = *exit_status;
        int restart_status = emtask_term_spawn_locked(term, 1);
        if (restart_status == SSH_OK) {
            *exited = 0;
            *exit_status = 0u;
            term->interrupt_restart_deadline_ms = 0u;
            emtask_logf("attached task command restarted after exit status=%u", observed_exit_status);
        } else {
            term->interrupt_restart_deadline_ms = 0u;
            emtask_logf("attached task command failed to restart after exit status=%u", observed_exit_status);
        }
    }
    if (status == SSH_OK && *exited == 0) {
        status = emtask_term_update_for_wait_locked(term);
    }
    emtask_mutex_unlock(&term->lock);
    return status;
}

static int emtask_term_close(void *ctx, void *handle_ptr)
{
    emtask_term_attachment_t *attachment = (emtask_term_attachment_t *)handle_ptr;
    emtask_term_t *term = (emtask_term_t *)ctx;

    if (term == NULL || attachment == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    emtask_mutex_lock(&term->lock);
    if (attachment->active) {
        attachment->active = 0;
        term->attached = 0;
    }
    emtask_mutex_unlock(&term->lock);
    free(attachment);
    return SSH_OK;
}

static int emtask_term_init(emtask_term_t *term, const emtask_task_config_t *config)
{
    int status;

    if (term == NULL || config == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(term, 0, sizeof(*term));
    status = emtask_mutex_init(&term->lock);
    if (status != SSH_OK) {
        return status;
    }
    status = emtask_copy_text(term->command, sizeof(term->command), config->command);
    if (status != SSH_OK) {
        emtask_mutex_deinit(&term->lock);
        return status;
    }
    status = emtask_copy_text(term->working_dir, sizeof(term->working_dir), config->working_dir);
    if (status != SSH_OK) {
        emtask_mutex_deinit(&term->lock);
        return status;
    }
    term->restart_limit = config->restart_limit;
    term->restart_window_ms = (uint64_t)config->restart_window_sec * 1000u;
    term->replay_on_attach = config->replay_on_attach;
    term->repaint_on_attach = config->repaint_on_attach;
    term->screen_snapshot = config->screen_snapshot;
    if (config->replay_buffer_bytes != 0u) {
        term->replay_buffer = (uint8_t *)calloc(1u, config->replay_buffer_bytes);
        if (term->replay_buffer == NULL) {
            emtask_mutex_deinit(&term->lock);
            return SSH_ERR_PLATFORM;
        }
        term->replay_capacity = config->replay_buffer_bytes;
    }
    term->cols = EMTASK_DEFAULT_TERM_COLS;
    term->rows = EMTASK_DEFAULT_TERM_ROWS;
    status = emtask_screen_resize_locked(term, term->cols, term->rows);
    if (status != SSH_OK) {
        free(term->replay_buffer);
        term->replay_buffer = NULL;
        emtask_mutex_deinit(&term->lock);
        return status;
    }
    term->api.spawn_shell = emtask_term_spawn_shell;
    term->api.spawn_exec = emtask_term_spawn_exec;
    term->api.write = emtask_term_write;
    term->api.read = emtask_term_read;
    term->api.resize = emtask_term_resize;
    term->api.signal = emtask_term_signal;
    term->api.wait_exit = emtask_term_wait_exit;
    term->api.close = emtask_term_close;
    term->api.ctx = term;
    term->initialized = 1;
    status = emtask_platform_term_init(term, config);
    if (status != SSH_OK) {
        term->initialized = 0;
        free(term->replay_buffer);
        term->replay_buffer = NULL;
        free(term->screen_cells);
        term->screen_cells = NULL;
        emtask_mutex_deinit(&term->lock);
        return status;
    }
    return SSH_OK;
}

static void emtask_term_deinit(emtask_term_t *term)
{
    if (term == NULL || !term->initialized) {
        return;
    }
    emtask_mutex_lock(&term->lock);
    term->stop_monitor = 1;
    emtask_mutex_unlock(&term->lock);
    emtask_platform_term_deinit(term);
    emtask_mutex_lock(&term->lock);
    emtask_term_close_handles_locked(term, 1);
    emtask_mutex_unlock(&term->lock);
    emtask_mutex_deinit(&term->lock);
    if (term->platform != NULL) {
        free(term->platform);
        term->platform = NULL;
    }
    free(term->replay_buffer);
    term->replay_buffer = NULL;
    free(term->screen_cells);
    term->screen_cells = NULL;
    memset(term, 0, sizeof(*term));
}

static const ssh_term_api_t *emtask_term_api(const emtask_term_t *term)
{
    return term != NULL && term->initialized ? &term->api : NULL;
}

static void emtask_session_manager_release(emtask_session_manager_t *manager, emtask_worker_t *worker)
{
    if (manager == NULL || worker == NULL || !manager->initialized) {
        return;
    }
    emtask_mutex_lock(&manager->lock);
    if (manager->active_worker == worker) {
        manager->active_worker = NULL;
        emtask_cond_broadcast(&manager->cv);
    }
    emtask_mutex_unlock(&manager->lock);
}

static int emtask_session_manager_takeover(emtask_session_manager_t *manager, emtask_worker_t *worker)
{
    if (manager == NULL || worker == NULL || !manager->initialized) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    for (;;) {
        emtask_mutex_lock(&manager->lock);
        if (manager->active_worker == NULL || manager->active_worker == worker) {
            manager->active_worker = worker;
            emtask_mutex_unlock(&manager->lock);
            return SSH_OK;
        }
        emtask_logf(
            "disconnecting previous session %s for new session %s",
            emtask_endpoint_peer(&manager->active_worker->endpoint),
            emtask_endpoint_peer(&worker->endpoint));
        emtask_endpoint_request_shutdown(&manager->active_worker->endpoint);
        while (manager->active_worker != NULL && manager->active_worker != worker) {
            emtask_cond_wait(&manager->cv, &manager->lock);
        }
        manager->active_worker = worker;
        emtask_mutex_unlock(&manager->lock);
        return SSH_OK;
    }
}

static int emtask_before_auto_channel_accept(
    void *ctx,
    ssh_server_channel_kind_t kind,
    struct ssh_transport_session *transport,
    void *conn)
{
    emtask_worker_t *worker;

    (void)transport;
    (void)conn;
    worker = (emtask_worker_t *)ctx;
    if (worker == NULL || worker->task == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (kind == SSH_SERVER_CHANNEL_KIND_TERMINAL) {
        return emtask_session_manager_takeover(&worker->task->session_manager, worker);
    }
    return SSH_OK;
}

static int emtask_run_worker_session(emtask_worker_t *worker)
{
    emtask_app_t *app;
    emtask_crypto_context_t crypto_ctx;
    ssh_platform_t platform;
    ssh_server_t server;
    ssh_server_config_t server_config;
    ssh_server_session_options_t options;
    ssh_transport_session_t transport;
    ssh_server_terminal_channel_t channel;
    ssh_server_sftp_channel_t sftp_channel;
    ssh_stdio_fs_t sftp_fs;
    ssh_server_channel_kind_t channel_kind;
    const ssh_crypto_api_t *crypto;
    int status;
    int server_initialized;
    int channel_initialized;
    int sftp_channel_initialized;
    int sftp_fs_initialized;

    if (worker == NULL || worker->app == NULL || worker->task == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    app = worker->app;
    memset(&crypto_ctx, 0, sizeof(crypto_ctx));
    memset(&platform, 0, sizeof(platform));
    memset(&server, 0, sizeof(server));
    memset(&transport, 0, sizeof(transport));
    memset(&channel, 0, sizeof(channel));
    memset(&sftp_channel, 0, sizeof(sftp_channel));
    memset(&sftp_fs, 0, sizeof(sftp_fs));
    channel_kind = SSH_SERVER_CHANNEL_KIND_NONE;
    server_initialized = 0;
    channel_initialized = 0;
    sftp_channel_initialized = 0;
    sftp_fs_initialized = 0;

    status = ssh_crypto_open(EMTASK_CTX_PTR(&crypto_ctx));
    if (status != SSH_OK) {
        return status;
    }

    crypto = ssh_crypto_api(EMTASK_CTX_CONST_PTR(&crypto_ctx));
    if (crypto == NULL || crypto->hostkey_import_private_auto == NULL) {
        ssh_crypto_close(EMTASK_CTX_PTR(&crypto_ctx));
        return SSH_ERR_UNSUPPORTED;
    }
    status = crypto->hostkey_import_private_auto(
        crypto->ctx,
        emtask_hostkey_algorithm_view(),
        app->hostkey_private,
        app->hostkey_private_len);
    if (status != SSH_OK) {
        ssh_crypto_close(EMTASK_CTX_PTR(&crypto_ctx));
        return status;
    }

    platform.net = &g_emtask_net_api;
    platform.term = emtask_term_api(&worker->task->term);
    if (worker->task->config.use_sftp) {
        const char *sftp_root = worker->task->config.working_dir[0] != '\0' ? worker->task->config.working_dir : ".";

        status = ssh_stdio_fs_init(&sftp_fs, sftp_root);
        if (status != SSH_OK) {
            ssh_crypto_close(EMTASK_CTX_PTR(&crypto_ctx));
            return status;
        }
        sftp_fs_initialized = 1;
        platform.fs = ssh_stdio_fs_api(&sftp_fs);
    }
    platform.crypto = crypto;
    platform.rng = ssh_crypto_rng_api(EMTASK_CTX_CONST_PTR(&crypto_ctx));

    ssh_server_config_defaults(&server_config);
    server_config.software_name = "emtask";
    if ((app->config.global.auth_backend == EMTASK_AUTH_BACKEND_INTERNAL && app->config.global.password[0] != '\0') ||
        app->config.global.auth_backend == EMTASK_AUTH_BACKEND_PASSWD) {
        server_config.password_auth = emtask_password_auth_dispatch;
    }
    if (app->config.global.authorized_keys_file[0] != '\0') {
        server_config.publickey_auth = emtask_publickey_auth_dispatch;
    }
    server_config.auth_ctx = app;

    status = ssh_server_init(&server, &platform, &server_config);
    if (status != SSH_OK) {
        if (sftp_fs_initialized) {
            ssh_stdio_fs_deinit(&sftp_fs);
        }
        ssh_crypto_close(EMTASK_CTX_PTR(&crypto_ctx));
        return status;
    }
    server_initialized = 1;

    ssh_server_session_options_defaults(&options);
    options.timeout_ms = app->config.global.timeout_ms;
    options.max_sftp_packets = 0u;

    status = ssh_server_run_transport_setup(&server, &worker->endpoint, &transport, &options);
    if (status == SSH_OK) {
        status = ssh_server_run_userauth(&transport, &worker->endpoint, &options);
    }
    if (status == SSH_OK) {
        if (worker->task->config.use_sftp) {
            status = ssh_server_accept_auto_channel(
                &transport,
                &worker->endpoint,
                &sftp_channel,
                &channel,
                &options,
                &channel_kind,
                emtask_before_auto_channel_accept,
                worker);
            if (status == SSH_OK && channel_kind == SSH_SERVER_CHANNEL_KIND_SFTP) {
                sftp_channel_initialized = 1;
            } else if (status == SSH_OK && channel_kind == SSH_SERVER_CHANNEL_KIND_TERMINAL) {
                channel_initialized = 1;
            } else if (status == SSH_OK) {
                status = SSH_ERR_UNSUPPORTED;
            }
        } else {
            status = emtask_session_manager_takeover(&worker->task->session_manager, worker);
            if (status == SSH_OK) {
                status = ssh_server_accept_terminal_channel(&transport, &worker->endpoint, &channel, &options);
            }
            if (status == SSH_OK) {
                channel_initialized = 1;
            }
        }
    }
    while (status == SSH_OK) {
        if (sftp_channel_initialized) {
            status = ssh_server_process_sftp_channel_data(&transport, &worker->endpoint, &sftp_channel, &options);
            if (status == SSH_ERR_NOT_FOUND) {
                status = SSH_OK;
            } else if (status == SSH_ERR_CLOSED) {
                status = SSH_OK;
                break;
            }
        } else {
            status = ssh_server_process_terminal_channel_data(&transport, &worker->endpoint, &channel, &options);
            if (status == SSH_ERR_NOT_FOUND) {
                status = SSH_OK;
            } else if (status == SSH_ERR_CLOSED) {
                status = SSH_OK;
                break;
            }
        }
    }

    if (sftp_channel_initialized) {
        ssh_server_sftp_channel_deinit(&sftp_channel);
    }
    if (channel_initialized) {
        ssh_server_terminal_channel_deinit(&transport, &channel);
    }
    emtask_session_manager_release(&worker->task->session_manager, worker);
    (void)emtask_endpoint_close(&worker->endpoint);

    if (server_initialized) {
        ssh_server_deinit(&server);
    }
    if (sftp_fs_initialized) {
        ssh_stdio_fs_deinit(&sftp_fs);
    }
    ssh_crypto_close(EMTASK_CTX_PTR(&crypto_ctx));
    return status;
}

void emtask_worker_thread_main(emtask_worker_t *worker)
{
    int status;

    if (worker != NULL) {
        status = emtask_run_worker_session(worker);
        if (status != SSH_OK) {
            emtask_logf(
                "session ended for %s: %s",
                emtask_endpoint_peer(&worker->endpoint),
                ssh_status_string(status));
        }
        if (worker->task != NULL && worker->app != NULL && worker->app->task_lock_initialized) {
            emtask_mutex_lock(&worker->app->task_lock);
            if (worker->task->worker_count > 0u) {
                --worker->task->worker_count;
            }
            emtask_mutex_unlock(&worker->app->task_lock);
        }
        emtask_worker_pool_release(&worker->app->pool);
        free(worker);
    }
}

static int emtask_start_worker_thread(emtask_worker_t *worker)
{
    return emtask_platform_start_worker_thread(worker);
}

static int emtask_task_open_listener(emtask_task_t *task)
{
    emtask_app_t *app;
    const char *listen_address;
    int status;

    if (task == NULL || task->app == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (task->listener_open) {
        return SSH_OK;
    }

    app = task->app;
    listen_address = task->config.listen_address[0] != '\0' ? task->config.listen_address : NULL;
    status = ssh_tcp_listen(
        &app->tcp,
        listen_address,
        task->config.port,
        (int)app->config.global.max_workers,
        &task->listener);
    if (status != SSH_OK) {
        emtask_logf(
            "task %s listen failed on %s:%u: %s",
            task->config.name,
            listen_address != NULL ? listen_address : "0.0.0.0",
            (unsigned)task->config.port,
            ssh_status_string(status));
        return status;
    }
    task->listener_open = 1;
    return SSH_OK;
}

void emtask_listener_thread_main(emtask_task_t *task)
{
    int status;
    unsigned bind_attempt;

    if (task == NULL || task->app == NULL) {
        return;
    }
    bind_attempt = 0u;
    task->listener_thread_running = 1;

    for (;;) {
        ssh_tcp_conn_t accepted;
        emtask_worker_t *worker;

        if (task->stop_requested || task->deleted) {
            break;
        }
        if (!task->listener_open) {
            status = emtask_task_open_listener(task);
            if (status != SSH_OK) {
                unsigned delay_sec;

                if (task->stop_requested || task->deleted) {
                    break;
                }
                if (!emtask_bind_retry_enabled(task->app)) {
                    emtask_logf("task %s listener disabled after bind failure", task->config.name);
                    break;
                }
                delay_sec = emtask_bind_retry_delay_sec(&task->app->config.global, bind_attempt);
                emtask_logf(
                    "task %s listen retry in %u second(s), attempt=%u, max=%us",
                    task->config.name,
                    delay_sec,
                    bind_attempt + 1u,
                    emtask_bind_retry_max_sec(&task->app->config.global));
                emtask_bind_retry_sleep(&task->app->config.global, &bind_attempt);
                continue;
            }
            if (bind_attempt != 0u) {
                emtask_logf(
                    "task %s listener recovered on %s:%u",
                    task->config.name,
                    task->config.listen_address[0] != '\0' ? task->config.listen_address : "0.0.0.0",
                    (unsigned)task->config.port);
                bind_attempt = 0u;
            }
        }

        memset(&accepted, 0, sizeof(accepted));
        emtask_worker_pool_reserve(&task->app->pool);
        status = ssh_tcp_accept(&task->app->tcp, &task->listener, &accepted, 0u);
        if (status != SSH_OK) {
            emtask_worker_pool_release(&task->app->pool);
            if (task->stop_requested || task->deleted) {
                break;
            }
            emtask_logf("task %s accept failed: %s", task->config.name, ssh_status_string(status));
            continue;
        }

        worker = (emtask_worker_t *)calloc(1u, sizeof(*worker));
        if (worker == NULL) {
            (void)ssh_tcp_conn_close(&task->app->tcp, &accepted);
            emtask_worker_pool_release(&task->app->pool);
            emtask_logf("task %s worker alloc failed", task->config.name);
            continue;
        }

        worker->app = task->app;
        worker->task = task;
        emtask_endpoint_init(&worker->endpoint, &accepted);
        if (task->app->task_lock_initialized) {
            emtask_mutex_lock(&task->app->task_lock);
            if (task->stop_requested || task->deleted) {
                emtask_mutex_unlock(&task->app->task_lock);
                (void)emtask_endpoint_close(&worker->endpoint);
                emtask_worker_pool_release(&task->app->pool);
                free(worker);
                break;
            }
            ++task->worker_count;
            emtask_mutex_unlock(&task->app->task_lock);
        }
        emtask_logf(
            "task %s accepted connection from %s",
            task->config.name,
            emtask_endpoint_peer(&worker->endpoint));

        status = emtask_start_worker_thread(worker);
        if (status != SSH_OK) {
            (void)emtask_endpoint_close(&worker->endpoint);
            if (task->app->task_lock_initialized) {
                emtask_mutex_lock(&task->app->task_lock);
                if (task->worker_count > 0u) {
                    --task->worker_count;
                }
                emtask_mutex_unlock(&task->app->task_lock);
            }
            emtask_worker_pool_release(&task->app->pool);
            free(worker);
            emtask_logf("task %s failed to start worker thread", task->config.name);
        }
    }
    task->listener_thread_running = 0;
}

static int emtask_task_init(emtask_app_t *app, emtask_task_t *task, const emtask_task_config_t *config)
{
    int status;

    if (app == NULL || task == NULL || config == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(task, 0, sizeof(*task));
    task->app = app;
    task->config = *config;

    status = emtask_session_manager_init(&task->session_manager);
    if (status != SSH_OK) {
        emtask_logf("task %s session manager init failed: %s", task->config.name, ssh_status_string(status));
        return status;
    }
    status = emtask_term_init(&task->term, &task->config);
    if (status != SSH_OK) {
        emtask_logf("task %s terminal init failed: %s", task->config.name, ssh_status_string(status));
        emtask_session_manager_deinit(&task->session_manager);
        return status;
    }
    status = emtask_term_start_initial(&task->term);
    if (status != SSH_OK) {
        emtask_logf("task %s command start failed; task will stay available for manual rerun: %s", task->config.name, ssh_status_string(status));
    }
    status = emtask_task_open_listener(task);
    if (status != SSH_OK) {
        if (!emtask_bind_retry_enabled(app)) {
            emtask_term_deinit(&task->term);
            emtask_session_manager_deinit(&task->session_manager);
            return status;
        }
        emtask_logf(
            "task %s listener pending; bind retry enabled, max interval=%us",
            task->config.name,
            emtask_bind_retry_max_sec(&app->config.global));
    }

    task->initialized = 1;
    return SSH_OK;
}

static void emtask_task_deinit(emtask_app_t *app, emtask_task_t *task)
{
    if (task == NULL || !task->initialized) {
        return;
    }
    task->stop_requested = 1;
    if (task->listener_open) {
        (void)ssh_tcp_listener_close(app != NULL ? &app->tcp : NULL, &task->listener);
        task->listener_open = 0;
    }
    emtask_term_deinit(&task->term);
    emtask_session_manager_deinit(&task->session_manager);
    task->initialized = 0;
}

static int emtask_panel_init(emtask_app_t *app)
{
    int status;

    if (app == NULL || !app->config.global.panel_enabled) {
        return SSH_OK;
    }

    status = emtask_panel_open_listener(app);
    if (status != SSH_OK) {
        if (!emtask_bind_retry_enabled(app)) {
            return status;
        }
        emtask_logf(
            "panel listener pending; bind retry enabled, max interval=%us",
            emtask_bind_retry_max_sec(&app->config.global));
    }
    return SSH_OK;
}

static void emtask_panel_deinit(emtask_app_t *app)
{
    if (app == NULL || !app->panel_listener_open) {
        return;
    }
    (void)ssh_tcp_listener_close(&app->tcp, &app->panel_listener);
    app->panel_listener_open = 0;
}

static void emtask_usage(const char *program)
{
    fprintf(
        stderr,
        "usage: %s [--config <path>]\n"
        "default config path: emtask.conf\n",
        program);
}

int main(int argc, char **argv)
{
    const char *config_path;
    emtask_app_t app;
    int status;
    size_t i;

    config_path = "emtask.conf";
    if (argc == 3 && strcmp(argv[1], "--config") == 0) {
        config_path = argv[2];
    } else if (argc != 1) {
        emtask_usage(argv[0]);
        return 2;
    }

    memset(&app, 0, sizeof(app));

    status = emtask_load_config(config_path, &app.config);
    if (status != SSH_OK) {
        emtask_logf("failed to load config %s: %s", config_path, ssh_status_string(status));
        return 2;
    }
    status = emtask_prepare_hostkey(&app);
    if (status != SSH_OK) {
        emtask_logf("hostkey setup failed: %s", ssh_status_string(status));
        return 2;
    }
    status = emtask_passwd_auth_init(&app);
    if (status != SSH_OK) {
        emtask_logf("passwd auth init failed: %s", ssh_status_string(status));
        return 2;
    }
    status = ssh_tcp_platform_init(&app.tcp);
    if (status != SSH_OK) {
        emtask_logf("tcp init failed: %s", ssh_status_string(status));
        emtask_passwd_auth_deinit(&app);
        return 2;
    }
    status = emtask_worker_pool_init(&app.pool, app.config.global.max_workers);
    if (status != SSH_OK) {
        emtask_logf("worker pool init failed: %s", ssh_status_string(status));
        ssh_tcp_platform_deinit(&app.tcp);
        emtask_passwd_auth_deinit(&app);
        return 2;
    }
    status = emtask_mutex_init(&app.task_lock);
    if (status != SSH_OK) {
        emtask_logf("task lock init failed: %s", ssh_status_string(status));
        emtask_worker_pool_deinit(&app.pool);
        ssh_tcp_platform_deinit(&app.tcp);
        emtask_passwd_auth_deinit(&app);
        return 2;
    }
    app.task_lock_initialized = 1;
    app.started_ms = emtask_platform_monotonic_ms();

    app.task_count = app.config.task_count;
    app.task_capacity = EMTASK_MAX_TASKS;
    app.tasks = (emtask_task_t *)calloc(app.task_capacity, sizeof(*app.tasks));
    if (app.tasks == NULL) {
        emtask_logf("task array alloc failed");
        emtask_mutex_deinit(&app.task_lock);
        app.task_lock_initialized = 0;
        emtask_worker_pool_deinit(&app.pool);
        ssh_tcp_platform_deinit(&app.tcp);
        emtask_passwd_auth_deinit(&app);
        return 2;
    }

    for (i = 0u; i < app.task_count; ++i) {
        status = emtask_task_init(&app, &app.tasks[i], &app.config.tasks[i]);
        if (status != SSH_OK) {
            emtask_logf("task %s init failed: %s", app.config.tasks[i].name, ssh_status_string(status));
            while (i > 0u) {
                --i;
                emtask_task_deinit(&app, &app.tasks[i]);
            }
            free(app.tasks);
            emtask_mutex_deinit(&app.task_lock);
            app.task_lock_initialized = 0;
            emtask_worker_pool_deinit(&app.pool);
            ssh_tcp_platform_deinit(&app.tcp);
            emtask_passwd_auth_deinit(&app);
            return 2;
        }
    }

    status = emtask_panel_init(&app);
    if (status != SSH_OK) {
        while (i > 0u) {
            --i;
            emtask_task_deinit(&app, &app.tasks[i]);
        }
        free(app.tasks);
        emtask_mutex_deinit(&app.task_lock);
        app.task_lock_initialized = 0;
        emtask_worker_pool_deinit(&app.pool);
        ssh_tcp_platform_deinit(&app.tcp);
        emtask_passwd_auth_deinit(&app);
        return 2;
    }

    printf(
        "emtask starting %u task(s), auth=%s, user=%s, backend=mbedtls_legacy\n",
        (unsigned)app.task_count,
        app.config.global.auth_backend == EMTASK_AUTH_BACKEND_PASSWD ? "passwd" : "internal",
        app.config.global.username[0] != '\0' ? app.config.global.username : "<system>");
    for (i = 0u; i < app.task_count; ++i) {
        printf(
            "  task %s %s on %s:%u, restart_limit=%u/%us\n",
            app.tasks[i].config.name,
            app.tasks[i].listener_open ? "listening" : "listener pending",
            app.tasks[i].config.listen_address[0] != '\0' ? app.tasks[i].config.listen_address : "0.0.0.0",
            (unsigned)app.tasks[i].config.port,
            app.tasks[i].config.restart_limit,
            app.tasks[i].config.restart_window_sec);
    }
    if (app.config.global.panel_enabled) {
        printf(
            "  panel %s on %s:%u\n",
            app.panel_listener_open ? "listening" : "listener pending",
            app.config.global.panel_listen_address[0] != '\0'
                ? app.config.global.panel_listen_address
                : EMTASK_DEFAULT_PANEL_LISTEN_ADDRESS,
            (unsigned)app.config.global.panel_port);
    }
    fflush(stdout);

    if (app.config.global.panel_enabled) {
        for (i = 0u; i < app.task_count; ++i) {
            app.tasks[i].listener_thread_running = 1;
            status = emtask_platform_start_listener_thread(&app.tasks[i]);
            if (status != SSH_OK) {
                app.tasks[i].listener_thread_running = 0;
                emtask_logf("task %s listener thread start failed: %s", app.tasks[i].config.name, ssh_status_string(status));
                return 2;
            }
        }
        emtask_panel_thread_main(&app);
        return 0;
    }

    for (i = 1u; i < app.task_count; ++i) {
        app.tasks[i].listener_thread_running = 1;
        status = emtask_platform_start_listener_thread(&app.tasks[i]);
        if (status != SSH_OK) {
            app.tasks[i].listener_thread_running = 0;
            emtask_logf("task %s listener thread start failed: %s", app.tasks[i].config.name, ssh_status_string(status));
            return 2;
        }
    }

    app.tasks[0].listener_thread_running = 1;
    emtask_listener_thread_main(&app.tasks[0]);
    return 0;
}
