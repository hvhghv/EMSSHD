#include "emtask_internal.h"

#include "emssh/crypto_mbedtls.h"
#include "emssh/ssh_crypto.h"
#include "emssh/ssh_transport.h"

typedef ssh_crypto_context_mbedtls_legacy_t emtask_crypto_context_t;
#define EMTASK_CTX_PTR(ctx) ((ssh_crypto_context_t *)(ctx))
#define EMTASK_CTX_CONST_PTR(ctx) ((const ssh_crypto_context_t *)(ctx))

static int emtask_net_read(void *ctx, void *conn, uint8_t *buf, size_t len, uint32_t timeout_ms);
static int emtask_net_write(void *ctx, void *conn, const uint8_t *buf, size_t len, uint32_t timeout_ms);
static int emtask_net_close(void *ctx, void *conn);

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
    (void)emtask_copy_text(config->global.hostkey_file, sizeof(config->global.hostkey_file), "emtask_hostkey_p256.raw");
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
                 emtask_key_equals(key, "restart_limit") ||
                 emtask_key_equals(key, "restart_window_sec") ||
                 emtask_key_equals(key, "replay_buffer_bytes") ||
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

    if (config->global.auth_backend == EMTASK_AUTH_BACKEND_INTERNAL && config->global.username[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (config->global.auth_backend == EMTASK_AUTH_BACKEND_INTERNAL &&
        config->global.password[0] == '\0' &&
        config->global.authorized_keys_file[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (config->global.max_workers == 0u || config->task_count == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    for (size_t i = 0u; i < config->task_count; ++i) {
        if (config->tasks[i].name[0] == '\0' || config->tasks[i].command[0] == '\0' || config->tasks[i].port == 0u) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
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
        emtask_logf("started task command: %s", term->command);
    } else {
        term->faulted = 1;
        emtask_logf("failed to start task command: %s", term->command);
    }
    return status;
}

static int emtask_term_poll_exit_locked(emtask_term_t *term, int *exited, uint32_t *exit_status)
{
    if (exited != NULL) {
        *exited = 0;
    }
    if (exit_status != NULL) {
        *exit_status = term != NULL ? term->last_exit_status : 0u;
    }
    if (term == NULL || !term->running) {
        return SSH_OK;
    }

    return emtask_platform_term_poll_exit_locked(term, exited, exit_status);
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

    (void)signal_name;

    if (term == NULL || attachment == NULL || !attachment->active) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    emtask_mutex_lock(&term->lock);
    if (!term->running) {
        emtask_mutex_unlock(&term->lock);
        return SSH_OK;
    }

    {
        int status = emtask_platform_term_signal_locked(term, signal_name);
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
    const ssh_crypto_api_t *crypto;
    int status;
    int server_initialized;
    int channel_initialized;

    if (worker == NULL || worker->app == NULL || worker->task == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    app = worker->app;
    memset(&crypto_ctx, 0, sizeof(crypto_ctx));
    memset(&platform, 0, sizeof(platform));
    memset(&server, 0, sizeof(server));
    memset(&transport, 0, sizeof(transport));
    memset(&channel, 0, sizeof(channel));
    server_initialized = 0;
    channel_initialized = 0;

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
        status = emtask_session_manager_takeover(&worker->task->session_manager, worker);
    }
    if (status == SSH_OK) {
        status = ssh_server_accept_terminal_channel(&transport, &worker->endpoint, &channel, &options);
        if (status == SSH_OK) {
            channel_initialized = 1;
        }
    }
    while (status == SSH_OK) {
        status = ssh_server_process_terminal_channel_data(&transport, &worker->endpoint, &channel, &options);
        if (status == SSH_ERR_NOT_FOUND) {
            status = SSH_OK;
        } else if (status == SSH_ERR_CLOSED) {
            status = SSH_OK;
            break;
        }
    }

    if (channel_initialized) {
        ssh_server_terminal_channel_deinit(&transport, &channel);
    }
    emtask_session_manager_release(&worker->task->session_manager, worker);
    (void)emtask_endpoint_close(&worker->endpoint);

    if (server_initialized) {
        ssh_server_deinit(&server);
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
        emtask_worker_pool_release(&worker->app->pool);
        free(worker);
    }
}

static int emtask_start_worker_thread(emtask_worker_t *worker)
{
    return emtask_platform_start_worker_thread(worker);
}

void emtask_listener_thread_main(emtask_task_t *task)
{
    int status;

    if (task == NULL || task->app == NULL) {
        return;
    }

    for (;;) {
        ssh_tcp_conn_t accepted;
        emtask_worker_t *worker;

        memset(&accepted, 0, sizeof(accepted));
        emtask_worker_pool_reserve(&task->app->pool);
        status = ssh_tcp_accept(&task->app->tcp, &task->listener, &accepted, 0u);
        if (status != SSH_OK) {
            emtask_worker_pool_release(&task->app->pool);
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
        emtask_logf(
            "task %s accepted connection from %s",
            task->config.name,
            emtask_endpoint_peer(&worker->endpoint));

        status = emtask_start_worker_thread(worker);
        if (status != SSH_OK) {
            (void)emtask_endpoint_close(&worker->endpoint);
            emtask_worker_pool_release(&task->app->pool);
            free(worker);
            emtask_logf("task %s failed to start worker thread", task->config.name);
        }
    }
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
        emtask_logf("task %s command start failed: %s", task->config.name, ssh_status_string(status));
        emtask_term_deinit(&task->term);
        emtask_session_manager_deinit(&task->session_manager);
        return status;
    }
    status = ssh_tcp_listen(
        &app->tcp,
        task->config.listen_address[0] != '\0' ? task->config.listen_address : NULL,
        task->config.port,
        (int)app->config.global.max_workers,
        &task->listener);
    if (status != SSH_OK) {
        emtask_logf(
            "task %s listen failed on %s:%u: %s",
            task->config.name,
            task->config.listen_address[0] != '\0' ? task->config.listen_address : "0.0.0.0",
            (unsigned)task->config.port,
            ssh_status_string(status));
        emtask_term_deinit(&task->term);
        emtask_session_manager_deinit(&task->session_manager);
        return status;
    }

    task->listener_open = 1;
    task->initialized = 1;
    return SSH_OK;
}

static void emtask_task_deinit(emtask_app_t *app, emtask_task_t *task)
{
    if (task == NULL || !task->initialized) {
        return;
    }
    if (task->listener_open) {
        (void)ssh_tcp_listener_close(app != NULL ? &app->tcp : NULL, &task->listener);
        task->listener_open = 0;
    }
    emtask_term_deinit(&task->term);
    emtask_session_manager_deinit(&task->session_manager);
    task->initialized = 0;
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

    app.task_count = app.config.task_count;
    app.tasks = (emtask_task_t *)calloc(app.task_count, sizeof(*app.tasks));
    if (app.tasks == NULL) {
        emtask_logf("task array alloc failed");
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
            emtask_worker_pool_deinit(&app.pool);
            ssh_tcp_platform_deinit(&app.tcp);
            emtask_passwd_auth_deinit(&app);
            return 2;
        }
    }

    printf(
        "emtask starting %u task(s), auth=%s, user=%s, backend=mbedtls_legacy\n",
        (unsigned)app.task_count,
        app.config.global.auth_backend == EMTASK_AUTH_BACKEND_PASSWD ? "passwd" : "internal",
        app.config.global.username[0] != '\0' ? app.config.global.username : "<system>");
    for (i = 0u; i < app.task_count; ++i) {
        printf(
            "  task %s listening on %s:%u, restart_limit=%u/%us\n",
            app.tasks[i].config.name,
            app.tasks[i].config.listen_address[0] != '\0' ? app.tasks[i].config.listen_address : "0.0.0.0",
            (unsigned)app.tasks[i].config.port,
            app.tasks[i].config.restart_limit,
            app.tasks[i].config.restart_window_sec);
    }
    fflush(stdout);

    for (i = 1u; i < app.task_count; ++i) {
        status = emtask_platform_start_listener_thread(&app.tasks[i]);
        if (status != SSH_OK) {
            emtask_logf("task %s listener thread start failed: %s", app.tasks[i].config.name, ssh_status_string(status));
            return 2;
        }
    }

    emtask_listener_thread_main(&app.tasks[0]);
    return 0;
}
