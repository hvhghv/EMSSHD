#include "emssh/sshd_config_file.h"

#include <string.h>

#include "emssh/sftp.h"
#include "emssh/ssh_error.h"

static int is_space_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

static char *trim_left(char *text)
{
    while (text != NULL && *text != '\0' && is_space_char(*text)) {
        ++text;
    }
    return text;
}

static void trim_right_inplace(char *text)
{
    size_t len;

    if (text == NULL) {
        return;
    }
    len = strlen(text);
    while (len > 0u && is_space_char(text[len - 1u])) {
        text[len - 1u] = '\0';
        --len;
    }
}

static int str_ieq(const char *a, const char *b)
{
    unsigned char ca;
    unsigned char cb;

    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a != '\0' && *b != '\0') {
        ca = (unsigned char)*a;
        cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') {
            ca = (unsigned char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (unsigned char)(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return 0;
        }
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

static int parse_bool_value(const char *value, int *out)
{
    if (value == NULL || out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (str_ieq(value, "yes") || str_ieq(value, "true") || str_ieq(value, "on") || str_ieq(value, "1")) {
        *out = 1;
        return SSH_OK;
    }
    if (str_ieq(value, "no") || str_ieq(value, "false") || str_ieq(value, "off") || str_ieq(value, "0")) {
        *out = 0;
        return SSH_OK;
    }
    return SSH_ERR_INVALID_ARGUMENT;
}

static int parse_permit_root_login_value(const char *value, int *out)
{
    if (value == NULL || out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (str_ieq(value, "yes")) {
        *out = EMSSH_PERMIT_ROOT_LOGIN_YES;
        return SSH_OK;
    }
    if (str_ieq(value, "no")) {
        *out = EMSSH_PERMIT_ROOT_LOGIN_NO;
        return SSH_OK;
    }
    if (str_ieq(value, "prohibit-password") ||
        str_ieq(value, "without-password") ||
        str_ieq(value, "forced-commands-only")) {
        *out = EMSSH_PERMIT_ROOT_LOGIN_PROHIBIT_PASSWORD;
        return SSH_OK;
    }

    return SSH_ERR_INVALID_ARGUMENT;
}

static int parse_uint_in_range(const char *value, unsigned long max_value, unsigned long *out);

static int parse_listen_address(const char *value, char *host_out, size_t host_out_capacity, uint16_t *port_out)
{
    size_t len;

    if (value == NULL || value[0] == '\0' || host_out == NULL || host_out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    len = strlen(value);
    if (len >= host_out_capacity) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    memcpy(host_out, value, len + 1u);

    if (port_out != NULL && value[0] == '[') {
        const char *close = strchr(value, ']');
        if (close != NULL && close[1] == ':' && close[2] != '\0') {
            unsigned long parsed_ulong = 0ul;
            int rc = parse_uint_in_range(close + 2, 65535ul, &parsed_ulong);
            if (rc != SSH_OK) {
                return rc;
            }
            *port_out = (uint16_t)parsed_ulong;
        }
    }

    return SSH_OK;
}

static int parse_subsystem_value(const char *value, char *name_out, size_t name_out_capacity)
{
    const char *p;
    size_t len;

    if (value == NULL || name_out == NULL || name_out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    p = value;
    while (*p != '\0' && is_space_char(*p)) {
        ++p;
    }
    if (*p == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    value = p;
    while (*p != '\0' && !is_space_char(*p)) {
        ++p;
    }
    len = (size_t)(p - value);
    if (len == 0u || len >= name_out_capacity) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memcpy(name_out, value, len);
    name_out[len] = '\0';
    return SSH_OK;
}

static int parse_uint_in_range(const char *value, unsigned long max_value, unsigned long *out)
{
    unsigned long parsed;
    size_t i;

    if (value == NULL || out == NULL || value[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    parsed = 0ul;
    for (i = 0u; value[i] != '\0'; ++i) {
        unsigned long digit;

        if (value[i] < '0' || value[i] > '9') {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        digit = (unsigned long)(value[i] - '0');
        if (parsed > (max_value - digit) / 10ul) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        parsed = parsed * 10ul + digit;
    }
    if (parsed == 0ul) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *out = parsed;
    return SSH_OK;
}

static int set_string_value(char *dst, size_t dst_capacity, int *has_value, const char *src)
{
    size_t len;

    if (dst == NULL || dst_capacity == 0u || has_value == NULL || src == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    len = strlen(src);
    if (len == 0u || len >= dst_capacity) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memcpy(dst, src, len + 1u);
    *has_value = 1;
    return SSH_OK;
}

static int parse_one_directive(char *key, char *value, ssh_sshd_config_file_t *config)
{
    unsigned long parsed_ulong;
    int parsed_bool;
    int rc;

    if (key == NULL || value == NULL || config == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (str_ieq(key, "Port")) {
        rc = parse_uint_in_range(value, 65535ul, &parsed_ulong);
        if (rc != SSH_OK) {
            return rc;
        }
        config->has_port = 1;
        config->port = (uint16_t)parsed_ulong;
        return SSH_OK;
    }

    if (str_ieq(key, "ListenAddress")) {
        rc = parse_listen_address(
            value,
            config->listen_address,
            sizeof(config->listen_address),
            config->has_port ? NULL : &config->port);
        if (rc != SSH_OK) {
            return rc;
        }
        config->has_listen_address = 1;
        if (!config->has_port && config->port != 0u) {
            config->has_port = 1;
        }
        return SSH_OK;
    }

    if (str_ieq(key, "MaxAuthTries")) {
        rc = parse_uint_in_range(value, 255ul, &parsed_ulong);
        if (rc != SSH_OK) {
            return rc;
        }
        config->has_max_auth_tries = 1;
        config->max_auth_tries = (unsigned)parsed_ulong;
        return SSH_OK;
    }

    if (str_ieq(key, "PasswordAuthentication")) {
        rc = parse_bool_value(value, &parsed_bool);
        if (rc != SSH_OK) {
            return rc;
        }
        config->has_password_authentication = 1;
        config->password_authentication = parsed_bool;
        return SSH_OK;
    }

    if (str_ieq(key, "PubkeyAuthentication")) {
        rc = parse_bool_value(value, &parsed_bool);
        if (rc != SSH_OK) {
            return rc;
        }
        config->has_pubkey_authentication = 1;
        config->pubkey_authentication = parsed_bool;
        return SSH_OK;
    }

    if (str_ieq(key, "PermitRootLogin")) {
        rc = parse_permit_root_login_value(value, &config->permit_root_login);
        if (rc != SSH_OK) {
            return rc;
        }
        config->has_permit_root_login = 1;
        return SSH_OK;
    }

    if (str_ieq(key, "AllowUsers")) {
        return set_string_value(
            config->allow_users,
            sizeof(config->allow_users),
            &config->has_allow_users,
            value);
    }

    if (str_ieq(key, "Subsystem")) {
        rc = parse_subsystem_value(
            value,
            config->subsystem_name,
            sizeof(config->subsystem_name));
        if (rc != SSH_OK) {
            return rc;
        }
        config->has_subsystem = 1;
        return SSH_OK;
    }

    if (str_ieq(key, "AuthorizedKeysFile")) {
        return set_string_value(
            config->authorized_keys_file,
            sizeof(config->authorized_keys_file),
            &config->has_authorized_keys_file,
            value);
    }

    if (str_ieq(key, "KexAlgorithms")) {
        return set_string_value(
            config->kex_algorithms,
            sizeof(config->kex_algorithms),
            &config->has_kex_algorithms,
            value);
    }

    if (str_ieq(key, "HostKeyAlgorithms")) {
        return set_string_value(
            config->hostkey_algorithms,
            sizeof(config->hostkey_algorithms),
            &config->has_hostkey_algorithms,
            value);
    }

    if (str_ieq(key, "Ciphers")) {
        return set_string_value(
            config->ciphers,
            sizeof(config->ciphers),
            &config->has_ciphers,
            value);
    }

    if (str_ieq(key, "MACs")) {
        return set_string_value(
            config->macs,
            sizeof(config->macs),
            &config->has_macs,
            value);
    }

    if (str_ieq(key, "Compression")) {
        rc = parse_bool_value(value, &parsed_bool);
        if (rc != SSH_OK) {
            return rc;
        }
        if (parsed_bool) {
            return set_string_value(
                config->compression_algorithms,
                sizeof(config->compression_algorithms),
                &config->has_compression_algorithms,
                "none");
        }
        return set_string_value(
            config->compression_algorithms,
            sizeof(config->compression_algorithms),
            &config->has_compression_algorithms,
            "none");
    }

    return SSH_OK;
}

static int parse_line_inplace(char *line, ssh_sshd_config_file_t *config)
{
    char *hash_pos;
    char *key;
    char *value;
    char *p;
    size_t value_len;

    if (line == NULL || config == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    hash_pos = strchr(line, '#');
    if (hash_pos != NULL) {
        *hash_pos = '\0';
    }
    trim_right_inplace(line);
    key = trim_left(line);
    if (key == NULL || key[0] == '\0') {
        return SSH_OK;
    }

    p = key;
    while (*p != '\0' && !is_space_char(*p) && *p != '=') {
        ++p;
    }
    if (*p == '\0') {
        return SSH_OK;
    }

    *p = '\0';
    ++p;
    while (*p != '\0' && (is_space_char(*p) || *p == '=')) {
        ++p;
    }
    value = p;
    trim_right_inplace(value);
    value = trim_left(value);
    if (value[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    value_len = strlen(value);
    if ((value[0] == '"' && value_len >= 2u && value[value_len - 1u] == '"') ||
        (value[0] == '\'' && value_len >= 2u && value[value_len - 1u] == '\'')) {
        value[value_len - 1u] = '\0';
        ++value;
    }

    return parse_one_directive(key, value, config);
}

static int read_and_parse_file_via_fs(const ssh_fs_api_t *fs, const char *path, ssh_sshd_config_file_t *config)
{
    void *handle;
    char chunk[512];
    char line[1024];
    size_t line_len;
    int status;
    size_t i;
    size_t read_len;

    if (fs == NULL || fs->open == NULL || fs->read == NULL || fs->close == NULL ||
        path == NULL || config == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

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
                line[line_len] = '\0';
                status = parse_line_inplace(line, config);
                if (status != SSH_OK) {
                    (void)fs->close(fs->ctx, handle);
                    return status;
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
        line[line_len] = '\0';
        status = parse_line_inplace(line, config);
        if (status != SSH_OK) {
            (void)fs->close(fs->ctx, handle);
            return status;
        }
    }

    (void)fs->close(fs->ctx, handle);
    return SSH_OK;
}

void ssh_sshd_config_file_defaults(ssh_sshd_config_file_t *config)
{
    if (config == NULL) {
        return;
    }
    memset(config, 0, sizeof(*config));
}

int ssh_sshd_config_file_load(
    const ssh_fs_api_t *fs,
    const char *path,
    ssh_sshd_config_file_t *config)
{
    if (config == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_sshd_config_file_defaults(config);
    return read_and_parse_file_via_fs(fs, path, config);
}

int ssh_sshd_config_file_apply(
    const ssh_sshd_config_file_t *config,
    ssh_server_config_t *server_config,
    ssh_server_session_options_t *session_options,
    ssh_kexinit_algorithm_set_t *algorithms,
    uint16_t *port)
{
    if (config == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (port != NULL && config->has_port) {
        *port = config->port;
    }

    if (server_config != NULL) {
        if (config->has_listen_address) {
            server_config->listen_address = config->listen_address;
        }
        if (config->has_max_auth_tries) {
            server_config->max_auth_tries = config->max_auth_tries;
        }
        if (config->has_password_authentication && !config->password_authentication) {
            server_config->password_auth = NULL;
        }
        if (config->has_pubkey_authentication && !config->pubkey_authentication) {
            server_config->publickey_auth = NULL;
        }
        if (config->has_permit_root_login) {
            server_config->permit_root_login = config->permit_root_login;
        }
        if (config->has_allow_users) {
            server_config->allow_users = config->allow_users;
        }
        if (config->has_authorized_keys_file) {
            server_config->authorized_keys_file = config->authorized_keys_file;
        }
    }

    if (session_options != NULL) {
        if (config->has_subsystem) {
            session_options->sftp_subsystem_name = config->subsystem_name;
        }
    }

    if (algorithms != NULL) {
        if (config->has_kex_algorithms) {
            algorithms->kex_algorithms = config->kex_algorithms;
        }
        if (config->has_hostkey_algorithms) {
            algorithms->server_host_key_algorithms = config->hostkey_algorithms;
        }
        if (config->has_ciphers) {
            algorithms->encryption_algorithms_client_to_server = config->ciphers;
            algorithms->encryption_algorithms_server_to_client = config->ciphers;
        }
        if (config->has_macs) {
            algorithms->mac_algorithms_client_to_server = config->macs;
            algorithms->mac_algorithms_server_to_client = config->macs;
        }
        if (config->has_compression_algorithms) {
            algorithms->compression_algorithms_client_to_server = config->compression_algorithms;
            algorithms->compression_algorithms_server_to_client = config->compression_algorithms;
        }
    }

    return SSH_OK;
}
