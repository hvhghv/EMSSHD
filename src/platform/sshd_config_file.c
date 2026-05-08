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

static int first_token_is_all(const char *value)
{
    const char *p;
    const char *start;
    size_t len;

    if (value == NULL) {
        return 0;
    }

    p = value;
    while (*p != '\0' && is_space_char(*p)) {
        ++p;
    }
    if (*p == '\0') {
        return 0;
    }

    start = p;
    while (*p != '\0' && !is_space_char(*p)) {
        ++p;
    }
    len = (size_t)(p - start);
    return len == 3u &&
           ((start[0] == 'a') || (start[0] == 'A')) &&
           ((start[1] == 'l') || (start[1] == 'L')) &&
           ((start[2] == 'l') || (start[2] == 'L'));
}

static int pattern_matches_wildcards(const char *pattern, size_t pattern_len, const char *value, size_t value_len)
{
    size_t p;
    size_t v;
    size_t star_p;
    size_t star_v;

    if (pattern == NULL || value == NULL) {
        return 0;
    }

    p = 0u;
    v = 0u;
    star_p = (size_t)-1;
    star_v = 0u;
    while (v < value_len) {
        if (p < pattern_len && (pattern[p] == '?' || pattern[p] == value[v])) {
            ++p;
            ++v;
            continue;
        }
        if (p < pattern_len && pattern[p] == '*') {
            star_p = ++p;
            star_v = v;
            continue;
        }
        if (star_p != (size_t)-1) {
            p = star_p;
            ++star_v;
            v = star_v;
            continue;
        }
        return 0;
    }

    while (p < pattern_len && pattern[p] == '*') {
        ++p;
    }
    return p == pattern_len;
}

static int list_pattern_matches(const char *pattern_list, const char *value)
{
    const char *p;
    int saw_positive;
    int matched_positive;

    if (pattern_list == NULL || value == NULL || value[0] == '\0') {
        return 0;
    }

    p = pattern_list;
    saw_positive = 0;
    matched_positive = 0;
    while (*p != '\0') {
        const char *start;
        const char *end;
        size_t len;
        int negated;

        while (*p == ',' || is_space_char(*p)) {
            ++p;
        }
        if (*p == '\0') {
            break;
        }

        negated = 0;
        if (*p == '!') {
            negated = 1;
            ++p;
        }

        start = p;
        while (*p != '\0' && *p != ',' && !is_space_char(*p)) {
            ++p;
        }
        end = p;
        len = (size_t)(end - start);
        if (len == 0u) {
            continue;
        }

        if (pattern_matches_wildcards(start, len, value, strlen(value))) {
            if (negated) {
                return 0;
            }
            matched_positive = 1;
        }
        if (!negated) {
            saw_positive = 1;
        }
    }

    if (!saw_positive) {
        return 1;
    }
    return matched_positive;
}

static int parse_local_port_token(const char *token, uint16_t *port_out)
{
    unsigned long parsed;
    size_t i;

    if (token == NULL || port_out == NULL || token[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    parsed = 0ul;
    for (i = 0u; token[i] != '\0'; ++i) {
        unsigned long digit;
        if (token[i] < '0' || token[i] > '9') {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        digit = (unsigned long)(token[i] - '0');
        if (parsed > (65535ul - digit) / 10ul) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        parsed = parsed * 10ul + digit;
    }
    if (parsed == 0ul) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *port_out = (uint16_t)parsed;
    return SSH_OK;
}

static int match_local_port_list(const char *pattern_list, uint16_t local_port)
{
    const char *p;
    int saw_positive;
    int matched_positive;

    if (pattern_list == NULL || pattern_list[0] == '\0' || local_port == 0u) {
        return 0;
    }

    p = pattern_list;
    saw_positive = 0;
    matched_positive = 0;
    while (*p != '\0') {
        const char *start;
        const char *end;
        int negated;
        char token[16];
        size_t len;
        uint16_t parsed_port;

        while (*p == ',' || is_space_char(*p)) {
            ++p;
        }
        if (*p == '\0') {
            break;
        }

        negated = 0;
        if (*p == '!') {
            negated = 1;
            ++p;
        }

        start = p;
        while (*p != '\0' && *p != ',' && !is_space_char(*p)) {
            ++p;
        }
        end = p;
        len = (size_t)(end - start);
        if (len == 0u || len >= sizeof(token)) {
            return 0;
        }

        memcpy(token, start, len);
        token[len] = '\0';
        if (parse_local_port_token(token, &parsed_port) != SSH_OK) {
            return 0;
        }

        if (parsed_port == local_port) {
            if (negated) {
                return 0;
            }
            matched_positive = 1;
        }
        if (!negated) {
            saw_positive = 1;
        }
    }

    if (!saw_positive) {
        return 1;
    }
    return matched_positive;
}

static int evaluate_match_criterion(
    const char *keyword,
    const char *pattern_list,
    const ssh_sshd_match_context_t *ctx,
    int *is_match)
{
    if (keyword == NULL || pattern_list == NULL || is_match == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (str_ieq(keyword, "User")) {
        *is_match = ctx != NULL ? list_pattern_matches(pattern_list, ctx->user) : 0;
        return SSH_OK;
    }
    if (str_ieq(keyword, "Group")) {
        *is_match = ctx != NULL ? list_pattern_matches(pattern_list, ctx->group) : 0;
        return SSH_OK;
    }
    if (str_ieq(keyword, "Host")) {
        *is_match = ctx != NULL ? list_pattern_matches(pattern_list, ctx->host) : 0;
        return SSH_OK;
    }
    if (str_ieq(keyword, "Address")) {
        *is_match = ctx != NULL ? list_pattern_matches(pattern_list, ctx->address) : 0;
        return SSH_OK;
    }
    if (str_ieq(keyword, "LocalAddress")) {
        *is_match = ctx != NULL ? list_pattern_matches(pattern_list, ctx->local_address) : 0;
        return SSH_OK;
    }
    if (str_ieq(keyword, "LocalPort")) {
        *is_match = ctx != NULL ? match_local_port_list(pattern_list, ctx->local_port) : 0;
        return SSH_OK;
    }
    if (str_ieq(keyword, "RDomain")) {
        *is_match = ctx != NULL ? list_pattern_matches(pattern_list, ctx->rdomain) : 0;
        return SSH_OK;
    }

    return SSH_ERR_UNSUPPORTED;
}

static int evaluate_match_expression(const char *value, const ssh_sshd_match_context_t *ctx, int *is_match)
{
    char work[EMSSH_SSHD_CONFIG_VALUE_MAX];
    char *p;
    int matched;

    if (value == NULL || is_match == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (!first_token_is_all(value)) {
        size_t len = strlen(value);
        if (len == 0u || len >= sizeof(work)) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        memcpy(work, value, len + 1u);
        p = trim_left(work);
    } else {
        char *q;
        size_t len = strlen(value);
        if (len == 0u || len >= sizeof(work)) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        memcpy(work, value, len + 1u);
        p = trim_left(work);
        q = p;
        while (*q != '\0' && !is_space_char(*q)) {
            ++q;
        }
        while (*q != '\0' && is_space_char(*q)) {
            ++q;
        }
        if (*q != '\0') {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        *is_match = 1;
        return SSH_OK;
    }

    matched = 1;
    while (*p != '\0') {
        char *keyword_start;
        char *keyword_end;
        char *arg_start;
        char *arg_end;
        int negate_keyword;
        int criterion_match;
        int rc;

        while (*p != '\0' && is_space_char(*p)) {
            ++p;
        }
        if (*p == '\0') {
            break;
        }

        negate_keyword = 0;
        if (*p == '!') {
            negate_keyword = 1;
            ++p;
        }

        keyword_start = p;
        while (*p != '\0' && !is_space_char(*p)) {
            ++p;
        }
        keyword_end = p;
        if (keyword_end == keyword_start) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        if (*p == '\0') {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        *keyword_end = '\0';
        ++p;

        while (*p != '\0' && is_space_char(*p)) {
            ++p;
        }
        if (*p == '\0') {
            return SSH_ERR_INVALID_ARGUMENT;
        }

        arg_start = p;
        while (*p != '\0' && !is_space_char(*p)) {
            ++p;
        }
        arg_end = p;
        *arg_end = '\0';
        if (*p != '\0') {
            ++p;
        }

        rc = evaluate_match_criterion(keyword_start, arg_start, ctx, &criterion_match);
        if (rc != SSH_OK) {
            return rc;
        }
        if (negate_keyword) {
            criterion_match = !criterion_match;
        }
        matched = matched && criterion_match;
    }

    *is_match = matched;
    return SSH_OK;
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
    const char *host_begin;
    const char *host_end;
    size_t len;

    if (value == NULL || value[0] == '\0' || host_out == NULL || host_out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    host_begin = value;
    host_end = value + strlen(value);

    if (value[0] == '[') {
        const char *close = strchr(value, ']');
        if (close == NULL || close == value + 1) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        host_begin = value + 1;
        host_end = close;
        if (port_out != NULL && close[1] == ':' && close[2] != '\0') {
            unsigned long parsed_ulong = 0ul;
            int rc = parse_uint_in_range(close + 2, 65535ul, &parsed_ulong);
            if (rc != SSH_OK) {
                return rc;
            }
            *port_out = (uint16_t)parsed_ulong;
        }
    } else if (port_out != NULL) {
        const char *last_colon = strrchr(value, ':');
        if (last_colon != NULL && strchr(last_colon + 1, ':') == NULL && last_colon[1] != '\0') {
            unsigned long parsed_ulong = 0ul;
            int rc = parse_uint_in_range(last_colon + 1, 65535ul, &parsed_ulong);
            if (rc == SSH_OK) {
                *port_out = (uint16_t)parsed_ulong;
                host_end = last_colon;
            }
        }
    }

    len = (size_t)(host_end - host_begin);
    if (len == 0u || len >= host_out_capacity) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    memcpy(host_out, host_begin, len);
    host_out[len] = '\0';

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

    if (str_ieq(key, "ChrootDirectory")) {
        return set_string_value(
            config->chroot_directory,
            sizeof(config->chroot_directory),
            &config->has_chroot_directory,
            value);
    }

    if (str_ieq(key, "HostKey")) {
        return set_string_value(
            config->host_key_file,
            sizeof(config->host_key_file),
            &config->has_host_key,
            value);
    }

    if (str_ieq(key, "KexAlgorithms")) {
        return SSH_OK;
    }

    if (str_ieq(key, "HostKeyAlgorithms")) {
        return SSH_OK;
    }

    if (str_ieq(key, "Ciphers")) {
        return SSH_OK;
    }

    if (str_ieq(key, "MACs")) {
        return SSH_OK;
    }

    if (str_ieq(key, "Compression")) {
        (void)parsed_bool;
        return SSH_OK;
    }

    return SSH_OK;
}

static int parse_line_inplace(
    char *line,
    ssh_sshd_config_file_t *config,
    const ssh_sshd_match_context_t *match_context,
    int *match_block_active)
{
    char *hash_pos;
    char *key;
    char *value;
    char *p;
    size_t value_len;

    if (line == NULL || config == NULL || match_block_active == NULL) {
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

    if (str_ieq(key, "Match")) {
        int is_match = 0;
        int rc = evaluate_match_expression(value, match_context, &is_match);
        if (rc != SSH_OK) {
            return rc;
        }
        *match_block_active = is_match;
        return SSH_OK;
    }

    if (!*match_block_active) {
        return SSH_OK;
    }

    return parse_one_directive(key, value, config);
}

static int read_and_parse_file_via_fs(
    const ssh_fs_api_t *fs,
    const char *path,
    const ssh_sshd_match_context_t *match_context,
    ssh_sshd_config_file_t *config)
{
    void *handle;
    char chunk[512];
    char line[1024];
    size_t line_len;
    int match_block_active;
    int status;
    size_t i;
    size_t read_len;

    if (fs == NULL || fs->open == NULL || fs->read == NULL || fs->close == NULL ||
        path == NULL || config == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    handle = NULL;
    line_len = 0u;
    match_block_active = 1;

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
                status = parse_line_inplace(line, config, match_context, &match_block_active);
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
        status = parse_line_inplace(line, config, match_context, &match_block_active);
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
    return ssh_sshd_config_file_load_with_match_context(fs, path, NULL, config);
}

int ssh_sshd_config_file_load_with_match_context(
    const ssh_fs_api_t *fs,
    const char *path,
    const ssh_sshd_match_context_t *match_context,
    ssh_sshd_config_file_t *config)
{
    if (config == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_sshd_config_file_defaults(config);
    return read_and_parse_file_via_fs(fs, path, match_context, config);
}

int ssh_sshd_config_file_apply(
    const ssh_sshd_config_file_t *config,
    ssh_server_config_t *server_config,
    ssh_server_session_options_t *session_options,
    ssh_kexinit_algorithm_set_t *algorithms,
    uint16_t *port,
    const char **chroot_directory,
    const char **host_key_file)
{
    if (config == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (port != NULL && config->has_port) {
        *port = config->port;
    }
    if (chroot_directory != NULL && config->has_chroot_directory) {
        *chroot_directory = config->chroot_directory;
    }
    if (host_key_file != NULL && config->has_host_key) {
        *host_key_file = config->host_key_file;
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

    (void)algorithms;

    return SSH_OK;
}
