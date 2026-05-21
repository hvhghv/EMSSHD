#include "emssh/ssh_userauth.h"

#include <string.h>

#include "emssh/ssh_error.h"
#include "emssh/ssh_service.h"

static int view_eq(ssh_string_view_t view, const char *value)
{
    size_t len;

    if (value == NULL || view.data == NULL) {
        return 0;
    }

    len = strlen(value);
    return view.len == len && memcmp(view.data, value, len) == 0;
}

static int name_list_contains_view(const char *name_list, ssh_string_view_t name)
{
    const char *p;

    if (name_list == NULL || name.data == NULL || name.len == 0u) {
        return 0;
    }

    p = name_list;
    while (*p != '\0') {
        const char *token_start;
        const char *token_end;
        size_t token_len;

        token_start = p;
        while (*p != '\0' && *p != ',') {
            ++p;
        }
        token_end = p;
        token_len = (size_t)(token_end - token_start);
        if (token_len == name.len && memcmp(token_start, name.data, name.len) == 0) {
            return 1;
        }
        if (*p == ',') {
            ++p;
        }
    }

    return 0;
}

static int is_separator_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == ',';
}

static int username_is_root(ssh_string_view_t username)
{
    return view_eq(username, "root");
}

static int username_pattern_matches(
    const char *pattern,
    size_t pattern_len,
    const uint8_t *username,
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
        if (p < pattern_len && (pattern[p] == '?' || (uint8_t)pattern[p] == username[u])) {
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

static int username_allowed_by_allow_users(const char *allow_users, ssh_string_view_t username)
{
    const char *p;

    if (allow_users == NULL || allow_users[0] == '\0') {
        return 1;
    }
    if (username.data == NULL || username.len == 0u) {
        return 0;
    }

    p = allow_users;
    while (*p != '\0') {
        const char *token_start;
        const char *token_end;
        const char *at;
        size_t token_len;

        while (*p != '\0' && is_separator_char(*p)) {
            ++p;
        }
        if (*p == '\0') {
            break;
        }

        token_start = p;
        while (*p != '\0' && !is_separator_char(*p)) {
            ++p;
        }
        token_end = p;
        token_len = (size_t)(token_end - token_start);
        if (token_len == 0u) {
            continue;
        }

        at = token_start;
        while (at < token_end && *at != '@') {
            ++at;
        }
        if (at < token_end) {
            token_end = at;
            token_len = (size_t)(token_end - token_start);
            if (token_len == 0u) {
                continue;
            }
        }

        if (username_pattern_matches(token_start, token_len, username.data, username.len)) {
            return 1;
        }
    }

    return 0;
}

static int request_allowed_by_server_policy(const ssh_server_t *server, const ssh_userauth_request_t *request)
{
    if (server == NULL || request == NULL) {
        return 0;
    }

    if (!username_allowed_by_allow_users(server->config.allow_users, request->username)) {
        return 0;
    }

    if (username_is_root(request->username)) {
        int mode = server->config.permit_root_login;
        if (mode == EMSSH_PERMIT_ROOT_LOGIN_DEFAULT) {
            mode = EMSSH_PERMIT_ROOT_LOGIN_PROHIBIT_PASSWORD;
        }
        if (mode == EMSSH_PERMIT_ROOT_LOGIN_NO) {
            return 0;
        }
        if (mode == EMSSH_PERMIT_ROOT_LOGIN_PROHIBIT_PASSWORD &&
            view_eq(request->method_name, SSH_AUTH_METHOD_PASSWORD)) {
            return 0;
        }
    }

    return 1;
}

static int append_method_name(char *methods, size_t capacity, size_t *len, const char *name)
{
    size_t name_len;

    if (methods == NULL || len == NULL || name == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    name_len = strlen(name);
    if (*len != 0u) {
        if (*len + 1u >= capacity) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        methods[*len] = ',';
        ++(*len);
    }

    if (*len + name_len >= capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(methods + *len, name, name_len);
    *len += name_len;
    methods[*len] = '\0';
    return SSH_OK;
}

int ssh_userauth_failure_methods(
    const ssh_server_t *server,
    char *methods,
    size_t methods_capacity)
{
    size_t len;
    int status;

    if (server == NULL || methods == NULL || methods_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    methods[0] = '\0';
    len = 0u;

    if (server->config.publickey_auth != NULL) {
        status = append_method_name(methods, methods_capacity, &len, SSH_AUTH_METHOD_PUBLICKEY);
        if (status != SSH_OK) {
            return status;
        }
    }

    if (server->config.password_auth != NULL) {
        status = append_method_name(methods, methods_capacity, &len, SSH_AUTH_METHOD_PASSWORD);
        if (status != SSH_OK) {
            return status;
        }
    }

    return SSH_OK;
}

int ssh_userauth_request_none_encode(
    ssh_buffer_t *buf,
    const char *username,
    const char *service_name)
{
    int status;

    if (buf == NULL || username == NULL || service_name == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_USERAUTH_REQUEST);
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(buf, username);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(buf, service_name);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(buf, SSH_AUTH_METHOD_NONE);
    }

    return status;
}

int ssh_userauth_request_password_encode(
    ssh_buffer_t *buf,
    const char *username,
    const char *service_name,
    const char *password)
{
    int status;

    if (buf == NULL || username == NULL || service_name == NULL || password == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_USERAUTH_REQUEST);
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(buf, username);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(buf, service_name);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(buf, SSH_AUTH_METHOD_PASSWORD);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_bool(buf, 0);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(buf, password);
    }

    return status;
}

int ssh_userauth_request_decode(ssh_buffer_t *payload, ssh_userauth_request_t *request)
{
    uint8_t message_id;
    int status;

    if (payload == NULL || request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(request, 0, sizeof(*request));

    status = ssh_buffer_get_u8(payload, &message_id);
    if (status != SSH_OK) {
        return status;
    }
    if (message_id != SSH_MSG_USERAUTH_REQUEST) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    status = ssh_buffer_get_string_view(payload, &request->username);
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(payload, &request->service_name);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(payload, &request->method_name);
    }
    if (status != SSH_OK) {
        return status;
    }

    if (request->username.len == 0u ||
        !view_eq(request->service_name, SSH_SERVICE_CONNECTION)) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    if (view_eq(request->method_name, SSH_AUTH_METHOD_NONE)) {
        return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_MALFORMED_PACKET;
    }

    if (view_eq(request->method_name, SSH_AUTH_METHOD_PASSWORD)) {
        status = ssh_buffer_get_bool(payload, &request->password_change_request);
        if (status != SSH_OK) {
            return status;
        }
        status = ssh_buffer_get_string_view(payload, &request->password);
        if (status != SSH_OK) {
            return status;
        }
        return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_MALFORMED_PACKET;
    }

    if (view_eq(request->method_name, SSH_AUTH_METHOD_PUBLICKEY)) {
        status = ssh_buffer_get_bool(payload, &request->publickey_has_signature);
        if (status == SSH_OK) {
            status = ssh_buffer_get_string_view(payload, &request->publickey_algorithm);
        }
        if (status == SSH_OK) {
            status = ssh_buffer_get_string_view(payload, &request->publickey_blob);
        }
        if (status != SSH_OK) {
            return status;
        }
        if (request->publickey_algorithm.len == 0u || request->publickey_blob.len == 0u) {
            return SSH_ERR_MALFORMED_PACKET;
        }
        if (request->publickey_has_signature) {
            status = ssh_buffer_get_string_view(payload, &request->publickey_signature);
            if (status != SSH_OK || request->publickey_signature.len == 0u) {
                return status != SSH_OK ? status : SSH_ERR_MALFORMED_PACKET;
            }
        }
        return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_MALFORMED_PACKET;
    }

    /*
     * Method-specific payloads for unsupported auth methods are opaque here.
     * Keep the request decodable so the server can send USERAUTH_FAILURE and
     * let the client try another method instead of dropping the connection.
     */
    return SSH_OK;
}

int ssh_userauth_failure_encode(
    ssh_buffer_t *buf,
    const char *methods,
    int partial_success)
{
    int status;

    if (buf == NULL || methods == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_USERAUTH_FAILURE);
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(buf, methods);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_bool(buf, partial_success);
    }

    return status;
}

int ssh_userauth_pk_ok_encode(
    ssh_buffer_t *buf,
    ssh_string_view_t publickey_algorithm,
    ssh_string_view_t publickey_blob)
{
    int status;

    if (buf == NULL ||
        publickey_algorithm.data == NULL || publickey_algorithm.len == 0u ||
        publickey_blob.data == NULL || publickey_blob.len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_USERAUTH_PK_OK);
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(buf, publickey_algorithm.data, publickey_algorithm.len);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(buf, publickey_blob.data, publickey_blob.len);
    }

    return status;
}

int ssh_userauth_success_encode(ssh_buffer_t *buf)
{
    if (buf == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    return ssh_buffer_put_u8(buf, SSH_MSG_USERAUTH_SUCCESS);
}

int ssh_userauth_authenticate_password(
    const ssh_server_t *server,
    const ssh_userauth_request_t *request)
{
    ssh_password_auth_request_t auth_request;

    if (server == NULL || request == NULL ||
        !view_eq(request->method_name, SSH_AUTH_METHOD_PASSWORD) ||
        request->password_change_request ||
        !view_eq(request->service_name, SSH_SERVICE_CONNECTION)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (server->config.password_auth == NULL) {
        return SSH_ERR_SECURITY;
    }
    if (!request_allowed_by_server_policy(server, request)) {
        return SSH_ERR_SECURITY;
    }

    memset(&auth_request, 0, sizeof(auth_request));
    auth_request.username = (const char *)request->username.data;
    auth_request.username_len = request->username.len;
    auth_request.service_name = (const char *)request->service_name.data;
    auth_request.service_name_len = request->service_name.len;
    auth_request.password = (const char *)request->password.data;
    auth_request.password_len = request->password.len;

    return server->config.password_auth(server->config.auth_ctx, &auth_request) ? SSH_OK : SSH_ERR_SECURITY;
}

int ssh_userauth_publickey_is_acceptable(
    const ssh_server_t *server,
    const ssh_userauth_request_t *request)
{
    ssh_publickey_auth_request_t auth_request;
    const char *signature_algorithms;

    if (server == NULL || request == NULL ||
        !view_eq(request->method_name, SSH_AUTH_METHOD_PUBLICKEY) ||
        !view_eq(request->service_name, SSH_SERVICE_CONNECTION) ||
        request->publickey_algorithm.data == NULL ||
        request->publickey_blob.data == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (server->config.publickey_auth == NULL) {
        return SSH_ERR_SECURITY;
    }
    if (!request_allowed_by_server_policy(server, request)) {
        return SSH_ERR_SECURITY;
    }

    signature_algorithms = server->config.publickey_signature_algorithms;
    if (signature_algorithms == NULL) {
        signature_algorithms = ssh_crypto_publickey_signature_algorithms();
    }
    if (signature_algorithms != NULL &&
        signature_algorithms[0] != '\0' &&
        !name_list_contains_view(signature_algorithms, request->publickey_algorithm)) {
        return SSH_ERR_SECURITY;
    }

    memset(&auth_request, 0, sizeof(auth_request));
    auth_request.username = (const char *)request->username.data;
    auth_request.username_len = request->username.len;
    auth_request.service_name = (const char *)request->service_name.data;
    auth_request.service_name_len = request->service_name.len;
    auth_request.algorithm = (const char *)request->publickey_algorithm.data;
    auth_request.algorithm_len = request->publickey_algorithm.len;
    auth_request.publickey_blob = request->publickey_blob.data;
    auth_request.publickey_blob_len = request->publickey_blob.len;

    return server->config.publickey_auth(server->config.auth_ctx, &auth_request) ? SSH_OK : SSH_ERR_SECURITY;
}

int ssh_userauth_authenticate_publickey(
    const ssh_server_t *server,
    const ssh_userauth_request_t *request,
    const uint8_t *session_id,
    size_t session_id_len)
{
    uint8_t signed_data[EMSSH_MAX_USERAUTH_PAYLOAD + EMSSH_MAX_EXCHANGE_HASH + 8u];
    ssh_buffer_t buf;
    const ssh_crypto_api_t *crypto;
    int status;

    if (server == NULL || request == NULL ||
        session_id == NULL || session_id_len == 0u ||
        !request->publickey_has_signature ||
        request->publickey_signature.data == NULL ||
        request->publickey_signature.len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_userauth_publickey_is_acceptable(server, request);
    if (status != SSH_OK) {
        return status;
    }

    crypto = server->platform.crypto;
    if (crypto == NULL || crypto->publickey_verify == NULL) {
        return SSH_ERR_PLATFORM;
    }

    ssh_buffer_init(&buf, signed_data, sizeof(signed_data));
    status = ssh_buffer_put_string(&buf, session_id, session_id_len);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u8(&buf, SSH_MSG_USERAUTH_REQUEST);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(&buf, request->username.data, request->username.len);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(&buf, request->service_name.data, request->service_name.len);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(&buf, request->method_name.data, request->method_name.len);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_bool(&buf, 1);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(&buf, request->publickey_algorithm.data, request->publickey_algorithm.len);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(&buf, request->publickey_blob.data, request->publickey_blob.len);
    }
    if (status != SSH_OK) {
        return status;
    }

    status = crypto->publickey_verify(
        crypto->ctx,
        request->publickey_algorithm,
        request->publickey_blob.data,
        request->publickey_blob.len,
        signed_data,
        ssh_buffer_len(&buf),
        request->publickey_signature.data,
        request->publickey_signature.len);

    if (crypto->secure_zero != NULL) {
        crypto->secure_zero(crypto->ctx, signed_data, sizeof(signed_data));
    } else {
        memset(signed_data, 0, sizeof(signed_data));
    }

    if (status == SSH_OK || status == SSH_ERR_UNSUPPORTED) {
        return status;
    }

    return SSH_ERR_SECURITY;
}

int ssh_userauth_evaluate_request(
    const ssh_server_t *server,
    const ssh_userauth_request_t *request,
    const uint8_t *session_id,
    size_t session_id_len,
    ssh_userauth_decision_t *decision)
{
    int status;

    if (server == NULL || request == NULL || decision == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *decision = SSH_USERAUTH_DECISION_FAILURE;

    if (view_eq(request->method_name, SSH_AUTH_METHOD_PASSWORD)) {
        status = ssh_userauth_authenticate_password(server, request);
        if (status == SSH_OK) {
            *decision = SSH_USERAUTH_DECISION_SUCCESS;
            return SSH_OK;
        }
        if (status == SSH_ERR_SECURITY) {
            *decision = SSH_USERAUTH_DECISION_FAILURE;
            return SSH_OK;
        }
        return status;
    }

    if (view_eq(request->method_name, SSH_AUTH_METHOD_PUBLICKEY)) {
        if (request->publickey_has_signature) {
            if (session_id == NULL || session_id_len == 0u) {
                return SSH_ERR_INVALID_ARGUMENT;
            }
            status = ssh_userauth_authenticate_publickey(server, request, session_id, session_id_len);
            if (status == SSH_OK) {
                *decision = SSH_USERAUTH_DECISION_SUCCESS;
                return SSH_OK;
            }
            if (status == SSH_ERR_SECURITY || status == SSH_ERR_UNSUPPORTED) {
                *decision = SSH_USERAUTH_DECISION_FAILURE;
                return SSH_OK;
            }
            return status;
        }

        status = ssh_userauth_publickey_is_acceptable(server, request);
        if (status == SSH_OK) {
            *decision = SSH_USERAUTH_DECISION_PK_OK;
            return SSH_OK;
        }
        if (status == SSH_ERR_SECURITY) {
            *decision = SSH_USERAUTH_DECISION_FAILURE;
            return SSH_OK;
        }
        return status;
    }

    *decision = SSH_USERAUTH_DECISION_FAILURE;
    return SSH_OK;
}
