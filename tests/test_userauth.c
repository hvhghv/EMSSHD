#include <stdio.h>
#include <string.h>

#include "emssh/ssh_error.h"
#include "emssh/ssh_platform.h"
#include "emssh/ssh_server.h"
#include "emssh/ssh_service.h"
#include "emssh/ssh_userauth.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static int view_eq(ssh_string_view_t view, const char *value)
{
    size_t len = strlen(value);
    return view.len == len && memcmp(view.data, value, len) == 0;
}

static int password_auth(void *ctx, const ssh_password_auth_request_t *request)
{
    (void)ctx;

    return request != NULL &&
           request->username_len == strlen("alice") &&
           memcmp(request->username, "alice", request->username_len) == 0 &&
           request->password_len == strlen("secret") &&
           memcmp(request->password, "secret", request->password_len) == 0;
}

static int publickey_auth(void *ctx, const ssh_publickey_auth_request_t *request)
{
    (void)ctx;

    return request != NULL &&
           request->username_len == strlen("alice") &&
           memcmp(request->username, "alice", request->username_len) == 0 &&
           request->algorithm_len == strlen("ecdsa-sha2-nistp256") &&
           memcmp(request->algorithm, "ecdsa-sha2-nistp256", request->algorithm_len) == 0 &&
           request->publickey_blob_len == strlen("dummy-key") &&
           memcmp(request->publickey_blob, "dummy-key", request->publickey_blob_len) == 0;
}

static int password_auth_any(void *ctx, const ssh_password_auth_request_t *request)
{
    (void)ctx;
    return request != NULL &&
           request->username_len != 0u &&
           request->password_len == strlen("secret") &&
           memcmp(request->password, "secret", request->password_len) == 0;
}

static int publickey_verify_unsupported(
    void *ctx,
    ssh_string_view_t publickey_algorithm,
    const uint8_t *publickey_blob,
    size_t publickey_blob_len,
    const uint8_t *signed_data,
    size_t signed_data_len,
    const uint8_t *signature,
    size_t signature_len)
{
    (void)ctx;
    (void)publickey_algorithm;
    (void)publickey_blob;
    (void)publickey_blob_len;
    (void)signed_data;
    (void)signed_data_len;
    (void)signature;
    (void)signature_len;
    return SSH_ERR_UNSUPPORTED;
}

int main(void)
{
    uint8_t storage[128];
    uint8_t session_id[4] = {1u, 2u, 3u, 4u};
    char failure_methods[EMSSH_MAX_USERAUTH_FAILURE_METHODS];
    ssh_platform_t platform;
    ssh_server_config_t config;
    ssh_server_t server;
    ssh_crypto_api_t crypto_api;
    ssh_buffer_t buf;
    ssh_userauth_request_t request;
    ssh_userauth_decision_t decision;

    memset(&platform, 0, sizeof(platform));
    ssh_server_config_defaults(&config);
    config.password_auth = password_auth;
    config.publickey_auth = publickey_auth;
    CHECK(ssh_server_init(&server, &platform, &config) == SSH_OK);
    CHECK(ssh_userauth_failure_methods(&server, failure_methods, sizeof(failure_methods)) == SSH_OK);
    CHECK(strcmp(failure_methods, SSH_AUTH_DEFAULT_FAILURE_METHODS) == 0);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_userauth_request_none_encode(&buf, "alice", SSH_SERVICE_CONNECTION) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_userauth_request_decode(&buf, &request) == SSH_OK);
    CHECK(view_eq(request.username, "alice"));
    CHECK(view_eq(request.service_name, SSH_SERVICE_CONNECTION));
    CHECK(view_eq(request.method_name, SSH_AUTH_METHOD_NONE));

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_userauth_request_password_encode(&buf, "alice", SSH_SERVICE_CONNECTION, "secret") == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_userauth_request_decode(&buf, &request) == SSH_OK);
    CHECK(view_eq(request.username, "alice"));
    CHECK(view_eq(request.method_name, SSH_AUTH_METHOD_PASSWORD));
    CHECK(view_eq(request.password, "secret"));
    CHECK(ssh_userauth_authenticate_password(&server, &request) == SSH_OK);
    CHECK(ssh_userauth_evaluate_request(&server, &request, session_id, sizeof(session_id), &decision) == SSH_OK);
    CHECK(decision == SSH_USERAUTH_DECISION_SUCCESS);

    ssh_server_deinit(&server);
    ssh_server_config_defaults(&config);
    config.password_auth = password_auth_any;
    config.publickey_auth = publickey_auth;
    config.allow_users = "alice";
    config.permit_root_login = EMSSH_PERMIT_ROOT_LOGIN_PROHIBIT_PASSWORD;
    CHECK(ssh_server_init(&server, &platform, &config) == SSH_OK);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_userauth_request_password_encode(&buf, "bob", SSH_SERVICE_CONNECTION, "secret") == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_userauth_request_decode(&buf, &request) == SSH_OK);
    CHECK(ssh_userauth_authenticate_password(&server, &request) == SSH_ERR_SECURITY);
    CHECK(ssh_userauth_evaluate_request(&server, &request, session_id, sizeof(session_id), &decision) == SSH_OK);
    CHECK(decision == SSH_USERAUTH_DECISION_FAILURE);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_userauth_request_password_encode(&buf, "root", SSH_SERVICE_CONNECTION, "secret") == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_userauth_request_decode(&buf, &request) == SSH_OK);
    CHECK(ssh_userauth_authenticate_password(&server, &request) == SSH_ERR_SECURITY);
    CHECK(ssh_userauth_evaluate_request(&server, &request, session_id, sizeof(session_id), &decision) == SSH_OK);
    CHECK(decision == SSH_USERAUTH_DECISION_FAILURE);

    ssh_server_deinit(&server);
    ssh_server_config_defaults(&config);
    config.password_auth = password_auth_any;
    config.publickey_auth = publickey_auth;
    config.allow_users = "alice,root";
    config.permit_root_login = EMSSH_PERMIT_ROOT_LOGIN_YES;
    CHECK(ssh_server_init(&server, &platform, &config) == SSH_OK);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_userauth_request_password_encode(&buf, "root", SSH_SERVICE_CONNECTION, "secret") == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_userauth_request_decode(&buf, &request) == SSH_OK);
    CHECK(ssh_userauth_authenticate_password(&server, &request) == SSH_OK);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_userauth_request_password_encode(&buf, "alice", SSH_SERVICE_CONNECTION, "wrong") == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_userauth_request_decode(&buf, &request) == SSH_OK);
    CHECK(ssh_userauth_authenticate_password(&server, &request) == SSH_ERR_SECURITY);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_buffer_put_u8(&buf, SSH_MSG_USERAUTH_REQUEST) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "alice") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, SSH_SERVICE_CONNECTION) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, SSH_AUTH_METHOD_PUBLICKEY) == SSH_OK);
    CHECK(ssh_buffer_put_bool(&buf, 0) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "ecdsa-sha2-nistp256") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "dummy-key") == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_userauth_request_decode(&buf, &request) == SSH_OK);
    CHECK(view_eq(request.username, "alice"));
    CHECK(view_eq(request.method_name, SSH_AUTH_METHOD_PUBLICKEY));
    CHECK(!request.publickey_has_signature);
    CHECK(view_eq(request.publickey_algorithm, "ecdsa-sha2-nistp256"));
    CHECK(view_eq(request.publickey_blob, "dummy-key"));
    CHECK(ssh_userauth_publickey_is_acceptable(&server, &request) == SSH_OK);
    CHECK(ssh_userauth_authenticate_password(&server, &request) == SSH_ERR_INVALID_ARGUMENT);
    CHECK(ssh_userauth_evaluate_request(&server, &request, session_id, sizeof(session_id), &decision) == SSH_OK);
    CHECK(decision == SSH_USERAUTH_DECISION_PK_OK);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_userauth_pk_ok_encode(&buf, request.publickey_algorithm, request.publickey_blob) == SSH_OK);
    CHECK(storage[0] == SSH_MSG_USERAUTH_PK_OK);

    memset(&crypto_api, 0, sizeof(crypto_api));
    crypto_api.publickey_verify = publickey_verify_unsupported;
    platform.crypto = &crypto_api;
    ssh_server_deinit(&server);
    CHECK(ssh_server_init(&server, &platform, &config) == SSH_OK);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_buffer_put_u8(&buf, SSH_MSG_USERAUTH_REQUEST) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "alice") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, SSH_SERVICE_CONNECTION) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, SSH_AUTH_METHOD_PUBLICKEY) == SSH_OK);
    CHECK(ssh_buffer_put_bool(&buf, 1) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "ecdsa-sha2-nistp256") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "dummy-key") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "fake-signature") == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_userauth_request_decode(&buf, &request) == SSH_OK);
    CHECK(ssh_userauth_authenticate_publickey(&server, &request, session_id, sizeof(session_id)) == SSH_ERR_UNSUPPORTED);
    CHECK(ssh_userauth_evaluate_request(&server, &request, session_id, sizeof(session_id), &decision) == SSH_OK);
    CHECK(decision == SSH_USERAUTH_DECISION_FAILURE);
    CHECK(ssh_userauth_evaluate_request(&server, &request, NULL, 0u, &decision) == SSH_ERR_INVALID_ARGUMENT);
    ssh_server_deinit(&server);
    memset(&platform, 0, sizeof(platform));
    CHECK(ssh_server_init(&server, &platform, &config) == SSH_OK);
    CHECK(ssh_userauth_failure_methods(&server, failure_methods, sizeof(failure_methods)) == SSH_OK);
    CHECK(strcmp(failure_methods, SSH_AUTH_DEFAULT_FAILURE_METHODS) == 0);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_buffer_put_u8(&buf, SSH_MSG_USERAUTH_REQUEST) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "alice") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, SSH_SERVICE_CONNECTION) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "keyboard-interactive") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "") == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_userauth_request_decode(&buf, &request) == SSH_OK);
    CHECK(view_eq(request.method_name, "keyboard-interactive"));
    CHECK(ssh_userauth_authenticate_password(&server, &request) == SSH_ERR_INVALID_ARGUMENT);
    CHECK(ssh_userauth_evaluate_request(&server, &request, session_id, sizeof(session_id), &decision) == SSH_OK);
    CHECK(decision == SSH_USERAUTH_DECISION_FAILURE);

    ssh_server_deinit(&server);
    ssh_server_config_defaults(&config);
    config.password_auth = password_auth;
    CHECK(ssh_server_init(&server, &platform, &config) == SSH_OK);
    CHECK(ssh_userauth_failure_methods(&server, failure_methods, sizeof(failure_methods)) == SSH_OK);
    CHECK(strcmp(failure_methods, SSH_AUTH_METHOD_PASSWORD) == 0);

    ssh_server_deinit(&server);
    ssh_server_config_defaults(&config);
    CHECK(ssh_server_init(&server, &platform, &config) == SSH_OK);
    CHECK(ssh_userauth_failure_methods(&server, failure_methods, sizeof(failure_methods)) == SSH_OK);
    CHECK(strcmp(failure_methods, "") == 0);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_userauth_failure_encode(&buf, SSH_AUTH_DEFAULT_FAILURE_METHODS, 0) == SSH_OK);
    CHECK(ssh_buffer_len(&buf) > 0u);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_userauth_success_encode(&buf) == SSH_OK);
    CHECK(ssh_buffer_len(&buf) == 1u);
    CHECK(storage[0] == SSH_MSG_USERAUTH_SUCCESS);

    ssh_server_deinit(&server);
    ssh_server_config_defaults(&config);
    config.publickey_signature_algorithms = "rsa-sha2-256, bad";
    CHECK(ssh_server_init(&server, &platform, &config) == SSH_OK);
    ssh_server_deinit(&server);

    ssh_server_config_defaults(&config);
    config.publickey_signature_algorithms = "rsa-sha2-256,";
    CHECK(ssh_server_init(&server, &platform, &config) == SSH_OK);
    ssh_server_deinit(&server);

    ssh_server_config_defaults(&config);
    config.publickey_signature_algorithms = "";
    CHECK(ssh_server_init(&server, &platform, &config) == SSH_OK);

    ssh_server_deinit(&server);
    return 0;
}
