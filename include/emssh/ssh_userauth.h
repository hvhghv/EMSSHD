#ifndef EMSSH_SSH_USERAUTH_H
#define EMSSH_SSH_USERAUTH_H

#include "emssh/ssh_buffer.h"
#include "emssh/ssh_server.h"

#define SSH_MSG_USERAUTH_REQUEST 50u
#define SSH_MSG_USERAUTH_FAILURE 51u
#define SSH_MSG_USERAUTH_SUCCESS 52u
#define SSH_MSG_USERAUTH_BANNER 53u
#define SSH_MSG_USERAUTH_PK_OK 60u

#define SSH_AUTH_METHOD_NONE "none"
#define SSH_AUTH_METHOD_PASSWORD "password"
#define SSH_AUTH_METHOD_PUBLICKEY "publickey"
#define SSH_AUTH_DEFAULT_FAILURE_METHODS "publickey,password"
#define EMSSH_MAX_USERAUTH_PAYLOAD 2048u
#define EMSSH_MAX_USERAUTH_FAILURE_METHODS 64u

typedef struct ssh_userauth_request {
    ssh_string_view_t username;
    ssh_string_view_t service_name;
    ssh_string_view_t method_name;
    int password_change_request;
    ssh_string_view_t password;
    int publickey_has_signature;
    ssh_string_view_t publickey_algorithm;
    ssh_string_view_t publickey_blob;
    ssh_string_view_t publickey_signature;
} ssh_userauth_request_t;

typedef enum ssh_userauth_decision {
    SSH_USERAUTH_DECISION_FAILURE = 0,
    SSH_USERAUTH_DECISION_SUCCESS = 1,
    SSH_USERAUTH_DECISION_PK_OK = 2
} ssh_userauth_decision_t;

int ssh_userauth_request_none_encode(
    ssh_buffer_t *buf,
    const char *username,
    const char *service_name);

int ssh_userauth_request_password_encode(
    ssh_buffer_t *buf,
    const char *username,
    const char *service_name,
    const char *password);

int ssh_userauth_request_decode(ssh_buffer_t *payload, ssh_userauth_request_t *request);

int ssh_userauth_failure_encode(
    ssh_buffer_t *buf,
    const char *methods,
    int partial_success);

int ssh_userauth_pk_ok_encode(
    ssh_buffer_t *buf,
    ssh_string_view_t publickey_algorithm,
    ssh_string_view_t publickey_blob);

int ssh_userauth_success_encode(ssh_buffer_t *buf);

int ssh_userauth_failure_methods(
    const ssh_server_t *server,
    char *methods,
    size_t methods_capacity);

int ssh_userauth_authenticate_password(
    const ssh_server_t *server,
    const ssh_userauth_request_t *request);

int ssh_userauth_publickey_is_acceptable(
    const ssh_server_t *server,
    const ssh_userauth_request_t *request);

int ssh_userauth_authenticate_publickey(
    const ssh_server_t *server,
    const ssh_userauth_request_t *request,
    const uint8_t *session_id,
    size_t session_id_len);

int ssh_userauth_evaluate_request(
    const ssh_server_t *server,
    const ssh_userauth_request_t *request,
    const uint8_t *session_id,
    size_t session_id_len,
    ssh_userauth_decision_t *decision);

#endif
