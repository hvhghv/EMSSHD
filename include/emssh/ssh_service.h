#ifndef EMSSH_SSH_SERVICE_H
#define EMSSH_SSH_SERVICE_H

#include "emssh/ssh_buffer.h"

#define SSH_SERVICE_USERAUTH "ssh-userauth"
#define SSH_SERVICE_CONNECTION "ssh-connection"

typedef struct ssh_service_request {
    ssh_string_view_t service_name;
} ssh_service_request_t;

int ssh_service_request_encode(ssh_buffer_t *buf, const char *service_name);
int ssh_service_request_decode(ssh_buffer_t *payload, ssh_service_request_t *request);

int ssh_service_accept_encode(ssh_buffer_t *buf, const char *service_name);
int ssh_service_accept_decode(ssh_buffer_t *payload, ssh_service_request_t *accept);

int ssh_service_name_is_supported(ssh_string_view_t service_name);

#endif

