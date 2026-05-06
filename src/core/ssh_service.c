#include "emssh/ssh_service.h"

#include <string.h>

#include "emssh/ssh_error.h"
#include "emssh/ssh_transport.h"

static int view_eq(ssh_string_view_t view, const char *value)
{
    size_t len;

    if (value == NULL || view.data == NULL) {
        return 0;
    }

    len = strlen(value);
    return view.len == len && memcmp(view.data, value, len) == 0;
}

int ssh_service_request_encode(ssh_buffer_t *buf, const char *service_name)
{
    int status;

    if (buf == NULL || service_name == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_SERVICE_REQUEST);
    if (status != SSH_OK) {
        return status;
    }

    return ssh_buffer_put_cstring(buf, service_name);
}

int ssh_service_request_decode(ssh_buffer_t *payload, ssh_service_request_t *request)
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

    if (message_id != SSH_MSG_SERVICE_REQUEST) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    status = ssh_buffer_get_string_view(payload, &request->service_name);
    if (status != SSH_OK) {
        return status;
    }

    if (request->service_name.len == 0u || ssh_buffer_remaining_read(payload) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return SSH_OK;
}

int ssh_service_accept_encode(ssh_buffer_t *buf, const char *service_name)
{
    int status;

    if (buf == NULL || service_name == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_SERVICE_ACCEPT);
    if (status != SSH_OK) {
        return status;
    }

    return ssh_buffer_put_cstring(buf, service_name);
}

int ssh_service_accept_decode(ssh_buffer_t *payload, ssh_service_request_t *accept)
{
    uint8_t message_id;
    int status;

    if (payload == NULL || accept == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(accept, 0, sizeof(*accept));

    status = ssh_buffer_get_u8(payload, &message_id);
    if (status != SSH_OK) {
        return status;
    }

    if (message_id != SSH_MSG_SERVICE_ACCEPT) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    status = ssh_buffer_get_string_view(payload, &accept->service_name);
    if (status != SSH_OK) {
        return status;
    }

    if (accept->service_name.len == 0u || ssh_buffer_remaining_read(payload) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return SSH_OK;
}

int ssh_service_name_is_supported(ssh_string_view_t service_name)
{
    return view_eq(service_name, SSH_SERVICE_USERAUTH);
}

