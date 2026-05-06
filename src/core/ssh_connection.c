#include "emssh/ssh_connection.h"

#include <string.h>

#include "emssh/ssh_error.h"

static int view_eq(ssh_string_view_t view, const char *value)
{
    size_t len;

    if (value == NULL || view.data == NULL) {
        return 0;
    }

    len = strlen(value);
    return view.len == len && memcmp(view.data, value, len) == 0;
}

int ssh_channel_open_session_encode(
    ssh_buffer_t *buf,
    uint32_t sender_channel,
    uint32_t initial_window_size,
    uint32_t maximum_packet_size)
{
    int status;

    if (buf == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_CHANNEL_OPEN);
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(buf, SSH_CHANNEL_TYPE_SESSION);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, sender_channel);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, initial_window_size);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, maximum_packet_size);
    }

    return status;
}

int ssh_channel_open_decode(ssh_buffer_t *payload, ssh_channel_open_t *open)
{
    uint8_t message_id;
    int status;

    if (payload == NULL || open == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(open, 0, sizeof(*open));

    status = ssh_buffer_get_u8(payload, &message_id);
    if (status != SSH_OK) {
        return status;
    }
    if (message_id != SSH_MSG_CHANNEL_OPEN) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    status = ssh_buffer_get_string_view(payload, &open->channel_type);
    if (status == SSH_OK) {
        status = ssh_buffer_get_u32(payload, &open->sender_channel);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_u32(payload, &open->initial_window_size);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_u32(payload, &open->maximum_packet_size);
    }
    if (status != SSH_OK) {
        return status;
    }

    return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_MALFORMED_PACKET;
}

int ssh_global_request_decode(ssh_buffer_t *payload, ssh_global_request_t *request)
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
    if (message_id != SSH_MSG_GLOBAL_REQUEST) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    status = ssh_buffer_get_string_view(payload, &request->request_name);
    if (status == SSH_OK) {
        status = ssh_buffer_get_bool(payload, &request->want_reply);
    }
    if (status != SSH_OK) {
        return status;
    }

    return SSH_OK;
}

int ssh_global_request_failure_encode(ssh_buffer_t *buf)
{
    if (buf == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    return ssh_buffer_put_u8(buf, SSH_MSG_REQUEST_FAILURE);
}

int ssh_channel_open_confirmation_encode(
    ssh_buffer_t *buf,
    uint32_t recipient_channel,
    uint32_t sender_channel,
    uint32_t initial_window_size,
    uint32_t maximum_packet_size)
{
    int status;

    if (buf == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, recipient_channel);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, sender_channel);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, initial_window_size);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, maximum_packet_size);
    }

    return status;
}

int ssh_channel_open_failure_encode(
    ssh_buffer_t *buf,
    uint32_t recipient_channel,
    uint32_t reason_code,
    const char *description,
    const char *language_tag)
{
    int status;

    if (buf == NULL || description == NULL || language_tag == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_CHANNEL_OPEN_FAILURE);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, recipient_channel);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, reason_code);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(buf, description);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(buf, language_tag);
    }

    return status;
}

int ssh_channel_request_subsystem_encode(
    ssh_buffer_t *buf,
    uint32_t recipient_channel,
    int want_reply,
    const char *subsystem_name)
{
    int status;

    if (buf == NULL || subsystem_name == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_CHANNEL_REQUEST);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, recipient_channel);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(buf, SSH_CHANNEL_REQUEST_SUBSYSTEM);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_bool(buf, want_reply);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(buf, subsystem_name);
    }

    return status;
}

int ssh_channel_request_exit_status_encode(
    ssh_buffer_t *buf,
    uint32_t recipient_channel,
    int want_reply,
    uint32_t exit_status)
{
    int status;

    if (buf == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_CHANNEL_REQUEST);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, recipient_channel);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(buf, "exit-status");
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_bool(buf, want_reply);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, exit_status);
    }

    return status;
}

static int channel_request_decode_fields(ssh_buffer_t *payload, ssh_channel_request_t *request)
{
    int status;

    status = ssh_buffer_get_u32(payload, &request->recipient_channel);
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(payload, &request->request_type);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_bool(payload, &request->want_reply);
    }
    if (status != SSH_OK) {
        return status;
    }

    if (view_eq(request->request_type, SSH_CHANNEL_REQUEST_SUBSYSTEM)) {
        status = ssh_buffer_get_string_view(payload, &request->subsystem_name);
        if (status != SSH_OK) {
            return status;
        }
        return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_MALFORMED_PACKET;
    }

    if (view_eq(request->request_type, SSH_CHANNEL_REQUEST_PTY_REQ)) {
        status = ssh_buffer_get_string_view(payload, &request->term_type);
        if (status == SSH_OK) {
            status = ssh_buffer_get_u32(payload, &request->cols);
        }
        if (status == SSH_OK) {
            status = ssh_buffer_get_u32(payload, &request->rows);
        }
        if (status == SSH_OK) {
            status = ssh_buffer_get_u32(payload, &request->width_px);
        }
        if (status == SSH_OK) {
            status = ssh_buffer_get_u32(payload, &request->height_px);
        }
        if (status == SSH_OK) {
            status = ssh_buffer_get_string_view(payload, &request->pty_modes);
        }
        if (status != SSH_OK) {
            return SSH_ERR_UNSUPPORTED;
        }
        return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_UNSUPPORTED;
    }

    if (view_eq(request->request_type, SSH_CHANNEL_REQUEST_SHELL)) {
        return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_UNSUPPORTED;
    }

    if (view_eq(request->request_type, SSH_CHANNEL_REQUEST_EXEC)) {
        status = ssh_buffer_get_string_view(payload, &request->command);
        if (status != SSH_OK) {
            return SSH_ERR_UNSUPPORTED;
        }
        return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_UNSUPPORTED;
    }

    if (view_eq(request->request_type, SSH_CHANNEL_REQUEST_ENV)) {
        status = ssh_buffer_get_string_view(payload, &request->env_name);
        if (status == SSH_OK) {
            status = ssh_buffer_get_string_view(payload, &request->env_value);
        }
        if (status != SSH_OK) {
            return SSH_ERR_UNSUPPORTED;
        }
        return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_UNSUPPORTED;
    }

    if (view_eq(request->request_type, SSH_CHANNEL_REQUEST_WINDOW_CHANGE)) {
        status = ssh_buffer_get_u32(payload, &request->cols);
        if (status == SSH_OK) {
            status = ssh_buffer_get_u32(payload, &request->rows);
        }
        if (status == SSH_OK) {
            status = ssh_buffer_get_u32(payload, &request->width_px);
        }
        if (status == SSH_OK) {
            status = ssh_buffer_get_u32(payload, &request->height_px);
        }
        if (status != SSH_OK) {
            return SSH_ERR_UNSUPPORTED;
        }
        return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_UNSUPPORTED;
    }

    if (view_eq(request->request_type, SSH_CHANNEL_REQUEST_SIGNAL)) {
        status = ssh_buffer_get_string_view(payload, &request->signal_name);
        if (status != SSH_OK) {
            return SSH_ERR_UNSUPPORTED;
        }
        return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_UNSUPPORTED;
    }

    return SSH_ERR_UNSUPPORTED;
}

int ssh_channel_request_decode(ssh_buffer_t *payload, ssh_channel_request_t *request)
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
    if (message_id != SSH_MSG_CHANNEL_REQUEST) {
        return SSH_ERR_MALFORMED_PACKET;
    }
    return channel_request_decode_fields(payload, request);
}

int ssh_channel_success_encode(ssh_buffer_t *buf, uint32_t recipient_channel)
{
    int status;

    if (buf == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_CHANNEL_SUCCESS);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, recipient_channel);
    }

    return status;
}

int ssh_channel_failure_encode(ssh_buffer_t *buf, uint32_t recipient_channel)
{
    int status;

    if (buf == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_CHANNEL_FAILURE);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, recipient_channel);
    }

    return status;
}

int ssh_channel_window_adjust_encode(
    ssh_buffer_t *buf,
    uint32_t recipient_channel,
    uint32_t bytes_to_add)
{
    int status;

    if (buf == NULL || bytes_to_add == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_CHANNEL_WINDOW_ADJUST);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, recipient_channel);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, bytes_to_add);
    }

    return status;
}

static int ssh_channel_simple_encode(ssh_buffer_t *buf, uint8_t message_id, uint32_t recipient_channel)
{
    int status;

    if (buf == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, message_id);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, recipient_channel);
    }

    return status;
}

int ssh_channel_eof_encode(ssh_buffer_t *buf, uint32_t recipient_channel)
{
    return ssh_channel_simple_encode(buf, SSH_MSG_CHANNEL_EOF, recipient_channel);
}

int ssh_channel_close_encode(ssh_buffer_t *buf, uint32_t recipient_channel)
{
    return ssh_channel_simple_encode(buf, SSH_MSG_CHANNEL_CLOSE, recipient_channel);
}

int ssh_channel_data_encode(
    ssh_buffer_t *buf,
    uint32_t recipient_channel,
    const uint8_t *data,
    size_t data_len)
{
    int status;

    if (buf == NULL || (data == NULL && data_len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_CHANNEL_DATA);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(buf, recipient_channel);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(buf, data, data_len);
    }

    return status;
}

int ssh_channel_data_decode(ssh_buffer_t *payload, ssh_channel_data_t *data)
{
    uint8_t message_id;
    int status;

    if (payload == NULL || data == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(data, 0, sizeof(*data));

    status = ssh_buffer_get_u8(payload, &message_id);
    if (status != SSH_OK) {
        return status;
    }
    if (message_id != SSH_MSG_CHANNEL_DATA) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    status = ssh_buffer_get_u32(payload, &data->recipient_channel);
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(payload, &data->data);
    }
    if (status != SSH_OK) {
        return status;
    }

    return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_MALFORMED_PACKET;
}

int ssh_channel_message_decode(ssh_buffer_t *payload, ssh_channel_message_t *message)
{
    uint8_t message_id;
    int status;

    if (payload == NULL || message == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(message, 0, sizeof(*message));

    status = ssh_buffer_get_u8(payload, &message_id);
    if (status != SSH_OK) {
        return status;
    }

    if (message_id != SSH_MSG_CHANNEL_WINDOW_ADJUST &&
        message_id != SSH_MSG_CHANNEL_DATA &&
        message_id != SSH_MSG_CHANNEL_REQUEST &&
        message_id != SSH_MSG_CHANNEL_EOF &&
        message_id != SSH_MSG_CHANNEL_CLOSE) {
        return SSH_ERR_UNSUPPORTED;
    }

    message->message_id = message_id;
    status = ssh_buffer_get_u32(payload, &message->recipient_channel);
    if (status != SSH_OK) {
        return status;
    }

    if (message_id == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
        status = ssh_buffer_get_u32(payload, &message->window_bytes);
        if (status != SSH_OK) {
            return status;
        }
        if (message->window_bytes == 0u) {
            return SSH_ERR_MALFORMED_PACKET;
        }
    } else if (message_id == SSH_MSG_CHANNEL_REQUEST) {
        message->channel_request.recipient_channel = message->recipient_channel;
        status = ssh_buffer_get_string_view(payload, &message->channel_request.request_type);
        if (status == SSH_OK) {
            status = ssh_buffer_get_bool(payload, &message->channel_request.want_reply);
        }
        if (status != SSH_OK) {
            return status;
        }

        if (view_eq(message->channel_request.request_type, SSH_CHANNEL_REQUEST_SUBSYSTEM)) {
            status = ssh_buffer_get_string_view(payload, &message->channel_request.subsystem_name);
            if (status != SSH_OK) {
                return status;
            }
            return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_MALFORMED_PACKET;
        }
        if (view_eq(message->channel_request.request_type, SSH_CHANNEL_REQUEST_PTY_REQ)) {
            status = ssh_buffer_get_string_view(payload, &message->channel_request.term_type);
            if (status == SSH_OK) {
                status = ssh_buffer_get_u32(payload, &message->channel_request.cols);
            }
            if (status == SSH_OK) {
                status = ssh_buffer_get_u32(payload, &message->channel_request.rows);
            }
            if (status == SSH_OK) {
                status = ssh_buffer_get_u32(payload, &message->channel_request.width_px);
            }
            if (status == SSH_OK) {
                status = ssh_buffer_get_u32(payload, &message->channel_request.height_px);
            }
            if (status == SSH_OK) {
                status = ssh_buffer_get_string_view(payload, &message->channel_request.pty_modes);
            }
            if (status != SSH_OK) {
                return SSH_ERR_UNSUPPORTED;
            }
            return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_UNSUPPORTED;
        }
        if (view_eq(message->channel_request.request_type, SSH_CHANNEL_REQUEST_SHELL)) {
            return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_UNSUPPORTED;
        }
        if (view_eq(message->channel_request.request_type, SSH_CHANNEL_REQUEST_EXEC)) {
            status = ssh_buffer_get_string_view(payload, &message->channel_request.command);
            if (status != SSH_OK) {
                return SSH_ERR_UNSUPPORTED;
            }
            return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_UNSUPPORTED;
        }
        if (view_eq(message->channel_request.request_type, SSH_CHANNEL_REQUEST_ENV)) {
            status = ssh_buffer_get_string_view(payload, &message->channel_request.env_name);
            if (status == SSH_OK) {
                status = ssh_buffer_get_string_view(payload, &message->channel_request.env_value);
            }
            if (status != SSH_OK) {
                return SSH_ERR_UNSUPPORTED;
            }
            return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_UNSUPPORTED;
        }
        if (view_eq(message->channel_request.request_type, SSH_CHANNEL_REQUEST_WINDOW_CHANGE)) {
            status = ssh_buffer_get_u32(payload, &message->channel_request.cols);
            if (status == SSH_OK) {
                status = ssh_buffer_get_u32(payload, &message->channel_request.rows);
            }
            if (status == SSH_OK) {
                status = ssh_buffer_get_u32(payload, &message->channel_request.width_px);
            }
            if (status == SSH_OK) {
                status = ssh_buffer_get_u32(payload, &message->channel_request.height_px);
            }
            if (status != SSH_OK) {
                return SSH_ERR_UNSUPPORTED;
            }
            return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_UNSUPPORTED;
        }
        if (view_eq(message->channel_request.request_type, SSH_CHANNEL_REQUEST_SIGNAL)) {
            status = ssh_buffer_get_string_view(payload, &message->channel_request.signal_name);
            if (status != SSH_OK) {
                return SSH_ERR_UNSUPPORTED;
            }
            return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_UNSUPPORTED;
        }
        return SSH_ERR_UNSUPPORTED;
    } else if (message_id == SSH_MSG_CHANNEL_DATA) {
        status = ssh_buffer_get_string_view(payload, &message->data);
        if (status != SSH_OK) {
            return status;
        }
    }

    return ssh_buffer_remaining_read(payload) == 0u ? SSH_OK : SSH_ERR_MALFORMED_PACKET;
}

int ssh_channel_type_is_session(ssh_string_view_t channel_type)
{
    return view_eq(channel_type, SSH_CHANNEL_TYPE_SESSION);
}

int ssh_channel_request_is_sftp_subsystem(const ssh_channel_request_t *request)
{
    return request != NULL &&
           view_eq(request->request_type, SSH_CHANNEL_REQUEST_SUBSYSTEM) &&
           view_eq(request->subsystem_name, SSH_SUBSYSTEM_SFTP);
}

int ssh_channel_request_is_terminal(const ssh_channel_request_t *request)
{
    return request != NULL &&
           (view_eq(request->request_type, SSH_CHANNEL_REQUEST_PTY_REQ) ||
            view_eq(request->request_type, SSH_CHANNEL_REQUEST_SHELL) ||
            view_eq(request->request_type, SSH_CHANNEL_REQUEST_EXEC) ||
            view_eq(request->request_type, SSH_CHANNEL_REQUEST_ENV) ||
            view_eq(request->request_type, SSH_CHANNEL_REQUEST_WINDOW_CHANGE) ||
            view_eq(request->request_type, SSH_CHANNEL_REQUEST_SIGNAL));
}
