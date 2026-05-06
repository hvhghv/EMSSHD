#include <stdio.h>
#include <string.h>

#include "emssh/ssh_connection.h"
#include "emssh/ssh_error.h"

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

int main(void)
{
    uint8_t storage[128];
    ssh_buffer_t buf;
    ssh_channel_open_t open;
    ssh_global_request_t global_request;
    ssh_channel_request_t request;
    ssh_channel_data_t data;
    ssh_channel_message_t message;

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_channel_open_session_encode(&buf, 7u, 65536u, 32768u) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_channel_open_decode(&buf, &open) == SSH_OK);
    CHECK(view_eq(open.channel_type, SSH_CHANNEL_TYPE_SESSION));
    CHECK(open.sender_channel == 7u);
    CHECK(open.initial_window_size == 65536u);
    CHECK(open.maximum_packet_size == 32768u);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_buffer_put_u8(&buf, SSH_MSG_CHANNEL_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "direct-tcpip") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 9u) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 1024u) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 512u) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_channel_open_decode(&buf, &open) == SSH_OK);
    CHECK(view_eq(open.channel_type, "direct-tcpip"));
    CHECK(open.sender_channel == 9u);
    CHECK(!ssh_channel_type_is_session(open.channel_type));

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_channel_open_confirmation_encode(&buf, 7u, 0u, 65536u, 32768u) == SSH_OK);
    CHECK(storage[0] == SSH_MSG_CHANNEL_OPEN_CONFIRMATION);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_buffer_put_u8(&buf, SSH_MSG_GLOBAL_REQUEST) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "hostkeys-00@openssh.com") == SSH_OK);
    CHECK(ssh_buffer_put_bool(&buf, 1) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_global_request_decode(&buf, &global_request) == SSH_OK);
    CHECK(view_eq(global_request.request_name, "hostkeys-00@openssh.com"));
    CHECK(global_request.want_reply);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_global_request_failure_encode(&buf) == SSH_OK);
    CHECK(ssh_buffer_len(&buf) == 1u);
    CHECK(storage[0] == SSH_MSG_REQUEST_FAILURE);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_channel_request_subsystem_encode(&buf, 0u, 1, SSH_SUBSYSTEM_SFTP) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_channel_request_decode(&buf, &request) == SSH_OK);
    CHECK(request.recipient_channel == 0u);
    CHECK(request.want_reply);
    CHECK(ssh_channel_request_is_sftp_subsystem(&request));
    CHECK(!ssh_channel_request_is_terminal(&request));

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_buffer_put_u8(&buf, SSH_MSG_CHANNEL_REQUEST) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 2u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, SSH_CHANNEL_REQUEST_SHELL) == SSH_OK);
    CHECK(ssh_buffer_put_bool(&buf, 1) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_channel_request_decode(&buf, &request) == SSH_OK);
    CHECK(request.recipient_channel == 2u);
    CHECK(request.want_reply);
    CHECK(ssh_channel_request_is_terminal(&request));

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_buffer_put_u8(&buf, SSH_MSG_CHANNEL_REQUEST) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 3u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, SSH_CHANNEL_REQUEST_EXEC) == SSH_OK);
    CHECK(ssh_buffer_put_bool(&buf, 0) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "id -u") == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_channel_request_decode(&buf, &request) == SSH_OK);
    CHECK(request.recipient_channel == 3u);
    CHECK(!request.want_reply);
    CHECK(view_eq(request.command, "id -u"));
    CHECK(ssh_channel_request_is_terminal(&request));

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_buffer_put_u8(&buf, SSH_MSG_CHANNEL_REQUEST) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 4u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, SSH_CHANNEL_REQUEST_PTY_REQ) == SSH_OK);
    CHECK(ssh_buffer_put_bool(&buf, 1) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "xterm-256color") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 120u) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 40u) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 0u) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 0u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&buf, (const uint8_t *)"", 0u) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_channel_request_decode(&buf, &request) == SSH_OK);
    CHECK(request.recipient_channel == 4u);
    CHECK(view_eq(request.term_type, "xterm-256color"));
    CHECK(request.cols == 120u);
    CHECK(request.rows == 40u);
    CHECK(ssh_channel_request_is_terminal(&request));

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_buffer_put_u8(&buf, SSH_MSG_CHANNEL_REQUEST) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 6u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, SSH_CHANNEL_REQUEST_WINDOW_CHANGE) == SSH_OK);
    CHECK(ssh_buffer_put_bool(&buf, 1) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 132u) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 43u) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 0u) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 0u) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_channel_message_decode(&buf, &message) == SSH_OK);
    CHECK(message.message_id == SSH_MSG_CHANNEL_REQUEST);
    CHECK(message.recipient_channel == 6u);
    CHECK(message.channel_request.want_reply);
    CHECK(view_eq(message.channel_request.request_type, SSH_CHANNEL_REQUEST_WINDOW_CHANGE));
    CHECK(message.channel_request.cols == 132u);
    CHECK(message.channel_request.rows == 43u);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_buffer_put_u8(&buf, SSH_MSG_CHANNEL_REQUEST) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 7u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, SSH_CHANNEL_REQUEST_SIGNAL) == SSH_OK);
    CHECK(ssh_buffer_put_bool(&buf, 1) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "TERM") == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_channel_message_decode(&buf, &message) == SSH_OK);
    CHECK(message.message_id == SSH_MSG_CHANNEL_REQUEST);
    CHECK(message.recipient_channel == 7u);
    CHECK(message.channel_request.want_reply);
    CHECK(view_eq(message.channel_request.request_type, SSH_CHANNEL_REQUEST_SIGNAL));
    CHECK(view_eq(message.channel_request.signal_name, "TERM"));

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_channel_success_encode(&buf, 7u) == SSH_OK);
    CHECK(storage[0] == SSH_MSG_CHANNEL_SUCCESS);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_channel_request_exit_status_encode(&buf, 7u, 0, 3u) == SSH_OK);
    CHECK(storage[0] == SSH_MSG_CHANNEL_REQUEST);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_channel_window_adjust_encode(&buf, 0u, 4096u) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_channel_message_decode(&buf, &message) == SSH_OK);
    CHECK(message.message_id == SSH_MSG_CHANNEL_WINDOW_ADJUST);
    CHECK(message.recipient_channel == 0u);
    CHECK(message.window_bytes == 4096u);
    CHECK(message.data.len == 0u);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_channel_data_encode(&buf, 0u, (const uint8_t *)"abc", 3u) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_channel_data_decode(&buf, &data) == SSH_OK);
    CHECK(data.recipient_channel == 0u);
    CHECK(data.data.len == 3u);
    CHECK(memcmp(data.data.data, "abc", 3u) == 0);

    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_channel_message_decode(&buf, &message) == SSH_OK);
    CHECK(message.message_id == SSH_MSG_CHANNEL_DATA);
    CHECK(message.recipient_channel == 0u);
    CHECK(message.data.len == 3u);
    CHECK(memcmp(message.data.data, "abc", 3u) == 0);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_channel_eof_encode(&buf, 0u) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_channel_message_decode(&buf, &message) == SSH_OK);
    CHECK(message.message_id == SSH_MSG_CHANNEL_EOF);
    CHECK(message.recipient_channel == 0u);
    CHECK(message.data.len == 0u);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_channel_close_encode(&buf, 0u) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_channel_message_decode(&buf, &message) == SSH_OK);
    CHECK(message.message_id == SSH_MSG_CHANNEL_CLOSE);
    CHECK(message.recipient_channel == 0u);
    CHECK(message.data.len == 0u);

    return 0;
}
