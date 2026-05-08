#ifndef EMSSH_SSH_CONNECTION_H
#define EMSSH_SSH_CONNECTION_H

#include <stdint.h>

#include "emssh/ssh_buffer.h"

#define SSH_MSG_CHANNEL_OPEN 90u
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91u
#define SSH_MSG_CHANNEL_OPEN_FAILURE 92u
#define SSH_MSG_CHANNEL_WINDOW_ADJUST 93u
#define SSH_MSG_CHANNEL_DATA 94u
#define SSH_MSG_CHANNEL_EXTENDED_DATA 95u
#define SSH_MSG_CHANNEL_EOF 96u
#define SSH_MSG_CHANNEL_CLOSE 97u
#define SSH_MSG_CHANNEL_REQUEST 98u
#define SSH_MSG_CHANNEL_SUCCESS 99u
#define SSH_MSG_CHANNEL_FAILURE 100u

#define SSH_MSG_GLOBAL_REQUEST 80u
#define SSH_MSG_REQUEST_SUCCESS 81u
#define SSH_MSG_REQUEST_FAILURE 82u

#define SSH_CHANNEL_TYPE_SESSION "session"
#define SSH_CHANNEL_REQUEST_SUBSYSTEM "subsystem"
#define SSH_CHANNEL_REQUEST_X11_REQ "x11-req"
#define SSH_CHANNEL_REQUEST_PTY_REQ "pty-req"
#define SSH_CHANNEL_REQUEST_SHELL "shell"
#define SSH_CHANNEL_REQUEST_EXEC "exec"
#define SSH_CHANNEL_REQUEST_ENV "env"
#define SSH_CHANNEL_REQUEST_WINDOW_CHANGE "window-change"
#define SSH_CHANNEL_REQUEST_SIGNAL "signal"
#define SSH_SUBSYSTEM_SFTP "sftp"

#define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED 1u
#define SSH_OPEN_CONNECT_FAILED 2u
#define SSH_OPEN_UNKNOWN_CHANNEL_TYPE 3u
#define SSH_OPEN_RESOURCE_SHORTAGE 4u

typedef struct ssh_channel_open {
    ssh_string_view_t channel_type;
    uint32_t sender_channel;
    uint32_t initial_window_size;
    uint32_t maximum_packet_size;
} ssh_channel_open_t;

typedef struct ssh_channel_request {
    uint32_t recipient_channel;
    ssh_string_view_t request_type;
    int want_reply;
    ssh_string_view_t subsystem_name;
    ssh_string_view_t term_type;
    ssh_string_view_t command;
    ssh_string_view_t env_name;
    ssh_string_view_t env_value;
    ssh_string_view_t signal_name;
    ssh_string_view_t pty_modes;
    uint32_t cols;
    uint32_t rows;
    uint32_t width_px;
    uint32_t height_px;
} ssh_channel_request_t;

typedef struct ssh_channel_data {
    uint32_t recipient_channel;
    ssh_string_view_t data;
} ssh_channel_data_t;

typedef struct ssh_global_request {
    ssh_string_view_t request_name;
    int want_reply;
} ssh_global_request_t;

typedef struct ssh_channel_message {
    uint8_t message_id;
    uint32_t recipient_channel;
    uint32_t window_bytes;
    ssh_string_view_t data;
    ssh_channel_request_t channel_request;
} ssh_channel_message_t;

int ssh_channel_open_session_encode(
    ssh_buffer_t *buf,
    uint32_t sender_channel,
    uint32_t initial_window_size,
    uint32_t maximum_packet_size);

int ssh_channel_open_decode(ssh_buffer_t *payload, ssh_channel_open_t *open);

int ssh_global_request_decode(ssh_buffer_t *payload, ssh_global_request_t *request);
int ssh_global_request_failure_encode(ssh_buffer_t *buf);

int ssh_channel_open_confirmation_encode(
    ssh_buffer_t *buf,
    uint32_t recipient_channel,
    uint32_t sender_channel,
    uint32_t initial_window_size,
    uint32_t maximum_packet_size);

int ssh_channel_open_failure_encode(
    ssh_buffer_t *buf,
    uint32_t recipient_channel,
    uint32_t reason_code,
    const char *description,
    const char *language_tag);

int ssh_channel_request_subsystem_encode(
    ssh_buffer_t *buf,
    uint32_t recipient_channel,
    int want_reply,
    const char *subsystem_name);
int ssh_channel_request_exit_status_encode(
    ssh_buffer_t *buf,
    uint32_t recipient_channel,
    int want_reply,
    uint32_t exit_status);

int ssh_channel_request_decode(ssh_buffer_t *payload, ssh_channel_request_t *request);

int ssh_channel_success_encode(ssh_buffer_t *buf, uint32_t recipient_channel);
int ssh_channel_failure_encode(ssh_buffer_t *buf, uint32_t recipient_channel);
int ssh_channel_window_adjust_encode(
    ssh_buffer_t *buf,
    uint32_t recipient_channel,
    uint32_t bytes_to_add);
int ssh_channel_eof_encode(ssh_buffer_t *buf, uint32_t recipient_channel);
int ssh_channel_close_encode(ssh_buffer_t *buf, uint32_t recipient_channel);

int ssh_channel_data_encode(
    ssh_buffer_t *buf,
    uint32_t recipient_channel,
    const uint8_t *data,
    size_t data_len);

int ssh_channel_data_decode(ssh_buffer_t *payload, ssh_channel_data_t *data);
int ssh_channel_message_decode(ssh_buffer_t *payload, ssh_channel_message_t *message);

int ssh_channel_type_is_session(ssh_string_view_t channel_type);
int ssh_channel_request_is_sftp_subsystem(const ssh_channel_request_t *request);
int ssh_channel_request_is_terminal(const ssh_channel_request_t *request);

#endif
