#ifndef EMSSH_SSH_SERVER_H
#define EMSSH_SSH_SERVER_H

#include <stddef.h>
#include <stdint.h>

#include "emssh/ssh_connection.h"
#include "emssh/sftp_server.h"
#include "emssh/ssh_kex.h"
#include "emssh/ssh_platform.h"

struct ssh_transport_session;

typedef struct ssh_password_auth_request {
    const char *username;
    size_t username_len;
    const char *service_name;
    size_t service_name_len;
    const char *password;
    size_t password_len;
} ssh_password_auth_request_t;

typedef struct ssh_publickey_auth_request {
    const char *username;
    size_t username_len;
    const char *service_name;
    size_t service_name_len;
    const char *algorithm;
    size_t algorithm_len;
    const uint8_t *publickey_blob;
    size_t publickey_blob_len;
} ssh_publickey_auth_request_t;

typedef int (*ssh_password_auth_fn)(void *ctx, const ssh_password_auth_request_t *request);
typedef int (*ssh_publickey_auth_fn)(void *ctx, const ssh_publickey_auth_request_t *request);
typedef int (*ssh_non_sftp_channel_request_policy_fn)(void *ctx, const ssh_channel_request_t *request);

#define EMSSH_SERVER_SIG_ALGS_DEFAULT_BASE "rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256"
#define EMSSH_SERVER_SIG_ALGS_DEFAULT "rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256,ssh-ed25519"

#define EMSSH_PERMIT_ROOT_LOGIN_DEFAULT 0
#define EMSSH_PERMIT_ROOT_LOGIN_NO 1
#define EMSSH_PERMIT_ROOT_LOGIN_YES 2
#define EMSSH_PERMIT_ROOT_LOGIN_PROHIBIT_PASSWORD 3

typedef struct ssh_server_config {
    const char *software_name;
    size_t max_packet_size;
    size_t max_payload_size;
    unsigned max_auth_tries;
    const char *listen_address;
    ssh_password_auth_fn password_auth;
    ssh_publickey_auth_fn publickey_auth;
    const char *publickey_signature_algorithms;
    int permit_root_login;
    const char *allow_users;
    const char *authorized_keys_file;
    void *auth_ctx;
} ssh_server_config_t;

typedef struct ssh_server {
    ssh_platform_t platform;
    ssh_server_config_t config;
    int initialized;
    uint8_t diag_last_received_message_id;
    int diag_last_received_message_id_valid;
} ssh_server_t;

typedef struct ssh_server_session_options {
    const ssh_kexinit_algorithm_set_t *algorithms;
    uint32_t timeout_ms;
    uint32_t server_channel;
    uint32_t channel_window_size;
    uint32_t channel_max_packet_size;
    unsigned max_sftp_packets;
    uint64_t rekey_after_packets;
    uint64_t rekey_after_bytes;
    sftp_policy_fn sftp_policy;
    void *sftp_policy_ctx;
    ssh_non_sftp_channel_request_policy_fn non_sftp_channel_request_policy;
    void *non_sftp_channel_request_policy_ctx;
    const char *sftp_subsystem_name;
} ssh_server_session_options_t;

typedef struct ssh_server_sftp_channel {
    uint32_t client_channel;
    uint32_t server_channel;
    uint32_t window_size;
    uint32_t window_max_size;
    uint32_t max_packet_size;
    uint32_t peer_window_size;
    uint32_t peer_max_packet_size;
    int initialized;
    int eof_sent;
    int close_sent;
    uint8_t sftp_rx[EMSSH_MAX_PACKET_SIZE];
    size_t sftp_rx_len;
    sftp_server_session_t sftp;
} ssh_server_sftp_channel_t;

typedef enum ssh_server_terminal_state {
    SSH_SERVER_TERMINAL_STATE_INIT = 0,
    SSH_SERVER_TERMINAL_STATE_SESSION_OPEN,
    SSH_SERVER_TERMINAL_STATE_PTY_CONFIGURED,
    SSH_SERVER_TERMINAL_STATE_RUNNING,
    SSH_SERVER_TERMINAL_STATE_CLOSED
} ssh_server_terminal_state_t;

typedef struct ssh_server_terminal_channel {
    uint32_t client_channel;
    uint32_t server_channel;
    uint32_t window_size;
    uint32_t window_max_size;
    uint32_t max_packet_size;
    uint32_t peer_window_size;
    uint32_t peer_max_packet_size;
    uint32_t cols;
    uint32_t rows;
    uint32_t width_px;
    uint32_t height_px;
    char term_type[64];
    int initialized;
    int pty_requested;
    int running;
    int eof_sent;
    int close_sent;
    int exit_status_sent;
    ssh_server_terminal_state_t state;
    void *term_handle;
} ssh_server_terminal_channel_t;

void ssh_server_config_defaults(ssh_server_config_t *config);
int ssh_server_init(ssh_server_t *server, const ssh_platform_t *platform, const ssh_server_config_t *config);
void ssh_server_deinit(ssh_server_t *server);
int ssh_server_format_identification(const ssh_server_t *server, char *out, size_t out_capacity);

void ssh_server_session_options_defaults(ssh_server_session_options_t *options);

int ssh_server_run_transport_setup(
    ssh_server_t *server,
    void *conn,
    struct ssh_transport_session *transport,
    const ssh_server_session_options_t *options);

int ssh_server_run_userauth(
    struct ssh_transport_session *transport,
    void *conn,
    const ssh_server_session_options_t *options);

int ssh_server_accept_sftp_channel(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_sftp_channel_t *channel,
    const ssh_server_session_options_t *options);

int ssh_server_process_sftp_channel_data(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_sftp_channel_t *channel,
    const ssh_server_session_options_t *options);

void ssh_server_sftp_channel_deinit(ssh_server_sftp_channel_t *channel);

int ssh_server_run_sftp_session(
    ssh_server_t *server,
    void *conn,
    const ssh_server_session_options_t *options);

int ssh_server_run_terminal_session(
    ssh_server_t *server,
    void *conn,
    const ssh_server_session_options_t *options);

int ssh_server_run_auto_session(
    ssh_server_t *server,
    void *conn,
    const ssh_server_session_options_t *options);

int ssh_server_accept_terminal_channel(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_terminal_channel_t *channel,
    const ssh_server_session_options_t *options);

int ssh_server_process_terminal_channel_data(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_terminal_channel_t *channel,
    const ssh_server_session_options_t *options);

void ssh_server_terminal_channel_deinit(
    struct ssh_transport_session *transport,
    ssh_server_terminal_channel_t *channel);

#endif
