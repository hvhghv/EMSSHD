#ifndef EMSSH_SSH_TRANSPORT_H
#define EMSSH_SSH_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include "emssh/ssh_buffer.h"
#include "emssh/ssh_connection.h"
#include "emssh/ssh_crypto.h"
#include "emssh/ssh_kex.h"
#include "emssh/ssh_packet.h"
#include "emssh/ssh_service.h"
#include "emssh/ssh_userauth.h"

#define SSH_MSG_DISCONNECT 1u
#define SSH_MSG_IGNORE 2u
#define SSH_MSG_UNIMPLEMENTED 3u
#define SSH_MSG_DEBUG 4u
#define SSH_MSG_SERVICE_REQUEST 5u
#define SSH_MSG_SERVICE_ACCEPT 6u
#define SSH_MSG_EXT_INFO 7u
#define EMSSH_MAX_IDENTIFICATION_LINE 255u
#define EMSSH_MAX_KEXINIT_PAYLOAD 2048u
#define EMSSH_MAX_KEX_REPLY_PAYLOAD 2048u
#define EMSSH_MAX_SERVICE_PAYLOAD 256u
#define EMSSH_MAX_EXT_INFO_PAYLOAD 256u
#define EMSSH_MAX_CHANNEL_OPEN_PAYLOAD 512u
#define EMSSH_MAX_CHANNEL_REQUEST_PAYLOAD 512u
#define EMSSH_MAX_CHANNEL_MESSAGE_PAYLOAD (EMSSH_MAX_PAYLOAD_SIZE + 16u)

struct ssh_server;

typedef struct ssh_identification {
    ssh_string_view_t raw;
    ssh_string_view_t protocol_version;
    ssh_string_view_t software_version;
    ssh_string_view_t comments;
} ssh_identification_t;

typedef enum ssh_transport_state {
    SSH_TRANSPORT_STATE_INIT = 0,
    SSH_TRANSPORT_STATE_IDENT_SENT,
    SSH_TRANSPORT_STATE_IDENT_RECEIVED,
    SSH_TRANSPORT_STATE_KEXINIT_SENT,
    SSH_TRANSPORT_STATE_KEXINIT_RECEIVED,
    SSH_TRANSPORT_STATE_NEGOTIATED,
    SSH_TRANSPORT_STATE_KEX_ECDH_INIT_RECEIVED,
    SSH_TRANSPORT_STATE_KEX_ECDH_REPLY_SENT,
    SSH_TRANSPORT_STATE_NEWKEYS_SENT,
    SSH_TRANSPORT_STATE_NEWKEYS_RECEIVED,
    SSH_TRANSPORT_STATE_SERVICE_REQUEST_RECEIVED,
    SSH_TRANSPORT_STATE_SERVICE_ACCEPT_SENT,
    SSH_TRANSPORT_STATE_USERAUTH_REQUEST_RECEIVED,
    SSH_TRANSPORT_STATE_USERAUTH_PK_OK_SENT,
    SSH_TRANSPORT_STATE_USERAUTH_SUCCESS_SENT,
    SSH_TRANSPORT_STATE_USERAUTH_FAILURE_SENT,
    SSH_TRANSPORT_STATE_GLOBAL_REQUEST_RECEIVED,
    SSH_TRANSPORT_STATE_REQUEST_FAILURE_SENT,
    SSH_TRANSPORT_STATE_CHANNEL_OPEN_RECEIVED,
    SSH_TRANSPORT_STATE_CHANNEL_OPEN_CONFIRMATION_SENT,
    SSH_TRANSPORT_STATE_CHANNEL_OPEN_FAILURE_SENT,
    SSH_TRANSPORT_STATE_CHANNEL_REQUEST_RECEIVED,
    SSH_TRANSPORT_STATE_CHANNEL_SUCCESS_SENT,
    SSH_TRANSPORT_STATE_CHANNEL_FAILURE_SENT,
    SSH_TRANSPORT_STATE_CHANNEL_WINDOW_ADJUST_RECEIVED,
    SSH_TRANSPORT_STATE_CHANNEL_WINDOW_ADJUST_SENT,
    SSH_TRANSPORT_STATE_CHANNEL_DATA_RECEIVED,
    SSH_TRANSPORT_STATE_CHANNEL_DATA_SENT,
    SSH_TRANSPORT_STATE_CHANNEL_EOF_RECEIVED,
    SSH_TRANSPORT_STATE_CHANNEL_EOF_SENT,
    SSH_TRANSPORT_STATE_CHANNEL_CLOSE_RECEIVED,
    SSH_TRANSPORT_STATE_CHANNEL_CLOSE_SENT
} ssh_transport_state_t;

typedef struct ssh_transport_session {
    const struct ssh_server *server;
    ssh_transport_state_t state;

    uint8_t server_identification_line[EMSSH_MAX_IDENTIFICATION_LINE + 2u];
    size_t server_identification_len;
    ssh_identification_t server_identification;

    uint8_t client_identification_line[EMSSH_MAX_IDENTIFICATION_LINE + 2u];
    size_t client_identification_len;
    ssh_identification_t client_identification;

    ssh_kexinit_algorithm_set_t server_algorithms;

    uint8_t server_kexinit_payload[EMSSH_MAX_KEXINIT_PAYLOAD];
    size_t server_kexinit_payload_len;

    uint8_t client_kexinit_payload[EMSSH_MAX_KEXINIT_PAYLOAD];
    size_t client_kexinit_payload_len;
    ssh_kexinit_t client_kexinit;
    int client_supports_ext_info;

    uint32_t inbound_sequence;
    uint32_t outbound_sequence;

    uint64_t rekey_after_packets;
    uint64_t rekey_after_bytes;
    uint64_t inbound_rekey_packets;
    uint64_t outbound_rekey_packets;
    uint64_t inbound_rekey_bytes;
    uint64_t outbound_rekey_bytes;
    int rekey_needed;

    ssh_kex_negotiation_t negotiation;

    uint8_t client_kex_public_key[EMSSH_MAX_KEX_PUBLIC_KEY];
    size_t client_kex_public_key_len;

    uint8_t server_kex_public_key[EMSSH_MAX_KEX_PUBLIC_KEY];
    size_t server_kex_public_key_len;

    uint8_t server_kex_private_key[EMSSH_MAX_KEX_PRIVATE_KEY];
    size_t server_kex_private_key_len;

    uint8_t shared_secret[EMSSH_MAX_KEX_SHARED_SECRET];
    size_t shared_secret_len;

    uint8_t exchange_hash[EMSSH_MAX_EXCHANGE_HASH];
    size_t exchange_hash_len;

    uint8_t session_id[EMSSH_MAX_EXCHANGE_HASH];
    size_t session_id_len;

    uint8_t server_host_key[EMSSH_MAX_HOST_KEY_BLOB];
    size_t server_host_key_len;

    uint8_t server_signature[EMSSH_MAX_SIGNATURE];
    size_t server_signature_len;

    ssh_packet_protection_t inbound;
    ssh_packet_protection_t outbound;

    uint8_t service_payload[EMSSH_MAX_SERVICE_PAYLOAD];
    size_t service_payload_len;
    uint8_t channel_open_payload[EMSSH_MAX_CHANNEL_OPEN_PAYLOAD];
    size_t channel_open_payload_len;
    uint8_t channel_request_payload[EMSSH_MAX_CHANNEL_REQUEST_PAYLOAD];
    size_t channel_request_payload_len;
    uint8_t channel_message_payload[EMSSH_MAX_CHANNEL_MESSAGE_PAYLOAD];
    size_t channel_message_payload_len;
    uint8_t userauth_payload[EMSSH_MAX_USERAUTH_PAYLOAD];
    size_t userauth_payload_len;
    char authenticated_username[EMSSH_MAX_USERAUTH_PAYLOAD];
    size_t authenticated_username_len;
    uint8_t last_received_message_id;
    int last_received_message_id_valid;
    char last_channel_request_type[64];
    int last_channel_request_type_valid;
    int last_channel_request_want_reply;
} ssh_transport_session_t;

int ssh_identification_parse_line(const uint8_t *line, size_t len, ssh_identification_t *ident);
int ssh_identification_is_ssh2_compatible(const ssh_identification_t *ident);

int ssh_transport_session_init(
    ssh_transport_session_t *session,
    const struct ssh_server *server,
    const ssh_kexinit_algorithm_set_t *server_algorithms);

int ssh_transport_set_rekey_limits(
    ssh_transport_session_t *session,
    uint64_t packets,
    uint64_t bytes);

int ssh_transport_rekey_needed(const ssh_transport_session_t *session);

int ssh_transport_send_identification(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms);

int ssh_transport_receive_identification(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms);

int ssh_transport_send_kexinit(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms);

int ssh_transport_receive_kexinit(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms);

int ssh_transport_receive_kex_ecdh_init(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms);

int ssh_transport_send_kex_ecdh_reply(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms);

int ssh_transport_send_newkeys(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms);

int ssh_transport_receive_newkeys(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms);

int ssh_transport_send_ext_info(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms);

int ssh_transport_send_protected_payload(
    ssh_transport_session_t *session,
    void *conn,
    const uint8_t *payload,
    size_t payload_len,
    uint32_t timeout_ms);

int ssh_transport_receive_protected_payload(
    ssh_transport_session_t *session,
    void *conn,
    uint8_t *payload_out,
    size_t payload_capacity,
    size_t *payload_len,
    uint32_t timeout_ms);

int ssh_transport_receive_service_request(
    ssh_transport_session_t *session,
    void *conn,
    ssh_service_request_t *request,
    uint32_t timeout_ms);

int ssh_transport_send_service_accept(
    ssh_transport_session_t *session,
    void *conn,
    const char *service_name,
    uint32_t timeout_ms);

int ssh_transport_receive_userauth_request(
    ssh_transport_session_t *session,
    void *conn,
    ssh_userauth_request_t *request,
    uint32_t timeout_ms);

int ssh_transport_send_userauth_success(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms);

int ssh_transport_send_userauth_failure(
    ssh_transport_session_t *session,
    void *conn,
    const char *methods,
    int partial_success,
    uint32_t timeout_ms);

int ssh_transport_send_userauth_pk_ok(
    ssh_transport_session_t *session,
    void *conn,
    ssh_string_view_t publickey_algorithm,
    ssh_string_view_t publickey_blob,
    uint32_t timeout_ms);

int ssh_transport_handle_userauth_request(
    ssh_transport_session_t *session,
    void *conn,
    const ssh_userauth_request_t *request,
    uint32_t timeout_ms);

int ssh_transport_receive_channel_open(
    ssh_transport_session_t *session,
    void *conn,
    ssh_channel_open_t *open,
    uint32_t timeout_ms);

int ssh_transport_receive_channel_open_skip_global_requests(
    ssh_transport_session_t *session,
    void *conn,
    ssh_channel_open_t *open,
    uint32_t timeout_ms);

int ssh_transport_send_global_request_failure(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms);

int ssh_transport_send_channel_open_confirmation(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint32_t sender_channel,
    uint32_t initial_window_size,
    uint32_t maximum_packet_size,
    uint32_t timeout_ms);

int ssh_transport_send_channel_open_failure(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint32_t reason_code,
    const char *description,
    uint32_t timeout_ms);

int ssh_transport_receive_channel_request(
    ssh_transport_session_t *session,
    void *conn,
    ssh_channel_request_t *request,
    uint32_t timeout_ms);

int ssh_transport_send_channel_success(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint32_t timeout_ms);

int ssh_transport_send_channel_failure(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint32_t timeout_ms);

int ssh_transport_receive_channel_data(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t *recipient_channel,
    uint8_t *data_out,
    size_t data_capacity,
    size_t *data_len,
    uint32_t timeout_ms);

int ssh_transport_receive_channel_message(
    ssh_transport_session_t *session,
    void *conn,
    ssh_channel_message_t *message,
    uint8_t *data_out,
    size_t data_capacity,
    size_t *data_len,
    uint32_t timeout_ms);

int ssh_transport_send_channel_data(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    const uint8_t *data,
    size_t data_len,
    uint32_t timeout_ms);

int ssh_transport_send_channel_window_adjust(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint32_t bytes_to_add,
    uint32_t timeout_ms);

int ssh_transport_send_channel_eof(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint32_t timeout_ms);

int ssh_transport_send_channel_close(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint32_t timeout_ms);

int ssh_transport_send_channel_exit_status(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint32_t exit_status,
    uint32_t timeout_ms);

#endif
