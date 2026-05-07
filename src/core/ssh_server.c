#include "emssh/ssh_server.h"

#include <string.h>

#include "emssh/sftp_server.h"
#include "emssh/ssh_buffer.h"
#include "emssh/ssh_config.h"
#include "emssh/ssh_connection.h"
#include "emssh/ssh_error.h"
#include "emssh/ssh_service.h"
#include "emssh/ssh_transport.h"
#include "emssh/ssh_userauth.h"

#define EMSSH_DEFAULT_SESSION_TIMEOUT_MS 10000u
#define EMSSH_DEFAULT_CHANNEL_WINDOW_SIZE 65536u
#define EMSSH_DEFAULT_CHANNEL_MAX_PACKET_SIZE 32768u

static int view_equals_cstr(ssh_string_view_t view, const char *value)
{
    size_t len;

    if (value == NULL || view.data == NULL) {
        return 0;
    }

    len = strlen(value);
    return view.len == len && memcmp(view.data, value, len) == 0;
}

static int channel_request_is_subsystem_name(const ssh_channel_request_t *request, const char *subsystem_name)
{
    if (request == NULL || subsystem_name == NULL) {
        return 0;
    }
    return view_equals_cstr(request->request_type, SSH_CHANNEL_REQUEST_SUBSYSTEM) &&
           view_equals_cstr(request->subsystem_name, subsystem_name);
}

static uint32_t add_u32_saturating(uint32_t lhs, uint32_t rhs)
{
    if (UINT32_MAX - lhs < rhs) {
        return UINT32_MAX;
    }

    return lhs + rhs;
}

static uint32_t read_u32_be_local(const uint8_t data[4])
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static uint32_t min_u32_local(uint32_t lhs, uint32_t rhs)
{
    return lhs < rhs ? lhs : rhs;
}

static int view_to_cstring(ssh_string_view_t view, char *out, size_t out_capacity)
{
    if (out == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (view.data == NULL) {
        out[0] = '\0';
        return SSH_OK;
    }
    if (view.len + 1u > out_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(out, view.data, view.len);
    out[view.len] = '\0';
    return SSH_OK;
}

static int maybe_replenish_terminal_receive_window(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_terminal_channel_t *channel,
    uint32_t timeout_ms)
{
    uint32_t threshold;
    uint32_t bytes_to_add;
    int status;

    if (transport == NULL || conn == NULL || channel == NULL || channel->window_max_size == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    threshold = channel->window_max_size / 2u;
    if (channel->window_size > threshold) {
        return SSH_OK;
    }

    bytes_to_add = channel->window_max_size - channel->window_size;
    if (bytes_to_add == 0u) {
        return SSH_OK;
    }

    status = ssh_transport_send_channel_window_adjust(
        transport,
        conn,
        channel->client_channel,
        bytes_to_add,
        timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    channel->window_size += bytes_to_add;
    return SSH_OK;
}

static int maybe_replenish_receive_window(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_sftp_channel_t *channel,
    uint32_t timeout_ms)
{
    uint32_t threshold;
    uint32_t bytes_to_add;
    int status;

    if (transport == NULL || conn == NULL || channel == NULL || channel->window_max_size == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    threshold = channel->window_max_size / 2u;
    if (channel->window_size > threshold) {
        return SSH_OK;
    }

    bytes_to_add = channel->window_max_size - channel->window_size;
    if (bytes_to_add == 0u) {
        return SSH_OK;
    }

    status = ssh_transport_send_channel_window_adjust(
        transport,
        conn,
        channel->client_channel,
        bytes_to_add,
        timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    channel->window_size += bytes_to_add;
    return SSH_OK;
}

static void effective_session_options(
    const ssh_server_session_options_t *options,
    ssh_server_session_options_t *effective)
{
    ssh_server_session_options_defaults(effective);
    if (options != NULL) {
        if (options->algorithms != NULL) {
            effective->algorithms = options->algorithms;
        }
        if (options->timeout_ms != 0u) {
            effective->timeout_ms = options->timeout_ms;
        }
        effective->server_channel = options->server_channel;
        if (options->channel_window_size != 0u) {
            effective->channel_window_size = options->channel_window_size;
        }
        if (options->channel_max_packet_size != 0u) {
            effective->channel_max_packet_size = options->channel_max_packet_size;
        }
        effective->max_sftp_packets = options->max_sftp_packets;
        effective->rekey_after_packets = options->rekey_after_packets;
        effective->rekey_after_bytes = options->rekey_after_bytes;
        effective->sftp_policy = options->sftp_policy;
        effective->sftp_policy_ctx = options->sftp_policy_ctx;
        effective->non_sftp_channel_request_policy = options->non_sftp_channel_request_policy;
        effective->non_sftp_channel_request_policy_ctx = options->non_sftp_channel_request_policy_ctx;
        if (options->sftp_subsystem_name != NULL) {
            effective->sftp_subsystem_name = options->sftp_subsystem_name;
        }
    }
}

const char *ssh_status_string(int status)
{
    switch (status) {
    case SSH_OK:
        return "ok";
    case SSH_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case SSH_ERR_BUFFER_TOO_SMALL:
        return "buffer too small";
    case SSH_ERR_BUFFER_OVERFLOW:
        return "buffer overflow";
    case SSH_ERR_BUFFER_UNDERFLOW:
        return "buffer underflow";
    case SSH_ERR_MALFORMED_PACKET:
        return "malformed packet";
    case SSH_ERR_UNSUPPORTED:
        return "unsupported";
    case SSH_ERR_PLATFORM:
        return "platform error";
    case SSH_ERR_SECURITY:
        return "security error";
    case SSH_ERR_CLOSED:
        return "closed";
    case SSH_ERR_NOT_FOUND:
        return "not found";
    case SSH_ERR_ALREADY_EXISTS:
        return "already exists";
    case SSH_ERR_DIR_NOT_EMPTY:
        return "directory not empty";
    case SSH_ERR_READ_ONLY:
        return "read only";
    default:
        return "unknown error";
    }
}

void ssh_server_config_defaults(ssh_server_config_t *config)
{
    if (config == NULL) {
        return;
    }

    config->software_name = EMSSH_SOFTWARE_NAME;
    config->max_packet_size = EMSSH_MAX_PACKET_SIZE;
    config->max_payload_size = EMSSH_MAX_PAYLOAD_SIZE;
    config->max_auth_tries = EMSSH_MAX_AUTH_TRIES;
    config->listen_address = NULL;
    config->password_auth = NULL;
    config->publickey_auth = NULL;
    config->publickey_signature_algorithms = NULL;
    config->permit_root_login = EMSSH_PERMIT_ROOT_LOGIN_DEFAULT;
    config->allow_users = NULL;
    config->authorized_keys_file = NULL;
    config->auth_ctx = NULL;
}

int ssh_server_init(ssh_server_t *server, const ssh_platform_t *platform, const ssh_server_config_t *config)
{
    ssh_server_config_t defaults;
    ssh_string_view_t signature_algorithms;

    if (server == NULL || platform == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(server, 0, sizeof(*server));

    ssh_server_config_defaults(&defaults);
    server->config = config != NULL ? *config : defaults;
    server->platform = *platform;

    if (server->config.software_name == NULL ||
        server->config.max_packet_size == 0u ||
        server->config.max_payload_size == 0u ||
        server->config.max_payload_size > server->config.max_packet_size) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (server->config.permit_root_login < EMSSH_PERMIT_ROOT_LOGIN_DEFAULT ||
        server->config.permit_root_login > EMSSH_PERMIT_ROOT_LOGIN_PROHIBIT_PASSWORD) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (server->config.publickey_signature_algorithms != NULL) {
        signature_algorithms.data = (const uint8_t *)server->config.publickey_signature_algorithms;
        signature_algorithms.len = strlen(server->config.publickey_signature_algorithms);
        if (!ssh_name_list_is_valid(signature_algorithms)) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
    }

    server->initialized = 1;
    return SSH_OK;
}

void ssh_server_deinit(ssh_server_t *server)
{
    if (server == NULL) {
        return;
    }

    memset(server, 0, sizeof(*server));
}

int ssh_server_format_identification(const ssh_server_t *server, char *out, size_t out_capacity)
{
    static const char prefix[] = "SSH-2.0-";
    static const char suffix[] = "\r\n";
    const char *software_name;
    size_t software_len;
    size_t total_len;

    if (server == NULL || out == NULL || out_capacity == 0u || !server->initialized) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    software_name = server->config.software_name != NULL ? server->config.software_name : EMSSH_SOFTWARE_NAME;
    software_len = strlen(software_name);
    total_len = (sizeof(prefix) - 1u) + software_len + (sizeof(suffix) - 1u);
    if (out_capacity <= total_len) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(out, prefix, sizeof(prefix) - 1u);
    memcpy(out + (sizeof(prefix) - 1u), software_name, software_len);
    memcpy(out + (sizeof(prefix) - 1u) + software_len, suffix, sizeof(suffix) - 1u);
    out[total_len] = '\0';

    return SSH_OK;
}

void ssh_server_session_options_defaults(ssh_server_session_options_t *options)
{
    if (options == NULL) {
        return;
    }

    memset(options, 0, sizeof(*options));
    options->timeout_ms = EMSSH_DEFAULT_SESSION_TIMEOUT_MS;
    options->server_channel = 0u;
    options->channel_window_size = EMSSH_DEFAULT_CHANNEL_WINDOW_SIZE;
    options->channel_max_packet_size = EMSSH_DEFAULT_CHANNEL_MAX_PACKET_SIZE;
    options->max_sftp_packets = 0u;
    options->sftp_policy = NULL;
    options->sftp_policy_ctx = NULL;
    options->non_sftp_channel_request_policy = NULL;
    options->non_sftp_channel_request_policy_ctx = NULL;
    options->sftp_subsystem_name = SSH_SUBSYSTEM_SFTP;
}

int ssh_server_run_transport_setup(
    ssh_server_t *server,
    void *conn,
    struct ssh_transport_session *transport,
    const ssh_server_session_options_t *options)
{
    ssh_server_session_options_t effective;
    int status;

    if (server == NULL || conn == NULL || transport == NULL || !server->initialized) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    effective_session_options(options, &effective);
    status = ssh_transport_session_init(transport, server, effective.algorithms);
    if (status == SSH_OK) {
        status = ssh_transport_set_rekey_limits(
            transport,
            effective.rekey_after_packets,
            effective.rekey_after_bytes);
    }
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_transport_send_identification(transport, conn, effective.timeout_ms);
    if (status == SSH_OK) {
        status = ssh_transport_receive_identification(transport, conn, effective.timeout_ms);
    }
    if (status == SSH_OK) {
        status = ssh_transport_send_kexinit(transport, conn, effective.timeout_ms);
    }
    if (status == SSH_OK) {
        status = ssh_transport_receive_kexinit(transport, conn, effective.timeout_ms);
    }
    if (status == SSH_OK) {
        status = ssh_transport_receive_kex_ecdh_init(transport, conn, effective.timeout_ms);
    }
    if (status == SSH_OK) {
        status = ssh_transport_send_kex_ecdh_reply(transport, conn, effective.timeout_ms);
    }
    if (status == SSH_OK) {
        status = ssh_transport_send_newkeys(transport, conn, effective.timeout_ms);
    }
    if (status == SSH_OK) {
        status = ssh_transport_send_ext_info(transport, conn, effective.timeout_ms);
    }
    if (status == SSH_OK) {
        status = ssh_transport_receive_newkeys(transport, conn, effective.timeout_ms);
    }

    return status;
}

int ssh_server_run_userauth(
    struct ssh_transport_session *transport,
    void *conn,
    const ssh_server_session_options_t *options)
{
    ssh_server_session_options_t effective;
    ssh_service_request_t service_request;
    char failure_methods[EMSSH_MAX_USERAUTH_FAILURE_METHODS];
    unsigned tries;
    int status;

    if (transport == NULL || transport->server == NULL || conn == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    transport->authenticated_username[0] = '\0';
    transport->authenticated_username_len = 0u;

    effective_session_options(options, &effective);
    status = ssh_transport_receive_service_request(transport, conn, &service_request, effective.timeout_ms);
    if (status != SSH_OK) {
        return status;
    }
    if (!view_equals_cstr(service_request.service_name, SSH_SERVICE_USERAUTH)) {
        return SSH_ERR_UNSUPPORTED;
    }

    status = ssh_transport_send_service_accept(transport, conn, SSH_SERVICE_USERAUTH, effective.timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    tries = 0u;
    while (tries < transport->server->config.max_auth_tries) {
        ssh_userauth_request_t request;
        ssh_userauth_decision_t decision;

        status = ssh_transport_receive_userauth_request(transport, conn, &request, effective.timeout_ms);
        if (status != SSH_OK) {
            return status;
        }

        status = ssh_userauth_evaluate_request(
            transport->server,
            &request,
            transport->session_id,
            transport->session_id_len,
            &decision);
        if (status != SSH_OK) {
            return status;
        }

        if (decision == SSH_USERAUTH_DECISION_SUCCESS) {
            status = view_to_cstring(
                request.username,
                transport->authenticated_username,
                sizeof(transport->authenticated_username));
            if (status != SSH_OK) {
                return status;
            }
            transport->authenticated_username_len = request.username.len;
            return ssh_transport_send_userauth_success(transport, conn, effective.timeout_ms);
        }
        if (decision == SSH_USERAUTH_DECISION_PK_OK) {
            status = ssh_transport_send_userauth_pk_ok(
                transport,
                conn,
                request.publickey_algorithm,
                request.publickey_blob,
                effective.timeout_ms);
            if (status != SSH_OK) {
                return status;
            }
            continue;
        } else {
            ++tries;
        }

        status = ssh_userauth_failure_methods(
            transport->server,
            failure_methods,
            sizeof(failure_methods));
        if (status != SSH_OK) {
            return status;
        }
        status = ssh_transport_send_userauth_failure(
            transport,
            conn,
            failure_methods,
            0,
            effective.timeout_ms);
        if (status != SSH_OK) {
            return status;
        }
    }

    return SSH_ERR_SECURITY;
}

int ssh_server_accept_sftp_channel(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_sftp_channel_t *channel,
    const ssh_server_session_options_t *options)
{
    ssh_server_session_options_t effective;
    ssh_channel_open_t open;
    ssh_channel_request_t request;
    unsigned non_sftp_attempts;
    int accepted_subsystem;
    int status;

    if (transport == NULL || transport->server == NULL || conn == NULL || channel == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (transport->server->platform.fs == NULL) {
        return SSH_ERR_PLATFORM;
    }

    effective_session_options(options, &effective);
    memset(channel, 0, sizeof(*channel));

    status = ssh_transport_receive_channel_open_skip_global_requests(transport, conn, &open, effective.timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    if (!ssh_channel_type_is_session(open.channel_type)) {
        (void)ssh_transport_send_channel_open_failure(
            transport,
            conn,
            open.sender_channel,
            SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
            "unsupported channel type",
            effective.timeout_ms);
        return SSH_ERR_UNSUPPORTED;
    }

    status = ssh_transport_send_channel_open_confirmation(
        transport,
        conn,
        open.sender_channel,
        effective.server_channel,
        effective.channel_window_size,
        effective.channel_max_packet_size,
        effective.timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    accepted_subsystem = 0;
    for (non_sftp_attempts = 0u; non_sftp_attempts < 8u; ++non_sftp_attempts) {
        status = ssh_transport_receive_channel_request(transport, conn, &request, effective.timeout_ms);
        if (status != SSH_OK && status != SSH_ERR_UNSUPPORTED) {
            return status;
        }
        if (status == SSH_OK &&
            request.recipient_channel == effective.server_channel &&
            channel_request_is_subsystem_name(
                &request,
                effective.sftp_subsystem_name != NULL ? effective.sftp_subsystem_name : SSH_SUBSYSTEM_SFTP)) {
            accepted_subsystem = 1;
            break;
        }

        if (request.want_reply) {
            (void)ssh_transport_send_channel_failure(
                transport,
                conn,
                open.sender_channel,
                effective.timeout_ms);
        }
        if (effective.non_sftp_channel_request_policy == NULL ||
            effective.non_sftp_channel_request_policy(
                effective.non_sftp_channel_request_policy_ctx,
                &request) != SSH_OK) {
            return SSH_ERR_UNSUPPORTED;
        }
    }
    if (!accepted_subsystem) {
        return SSH_ERR_UNSUPPORTED;
    }

    if (request.want_reply) {
        status = ssh_transport_send_channel_success(
            transport,
            conn,
            open.sender_channel,
            effective.timeout_ms);
        if (status != SSH_OK) {
            return status;
        }
    }

    status = sftp_server_session_init(&channel->sftp, transport->server->platform.fs);
    if (status != SSH_OK) {
        return status;
    }
    if (effective.sftp_policy != NULL) {
        status = sftp_server_session_set_policy(&channel->sftp, effective.sftp_policy, effective.sftp_policy_ctx);
        if (status != SSH_OK) {
            sftp_server_session_deinit(&channel->sftp);
            return status;
        }
    }

    channel->client_channel = open.sender_channel;
    channel->server_channel = effective.server_channel;
    channel->window_size = effective.channel_window_size;
    channel->window_max_size = effective.channel_window_size;
    channel->max_packet_size = effective.channel_max_packet_size;
    channel->peer_window_size = open.initial_window_size;
    channel->peer_max_packet_size = open.maximum_packet_size;
    channel->initialized = 1;
    return SSH_OK;
}

int ssh_server_process_sftp_channel_data(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_sftp_channel_t *channel,
    const ssh_server_session_options_t *options)
{
    ssh_server_session_options_t effective;
    uint8_t channel_data[EMSSH_SFTP_MAX_IO + 256u];
    uint8_t response[EMSSH_SFTP_MAX_IO + 256u];
    ssh_channel_message_t message;
    size_t channel_data_len;
    size_t response_len;
    int status;

    if (transport == NULL || conn == NULL || channel == NULL || !channel->initialized) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    effective_session_options(options, &effective);
    status = ssh_transport_receive_channel_message(
        transport,
        conn,
        &message,
        channel_data,
        sizeof(channel_data),
        &channel_data_len,
        effective.timeout_ms);
    if (status != SSH_OK) {
        return status;
    }
    if (message.recipient_channel != channel->server_channel) {
        return SSH_ERR_SECURITY;
    }

    if (message.message_id == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
        channel->peer_window_size = add_u32_saturating(channel->peer_window_size, message.window_bytes);
        return SSH_OK;
    }

    if (message.message_id == SSH_MSG_CHANNEL_EOF) {
        if (!channel->eof_sent) {
            status = ssh_transport_send_channel_eof(
                transport,
                conn,
                channel->client_channel,
                effective.timeout_ms);
            if (status != SSH_OK) {
                return status;
            }
            channel->eof_sent = 1;
        }
        if (!channel->close_sent) {
            status = ssh_transport_send_channel_close(
                transport,
                conn,
                channel->client_channel,
                effective.timeout_ms);
            if (status != SSH_OK) {
                return status;
            }
            channel->close_sent = 1;
        }
        return SSH_ERR_CLOSED;
    }

    if (message.message_id == SSH_MSG_CHANNEL_CLOSE) {
        if (!channel->close_sent) {
            status = ssh_transport_send_channel_close(
                transport,
                conn,
                channel->client_channel,
                effective.timeout_ms);
            if (status != SSH_OK) {
                return status;
            }
            channel->close_sent = 1;
        }
        return SSH_ERR_CLOSED;
    }

    if (message.message_id != SSH_MSG_CHANNEL_DATA) {
        return SSH_ERR_UNSUPPORTED;
    }

    if (channel_data_len > channel->window_size) {
        return SSH_ERR_SECURITY;
    }
    channel->window_size -= (uint32_t)channel_data_len;
    status = maybe_replenish_receive_window(transport, conn, channel, effective.timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    if (channel_data_len > sizeof(channel->sftp_rx) - channel->sftp_rx_len) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(channel->sftp_rx + channel->sftp_rx_len, channel_data, channel_data_len);
    channel->sftp_rx_len += channel_data_len;

    while (channel->sftp_rx_len >= 4u) {
        uint32_t sftp_packet_length = read_u32_be_local(channel->sftp_rx);
        size_t sftp_wire_len;
        size_t remaining_len;

        if (sftp_packet_length == 0u || sftp_packet_length > EMSSH_MAX_PACKET_SIZE - 4u) {
            return SSH_ERR_MALFORMED_PACKET;
        }

        sftp_wire_len = (size_t)sftp_packet_length + 4u;
        if (channel->sftp_rx_len < sftp_wire_len) {
            break;
        }

        status = sftp_server_handle_packet(
            &channel->sftp,
            channel->sftp_rx,
            sftp_wire_len,
            response,
            sizeof(response),
            &response_len);
        if (status != SSH_OK) {
            return status;
        }

        if (channel->peer_max_packet_size != 0u && response_len > channel->peer_max_packet_size) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        if (response_len > channel->peer_window_size) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }

        status = ssh_transport_send_channel_data(
            transport,
            conn,
            channel->client_channel,
            response,
            response_len,
            effective.timeout_ms);
        if (status != SSH_OK) {
            return status;
        }
        channel->peer_window_size -= (uint32_t)response_len;

        remaining_len = channel->sftp_rx_len - sftp_wire_len;
        if (remaining_len != 0u) {
            memmove(channel->sftp_rx, channel->sftp_rx + sftp_wire_len, remaining_len);
        }
        channel->sftp_rx_len = remaining_len;
    }

    return SSH_OK;
}

void ssh_server_sftp_channel_deinit(ssh_server_sftp_channel_t *channel)
{
    if (channel == NULL || !channel->initialized) {
        return;
    }

    sftp_server_session_deinit(&channel->sftp);
    memset(channel, 0, sizeof(*channel));
}

int ssh_server_run_sftp_session(
    ssh_server_t *server,
    void *conn,
    const ssh_server_session_options_t *options)
{
    ssh_server_session_options_t effective;
    ssh_transport_session_t transport;
    ssh_server_sftp_channel_t channel;
    unsigned processed;
    int status;

    if (server == NULL || conn == NULL || !server->initialized) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    effective_session_options(options, &effective);
    memset(&channel, 0, sizeof(channel));

    status = ssh_server_run_transport_setup(server, conn, &transport, &effective);
    if (status == SSH_OK) {
        status = ssh_server_run_userauth(&transport, conn, &effective);
    }
    if (status == SSH_OK) {
        status = ssh_server_accept_sftp_channel(&transport, conn, &channel, &effective);
    }
    if (status != SSH_OK) {
        ssh_server_sftp_channel_deinit(&channel);
        return status;
    }

    processed = 0u;
    while (effective.max_sftp_packets == 0u || processed < effective.max_sftp_packets) {
        status = ssh_server_process_sftp_channel_data(&transport, conn, &channel, &effective);
        if (status == SSH_ERR_CLOSED) {
            status = SSH_OK;
            break;
        }
        if (status != SSH_OK) {
            break;
        }
        ++processed;
    }

    ssh_server_sftp_channel_deinit(&channel);
    if (effective.max_sftp_packets != 0u && processed == effective.max_sftp_packets) {
        return SSH_OK;
    }

    return status;
}

int ssh_server_run_terminal_session(
    ssh_server_t *server,
    void *conn,
    const ssh_server_session_options_t *options)
{
    ssh_server_session_options_t effective;
    ssh_transport_session_t transport;
    ssh_server_terminal_channel_t channel;
    unsigned processed;
    int status;

    if (server == NULL || conn == NULL || !server->initialized) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    effective_session_options(options, &effective);
    memset(&channel, 0, sizeof(channel));

    status = ssh_server_run_transport_setup(server, conn, &transport, &effective);
    if (status == SSH_OK) {
        status = ssh_server_run_userauth(&transport, conn, &effective);
    }
    if (status == SSH_OK) {
        status = ssh_server_accept_terminal_channel(&transport, conn, &channel, &effective);
    }
    if (status != SSH_OK) {
        ssh_server_terminal_channel_deinit(&transport, &channel);
        return status;
    }

    processed = 0u;
    while (effective.max_sftp_packets == 0u || processed < effective.max_sftp_packets) {
        status = ssh_server_process_terminal_channel_data(&transport, conn, &channel, &effective);
        if (status == SSH_ERR_CLOSED) {
            status = SSH_OK;
            break;
        }
        if (status != SSH_OK) {
            break;
        }
        ++processed;
    }

    ssh_server_terminal_channel_deinit(&transport, &channel);
    if (effective.max_sftp_packets != 0u && processed == effective.max_sftp_packets) {
        return SSH_OK;
    }
    return status;
}

int ssh_server_accept_terminal_channel(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_terminal_channel_t *channel,
    const ssh_server_session_options_t *options)
{
    ssh_server_session_options_t effective;
    ssh_channel_open_t open;
    ssh_channel_request_t request;
    const ssh_term_api_t *term;
    unsigned attempts;
    int status;

    if (transport == NULL || transport->server == NULL || conn == NULL || channel == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    term = transport->server->platform.term;
    if (term == NULL || (term->spawn_shell == NULL && term->spawn_exec == NULL)) {
        return SSH_ERR_UNSUPPORTED;
    }

    effective_session_options(options, &effective);
    memset(channel, 0, sizeof(*channel));

    status = ssh_transport_receive_channel_open_skip_global_requests(transport, conn, &open, effective.timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    if (!ssh_channel_type_is_session(open.channel_type)) {
        (void)ssh_transport_send_channel_open_failure(
            transport,
            conn,
            open.sender_channel,
            SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
            "unsupported channel type",
            effective.timeout_ms);
        return SSH_ERR_UNSUPPORTED;
    }

    status = ssh_transport_send_channel_open_confirmation(
        transport,
        conn,
        open.sender_channel,
        effective.server_channel,
        effective.channel_window_size,
        effective.channel_max_packet_size,
        effective.timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    channel->client_channel = open.sender_channel;
    channel->server_channel = effective.server_channel;
    channel->window_size = effective.channel_window_size;
    channel->window_max_size = effective.channel_window_size;
    channel->max_packet_size = effective.channel_max_packet_size;
    channel->peer_window_size = open.initial_window_size;
    channel->peer_max_packet_size = open.maximum_packet_size;
    channel->initialized = 1;
    channel->state = SSH_SERVER_TERMINAL_STATE_SESSION_OPEN;

    for (attempts = 0u; attempts < 16u; ++attempts) {
        status = ssh_transport_receive_channel_request(transport, conn, &request, effective.timeout_ms);
        if (status != SSH_OK && status != SSH_ERR_UNSUPPORTED) {
            return status;
        }

        if (status == SSH_OK && request.recipient_channel != channel->server_channel) {
            return SSH_ERR_SECURITY;
        }

        if (status == SSH_ERR_UNSUPPORTED) {
            if (request.want_reply) {
                (void)ssh_transport_send_channel_failure(
                    transport,
                    conn,
                    channel->client_channel,
                    effective.timeout_ms);
            }
            if (effective.non_sftp_channel_request_policy == NULL ||
                effective.non_sftp_channel_request_policy(
                    effective.non_sftp_channel_request_policy_ctx,
                    &request) != SSH_OK) {
                return SSH_ERR_UNSUPPORTED;
            }
            continue;
        }

        if (view_equals_cstr(request.request_type, SSH_CHANNEL_REQUEST_PTY_REQ)) {
            status = view_to_cstring(request.term_type, channel->term_type, sizeof(channel->term_type));
            if (status != SSH_OK) {
                return status;
            }
            channel->cols = request.cols;
            channel->rows = request.rows;
            channel->width_px = request.width_px;
            channel->height_px = request.height_px;
            channel->pty_requested = 1;
            channel->state = SSH_SERVER_TERMINAL_STATE_PTY_CONFIGURED;
            if (request.want_reply) {
                status = ssh_transport_send_channel_success(
                    transport,
                    conn,
                    channel->client_channel,
                    effective.timeout_ms);
                if (status != SSH_OK) {
                    return status;
                }
            }
            continue;
        }

        if (view_equals_cstr(request.request_type, SSH_CHANNEL_REQUEST_ENV)) {
            if (request.want_reply) {
                status = ssh_transport_send_channel_success(
                    transport,
                    conn,
                    channel->client_channel,
                    effective.timeout_ms);
                if (status != SSH_OK) {
                    return status;
                }
            }
            continue;
        }

        if (view_equals_cstr(request.request_type, SSH_CHANNEL_REQUEST_WINDOW_CHANGE)) {
            channel->cols = request.cols;
            channel->rows = request.rows;
            channel->width_px = request.width_px;
            channel->height_px = request.height_px;
            if (channel->running && term->resize != NULL && channel->term_handle != NULL) {
                status = term->resize(
                    term->ctx,
                    channel->term_handle,
                    channel->cols,
                    channel->rows,
                    channel->width_px,
                    channel->height_px);
                if (status != SSH_OK && request.want_reply) {
                    (void)ssh_transport_send_channel_failure(
                        transport,
                        conn,
                        channel->client_channel,
                        effective.timeout_ms);
                    continue;
                }
            }
            if (request.want_reply) {
                status = ssh_transport_send_channel_success(
                    transport,
                    conn,
                    channel->client_channel,
                    effective.timeout_ms);
                if (status != SSH_OK) {
                    return status;
                }
            }
            continue;
        }

        if (view_equals_cstr(request.request_type, SSH_CHANNEL_REQUEST_SIGNAL)) {
            if (channel->running && term->signal != NULL && channel->term_handle != NULL) {
                char signal_name[64];

                status = view_to_cstring(request.signal_name, signal_name, sizeof(signal_name));
                if (status != SSH_OK) {
                    return status;
                }
                status = term->signal(term->ctx, channel->term_handle, signal_name);
                if (status != SSH_OK && request.want_reply) {
                    (void)ssh_transport_send_channel_failure(
                        transport,
                        conn,
                        channel->client_channel,
                        effective.timeout_ms);
                    continue;
                }
            }
            if (request.want_reply) {
                status = ssh_transport_send_channel_success(
                    transport,
                    conn,
                    channel->client_channel,
                    effective.timeout_ms);
                if (status != SSH_OK) {
                    return status;
                }
            }
            continue;
        }

        if (view_equals_cstr(request.request_type, SSH_CHANNEL_REQUEST_SHELL) ||
            view_equals_cstr(request.request_type, SSH_CHANNEL_REQUEST_EXEC)) {
            if (channel->running) {
                if (request.want_reply) {
                    (void)ssh_transport_send_channel_failure(
                        transport,
                        conn,
                        channel->client_channel,
                        effective.timeout_ms);
                }
                return SSH_ERR_SECURITY;
            }

            if (view_equals_cstr(request.request_type, SSH_CHANNEL_REQUEST_SHELL)) {
                if (term->spawn_shell == NULL) {
                    if (request.want_reply) {
                        (void)ssh_transport_send_channel_failure(
                            transport,
                            conn,
                            channel->client_channel,
                            effective.timeout_ms);
                    }
                    return SSH_ERR_UNSUPPORTED;
                }
                status = term->spawn_shell(
                    term->ctx,
                    transport->authenticated_username_len != 0u ? transport->authenticated_username : NULL,
                    channel->pty_requested ? channel->term_type : NULL,
                    channel->cols,
                    channel->rows,
                    channel->width_px,
                    channel->height_px,
                    &channel->term_handle);
            } else {
                char command[256];

                if (term->spawn_exec == NULL) {
                    if (request.want_reply) {
                        (void)ssh_transport_send_channel_failure(
                            transport,
                            conn,
                            channel->client_channel,
                            effective.timeout_ms);
                    }
                    return SSH_ERR_UNSUPPORTED;
                }
                status = view_to_cstring(request.command, command, sizeof(command));
                if (status != SSH_OK) {
                    if (request.want_reply) {
                        (void)ssh_transport_send_channel_failure(
                            transport,
                            conn,
                            channel->client_channel,
                            effective.timeout_ms);
                    }
                    return status;
                }
                status = term->spawn_exec(
                    term->ctx,
                    transport->authenticated_username_len != 0u ? transport->authenticated_username : NULL,
                    command,
                    channel->pty_requested ? channel->term_type : NULL,
                    channel->cols,
                    channel->rows,
                    channel->width_px,
                    channel->height_px,
                    &channel->term_handle);
            }

            if (status != SSH_OK) {
                if (request.want_reply) {
                    (void)ssh_transport_send_channel_failure(
                        transport,
                        conn,
                        channel->client_channel,
                        effective.timeout_ms);
                }
                return status;
            }

            channel->running = 1;
            channel->state = SSH_SERVER_TERMINAL_STATE_RUNNING;
            if (request.want_reply) {
                status = ssh_transport_send_channel_success(
                    transport,
                    conn,
                    channel->client_channel,
                    effective.timeout_ms);
                if (status != SSH_OK) {
                    return status;
                }
            }
            return SSH_OK;
        }

        if (request.want_reply) {
            (void)ssh_transport_send_channel_failure(
                transport,
                conn,
                channel->client_channel,
                effective.timeout_ms);
        }
        if (effective.non_sftp_channel_request_policy == NULL ||
            effective.non_sftp_channel_request_policy(
                effective.non_sftp_channel_request_policy_ctx,
                &request) != SSH_OK) {
            return SSH_ERR_UNSUPPORTED;
        }
    }

    return SSH_ERR_UNSUPPORTED;
}

static int maybe_send_terminal_exit_and_close(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_terminal_channel_t *channel,
    const ssh_server_session_options_t *options,
    int *closed_now)
{
    const ssh_term_api_t *term;
    int exited;
    uint32_t exit_status;
    int status;

    if (closed_now == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    *closed_now = 0;

    if (transport == NULL || transport->server == NULL || conn == NULL || channel == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (!channel->running || channel->term_handle == NULL) {
        return SSH_OK;
    }

    term = transport->server->platform.term;
    if (term == NULL || term->wait_exit == NULL) {
        return SSH_OK;
    }

    exited = 0;
    exit_status = 0u;
    status = term->wait_exit(term->ctx, channel->term_handle, &exited, &exit_status);
    if (status != SSH_OK) {
        return status;
    }
    if (!exited) {
        return SSH_OK;
    }

    if (!channel->exit_status_sent) {
        status = ssh_transport_send_channel_exit_status(
            transport,
            conn,
            channel->client_channel,
            exit_status,
            options != NULL ? options->timeout_ms : EMSSH_DEFAULT_SESSION_TIMEOUT_MS);
        if (status != SSH_OK) {
            return status;
        }
        channel->exit_status_sent = 1;
    }

    if (!channel->eof_sent) {
        status = ssh_transport_send_channel_eof(
            transport,
            conn,
            channel->client_channel,
            options != NULL ? options->timeout_ms : EMSSH_DEFAULT_SESSION_TIMEOUT_MS);
        if (status != SSH_OK) {
            return status;
        }
        channel->eof_sent = 1;
    }
    if (!channel->close_sent) {
        status = ssh_transport_send_channel_close(
            transport,
            conn,
            channel->client_channel,
            options != NULL ? options->timeout_ms : EMSSH_DEFAULT_SESSION_TIMEOUT_MS);
        if (status != SSH_OK) {
            return status;
        }
        channel->close_sent = 1;
    }
    channel->state = SSH_SERVER_TERMINAL_STATE_CLOSED;
    channel->running = 0;
    *closed_now = 1;
    return SSH_OK;
}

static int maybe_pump_terminal_output(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_terminal_channel_t *channel,
    const ssh_server_session_options_t *options)
{
    const ssh_term_api_t *term;
    uint8_t outbuf[2048];
    size_t read_len;
    uint32_t max_send;
    int status;

    if (transport == NULL || transport->server == NULL || conn == NULL || channel == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (!channel->running || channel->term_handle == NULL) {
        return SSH_OK;
    }

    term = transport->server->platform.term;
    if (term == NULL || term->read == NULL) {
        return SSH_OK;
    }

    if (channel->peer_window_size == 0u) {
        return SSH_OK;
    }

    max_send = channel->peer_window_size;
    if (channel->peer_max_packet_size != 0u) {
        max_send = min_u32_local(max_send, channel->peer_max_packet_size);
    }
    max_send = min_u32_local(max_send, (uint32_t)sizeof(outbuf));
    if (max_send == 0u) {
        return SSH_OK;
    }

    read_len = 0u;
    status = term->read(term->ctx, channel->term_handle, outbuf, (size_t)max_send, &read_len);
    if (status == SSH_ERR_NOT_FOUND || status == SSH_ERR_UNSUPPORTED) {
        return SSH_OK;
    }
    if (status != SSH_OK) {
        return status;
    }
    if (read_len == 0u) {
        return SSH_OK;
    }

    status = ssh_transport_send_channel_data(
        transport,
        conn,
        channel->client_channel,
        outbuf,
        read_len,
        options != NULL ? options->timeout_ms : EMSSH_DEFAULT_SESSION_TIMEOUT_MS);
    if (status != SSH_OK) {
        return status;
    }
    channel->peer_window_size -= (uint32_t)read_len;
    return SSH_OK;
}

int ssh_server_process_terminal_channel_data(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_terminal_channel_t *channel,
    const ssh_server_session_options_t *options)
{
    ssh_server_session_options_t effective;
    const ssh_term_api_t *term;
    ssh_channel_message_t message;
    uint8_t channel_data[2048];
    size_t channel_data_len;
    size_t written_len;
    int status;
    int closed_now;

    if (transport == NULL || transport->server == NULL || conn == NULL || channel == NULL || !channel->initialized) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    effective_session_options(options, &effective);
    term = transport->server->platform.term;

    status = maybe_send_terminal_exit_and_close(transport, conn, channel, &effective, &closed_now);
    if (status != SSH_OK) {
        return status;
    }
    if (closed_now) {
        return SSH_ERR_CLOSED;
    }

    status = ssh_transport_receive_channel_message(
        transport,
        conn,
        &message,
        channel_data,
        sizeof(channel_data),
        &channel_data_len,
        effective.timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    if (message.recipient_channel != channel->server_channel) {
        return SSH_ERR_SECURITY;
    }

    if (message.message_id == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
        channel->peer_window_size = add_u32_saturating(channel->peer_window_size, message.window_bytes);
        return maybe_pump_terminal_output(transport, conn, channel, &effective);
    }

    if (message.message_id == SSH_MSG_CHANNEL_REQUEST) {
        const ssh_channel_request_t *request = &message.channel_request;
        int request_status = SSH_OK;

        if (view_equals_cstr(request->request_type, SSH_CHANNEL_REQUEST_WINDOW_CHANGE)) {
            channel->cols = request->cols;
            channel->rows = request->rows;
            channel->width_px = request->width_px;
            channel->height_px = request->height_px;
            if (channel->running && term != NULL && term->resize != NULL && channel->term_handle != NULL) {
                request_status = term->resize(
                    term->ctx,
                    channel->term_handle,
                    channel->cols,
                    channel->rows,
                    channel->width_px,
                    channel->height_px);
            }
        } else if (view_equals_cstr(request->request_type, SSH_CHANNEL_REQUEST_SIGNAL)) {
            if (channel->running && term != NULL && term->signal != NULL && channel->term_handle != NULL) {
                char signal_name[64];

                request_status = view_to_cstring(request->signal_name, signal_name, sizeof(signal_name));
                if (request_status == SSH_OK) {
                    request_status = term->signal(term->ctx, channel->term_handle, signal_name);
                }
            }
        } else if (view_equals_cstr(request->request_type, SSH_CHANNEL_REQUEST_ENV)) {
            request_status = SSH_OK;
        } else {
            request_status = SSH_ERR_UNSUPPORTED;
        }

        if (request->want_reply) {
            if (request_status == SSH_OK) {
                status = ssh_transport_send_channel_success(
                    transport,
                    conn,
                    request->recipient_channel,
                    effective.timeout_ms);
            } else {
                status = ssh_transport_send_channel_failure(
                    transport,
                    conn,
                    request->recipient_channel,
                    effective.timeout_ms);
            }
            if (status != SSH_OK) {
                return status;
            }
        }
        if (request_status == SSH_OK) {
            status = maybe_pump_terminal_output(transport, conn, channel, &effective);
            if (status != SSH_OK) {
                return status;
            }
            status = maybe_send_terminal_exit_and_close(transport, conn, channel, &effective, &closed_now);
            if (status != SSH_OK) {
                return status;
            }
            if (closed_now) {
                return SSH_ERR_CLOSED;
            }
        }
        return SSH_OK;
    }

    if (message.message_id == SSH_MSG_CHANNEL_EOF) {
        if (!channel->eof_sent) {
            status = ssh_transport_send_channel_eof(
                transport,
                conn,
                channel->client_channel,
                effective.timeout_ms);
            if (status != SSH_OK) {
                return status;
            }
            channel->eof_sent = 1;
        }
        if (!channel->close_sent) {
            status = ssh_transport_send_channel_close(
                transport,
                conn,
                channel->client_channel,
                effective.timeout_ms);
            if (status != SSH_OK) {
                return status;
            }
            channel->close_sent = 1;
        }
        channel->state = SSH_SERVER_TERMINAL_STATE_CLOSED;
        return SSH_ERR_CLOSED;
    }

    if (message.message_id == SSH_MSG_CHANNEL_CLOSE) {
        if (!channel->close_sent) {
            status = ssh_transport_send_channel_close(
                transport,
                conn,
                channel->client_channel,
                effective.timeout_ms);
            if (status != SSH_OK) {
                return status;
            }
            channel->close_sent = 1;
        }
        channel->state = SSH_SERVER_TERMINAL_STATE_CLOSED;
        return SSH_ERR_CLOSED;
    }

    if (message.message_id != SSH_MSG_CHANNEL_DATA) {
        return SSH_ERR_UNSUPPORTED;
    }

    if (channel_data_len > channel->window_size) {
        return SSH_ERR_SECURITY;
    }
    channel->window_size -= (uint32_t)channel_data_len;
    status = maybe_replenish_terminal_receive_window(transport, conn, channel, effective.timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    if (!channel->running || channel->term_handle == NULL || term == NULL || term->write == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }

    written_len = 0u;
    status = term->write(term->ctx, channel->term_handle, channel_data, channel_data_len, &written_len);
    if (status != SSH_OK) {
        return status;
    }
    if (written_len != channel_data_len) {
        return SSH_ERR_PLATFORM;
    }

    status = maybe_pump_terminal_output(transport, conn, channel, &effective);
    if (status != SSH_OK) {
        return status;
    }

    status = maybe_send_terminal_exit_and_close(transport, conn, channel, &effective, &closed_now);
    if (status != SSH_OK) {
        return status;
    }
    if (closed_now) {
        return SSH_ERR_CLOSED;
    }

    return SSH_OK;
}

void ssh_server_terminal_channel_deinit(
    struct ssh_transport_session *transport,
    ssh_server_terminal_channel_t *channel)
{
    const ssh_term_api_t *term;

    if (transport == NULL || transport->server == NULL || channel == NULL || !channel->initialized) {
        return;
    }

    term = transport->server->platform.term;
    if (channel->term_handle != NULL && term != NULL && term->close != NULL) {
        (void)term->close(term->ctx, channel->term_handle);
    }

    memset(channel, 0, sizeof(*channel));
}
