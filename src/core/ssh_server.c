#include "emssh/ssh_server.h"

#include <string.h>

#include "emssh/sftp.h"
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
#define EMSSH_TERMINAL_RECV_POLL_MS 50u

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

static int channel_request_is_default_ignorable_non_sftp(const ssh_channel_request_t *request)
{
    if (request == NULL) {
        return 0;
    }

    return
        view_equals_cstr(request->request_type, "simple@putty.projects.tartarus.org") ||
        view_equals_cstr(request->request_type, "winadj@putty.projects.tartarus.org") ||
        view_equals_cstr(request->request_type, SSH_CHANNEL_REQUEST_X11_REQ) ||
        view_equals_cstr(request->request_type, SSH_CHANNEL_REQUEST_PTY_REQ) ||
        view_equals_cstr(request->request_type, SSH_CHANNEL_REQUEST_SHELL) ||
        view_equals_cstr(request->request_type, SSH_CHANNEL_REQUEST_EXEC) ||
        view_equals_cstr(request->request_type, SSH_CHANNEL_REQUEST_ENV) ||
        view_equals_cstr(request->request_type, SSH_CHANNEL_REQUEST_WINDOW_CHANGE) ||
        view_equals_cstr(request->request_type, SSH_CHANNEL_REQUEST_SIGNAL);
}

static int non_sftp_channel_request_allowed_by_policy(
    const ssh_server_session_options_t *effective,
    const ssh_channel_request_t *request)
{
    if (effective != NULL && effective->non_sftp_channel_request_policy != NULL) {
        int policy_status = effective->non_sftp_channel_request_policy(
            effective->non_sftp_channel_request_policy_ctx,
            request);
        if (policy_status == SSH_OK) {
            return SSH_OK;
        }
    }

    return channel_request_is_default_ignorable_non_sftp(request) ? SSH_OK : SSH_ERR_UNSUPPORTED;
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

static void write_u32_be_local(uint8_t data[4], uint32_t value)
{
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

static int shrink_sftp_data_response_to_limit(
    uint8_t *response,
    size_t *response_len,
    size_t wire_limit)
{
    size_t payload_len;
    size_t max_data_len;

    if (response == NULL || response_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (*response_len < 13u) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    if (response[4] != SSH_FXP_DATA) {
        return SSH_ERR_UNSUPPORTED;
    }
    if (wire_limit >= *response_len) {
        return SSH_OK;
    }
    if (wire_limit <= 13u) {
        return SSH_ERR_NOT_FOUND;
    }

    max_data_len = wire_limit - 13u;
    payload_len = 1u + 4u + 4u + max_data_len;
    if (payload_len > 0xffffffffu || max_data_len > 0xffffffffu) {
        return SSH_ERR_BUFFER_OVERFLOW;
    }

    write_u32_be_local(response, (uint32_t)payload_len);
    write_u32_be_local(response + 9u, (uint32_t)max_data_len);
    *response_len = wire_limit;
    return SSH_OK;
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

static void append_lit_local(char *buf, size_t capacity, size_t *used, const char *text)
{
    size_t i;

    if (buf == NULL || used == NULL || text == NULL || *used >= capacity) {
        return;
    }
    for (i = 0u; text[i] != '\0' && *used + 1u < capacity; ++i) {
        buf[*used] = text[i];
        *used += 1u;
    }
}

static void append_u32_local(char *buf, size_t capacity, size_t *used, uint32_t value)
{
    char tmp[16];
    size_t pos;
    size_t i;

    if (buf == NULL || used == NULL || *used >= capacity) {
        return;
    }
    if (value == 0u) {
        if (*used + 1u < capacity) {
            buf[*used] = '0';
            *used += 1u;
        }
        return;
    }

    pos = 0u;
    while (value != 0u && pos < sizeof(tmp)) {
        tmp[pos++] = (char)('0' + (value % 10u));
        value /= 10u;
    }
    for (i = 0u; i < pos && *used + 1u < capacity; ++i) {
        buf[*used] = tmp[pos - 1u - i];
        *used += 1u;
    }
}

static void append_size_local(char *buf, size_t capacity, size_t *used, size_t value)
{
    if (value > 0xffffffffu) {
        append_lit_local(buf, capacity, used, "4294967295+");
        return;
    }
    append_u32_local(buf, capacity, used, (uint32_t)value);
}

static void append_i32_local(char *buf, size_t capacity, size_t *used, int value)
{
    if (value < 0) {
        append_lit_local(buf, capacity, used, "-");
        append_u32_local(buf, capacity, used, (uint32_t)(-(value + 1) + 1));
        return;
    }
    append_u32_local(buf, capacity, used, (uint32_t)value);
}

static const char *sftp_type_name_local(uint8_t type)
{
    switch (type) {
    case SSH_FXP_INIT:
        return "INIT";
    case SSH_FXP_VERSION:
        return "VERSION";
    case SSH_FXP_OPEN:
        return "OPEN";
    case SSH_FXP_CLOSE:
        return "CLOSE";
    case SSH_FXP_READ:
        return "READ";
    case SSH_FXP_WRITE:
        return "WRITE";
    case SSH_FXP_LSTAT:
        return "LSTAT";
    case SSH_FXP_FSTAT:
        return "FSTAT";
    case SSH_FXP_SETSTAT:
        return "SETSTAT";
    case SSH_FXP_FSETSTAT:
        return "FSETSTAT";
    case SSH_FXP_OPENDIR:
        return "OPENDIR";
    case SSH_FXP_READDIR:
        return "READDIR";
    case SSH_FXP_REMOVE:
        return "REMOVE";
    case SSH_FXP_MKDIR:
        return "MKDIR";
    case SSH_FXP_RMDIR:
        return "RMDIR";
    case SSH_FXP_REALPATH:
        return "REALPATH";
    case SSH_FXP_STAT:
        return "STAT";
    case SSH_FXP_RENAME:
        return "RENAME";
    case SSH_FXP_STATUS:
        return "STATUS";
    case SSH_FXP_HANDLE:
        return "HANDLE";
    case SSH_FXP_DATA:
        return "DATA";
    case SSH_FXP_NAME:
        return "NAME";
    case SSH_FXP_ATTRS:
        return "ATTRS";
    case SSH_FXP_EXTENDED:
        return "EXTENDED";
    case SSH_FXP_EXTENDED_REPLY:
        return "EXTENDED_REPLY";
    default:
        return "UNKNOWN";
    }
}

static void sftp_trace_log_line(
    const struct ssh_transport_session *transport,
    int trace_enabled,
    const char *line);

static void append_view_text_local(
    char *buf,
    size_t capacity,
    size_t *used,
    ssh_string_view_t view,
    size_t max_chars)
{
    size_t i;
    size_t limit;

    if (buf == NULL || used == NULL || *used >= capacity || view.data == NULL) {
        return;
    }

    limit = view.len;
    if (limit > max_chars) {
        limit = max_chars;
    }
    for (i = 0u; i < limit && *used + 1u < capacity; ++i) {
        uint8_t c = view.data[i];
        if (c >= 32u && c <= 126u) {
            buf[*used] = (char)c;
        } else {
            buf[*used] = '?';
        }
        *used += 1u;
    }
    if (view.len > limit) {
        append_lit_local(buf, capacity, used, "...");
    }
}

static void sftp_trace_log_request_paths(
    const struct ssh_transport_session *transport,
    int trace_enabled,
    uint8_t request_type,
    const uint8_t *request_packet,
    size_t request_packet_len)
{
    char line[320];
    size_t used = 0u;
    int status = SSH_ERR_UNSUPPORTED;

    if (!trace_enabled || request_packet == NULL || request_packet_len < 5u) {
        return;
    }

    append_lit_local(line, sizeof(line), &used, "sftp-trace: req-path type=");
    append_lit_local(line, sizeof(line), &used, sftp_type_name_local(request_type));

    if (request_type == SSH_FXP_REALPATH ||
        request_type == SSH_FXP_STAT ||
        request_type == SSH_FXP_LSTAT ||
        request_type == SSH_FXP_OPENDIR ||
        request_type == SSH_FXP_REMOVE ||
        request_type == SSH_FXP_RMDIR) {
        sftp_path_request_t req;
        status = (request_type == SSH_FXP_REALPATH)
                     ? sftp_realpath_request_decode(request_packet, request_packet_len, &req)
                 : (request_type == SSH_FXP_STAT)
                     ? sftp_stat_request_decode(request_packet, request_packet_len, &req)
                 : (request_type == SSH_FXP_LSTAT)
                     ? sftp_lstat_request_decode(request_packet, request_packet_len, &req)
                 : (request_type == SSH_FXP_OPENDIR)
                     ? sftp_opendir_request_decode(request_packet, request_packet_len, &req)
                 : (request_type == SSH_FXP_REMOVE)
                     ? sftp_remove_request_decode(request_packet, request_packet_len, &req)
                     : sftp_rmdir_request_decode(request_packet, request_packet_len, &req);
        if (status == SSH_OK) {
            append_lit_local(line, sizeof(line), &used, " path=");
            append_view_text_local(line, sizeof(line), &used, req.path, 160u);
        }
    } else if (request_type == SSH_FXP_OPEN) {
        sftp_open_request_t req;
        status = sftp_open_request_decode(request_packet, request_packet_len, &req);
        if (status == SSH_OK) {
            append_lit_local(line, sizeof(line), &used, " path=");
            append_view_text_local(line, sizeof(line), &used, req.filename, 160u);
        }
    } else if (request_type == SSH_FXP_MKDIR) {
        sftp_mkdir_request_t req;
        status = sftp_mkdir_request_decode(request_packet, request_packet_len, &req);
        if (status == SSH_OK) {
            append_lit_local(line, sizeof(line), &used, " path=");
            append_view_text_local(line, sizeof(line), &used, req.path, 160u);
        }
    } else if (request_type == SSH_FXP_SETSTAT) {
        sftp_setstat_request_t req;
        status = sftp_setstat_request_decode(request_packet, request_packet_len, &req);
        if (status == SSH_OK) {
            append_lit_local(line, sizeof(line), &used, " path=");
            append_view_text_local(line, sizeof(line), &used, req.path, 160u);
        }
    } else if (request_type == SSH_FXP_RENAME) {
        sftp_rename_request_t req;
        status = sftp_rename_request_decode(request_packet, request_packet_len, &req);
        if (status == SSH_OK) {
            append_lit_local(line, sizeof(line), &used, " old=");
            append_view_text_local(line, sizeof(line), &used, req.old_path, 120u);
            append_lit_local(line, sizeof(line), &used, " new=");
            append_view_text_local(line, sizeof(line), &used, req.new_path, 120u);
        }
    }

    if (status != SSH_OK) {
        append_lit_local(line, sizeof(line), &used, " decode-status=");
        append_i32_local(line, sizeof(line), &used, status);
    }
    line[used] = '\0';
    sftp_trace_log_line(transport, trace_enabled, line);
}

static void sftp_trace_log_line(
    const struct ssh_transport_session *transport,
    int trace_enabled,
    const char *line)
{
    const ssh_log_api_t *log;

    if (!trace_enabled || transport == NULL || transport->server == NULL || line == NULL) {
        return;
    }

    log = transport->server->platform.log;
    if (log == NULL || log->write == NULL) {
        return;
    }

    log->write(log->ctx, SSH_LOG_INFO, line);
}

static int should_tolerate_pre_request_malformed(
    const ssh_transport_session_t *transport,
    int status)
{
    if (status != SSH_ERR_MALFORMED_PACKET || transport == NULL) {
        return 0;
    }
    if (!transport->last_received_message_id_valid) {
        return 0;
    }
    return transport->last_received_message_id == SSH_MSG_CHANNEL_DATA ||
           transport->last_received_message_id == SSH_MSG_CHANNEL_EXTENDED_DATA;
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

static int maybe_flush_pending_sftp_response(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_sftp_channel_t *channel,
    const ssh_server_session_options_t *effective)
{
    int status;

    if (transport == NULL || conn == NULL || channel == NULL || effective == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (channel->sftp_tx_pending_len == 0u) {
        return SSH_OK;
    }
    if (channel->peer_max_packet_size != 0u &&
        channel->sftp_tx_pending_len > channel->peer_max_packet_size) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    if (channel->sftp_tx_pending_len > channel->peer_window_size) {
        return SSH_ERR_NOT_FOUND;
    }

    status = ssh_transport_send_channel_data(
        transport,
        conn,
        channel->client_channel,
        channel->sftp_tx_pending,
        channel->sftp_tx_pending_len,
        effective->timeout_ms);
    if (status != SSH_OK) {
        return status;
    }
    channel->peer_window_size -= (uint32_t)channel->sftp_tx_pending_len;
    channel->sftp_tx_pending_len = 0u;
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
        effective->sftp_trace_enabled = options->sftp_trace_enabled;
    }
}

static void update_server_diag_from_transport(
    ssh_server_t *server,
    const ssh_transport_session_t *transport)
{
    size_t len;

    if (server == NULL) {
        return;
    }
    server->diag_last_received_message_id = 0u;
    server->diag_last_received_message_id_valid = 0;
    server->diag_last_channel_request_type[0] = '\0';
    server->diag_last_channel_request_type_valid = 0;
    server->diag_last_channel_request_want_reply = 0;
    if (transport == NULL) {
        return;
    }
    if (transport->last_received_message_id_valid) {
        server->diag_last_received_message_id = transport->last_received_message_id;
        server->diag_last_received_message_id_valid = 1;
    }
    if (transport->last_channel_request_type_valid) {
        len = strlen(transport->last_channel_request_type);
        if (len >= sizeof(server->diag_last_channel_request_type)) {
            len = sizeof(server->diag_last_channel_request_type) - 1u;
        }
        memcpy(server->diag_last_channel_request_type, transport->last_channel_request_type, len);
        server->diag_last_channel_request_type[len] = '\0';
        server->diag_last_channel_request_type_valid = 1;
        server->diag_last_channel_request_want_reply = transport->last_channel_request_want_reply;
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
        return "no space left";
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
    config->permit_root_login = EMSSH_PERMIT_ROOT_LOGIN_PROHIBIT_PASSWORD;
    config->allow_users = NULL;
    config->authorized_keys_file = NULL;
    config->auth_ctx = NULL;
}

int ssh_server_init(ssh_server_t *server, const ssh_platform_t *platform, const ssh_server_config_t *config)
{
    ssh_server_config_t defaults;

    if (server == NULL || platform == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(server, 0, sizeof(*server));

    ssh_server_config_defaults(&defaults);
    server->config = config != NULL ? *config : defaults;
    server->platform = *platform;
    server->diag_last_received_message_id = 0u;
    server->diag_last_received_message_id_valid = 0;
    server->diag_last_channel_request_type[0] = '\0';
    server->diag_last_channel_request_type_valid = 0;
    server->diag_last_channel_request_want_reply = 0;

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
    options->sftp_trace_enabled = 0;
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

static int sftp_accept_after_open(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_sftp_channel_t *channel,
    const ssh_server_session_options_t *options,
    const ssh_channel_open_t *open,
    const ssh_channel_request_t *first_request,
    int has_first_request)
{
    ssh_server_session_options_t effective;
    ssh_channel_request_t request;
    unsigned non_sftp_attempts;
    int accepted_subsystem;
    int status;

    if (transport == NULL || transport->server == NULL || conn == NULL || channel == NULL || open == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (transport->server->platform.fs == NULL) {
        return SSH_ERR_PLATFORM;
    }

    effective_session_options(options, &effective);
    accepted_subsystem = 0;
    memset(&request, 0, sizeof(request));
    for (non_sftp_attempts = 0u; non_sftp_attempts < 8u; ++non_sftp_attempts) {
        if (has_first_request) {
            request = *first_request;
            status = SSH_OK;
            has_first_request = 0;
        } else {
            status = ssh_transport_receive_channel_request(transport, conn, &request, effective.timeout_ms);
        }
        if (status != SSH_OK && status != SSH_ERR_UNSUPPORTED) {
            if (should_tolerate_pre_request_malformed(transport, status)) {
                continue;
            }
            return status;
        }

        if (status == SSH_OK && request.recipient_channel != effective.server_channel) {
            return SSH_ERR_SECURITY;
        }
        if (status == SSH_OK &&
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
                open->sender_channel,
                effective.timeout_ms);
        }
        /* Request-level failure only: unsupported/non-allowed request must not tear down session. */
        (void)non_sftp_channel_request_allowed_by_policy(&effective, &request);
    }
    if (!accepted_subsystem) {
        return SSH_ERR_UNSUPPORTED;
    }

    if (request.want_reply) {
        status = ssh_transport_send_channel_success(
            transport,
            conn,
            open->sender_channel,
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

    channel->client_channel = open->sender_channel;
    channel->server_channel = effective.server_channel;
    channel->window_size = effective.channel_window_size;
    channel->window_max_size = effective.channel_window_size;
    channel->max_packet_size = effective.channel_max_packet_size;
    channel->peer_window_size = open->initial_window_size;
    channel->peer_max_packet_size = open->maximum_packet_size;
    channel->initialized = 1;
    return SSH_OK;
}

static int terminal_accept_after_open(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_terminal_channel_t *channel,
    const ssh_server_session_options_t *options,
    const ssh_channel_open_t *open,
    const ssh_channel_request_t *first_request,
    int has_first_request)
{
    ssh_server_session_options_t effective;
    ssh_channel_request_t request;
    const ssh_term_api_t *term;
    unsigned attempts;
    int status;

    if (transport == NULL || transport->server == NULL || conn == NULL || channel == NULL || open == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    term = transport->server->platform.term;
    if (term == NULL || (term->spawn_shell == NULL && term->spawn_exec == NULL)) {
        return SSH_ERR_UNSUPPORTED;
    }

    effective_session_options(options, &effective);

    channel->client_channel = open->sender_channel;
    channel->server_channel = effective.server_channel;
    channel->window_size = effective.channel_window_size;
    channel->window_max_size = effective.channel_window_size;
    channel->max_packet_size = effective.channel_max_packet_size;
    channel->peer_window_size = open->initial_window_size;
    channel->peer_max_packet_size = open->maximum_packet_size;
    channel->initialized = 1;
    channel->state = SSH_SERVER_TERMINAL_STATE_SESSION_OPEN;

    memset(&request, 0, sizeof(request));
    for (attempts = 0u; attempts < 16u; ++attempts) {
        if (has_first_request) {
            request = *first_request;
            status = SSH_OK;
            has_first_request = 0;
        } else {
            status = ssh_transport_receive_channel_request(transport, conn, &request, effective.timeout_ms);
        }
        if (status != SSH_OK && status != SSH_ERR_UNSUPPORTED) {
            if (should_tolerate_pre_request_malformed(transport, status)) {
                continue;
            }
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
            (void)non_sftp_channel_request_allowed_by_policy(&effective, &request);
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
                continue;
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
                    continue;
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
                    continue;
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
                    continue;
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
                continue;
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
        (void)non_sftp_channel_request_allowed_by_policy(&effective, &request);
    }

    return SSH_ERR_UNSUPPORTED;
}

int ssh_server_accept_sftp_channel(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_sftp_channel_t *channel,
    const ssh_server_session_options_t *options)
{
    ssh_channel_open_t open;
    ssh_server_session_options_t effective;
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

    return sftp_accept_after_open(transport, conn, channel, &effective, &open, NULL, 0);
}

int ssh_server_process_sftp_channel_data(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_sftp_channel_t *channel,
    const ssh_server_session_options_t *options)
{
    ssh_server_session_options_t effective;
    uint8_t channel_data[EMSSH_MAX_PACKET_SIZE];
    uint8_t response[EMSSH_MAX_PACKET_SIZE];
    ssh_channel_message_t message;
    size_t channel_data_len;
    int trace_enabled;
    size_t response_len;
    int status;

    if (transport == NULL || conn == NULL || channel == NULL || !channel->initialized) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    effective_session_options(options, &effective);
    trace_enabled = effective.sftp_trace_enabled;
    status = ssh_transport_receive_channel_message(
        transport,
        conn,
        &message,
        channel_data,
        sizeof(channel_data),
        &channel_data_len,
        effective.timeout_ms);
    if (status != SSH_OK) {
        if (status == SSH_ERR_NOT_FOUND && channel->sftp_rx_len != 0u) {
            status = SSH_OK;
        } else {
            if (status != SSH_ERR_NOT_FOUND) {
                char line[128];
                size_t used = 0u;

                append_lit_local(line, sizeof(line), &used, "sftp-trace: channel receive status=");
                append_i32_local(line, sizeof(line), &used, status);
                line[used] = '\0';
                sftp_trace_log_line(transport, trace_enabled, line);
            }
            return status;
        }
    } else {
        {
            char line[192];
            size_t used = 0u;

            append_lit_local(line, sizeof(line), &used, "sftp-trace: channel msg=");
            append_u32_local(line, sizeof(line), &used, (uint32_t)message.message_id);
            append_lit_local(line, sizeof(line), &used, " data_len=");
            append_size_local(line, sizeof(line), &used, channel_data_len);
            append_lit_local(line, sizeof(line), &used, " rx_buf=");
            append_size_local(line, sizeof(line), &used, channel->sftp_rx_len);
            line[used] = '\0';
            sftp_trace_log_line(transport, trace_enabled, line);
        }
        if (message.recipient_channel != channel->server_channel) {
            return SSH_ERR_SECURITY;
        }

        if (message.message_id == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
            channel->peer_window_size = add_u32_saturating(channel->peer_window_size, message.window_bytes);
            if (channel->sftp_rx_len == 0u) {
                return SSH_OK;
            }
        } else if (message.message_id == SSH_MSG_CHANNEL_REQUEST) {
            const ssh_channel_request_t *request = &message.channel_request;

            if (request->want_reply) {
                status = ssh_transport_send_channel_failure(
                    transport,
                    conn,
                    channel->client_channel,
                    effective.timeout_ms);
                if (status != SSH_OK) {
                    return status;
                }
            }
            (void)non_sftp_channel_request_allowed_by_policy(&effective, request);
            return SSH_OK;
        } else if (message.message_id == SSH_MSG_CHANNEL_EOF) {
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
        } else if (message.message_id == SSH_MSG_CHANNEL_CLOSE) {
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
        } else if (message.message_id == SSH_MSG_CHANNEL_DATA) {
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
        } else {
            return SSH_ERR_UNSUPPORTED;
        }
    }

    status = maybe_flush_pending_sftp_response(transport, conn, channel, &effective);
    if (status != SSH_OK) {
        return status;
    }

    while (channel->sftp_rx_len >= 4u) {
        uint32_t sftp_packet_length = read_u32_be_local(channel->sftp_rx);
        size_t sftp_wire_len;
        size_t remaining_len;
        uint8_t request_type;
        uint32_t request_id;
        int has_request_id;

        if (sftp_packet_length == 0u || sftp_packet_length > EMSSH_MAX_PACKET_SIZE - 4u) {
            char line[192];
            size_t used = 0u;

            append_lit_local(line, sizeof(line), &used, "sftp-trace: malformed sftp length=");
            append_u32_local(line, sizeof(line), &used, sftp_packet_length);
            append_lit_local(line, sizeof(line), &used, " rx_buf=");
            append_size_local(line, sizeof(line), &used, channel->sftp_rx_len);
            line[used] = '\0';
            sftp_trace_log_line(transport, trace_enabled, line);
            return SSH_ERR_MALFORMED_PACKET;
        }

        sftp_wire_len = (size_t)sftp_packet_length + 4u;
        if (channel->sftp_rx_len < sftp_wire_len) {
            break;
        }

        request_type = sftp_packet_length >= 1u ? channel->sftp_rx[4] : 0u;
        request_id = 0u;
        has_request_id = 0;
        if (sftp_packet_length >= 5u &&
            request_type != SSH_FXP_INIT &&
            request_type != SSH_FXP_VERSION) {
            request_id = read_u32_be_local(channel->sftp_rx + 5u);
            has_request_id = 1;
        }
        {
            char line[224];
            size_t used = 0u;

            append_lit_local(line, sizeof(line), &used, "sftp-trace: in type=");
            append_lit_local(line, sizeof(line), &used, sftp_type_name_local(request_type));
            append_lit_local(line, sizeof(line), &used, "(");
            append_u32_local(line, sizeof(line), &used, (uint32_t)request_type);
            append_lit_local(line, sizeof(line), &used, ") len=");
            append_u32_local(line, sizeof(line), &used, sftp_packet_length);
            append_lit_local(line, sizeof(line), &used, " wire=");
            append_size_local(line, sizeof(line), &used, sftp_wire_len);
            if (has_request_id) {
                append_lit_local(line, sizeof(line), &used, " id=");
                append_u32_local(line, sizeof(line), &used, request_id);
            }
            line[used] = '\0';
            sftp_trace_log_line(transport, trace_enabled, line);
        }
        sftp_trace_log_request_paths(
            transport,
            trace_enabled,
            request_type,
            channel->sftp_rx,
            sftp_wire_len);

        status = sftp_server_handle_packet(
            &channel->sftp,
            channel->sftp_rx,
            sftp_wire_len,
            response,
            sizeof(response),
            &response_len);
        if (status != SSH_OK) {
            char line[192];
            size_t used = 0u;

            append_lit_local(line, sizeof(line), &used, "sftp-trace: handle error status=");
            append_i32_local(line, sizeof(line), &used, status);
            append_lit_local(line, sizeof(line), &used, " type=");
            append_lit_local(line, sizeof(line), &used, sftp_type_name_local(request_type));
            if (has_request_id) {
                append_lit_local(line, sizeof(line), &used, " id=");
                append_u32_local(line, sizeof(line), &used, request_id);
            }
            line[used] = '\0';
            sftp_trace_log_line(transport, trace_enabled, line);
            return status;
        }
        {
            uint8_t response_type = response_len >= 5u ? response[4] : 0u;
            uint32_t response_id = 0u;
            uint32_t response_status_code = 0u;
            int has_response_id = 0;
            int has_response_status_code = 0;
            char line[224];
            size_t used = 0u;

            if (response_len >= 9u &&
                response_type != SSH_FXP_VERSION &&
                response_type != SSH_FXP_INIT) {
                response_id = read_u32_be_local(response + 5u);
                has_response_id = 1;
            }
            if (response_type == SSH_FXP_STATUS && response_len >= 13u) {
                response_status_code = read_u32_be_local(response + 9u);
                has_response_status_code = 1;
            }
            append_lit_local(line, sizeof(line), &used, "sftp-trace: out type=");
            append_lit_local(line, sizeof(line), &used, sftp_type_name_local(response_type));
            append_lit_local(line, sizeof(line), &used, "(");
            append_u32_local(line, sizeof(line), &used, (uint32_t)response_type);
            append_lit_local(line, sizeof(line), &used, ") wire=");
            append_size_local(line, sizeof(line), &used, response_len);
            if (has_response_id) {
                append_lit_local(line, sizeof(line), &used, " id=");
                append_u32_local(line, sizeof(line), &used, response_id);
            }
            if (has_response_status_code) {
                append_lit_local(line, sizeof(line), &used, " status=");
                append_u32_local(line, sizeof(line), &used, response_status_code);
            }
            line[used] = '\0';
            sftp_trace_log_line(transport, trace_enabled, line);
        }

        if (response_len > channel->peer_window_size) {
            return SSH_ERR_NOT_FOUND;
        }
        if (channel->peer_max_packet_size != 0u && response_len > channel->peer_max_packet_size) {
            status = shrink_sftp_data_response_to_limit(
                response,
                &response_len,
                (size_t)channel->peer_max_packet_size);
            if (status == SSH_ERR_UNSUPPORTED) {
                return SSH_ERR_BUFFER_TOO_SMALL;
            }
            if (status != SSH_OK) {
                return status;
            }
            if (response_len > channel->peer_window_size) {
                return SSH_ERR_NOT_FOUND;
            }
        }

        remaining_len = channel->sftp_rx_len - sftp_wire_len;
        if (remaining_len != 0u) {
            memmove(channel->sftp_rx, channel->sftp_rx + sftp_wire_len, remaining_len);
        }
        channel->sftp_rx_len = remaining_len;

        if (response_len > channel->peer_window_size) {
            if (response_len > sizeof(channel->sftp_tx_pending)) {
                return SSH_ERR_BUFFER_TOO_SMALL;
            }
            memcpy(channel->sftp_tx_pending, response, response_len);
            channel->sftp_tx_pending_len = response_len;
            return SSH_ERR_NOT_FOUND;
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
        update_server_diag_from_transport(server, &transport);
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
        if (status == SSH_ERR_NOT_FOUND) {
            continue;
        }
        if (status != SSH_OK) {
            break;
        }
        ++processed;
    }

    ssh_server_sftp_channel_deinit(&channel);
    if (effective.max_sftp_packets != 0u && processed == effective.max_sftp_packets) {
        update_server_diag_from_transport(server, &transport);
        return SSH_OK;
    }

    update_server_diag_from_transport(server, &transport);
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
        update_server_diag_from_transport(server, &transport);
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
        if (status == SSH_ERR_NOT_FOUND) {
            continue;
        }
        if (status != SSH_OK) {
            break;
        }
        ++processed;
    }

    ssh_server_terminal_channel_deinit(&transport, &channel);
    if (effective.max_sftp_packets != 0u && processed == effective.max_sftp_packets) {
        update_server_diag_from_transport(server, &transport);
        return SSH_OK;
    }
    update_server_diag_from_transport(server, &transport);
    return status;
}

int ssh_server_run_auto_session(
    ssh_server_t *server,
    void *conn,
    const ssh_server_session_options_t *options)
{
    ssh_server_session_options_t effective;
    ssh_transport_session_t transport;
    ssh_server_sftp_channel_t sftp_channel;
    ssh_server_terminal_channel_t term_channel;
    ssh_channel_open_t open;
    ssh_channel_request_t request;
    unsigned attempts;
    unsigned processed;
    int status;

    if (server == NULL || conn == NULL || !server->initialized) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    effective_session_options(options, &effective);
    memset(&sftp_channel, 0, sizeof(sftp_channel));
    memset(&term_channel, 0, sizeof(term_channel));
    memset(&open, 0, sizeof(open));
    memset(&request, 0, sizeof(request));

    status = ssh_server_run_transport_setup(server, conn, &transport, &effective);
    if (status == SSH_OK) {
        status = ssh_server_run_userauth(&transport, conn, &effective);
    }
    if (status != SSH_OK) {
        update_server_diag_from_transport(server, &transport);
        return status;
    }

    status = ssh_transport_receive_channel_open_skip_global_requests(&transport, conn, &open, effective.timeout_ms);
    if (status != SSH_OK) {
        update_server_diag_from_transport(server, &transport);
        return status;
    }
    if (!ssh_channel_type_is_session(open.channel_type)) {
        (void)ssh_transport_send_channel_open_failure(
            &transport,
            conn,
            open.sender_channel,
            SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
            "unsupported channel type",
            effective.timeout_ms);
        update_server_diag_from_transport(server, &transport);
        return SSH_ERR_UNSUPPORTED;
    }

    status = ssh_transport_send_channel_open_confirmation(
        &transport,
        conn,
        open.sender_channel,
        effective.server_channel,
        effective.channel_window_size,
        effective.channel_max_packet_size,
        effective.timeout_ms);
    if (status != SSH_OK) {
        update_server_diag_from_transport(server, &transport);
        return status;
    }

    for (attempts = 0u; attempts < 16u; ++attempts) {
        status = ssh_transport_receive_channel_request(&transport, conn, &request, effective.timeout_ms);
        if (status != SSH_OK && status != SSH_ERR_UNSUPPORTED) {
            if (should_tolerate_pre_request_malformed(&transport, status)) {
                continue;
            }
            update_server_diag_from_transport(server, &transport);
            return status;
        }
        if (status == SSH_OK && request.recipient_channel != effective.server_channel) {
            update_server_diag_from_transport(server, &transport);
            return SSH_ERR_SECURITY;
        }

        if (status == SSH_OK &&
            channel_request_is_subsystem_name(
                &request,
                effective.sftp_subsystem_name != NULL ? effective.sftp_subsystem_name : SSH_SUBSYSTEM_SFTP)) {
            status = sftp_accept_after_open(&transport, conn, &sftp_channel, &effective, &open, &request, 1);
            if (status != SSH_OK) {
                ssh_server_sftp_channel_deinit(&sftp_channel);
                update_server_diag_from_transport(server, &transport);
                return status;
            }
            processed = 0u;
            while (effective.max_sftp_packets == 0u || processed < effective.max_sftp_packets) {
                status = ssh_server_process_sftp_channel_data(&transport, conn, &sftp_channel, &effective);
                if (status == SSH_ERR_CLOSED) {
                    status = SSH_OK;
                    break;
                }
                if (status == SSH_ERR_NOT_FOUND) {
                    continue;
                }
                if (status != SSH_OK) {
                    break;
                }
                ++processed;
            }
            ssh_server_sftp_channel_deinit(&sftp_channel);
            if (effective.max_sftp_packets != 0u && processed == effective.max_sftp_packets) {
                update_server_diag_from_transport(server, &transport);
                return SSH_OK;
            }
            update_server_diag_from_transport(server, &transport);
            return status;
        }

        if (status == SSH_OK && ssh_channel_request_is_terminal(&request)) {
            status = terminal_accept_after_open(&transport, conn, &term_channel, &effective, &open, &request, 1);
            if (status != SSH_OK) {
                ssh_server_terminal_channel_deinit(&transport, &term_channel);
                update_server_diag_from_transport(server, &transport);
                return status;
            }
            processed = 0u;
            while (effective.max_sftp_packets == 0u || processed < effective.max_sftp_packets) {
                status = ssh_server_process_terminal_channel_data(&transport, conn, &term_channel, &effective);
                if (status == SSH_ERR_CLOSED) {
                    status = SSH_OK;
                    break;
                }
                if (status == SSH_ERR_NOT_FOUND) {
                    continue;
                }
                if (status != SSH_OK) {
                    break;
                }
                ++processed;
            }
            ssh_server_terminal_channel_deinit(&transport, &term_channel);
            if (effective.max_sftp_packets != 0u && processed == effective.max_sftp_packets) {
                update_server_diag_from_transport(server, &transport);
                return SSH_OK;
            }
            update_server_diag_from_transport(server, &transport);
            return status;
        }

        if (request.want_reply) {
            (void)ssh_transport_send_channel_failure(
                &transport,
                conn,
                open.sender_channel,
                effective.timeout_ms);
        }
        (void)non_sftp_channel_request_allowed_by_policy(&effective, &request);
    }

    update_server_diag_from_transport(server, &transport);
    return SSH_ERR_UNSUPPORTED;
}

int ssh_server_accept_terminal_channel(
    struct ssh_transport_session *transport,
    void *conn,
    ssh_server_terminal_channel_t *channel,
    const ssh_server_session_options_t *options)
{
    ssh_channel_open_t open;
    ssh_server_session_options_t effective;
    int status;

    if (transport == NULL || transport->server == NULL || conn == NULL || channel == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
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

    return terminal_accept_after_open(transport, conn, channel, &effective, &open, NULL, 0);
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
    uint32_t receive_timeout_ms;
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

    receive_timeout_ms = effective.timeout_ms;
    if (receive_timeout_ms == 0u || receive_timeout_ms > EMSSH_TERMINAL_RECV_POLL_MS) {
        receive_timeout_ms = EMSSH_TERMINAL_RECV_POLL_MS;
    }
    status = ssh_transport_receive_channel_message(
        transport,
        conn,
        &message,
        channel_data,
        sizeof(channel_data),
        &channel_data_len,
        receive_timeout_ms);
    if (status == SSH_ERR_NOT_FOUND) {
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
        return SSH_ERR_NOT_FOUND;
    }
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
