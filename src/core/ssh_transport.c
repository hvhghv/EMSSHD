#include "emssh/ssh_transport.h"

#include <string.h>

#include "emssh/ssh_config.h"
#include "emssh/ssh_connection.h"
#include "emssh/ssh_error.h"
#include "emssh/ssh_packet.h"
#include "emssh/ssh_server.h"
#include "emssh/ssh_service.h"
#include "emssh/ssh_userauth.h"

#define EMSSH_AUTO_SERVER_SIG_ALGS_ED25519_SUFFIX ",ssh-ed25519"
#define EMSSH_AUTO_SERVER_SIG_ALGS_CAPACITY \
    (sizeof(EMSSH_SERVER_SIG_ALGS_DEFAULT_BASE) + sizeof(EMSSH_AUTO_SERVER_SIG_ALGS_ED25519_SUFFIX) - 1u)

static int is_space(uint8_t c)
{
    return c == ' ';
}

static int is_ident_char(uint8_t c)
{
    return c >= 0x20u && c <= 0x7eu;
}

static int view_equals_cstr(ssh_string_view_t view, const char *value)
{
    size_t len;

    if (value == NULL || view.data == NULL) {
        return 0;
    }

    len = strlen(value);
    return view.len == len && memcmp(view.data, value, len) == 0;
}

static int name_list_contains(ssh_string_view_t list, const char *name)
{
    size_t name_len;
    size_t start;
    size_t i;

    if (list.data == NULL || name == NULL) {
        return 0;
    }

    name_len = strlen(name);
    start = 0u;
    for (i = 0u; i <= list.len; ++i) {
        if (i == list.len || list.data[i] == ',') {
            size_t item_len = i - start;
            if (item_len == name_len && memcmp(list.data + start, name, name_len) == 0) {
                return 1;
            }
            start = i + 1u;
        }
    }

    return 0;
}

static const char *resolve_auto_server_sig_algs(
    const ssh_transport_session_t *session,
    char *out,
    size_t out_capacity)
{
    ssh_string_view_t hostkey_algorithms;
    static const char ed25519_suffix[] = EMSSH_AUTO_SERVER_SIG_ALGS_ED25519_SUFFIX;
    size_t base_len;
    size_t suffix_len;

    if (session == NULL || out == NULL || out_capacity == 0u) {
        return "";
    }

    base_len = strlen(EMSSH_SERVER_SIG_ALGS_DEFAULT_BASE);
    if (base_len + 1u > out_capacity) {
        return "";
    }
    memcpy(out, EMSSH_SERVER_SIG_ALGS_DEFAULT_BASE, base_len + 1u);

    hostkey_algorithms.data = (const uint8_t *)session->server_algorithms.server_host_key_algorithms;
    hostkey_algorithms.len = session->server_algorithms.server_host_key_algorithms != NULL ?
        strlen(session->server_algorithms.server_host_key_algorithms) : 0u;
    if (!name_list_contains(hostkey_algorithms, "ssh-ed25519")) {
        return out;
    }

    suffix_len = sizeof(ed25519_suffix) - 1u;
    if (base_len + suffix_len + 1u > out_capacity) {
        return out;
    }
    memcpy(out + base_len, ed25519_suffix, suffix_len + 1u);
    return out;
}

static int signature_algorithms_valid(const char *value)
{
    ssh_string_view_t list;

    if (value == NULL || value[0] == '\0') {
        return 1;
    }

    list.data = (const uint8_t *)value;
    list.len = strlen(value);
    return ssh_name_list_is_valid(list);
}

static size_t view_algorithm_size(ssh_string_view_t view, const char *algorithm, size_t value)
{
    size_t len;

    len = strlen(algorithm);
    return view.len == len && memcmp(view.data, algorithm, len) == 0 ? value : 0u;
}

static int negotiated_packet_sizes(
    const ssh_kex_negotiation_t *negotiation,
    size_t *cipher_key_len,
    size_t *cipher_iv_len,
    size_t *block_size,
    size_t *mac_key_len,
    size_t *mac_len)
{
    if (negotiation == NULL || cipher_key_len == NULL || cipher_iv_len == NULL ||
        block_size == NULL || mac_key_len == NULL || mac_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *cipher_key_len = view_algorithm_size(negotiation->encryption_algorithm_client_to_server, "aes128-ctr", 16u);
    *cipher_iv_len = view_algorithm_size(negotiation->encryption_algorithm_client_to_server, "aes128-ctr", 16u);
    *block_size = view_algorithm_size(negotiation->encryption_algorithm_client_to_server, "aes128-ctr", 16u);
    *mac_key_len = view_algorithm_size(negotiation->mac_algorithm_client_to_server, "hmac-sha2-256", 32u);
    *mac_len = view_algorithm_size(negotiation->mac_algorithm_client_to_server, "hmac-sha2-256", 32u);

    if (*cipher_key_len == 0u || *cipher_iv_len == 0u || *block_size == 0u ||
        *mac_key_len == 0u || *mac_len == 0u) {
        return SSH_ERR_UNSUPPORTED;
    }

    return SSH_OK;
}

int ssh_identification_parse_line(const uint8_t *line, size_t len, ssh_identification_t *ident)
{
    size_t raw_len;
    size_t protocol_start;
    size_t protocol_end;
    size_t software_start;
    size_t software_end;
    size_t comments_start;
    size_t i;

    if (line == NULL || ident == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(ident, 0, sizeof(*ident));

    raw_len = len;
    if (raw_len >= 2u && line[raw_len - 2u] == '\r' && line[raw_len - 1u] == '\n') {
        raw_len -= 2u;
    } else if (raw_len >= 1u && line[raw_len - 1u] == '\n') {
        raw_len -= 1u;
    }

    if (raw_len == 0u || raw_len > EMSSH_MAX_IDENTIFICATION_LINE) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    for (i = 0u; i < raw_len; ++i) {
        if (!is_ident_char(line[i])) {
            return SSH_ERR_MALFORMED_PACKET;
        }
    }

    if (raw_len < 8u || memcmp(line, "SSH-", 4u) != 0) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    protocol_start = 4u;
    protocol_end = protocol_start;
    while (protocol_end < raw_len && line[protocol_end] != '-') {
        if (is_space(line[protocol_end])) {
            return SSH_ERR_MALFORMED_PACKET;
        }
        ++protocol_end;
    }

    if (protocol_end == protocol_start || protocol_end >= raw_len || line[protocol_end] != '-') {
        return SSH_ERR_MALFORMED_PACKET;
    }

    software_start = protocol_end + 1u;
    software_end = software_start;
    while (software_end < raw_len && !is_space(line[software_end])) {
        if (line[software_end] == '-') {
            /* Software version may contain '-' in practice. */
        }
        ++software_end;
    }

    if (software_end == software_start) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    comments_start = software_end;
    if (comments_start < raw_len && is_space(line[comments_start])) {
        ++comments_start;
    }

    ident->raw.data = line;
    ident->raw.len = raw_len;
    ident->protocol_version.data = line + protocol_start;
    ident->protocol_version.len = protocol_end - protocol_start;
    ident->software_version.data = line + software_start;
    ident->software_version.len = software_end - software_start;
    ident->comments.data = comments_start < raw_len ? line + comments_start : NULL;
    ident->comments.len = comments_start < raw_len ? raw_len - comments_start : 0u;

    return SSH_OK;
}

int ssh_identification_is_ssh2_compatible(const ssh_identification_t *ident)
{
    if (ident == NULL) {
        return 0;
    }

    return view_equals_cstr(ident->protocol_version, "2.0") ||
           view_equals_cstr(ident->protocol_version, "1.99");
}

static int net_read_exact(
    const ssh_transport_session_t *session,
    void *conn,
    uint8_t *buf,
    size_t len,
    uint32_t timeout_ms)
{
    size_t done;

    if (session == NULL || session->server == NULL || session->server->platform.net == NULL ||
        session->server->platform.net->read == NULL || (buf == NULL && len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    done = 0u;
    while (done < len) {
        int n = session->server->platform.net->read(
            session->server->platform.net->ctx,
            conn,
            buf + done,
            len - done,
            timeout_ms);

        if (n == 0) {
            return SSH_ERR_CLOSED;
        }
        if (n < 0) {
            return SSH_ERR_PLATFORM;
        }

        done += (size_t)n;
    }

    return SSH_OK;
}

static int net_write_all(
    const ssh_transport_session_t *session,
    void *conn,
    const uint8_t *buf,
    size_t len,
    uint32_t timeout_ms)
{
    size_t done;

    if (session == NULL || session->server == NULL || session->server->platform.net == NULL ||
        session->server->platform.net->write == NULL || (buf == NULL && len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    done = 0u;
    while (done < len) {
        int n = session->server->platform.net->write(
            session->server->platform.net->ctx,
            conn,
            buf + done,
            len - done,
            timeout_ms);

        if (n == 0) {
            return SSH_ERR_CLOSED;
        }
        if (n < 0) {
            return SSH_ERR_PLATFORM;
        }

        done += (size_t)n;
    }

    return SSH_OK;
}

static uint32_t read_u32_be(const uint8_t data[4])
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static uint64_t add_u64_saturating(uint64_t lhs, uint64_t rhs)
{
    if (UINT64_MAX - lhs < rhs) {
        return UINT64_MAX;
    }

    return lhs + rhs;
}

static void update_rekey_needed(ssh_transport_session_t *session)
{
    if (session == NULL) {
        return;
    }

    session->rekey_needed =
        (session->rekey_after_packets != 0u &&
         (session->inbound_rekey_packets >= session->rekey_after_packets ||
          session->outbound_rekey_packets >= session->rekey_after_packets)) ||
        (session->rekey_after_bytes != 0u &&
         (session->inbound_rekey_bytes >= session->rekey_after_bytes ||
          session->outbound_rekey_bytes >= session->rekey_after_bytes));
}

static void record_rekey_packet(ssh_transport_session_t *session, int outbound, size_t wire_len)
{
    uint64_t wire_len_u64;

    if (session == NULL) {
        return;
    }

    wire_len_u64 = (uint64_t)wire_len;
    if (outbound) {
        session->outbound_rekey_packets = add_u64_saturating(session->outbound_rekey_packets, 1u);
        session->outbound_rekey_bytes = add_u64_saturating(session->outbound_rekey_bytes, wire_len_u64);
    } else {
        session->inbound_rekey_packets = add_u64_saturating(session->inbound_rekey_packets, 1u);
        session->inbound_rekey_bytes = add_u64_saturating(session->inbound_rekey_bytes, wire_len_u64);
    }
    update_rekey_needed(session);
}

static void reset_rekey_direction(ssh_transport_session_t *session, int outbound)
{
    if (session == NULL) {
        return;
    }

    if (outbound) {
        session->outbound_rekey_packets = 0u;
        session->outbound_rekey_bytes = 0u;
    } else {
        session->inbound_rekey_packets = 0u;
        session->inbound_rekey_bytes = 0u;
    }
    update_rekey_needed(session);
}

static int receive_plain_packet(
    ssh_transport_session_t *session,
    void *conn,
    uint8_t *payload_out,
    size_t payload_capacity,
    size_t *payload_len,
    uint32_t timeout_ms)
{
    uint8_t packet[EMSSH_MAX_PACKET_SIZE + 4u];
    uint8_t header[4];
    ssh_packet_view_t view;
    uint32_t packet_length;
    int status;

    if (session == NULL || payload_out == NULL || payload_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = net_read_exact(session, conn, header, sizeof(header), timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    packet_length = read_u32_be(header);
    if (packet_length == 0u || packet_length > EMSSH_MAX_PACKET_SIZE) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    memcpy(packet, header, sizeof(header));
    status = net_read_exact(session, conn, packet + sizeof(header), packet_length, timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_packet_decode_plain(packet, (size_t)packet_length + sizeof(header), &view);
    if (status != SSH_OK) {
        return status;
    }

    if (view.payload_len > payload_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(payload_out, view.payload, view.payload_len);
    *payload_len = view.payload_len;
    ++session->inbound_sequence;
    return SSH_OK;
}

static void transport_copy_algorithms(
    ssh_kexinit_algorithm_set_t *dst,
    const ssh_kexinit_algorithm_set_t *src)
{
    if (src != NULL) {
        *dst = *src;
    } else {
        ssh_kexinit_algorithm_set_defaults(dst);
    }
}

static int derive_material(
    const ssh_transport_session_t *session,
    char key_id,
    uint8_t *out,
    size_t out_len)
{
    const ssh_crypto_api_t *crypto;
    size_t actual_len;
    int status;

    if (session == NULL || out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    crypto = session->server->platform.crypto;
    if (crypto == NULL || crypto->derive_key == NULL) {
        return SSH_ERR_PLATFORM;
    }

    status = crypto->derive_key(
        crypto->ctx,
        session->negotiation.kex_algorithm,
        session->shared_secret,
        session->shared_secret_len,
        session->exchange_hash,
        session->exchange_hash_len,
        session->session_id,
        session->session_id_len,
        key_id,
        out,
        out_len,
        &actual_len);
    if (status != SSH_OK || actual_len != out_len) {
        return SSH_ERR_PLATFORM;
    }

    return SSH_OK;
}

static int activate_packet_protection(ssh_transport_session_t *session, int outbound)
{
    uint8_t cipher_key[EMSSH_MAX_CIPHER_KEY];
    uint8_t cipher_iv[EMSSH_MAX_CIPHER_IV];
    uint8_t mac_key[EMSSH_MAX_MAC_KEY];
    size_t cipher_key_len;
    size_t cipher_iv_len;
    size_t block_size;
    size_t mac_key_len;
    size_t mac_len;
    char iv_id;
    char cipher_id;
    char mac_id;
    int status;

    if (session == NULL || session->server == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = negotiated_packet_sizes(
        &session->negotiation,
        &cipher_key_len,
        &cipher_iv_len,
        &block_size,
        &mac_key_len,
        &mac_len);
    if (status != SSH_OK) {
        return status;
    }

    if (session->session_id_len == 0u) {
        if (session->exchange_hash_len == 0u || session->exchange_hash_len > sizeof(session->session_id)) {
            return SSH_ERR_SECURITY;
        }
        memcpy(session->session_id, session->exchange_hash, session->exchange_hash_len);
        session->session_id_len = session->exchange_hash_len;
    }

    iv_id = outbound ? 'B' : 'A';
    cipher_id = outbound ? 'D' : 'C';
    mac_id = outbound ? 'F' : 'E';

    status = derive_material(session, iv_id, cipher_iv, cipher_iv_len);
    if (status != SSH_OK) {
        return status;
    }

    status = derive_material(session, cipher_id, cipher_key, cipher_key_len);
    if (status != SSH_OK) {
        return status;
    }

    status = derive_material(session, mac_id, mac_key, mac_key_len);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_packet_protection_set(
        outbound ? &session->outbound : &session->inbound,
        session->server->platform.crypto,
        outbound ? session->negotiation.encryption_algorithm_server_to_client : session->negotiation.encryption_algorithm_client_to_server,
        outbound ? session->negotiation.mac_algorithm_server_to_client : session->negotiation.mac_algorithm_client_to_server,
        cipher_key,
        cipher_key_len,
        cipher_iv,
        cipher_iv_len,
        mac_key,
        mac_key_len,
        block_size,
        mac_len);
    if (status == SSH_OK) {
        if (outbound) {
            session->outbound.sequence = session->outbound_sequence;
        } else {
            session->inbound.sequence = session->inbound_sequence;
        }
        reset_rekey_direction(session, outbound);
    }

    if (session->server->platform.crypto != NULL && session->server->platform.crypto->secure_zero != NULL) {
        session->server->platform.crypto->secure_zero(session->server->platform.crypto->ctx, cipher_key, sizeof(cipher_key));
        session->server->platform.crypto->secure_zero(session->server->platform.crypto->ctx, cipher_iv, sizeof(cipher_iv));
        session->server->platform.crypto->secure_zero(session->server->platform.crypto->ctx, mac_key, sizeof(mac_key));
    } else {
        memset(cipher_key, 0, sizeof(cipher_key));
        memset(cipher_iv, 0, sizeof(cipher_iv));
        memset(mac_key, 0, sizeof(mac_key));
    }

    return status;
}

static int receive_one_line(
    ssh_transport_session_t *session,
    void *conn,
    uint8_t *line,
    size_t capacity,
    size_t *line_len,
    uint32_t timeout_ms)
{
    size_t len;

    if (line == NULL || line_len == NULL || capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    len = 0u;
    for (;;) {
        uint8_t c;
        int status;

        if (len >= capacity) {
            return SSH_ERR_MALFORMED_PACKET;
        }

        status = net_read_exact(session, conn, &c, 1u, timeout_ms);
        if (status != SSH_OK) {
            return status;
        }

        line[len++] = c;
        if (c == '\n') {
            *line_len = len;
            return SSH_OK;
        }
    }
}

int ssh_transport_session_init(
    ssh_transport_session_t *session,
    const struct ssh_server *server,
    const ssh_kexinit_algorithm_set_t *server_algorithms)
{
    if (session == NULL || server == NULL || !server->initialized) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(session, 0, sizeof(*session));
    session->server = server;
    session->state = SSH_TRANSPORT_STATE_INIT;
    transport_copy_algorithms(&session->server_algorithms, server_algorithms);
    ssh_packet_protection_init(&session->inbound);
    ssh_packet_protection_init(&session->outbound);
    return SSH_OK;
}

int ssh_transport_set_rekey_limits(
    ssh_transport_session_t *session,
    uint64_t packets,
    uint64_t bytes)
{
    if (session == NULL || session->server == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    session->rekey_after_packets = packets;
    session->rekey_after_bytes = bytes;
    session->inbound_rekey_packets = 0u;
    session->outbound_rekey_packets = 0u;
    session->inbound_rekey_bytes = 0u;
    session->outbound_rekey_bytes = 0u;
    session->rekey_needed = 0;
    return SSH_OK;
}

int ssh_transport_rekey_needed(const ssh_transport_session_t *session)
{
    return session != NULL && session->rekey_needed;
}

int ssh_transport_send_identification(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms)
{
    int status;

    if (session == NULL || session->server == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_server_format_identification(
        session->server,
        (char *)session->server_identification_line,
        sizeof(session->server_identification_line));
    if (status != SSH_OK) {
        return status;
    }

    session->server_identification_len = strlen((const char *)session->server_identification_line);
    status = ssh_identification_parse_line(
        session->server_identification_line,
        session->server_identification_len,
        &session->server_identification);
    if (status != SSH_OK) {
        return status;
    }

    status = net_write_all(
        session,
        conn,
        session->server_identification_line,
        session->server_identification_len,
        timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_IDENT_SENT;
    return SSH_OK;
}

int ssh_transport_receive_identification(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms)
{
    unsigned skipped_lines;
    int status;

    if (session == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    for (skipped_lines = 0u; skipped_lines < 20u; ++skipped_lines) {
        status = receive_one_line(
            session,
            conn,
            session->client_identification_line,
            sizeof(session->client_identification_line),
            &session->client_identification_len,
            timeout_ms);
        if (status != SSH_OK) {
            return status;
        }

        if (session->client_identification_len >= 4u &&
            memcmp(session->client_identification_line, "SSH-", 4u) == 0) {
            status = ssh_identification_parse_line(
                session->client_identification_line,
                session->client_identification_len,
                &session->client_identification);
            if (status != SSH_OK) {
                return status;
            }

            if (!ssh_identification_is_ssh2_compatible(&session->client_identification)) {
                return SSH_ERR_UNSUPPORTED;
            }

            session->state = SSH_TRANSPORT_STATE_IDENT_RECEIVED;
            return SSH_OK;
        }
    }

    return SSH_ERR_MALFORMED_PACKET;
}

int ssh_transport_send_kexinit(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms)
{
    uint8_t cookie[SSH_KEX_COOKIE_LEN];
    uint8_t packet[EMSSH_MAX_KEXINIT_PAYLOAD + 64u];
    ssh_buffer_t payload;
    size_t packet_len;
    int status;

    if (session == NULL || session->server == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (session->server->platform.rng == NULL || session->server->platform.rng->fill == NULL) {
        return SSH_ERR_PLATFORM;
    }

    status = session->server->platform.rng->fill(session->server->platform.rng->ctx, cookie, sizeof(cookie));
    if (status != SSH_OK) {
        return SSH_ERR_PLATFORM;
    }

    ssh_buffer_init(&payload, session->server_kexinit_payload, sizeof(session->server_kexinit_payload));
    status = ssh_kexinit_encode(&payload, cookie, &session->server_algorithms, 0);
    if (status != SSH_OK) {
        return status;
    }

    session->server_kexinit_payload_len = ssh_buffer_len(&payload);
    status = ssh_packet_encode_plain(
        packet,
        sizeof(packet),
        &packet_len,
        session->server_kexinit_payload,
        session->server_kexinit_payload_len,
        SSH_PACKET_MIN_BLOCK_SIZE,
        session->server->platform.rng);
    if (status != SSH_OK) {
        return status;
    }

    status = net_write_all(session, conn, packet, packet_len, timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    ++session->outbound_sequence;
    session->state = SSH_TRANSPORT_STATE_KEXINIT_SENT;
    return SSH_OK;
}

int ssh_transport_receive_kexinit(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms)
{
    ssh_buffer_t payload;
    int status;

    if (session == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = receive_plain_packet(
        session,
        conn,
        session->client_kexinit_payload,
        sizeof(session->client_kexinit_payload),
        &session->client_kexinit_payload_len,
        timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    ssh_buffer_wrap(&payload, session->client_kexinit_payload, session->client_kexinit_payload_len);
    status = ssh_kexinit_decode(&payload, &session->client_kexinit);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_kex_negotiate(&session->client_kexinit, &session->server_algorithms, &session->negotiation);
    if (status != SSH_OK) {
        return status;
    }

    session->client_supports_ext_info = name_list_contains(
        session->client_kexinit.name_lists[SSH_KEX_ALGORITHMS],
        "ext-info-c");

    session->state = SSH_TRANSPORT_STATE_NEGOTIATED;
    return SSH_OK;
}

static int build_exchange_hash_input(ssh_transport_session_t *session, uint8_t *out, size_t out_capacity, size_t *out_len)
{
    ssh_buffer_t buf;
    int status;

    if (session == NULL || out == NULL || out_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, out, out_capacity);

    status = ssh_buffer_put_string(&buf, session->client_identification.raw.data, session->client_identification.raw.len);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_string(&buf, session->server_identification.raw.data, session->server_identification.raw.len);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_string(&buf, session->client_kexinit_payload, session->client_kexinit_payload_len);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_string(&buf, session->server_kexinit_payload, session->server_kexinit_payload_len);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_string(&buf, session->server_host_key, session->server_host_key_len);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_string(&buf, session->client_kex_public_key, session->client_kex_public_key_len);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_string(&buf, session->server_kex_public_key, session->server_kex_public_key_len);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_mpint_positive(&buf, session->shared_secret, session->shared_secret_len);
    if (status != SSH_OK) {
        return status;
    }

    *out_len = ssh_buffer_len(&buf);
    return SSH_OK;
}

int ssh_transport_receive_kex_ecdh_init(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms)
{
    uint8_t payload_storage[EMSSH_MAX_KEX_PUBLIC_KEY + 16u];
    size_t payload_len;
    ssh_buffer_t payload;
    ssh_kex_ecdh_init_t init;
    int status;

    if (session == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = receive_plain_packet(
        session,
        conn,
        payload_storage,
        sizeof(payload_storage),
        &payload_len,
        timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    ssh_buffer_wrap(&payload, payload_storage, payload_len);
    status = ssh_kex_ecdh_init_decode(&payload, &init);
    if (status != SSH_OK) {
        return status;
    }

    memcpy(session->client_kex_public_key, init.client_public_key.data, init.client_public_key.len);
    session->client_kex_public_key_len = init.client_public_key.len;
    session->state = SSH_TRANSPORT_STATE_KEX_ECDH_INIT_RECEIVED;
    return SSH_OK;
}

int ssh_transport_send_kex_ecdh_reply(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms)
{
    const ssh_crypto_api_t *crypto;
    uint8_t exchange_input[4096];
    size_t exchange_input_len;
    uint8_t reply_payload[EMSSH_MAX_KEX_REPLY_PAYLOAD];
    uint8_t packet[EMSSH_MAX_KEX_REPLY_PAYLOAD + 64u];
    ssh_buffer_t reply;
    size_t packet_len;
    int status;

    if (session == NULL || session->server == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    crypto = session->server->platform.crypto;
    if (crypto == NULL ||
        crypto->kex_generate_keypair == NULL ||
        crypto->kex_compute_shared_secret == NULL ||
        crypto->hostkey_public == NULL ||
        crypto->hash_exchange == NULL ||
        crypto->hostkey_sign == NULL) {
        return SSH_ERR_PLATFORM;
    }

    status = crypto->kex_generate_keypair(
        crypto->ctx,
        session->negotiation.kex_algorithm,
        session->server_kex_public_key,
        sizeof(session->server_kex_public_key),
        &session->server_kex_public_key_len,
        session->server_kex_private_key,
        sizeof(session->server_kex_private_key),
        &session->server_kex_private_key_len);
    if (status != SSH_OK) {
        return SSH_ERR_PLATFORM;
    }

    status = crypto->kex_compute_shared_secret(
        crypto->ctx,
        session->negotiation.kex_algorithm,
        session->server_kex_private_key,
        session->server_kex_private_key_len,
        session->client_kex_public_key,
        session->client_kex_public_key_len,
        session->shared_secret,
        sizeof(session->shared_secret),
        &session->shared_secret_len);
    if (status != SSH_OK) {
        return SSH_ERR_PLATFORM;
    }

    status = crypto->hostkey_public(
        crypto->ctx,
        session->negotiation.server_host_key_algorithm,
        session->server_host_key,
        sizeof(session->server_host_key),
        &session->server_host_key_len);
    if (status != SSH_OK) {
        return SSH_ERR_PLATFORM;
    }

    status = build_exchange_hash_input(session, exchange_input, sizeof(exchange_input), &exchange_input_len);
    if (status != SSH_OK) {
        return status;
    }

    status = crypto->hash_exchange(
        crypto->ctx,
        session->negotiation.kex_algorithm,
        exchange_input,
        exchange_input_len,
        session->exchange_hash,
        sizeof(session->exchange_hash),
        &session->exchange_hash_len);
    if (status != SSH_OK) {
        return SSH_ERR_PLATFORM;
    }

    status = crypto->hostkey_sign(
        crypto->ctx,
        session->negotiation.server_host_key_algorithm,
        session->exchange_hash,
        session->exchange_hash_len,
        session->server_signature,
        sizeof(session->server_signature),
        &session->server_signature_len);
    if (status != SSH_OK) {
        return SSH_ERR_PLATFORM;
    }

    if (session->session_id_len == 0u) {
        memcpy(session->session_id, session->exchange_hash, session->exchange_hash_len);
        session->session_id_len = session->exchange_hash_len;
    }

    ssh_buffer_init(&reply, reply_payload, sizeof(reply_payload));
    status = ssh_kex_ecdh_reply_encode(
        &reply,
        session->server_host_key,
        session->server_host_key_len,
        session->server_kex_public_key,
        session->server_kex_public_key_len,
        session->server_signature,
        session->server_signature_len);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_packet_encode_plain(
        packet,
        sizeof(packet),
        &packet_len,
        reply_payload,
        ssh_buffer_len(&reply),
        SSH_PACKET_MIN_BLOCK_SIZE,
        session->server->platform.rng);
    if (status != SSH_OK) {
        return status;
    }

    status = net_write_all(session, conn, packet, packet_len, timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    ++session->outbound_sequence;
    session->state = SSH_TRANSPORT_STATE_KEX_ECDH_REPLY_SENT;
    return SSH_OK;
}

int ssh_transport_send_newkeys(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms)
{
    uint8_t payload_storage[8];
    uint8_t packet[32];
    ssh_buffer_t payload;
    size_t packet_len;
    int status;

    if (session == NULL || session->server == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&payload, payload_storage, sizeof(payload_storage));
    status = ssh_kex_newkeys_encode(&payload);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_packet_encode_plain(
        packet,
        sizeof(packet),
        &packet_len,
        payload_storage,
        ssh_buffer_len(&payload),
        SSH_PACKET_MIN_BLOCK_SIZE,
        session->server->platform.rng);
    if (status != SSH_OK) {
        return status;
    }

    status = net_write_all(session, conn, packet, packet_len, timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    ++session->outbound_sequence;
    status = activate_packet_protection(session, 1);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_NEWKEYS_SENT;
    return SSH_OK;
}

int ssh_transport_receive_newkeys(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms)
{
    uint8_t payload_storage[8];
    size_t payload_len;
    ssh_buffer_t payload;
    int status;

    if (session == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = receive_plain_packet(
        session,
        conn,
        payload_storage,
        sizeof(payload_storage),
        &payload_len,
        timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    ssh_buffer_wrap(&payload, payload_storage, payload_len);
    status = ssh_kex_newkeys_decode(&payload);
    if (status != SSH_OK) {
        return status;
    }

    status = activate_packet_protection(session, 0);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_NEWKEYS_RECEIVED;
    return SSH_OK;
}

int ssh_transport_send_ext_info(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms)
{
    uint8_t payload_storage[EMSSH_MAX_EXT_INFO_PAYLOAD];
    ssh_buffer_t payload;
    char auto_signature_algorithms[EMSSH_AUTO_SERVER_SIG_ALGS_CAPACITY];
    const char *signature_algorithms;
    int status;

    if (session == NULL || session->server == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (!session->client_supports_ext_info) {
        return SSH_OK;
    }

    if (session->server->config.publickey_auth == NULL) {
        signature_algorithms = "";
    } else {
        signature_algorithms = session->server->config.publickey_signature_algorithms;
        if (signature_algorithms == NULL) {
            signature_algorithms = resolve_auto_server_sig_algs(
                session,
                auto_signature_algorithms,
                sizeof(auto_signature_algorithms));
        }
    }
    if (!signature_algorithms_valid(signature_algorithms)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&payload, payload_storage, sizeof(payload_storage));
    status = ssh_buffer_put_u8(&payload, SSH_MSG_EXT_INFO);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(&payload, signature_algorithms[0] == '\0' ? 0u : 1u);
    }
    if (status == SSH_OK && signature_algorithms[0] != '\0') {
        status = ssh_buffer_put_cstring(&payload, "server-sig-algs");
    }
    if (status == SSH_OK && signature_algorithms[0] != '\0') {
        status = ssh_buffer_put_cstring(&payload, signature_algorithms);
    }
    if (status != SSH_OK) {
        return status;
    }

    return ssh_transport_send_protected_payload(session, conn, payload_storage, ssh_buffer_len(&payload), timeout_ms);
}

int ssh_transport_send_protected_payload(
    ssh_transport_session_t *session,
    void *conn,
    const uint8_t *payload,
    size_t payload_len,
    uint32_t timeout_ms)
{
    uint8_t packet[EMSSH_MAX_PACKET_SIZE + 4u + EMSSH_MAX_MAC];
    size_t packet_len;
    int status;

    if (session == NULL || !session->outbound.active ||
        (payload == NULL && payload_len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_packet_encode_protected(
        &session->outbound,
        packet,
        sizeof(packet),
        &packet_len,
        payload,
        payload_len,
        session->server->platform.rng);
    if (status != SSH_OK) {
        return status;
    }

    status = net_write_all(session, conn, packet, packet_len, timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    session->outbound_sequence = session->outbound.sequence;
    record_rekey_packet(session, 1, packet_len);
    return SSH_OK;
}

int ssh_transport_receive_protected_payload(
    ssh_transport_session_t *session,
    void *conn,
    uint8_t *payload_out,
    size_t payload_capacity,
    size_t *payload_len,
    uint32_t timeout_ms)
{
    uint8_t packet[EMSSH_MAX_PACKET_SIZE + 4u + EMSSH_MAX_MAC];
    uint8_t first_block[EMSSH_MAX_CIPHER_IV];
    ssh_packet_view_t view;
    uint32_t packet_length;
    size_t block_size;
    size_t encrypted_len;
    size_t packet_len;
    int status;

    if (session == NULL || !session->inbound.active ||
        payload_out == NULL || payload_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    block_size = session->inbound.block_size;
    if (block_size < SSH_PACKET_MIN_BLOCK_SIZE || block_size > sizeof(first_block)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = net_read_exact(session, conn, packet, block_size, timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    memcpy(first_block, packet, block_size);
    status = session->inbound.crypto->cipher_crypt(
        session->inbound.crypto->ctx,
        session->inbound.cipher_algorithm,
        session->inbound.cipher_key,
        session->inbound.cipher_key_len,
        session->inbound.cipher_iv,
        session->inbound.cipher_iv_len,
        session->inbound.sequence,
        SSH_CIPHER_DECRYPT,
        first_block,
        block_size);
    if (status != SSH_OK) {
        return SSH_ERR_PLATFORM;
    }

    packet_length = read_u32_be(first_block);
    if (packet_length == 0u || packet_length > EMSSH_MAX_PACKET_SIZE) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    encrypted_len = (size_t)packet_length + 4u;
    if (encrypted_len < block_size ||
        encrypted_len > EMSSH_MAX_PACKET_SIZE + 4u ||
        (encrypted_len % block_size) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    status = net_read_exact(
        session,
        conn,
        packet + block_size,
        (encrypted_len - block_size) + session->inbound.mac_len,
        timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    packet_len = encrypted_len + session->inbound.mac_len;
    status = ssh_packet_decode_protected(&session->inbound, packet, packet_len, &view);
    if (status != SSH_OK) {
        return status;
    }

    if (view.payload_len > payload_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(payload_out, view.payload, view.payload_len);
    *payload_len = view.payload_len;
    session->inbound_sequence = session->inbound.sequence;
    record_rekey_packet(session, 0, packet_len);
    return SSH_OK;
}

static int transport_payload_is_ignorable(const uint8_t *payload, size_t payload_len)
{
    uint8_t message_id;

    if (payload == NULL || payload_len == 0u) {
        return 0;
    }

    message_id = payload[0];
    return message_id == SSH_MSG_IGNORE ||
           message_id == SSH_MSG_DEBUG ||
           message_id == SSH_MSG_UNIMPLEMENTED;
}

static int transport_payload_is_disconnect(const uint8_t *payload, size_t payload_len)
{
    return payload != NULL && payload_len != 0u && payload[0] == SSH_MSG_DISCONNECT;
}

static int receive_protected_payload_skip_ignorable(
    ssh_transport_session_t *session,
    void *conn,
    uint8_t *payload_out,
    size_t payload_capacity,
    size_t *payload_len,
    uint32_t timeout_ms)
{
    unsigned skipped;
    int status;

    if (session == NULL || payload_out == NULL || payload_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    for (skipped = 0u; skipped < 8u; ++skipped) {
        status = ssh_transport_receive_protected_payload(
            session,
            conn,
            payload_out,
            payload_capacity,
            payload_len,
            timeout_ms);
        if (status != SSH_OK) {
            return status;
        }
        if (transport_payload_is_disconnect(payload_out, *payload_len)) {
            return SSH_ERR_CLOSED;
        }
        if (!transport_payload_is_ignorable(payload_out, *payload_len)) {
            return SSH_OK;
        }
    }

    return SSH_ERR_MALFORMED_PACKET;
}

int ssh_transport_receive_service_request(
    ssh_transport_session_t *session,
    void *conn,
    ssh_service_request_t *request,
    uint32_t timeout_ms)
{
    ssh_buffer_t buf;
    int status;

    if (session == NULL || session->server == NULL || request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = receive_protected_payload_skip_ignorable(
        session,
        conn,
        session->service_payload,
        sizeof(session->service_payload),
        &session->service_payload_len,
        timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    ssh_buffer_wrap(&buf, session->service_payload, session->service_payload_len);
    status = ssh_service_request_decode(&buf, request);
    if (status != SSH_OK) {
        return status;
    }

    if (!ssh_service_name_is_supported(request->service_name)) {
        return SSH_ERR_UNSUPPORTED;
    }

    session->state = SSH_TRANSPORT_STATE_SERVICE_REQUEST_RECEIVED;
    return SSH_OK;
}

int ssh_transport_send_service_accept(
    ssh_transport_session_t *session,
    void *conn,
    const char *service_name,
    uint32_t timeout_ms)
{
    uint8_t payload[256];
    ssh_buffer_t buf;
    int status;

    if (session == NULL || service_name == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, payload, sizeof(payload));
    status = ssh_service_accept_encode(&buf, service_name);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_transport_send_protected_payload(session, conn, payload, ssh_buffer_len(&buf), timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_SERVICE_ACCEPT_SENT;
    return SSH_OK;
}

int ssh_transport_receive_userauth_request(
    ssh_transport_session_t *session,
    void *conn,
    ssh_userauth_request_t *request,
    uint32_t timeout_ms)
{
    ssh_buffer_t buf;
    int status;

    if (session == NULL || request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = receive_protected_payload_skip_ignorable(
        session,
        conn,
        session->userauth_payload,
        sizeof(session->userauth_payload),
        &session->userauth_payload_len,
        timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    ssh_buffer_wrap(&buf, session->userauth_payload, session->userauth_payload_len);
    status = ssh_userauth_request_decode(&buf, request);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_USERAUTH_REQUEST_RECEIVED;
    return SSH_OK;
}

int ssh_transport_send_userauth_pk_ok(
    ssh_transport_session_t *session,
    void *conn,
    ssh_string_view_t publickey_algorithm,
    ssh_string_view_t publickey_blob,
    uint32_t timeout_ms)
{
    uint8_t payload[EMSSH_MAX_USERAUTH_PAYLOAD];
    ssh_buffer_t buf;
    int status;

    if (session == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, payload, sizeof(payload));
    status = ssh_userauth_pk_ok_encode(&buf, publickey_algorithm, publickey_blob);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_transport_send_protected_payload(session, conn, payload, ssh_buffer_len(&buf), timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_USERAUTH_PK_OK_SENT;
    return SSH_OK;
}

int ssh_transport_send_userauth_success(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms)
{
    uint8_t payload[8];
    ssh_buffer_t buf;
    int status;

    if (session == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, payload, sizeof(payload));
    status = ssh_userauth_success_encode(&buf);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_transport_send_protected_payload(session, conn, payload, ssh_buffer_len(&buf), timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_USERAUTH_SUCCESS_SENT;
    return SSH_OK;
}

int ssh_transport_send_userauth_failure(
    ssh_transport_session_t *session,
    void *conn,
    const char *methods,
    int partial_success,
    uint32_t timeout_ms)
{
    uint8_t payload[128];
    ssh_buffer_t buf;
    int status;

    if (session == NULL || methods == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, payload, sizeof(payload));
    status = ssh_userauth_failure_encode(&buf, methods, partial_success);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_transport_send_protected_payload(session, conn, payload, ssh_buffer_len(&buf), timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_USERAUTH_FAILURE_SENT;
    return SSH_OK;
}

int ssh_transport_handle_userauth_request(
    ssh_transport_session_t *session,
    void *conn,
    const ssh_userauth_request_t *request,
    uint32_t timeout_ms)
{
    char failure_methods[EMSSH_MAX_USERAUTH_FAILURE_METHODS];
    ssh_userauth_decision_t decision;
    int status;

    if (session == NULL || session->server == NULL || request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_userauth_evaluate_request(
        session->server,
        request,
        session->session_id,
        session->session_id_len,
        &decision);
    if (status != SSH_OK) {
        return status;
    }

    if (decision == SSH_USERAUTH_DECISION_SUCCESS) {
        return ssh_transport_send_userauth_success(session, conn, timeout_ms);
    }
    if (decision == SSH_USERAUTH_DECISION_PK_OK) {
        return ssh_transport_send_userauth_pk_ok(
            session,
            conn,
            request->publickey_algorithm,
            request->publickey_blob,
            timeout_ms);
    }

    status = ssh_userauth_failure_methods(session->server, failure_methods, sizeof(failure_methods));
    if (status != SSH_OK) {
        return status;
    }

    return ssh_transport_send_userauth_failure(
        session,
        conn,
        failure_methods,
        0,
        timeout_ms);
}

int ssh_transport_receive_channel_open(
    ssh_transport_session_t *session,
    void *conn,
    ssh_channel_open_t *open,
    uint32_t timeout_ms)
{
    size_t payload_len;
    ssh_buffer_t buf;
    int status;

    if (session == NULL || open == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = receive_protected_payload_skip_ignorable(
        session,
        conn,
        session->channel_open_payload,
        sizeof(session->channel_open_payload),
        &payload_len,
        timeout_ms);
    if (status != SSH_OK) {
        return status;
    }
    session->channel_open_payload_len = payload_len;

    ssh_buffer_wrap(&buf, session->channel_open_payload, payload_len);
    status = ssh_channel_open_decode(&buf, open);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_CHANNEL_OPEN_RECEIVED;
    return SSH_OK;
}

int ssh_transport_send_global_request_failure(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t timeout_ms)
{
    uint8_t payload[8];
    ssh_buffer_t buf;
    int status;

    if (session == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, payload, sizeof(payload));
    status = ssh_global_request_failure_encode(&buf);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_transport_send_protected_payload(session, conn, payload, ssh_buffer_len(&buf), timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_REQUEST_FAILURE_SENT;
    return SSH_OK;
}

int ssh_transport_receive_channel_open_skip_global_requests(
    ssh_transport_session_t *session,
    void *conn,
    ssh_channel_open_t *open,
    uint32_t timeout_ms)
{
    size_t payload_len;
    ssh_buffer_t buf;
    unsigned skipped_global_requests;
    int status;

    if (session == NULL || open == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    for (skipped_global_requests = 0u; skipped_global_requests < 8u; ++skipped_global_requests) {
        status = receive_protected_payload_skip_ignorable(
            session,
            conn,
            session->channel_open_payload,
            sizeof(session->channel_open_payload),
            &payload_len,
            timeout_ms);
        if (status != SSH_OK) {
            return status;
        }
        session->channel_open_payload_len = payload_len;
        if (payload_len == 0u) {
            return SSH_ERR_MALFORMED_PACKET;
        }

        ssh_buffer_wrap(&buf, session->channel_open_payload, payload_len);
        if (session->channel_open_payload[0] == SSH_MSG_CHANNEL_OPEN) {
            status = ssh_channel_open_decode(&buf, open);
            if (status != SSH_OK) {
                return status;
            }
            session->state = SSH_TRANSPORT_STATE_CHANNEL_OPEN_RECEIVED;
            return SSH_OK;
        }

        if (session->channel_open_payload[0] == SSH_MSG_GLOBAL_REQUEST) {
            ssh_global_request_t request;

            status = ssh_global_request_decode(&buf, &request);
            if (status != SSH_OK) {
                return status;
            }
            session->state = SSH_TRANSPORT_STATE_GLOBAL_REQUEST_RECEIVED;
            if (request.want_reply) {
                status = ssh_transport_send_global_request_failure(session, conn, timeout_ms);
                if (status != SSH_OK) {
                    return status;
                }
            }
            continue;
        }

        return SSH_ERR_MALFORMED_PACKET;
    }

    return SSH_ERR_UNSUPPORTED;
}

int ssh_transport_send_channel_open_confirmation(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint32_t sender_channel,
    uint32_t initial_window_size,
    uint32_t maximum_packet_size,
    uint32_t timeout_ms)
{
    uint8_t payload[64];
    ssh_buffer_t buf;
    int status;

    if (session == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, payload, sizeof(payload));
    status = ssh_channel_open_confirmation_encode(
        &buf,
        recipient_channel,
        sender_channel,
        initial_window_size,
        maximum_packet_size);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_transport_send_protected_payload(session, conn, payload, ssh_buffer_len(&buf), timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_CHANNEL_OPEN_CONFIRMATION_SENT;
    return SSH_OK;
}

int ssh_transport_send_channel_open_failure(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint32_t reason_code,
    const char *description,
    uint32_t timeout_ms)
{
    uint8_t payload[256];
    ssh_buffer_t buf;
    int status;

    if (session == NULL || description == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, payload, sizeof(payload));
    status = ssh_channel_open_failure_encode(&buf, recipient_channel, reason_code, description, "");
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_transport_send_protected_payload(session, conn, payload, ssh_buffer_len(&buf), timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_CHANNEL_OPEN_FAILURE_SENT;
    return SSH_OK;
}

int ssh_transport_receive_channel_request(
    ssh_transport_session_t *session,
    void *conn,
    ssh_channel_request_t *request,
    uint32_t timeout_ms)
{
    size_t payload_len;
    ssh_buffer_t buf;
    int status;

    if (session == NULL || request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = receive_protected_payload_skip_ignorable(
        session,
        conn,
        session->channel_request_payload,
        sizeof(session->channel_request_payload),
        &payload_len,
        timeout_ms);
    if (status != SSH_OK) {
        return status;
    }
    session->channel_request_payload_len = payload_len;

    ssh_buffer_wrap(&buf, session->channel_request_payload, payload_len);
    status = ssh_channel_request_decode(&buf, request);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_CHANNEL_REQUEST_RECEIVED;
    return SSH_OK;
}

int ssh_transport_send_channel_success(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint32_t timeout_ms)
{
    uint8_t payload[16];
    ssh_buffer_t buf;
    int status;

    if (session == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, payload, sizeof(payload));
    status = ssh_channel_success_encode(&buf, recipient_channel);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_transport_send_protected_payload(session, conn, payload, ssh_buffer_len(&buf), timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_CHANNEL_SUCCESS_SENT;
    return SSH_OK;
}

int ssh_transport_send_channel_failure(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint32_t timeout_ms)
{
    uint8_t payload[16];
    ssh_buffer_t buf;
    int status;

    if (session == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, payload, sizeof(payload));
    status = ssh_channel_failure_encode(&buf, recipient_channel);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_transport_send_protected_payload(session, conn, payload, ssh_buffer_len(&buf), timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_CHANNEL_FAILURE_SENT;
    return SSH_OK;
}

int ssh_transport_receive_channel_data(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t *recipient_channel,
    uint8_t *data_out,
    size_t data_capacity,
    size_t *data_len,
    uint32_t timeout_ms)
{
    uint8_t payload[EMSSH_MAX_PAYLOAD_SIZE + 16u];
    size_t payload_len;
    ssh_buffer_t buf;
    ssh_channel_data_t channel_data;
    int status;

    if (session == NULL || recipient_channel == NULL || data_out == NULL || data_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = receive_protected_payload_skip_ignorable(session, conn, payload, sizeof(payload), &payload_len, timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    ssh_buffer_wrap(&buf, payload, payload_len);
    status = ssh_channel_data_decode(&buf, &channel_data);
    if (status != SSH_OK) {
        return status;
    }
    if (channel_data.data.len > data_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    *recipient_channel = channel_data.recipient_channel;
    memcpy(data_out, channel_data.data.data, channel_data.data.len);
    *data_len = channel_data.data.len;
    session->state = SSH_TRANSPORT_STATE_CHANNEL_DATA_RECEIVED;
    return SSH_OK;
}

int ssh_transport_receive_channel_message(
    ssh_transport_session_t *session,
    void *conn,
    ssh_channel_message_t *message,
    uint8_t *data_out,
    size_t data_capacity,
    size_t *data_len,
    uint32_t timeout_ms)
{
    size_t payload_len;
    ssh_buffer_t buf;
    int status;

    if (session == NULL || message == NULL || data_len == NULL ||
        (data_out == NULL && data_capacity != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *data_len = 0u;
    status = receive_protected_payload_skip_ignorable(
        session,
        conn,
        session->channel_message_payload,
        sizeof(session->channel_message_payload),
        &payload_len,
        timeout_ms);
    if (status != SSH_OK) {
        return status;
    }
    session->channel_message_payload_len = payload_len;

    ssh_buffer_wrap(&buf, session->channel_message_payload, payload_len);
    status = ssh_channel_message_decode(&buf, message);
    if (status != SSH_OK) {
        return status;
    }

    if (message->message_id == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
        session->state = SSH_TRANSPORT_STATE_CHANNEL_WINDOW_ADJUST_RECEIVED;
    } else if (message->message_id == SSH_MSG_CHANNEL_REQUEST) {
        session->state = SSH_TRANSPORT_STATE_CHANNEL_REQUEST_RECEIVED;
    } else if (message->message_id == SSH_MSG_CHANNEL_DATA) {
        if (message->data.len > data_capacity) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        if (message->data.len != 0u) {
            memcpy(data_out, message->data.data, message->data.len);
        }
        *data_len = message->data.len;
        session->state = SSH_TRANSPORT_STATE_CHANNEL_DATA_RECEIVED;
    } else if (message->message_id == SSH_MSG_CHANNEL_EOF) {
        session->state = SSH_TRANSPORT_STATE_CHANNEL_EOF_RECEIVED;
    } else if (message->message_id == SSH_MSG_CHANNEL_CLOSE) {
        session->state = SSH_TRANSPORT_STATE_CHANNEL_CLOSE_RECEIVED;
    }

    return SSH_OK;
}

int ssh_transport_send_channel_data(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    const uint8_t *data,
    size_t data_len,
    uint32_t timeout_ms)
{
    uint8_t payload[EMSSH_MAX_PAYLOAD_SIZE + 16u];
    ssh_buffer_t buf;
    int status;

    if (session == NULL || (data == NULL && data_len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, payload, sizeof(payload));
    status = ssh_channel_data_encode(&buf, recipient_channel, data, data_len);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_transport_send_protected_payload(session, conn, payload, ssh_buffer_len(&buf), timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_CHANNEL_DATA_SENT;
    return SSH_OK;
}

int ssh_transport_send_channel_window_adjust(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint32_t bytes_to_add,
    uint32_t timeout_ms)
{
    uint8_t payload[16];
    ssh_buffer_t buf;
    int status;

    if (session == NULL || bytes_to_add == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, payload, sizeof(payload));
    status = ssh_channel_window_adjust_encode(&buf, recipient_channel, bytes_to_add);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_transport_send_protected_payload(session, conn, payload, ssh_buffer_len(&buf), timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    session->state = SSH_TRANSPORT_STATE_CHANNEL_WINDOW_ADJUST_SENT;
    return SSH_OK;
}

static int send_channel_simple(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint8_t message_id,
    uint32_t timeout_ms)
{
    uint8_t payload[16];
    ssh_buffer_t buf;
    int status;

    if (session == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, payload, sizeof(payload));
    if (message_id == SSH_MSG_CHANNEL_EOF) {
        status = ssh_channel_eof_encode(&buf, recipient_channel);
    } else if (message_id == SSH_MSG_CHANNEL_CLOSE) {
        status = ssh_channel_close_encode(&buf, recipient_channel);
    } else {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_transport_send_protected_payload(session, conn, payload, ssh_buffer_len(&buf), timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    session->state = message_id == SSH_MSG_CHANNEL_EOF ?
        SSH_TRANSPORT_STATE_CHANNEL_EOF_SENT :
        SSH_TRANSPORT_STATE_CHANNEL_CLOSE_SENT;
    return SSH_OK;
}

int ssh_transport_send_channel_eof(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint32_t timeout_ms)
{
    return send_channel_simple(session, conn, recipient_channel, SSH_MSG_CHANNEL_EOF, timeout_ms);
}

int ssh_transport_send_channel_close(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint32_t timeout_ms)
{
    return send_channel_simple(session, conn, recipient_channel, SSH_MSG_CHANNEL_CLOSE, timeout_ms);
}

int ssh_transport_send_channel_exit_status(
    ssh_transport_session_t *session,
    void *conn,
    uint32_t recipient_channel,
    uint32_t exit_status,
    uint32_t timeout_ms)
{
    uint8_t payload[32];
    ssh_buffer_t buf;
    int status;

    if (session == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, payload, sizeof(payload));
    status = ssh_channel_request_exit_status_encode(&buf, recipient_channel, 0, exit_status);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_transport_send_protected_payload(session, conn, payload, ssh_buffer_len(&buf), timeout_ms);
    if (status != SSH_OK) {
        return status;
    }

    return SSH_OK;
}
