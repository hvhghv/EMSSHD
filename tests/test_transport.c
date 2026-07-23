#include <stdio.h>
#include <string.h>

#include "emssh/ssh_buffer.h"
#include "emssh/ssh_config.h"
#include "emssh/ssh_error.h"
#include "emssh/ssh_connection.h"
#include "emssh/ssh_kex.h"
#include "emssh/ssh_packet.h"
#include "emssh/ssh_server.h"
#include "emssh/ssh_transport.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static int view_eq(ssh_string_view_t view, const char *text)
{
    size_t len = strlen(text);
    return view.len == len && memcmp(view.data, text, len) == 0;
}

static ssh_string_view_t sv(const char *text)
{
    ssh_string_view_t view;
    view.data = (const uint8_t *)text;
    view.len = text != NULL ? strlen(text) : 0u;
    return view;
}

typedef struct memory_conn {
    const uint8_t *in;
    size_t in_len;
    size_t in_pos;
    uint8_t out[EMSSH_MAX_PACKET_SIZE * 4u];
    size_t out_len;
} memory_conn_t;

static int memory_read(void *ctx, void *conn, uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    memory_conn_t *memory = (memory_conn_t *)conn;
    size_t available;
    size_t chunk;

    (void)ctx;
    (void)timeout_ms;

    if (memory == NULL || buf == NULL || len == 0u) {
        return -1;
    }

    if (memory->in_pos >= memory->in_len) {
        return 0;
    }

    available = memory->in_len - memory->in_pos;
    chunk = len < available ? len : available;
    if (chunk > 3u) {
        chunk = 3u;
    }

    memcpy(buf, memory->in + memory->in_pos, chunk);
    memory->in_pos += chunk;
    return (int)chunk;
}

static int memory_write(void *ctx, void *conn, const uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    memory_conn_t *memory = (memory_conn_t *)conn;
    size_t chunk;

    (void)ctx;
    (void)timeout_ms;

    if (memory == NULL || (buf == NULL && len != 0u)) {
        return -1;
    }

    if (memory->out_len >= sizeof(memory->out)) {
        return 0;
    }

    chunk = sizeof(memory->out) - memory->out_len;
    if (chunk > len) {
        chunk = len;
    }
    if (chunk > 5u) {
        chunk = 5u;
    }

    memcpy(memory->out + memory->out_len, buf, chunk);
    memory->out_len += chunk;
    return (int)chunk;
}

static int memory_close(void *ctx, void *conn)
{
    (void)ctx;
    (void)conn;
    return SSH_OK;
}

static int deterministic_rng(void *ctx, uint8_t *buf, size_t len)
{
    size_t i;

    (void)ctx;

    for (i = 0u; i < len; ++i) {
        buf[i] = (uint8_t)(0x33u + i);
    }

    return SSH_OK;
}

static int test_password_auth(void *ctx, const ssh_password_auth_request_t *request)
{
    (void)ctx;

    return request != NULL &&
           request->username_len == strlen("alice") &&
           memcmp(request->username, "alice", request->username_len) == 0 &&
           request->password_len == strlen("secret") &&
           memcmp(request->password, "secret", request->password_len) == 0;
}

static int test_publickey_auth(void *ctx, const ssh_publickey_auth_request_t *request)
{
    (void)ctx;

    return request != NULL &&
           request->username_len == strlen("alice") &&
           memcmp(request->username, "alice", request->username_len) == 0 &&
           request->algorithm_len == strlen("ssh-ed25519") &&
           memcmp(request->algorithm, "ssh-ed25519", request->algorithm_len) == 0 &&
           request->publickey_blob_len == strlen("dummy-key") &&
           memcmp(request->publickey_blob, "dummy-key", request->publickey_blob_len) == 0;
}

static int copy_literal(uint8_t *out, size_t out_capacity, size_t *out_len, const char *value)
{
    size_t len;

    if (out == NULL || out_len == NULL || value == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    len = strlen(value);
    if (len > out_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(out, value, len);
    *out_len = len;
    return SSH_OK;
}

static void write_u32_be(uint8_t data[4], uint32_t value)
{
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

static int fake_kex_generate_keypair(
    void *ctx,
    ssh_string_view_t kex_algorithm,
    uint8_t *public_key,
    size_t public_key_capacity,
    size_t *public_key_len,
    uint8_t *private_key,
    size_t private_key_capacity,
    size_t *private_key_len)
{
    (void)ctx;
    CHECK(view_eq(kex_algorithm, "curve25519-sha256"));
    CHECK(copy_literal(public_key, public_key_capacity, public_key_len, "server-ephemeral") == SSH_OK);
    CHECK(copy_literal(private_key, private_key_capacity, private_key_len, "server-private") == SSH_OK);
    return SSH_OK;
}

static int fake_kex_compute_shared_secret(
    void *ctx,
    ssh_string_view_t kex_algorithm,
    const uint8_t *private_key,
    size_t private_key_len,
    const uint8_t *peer_public_key,
    size_t peer_public_key_len,
    uint8_t *shared_secret,
    size_t shared_secret_capacity,
    size_t *shared_secret_len)
{
    (void)ctx;
    CHECK(view_eq(kex_algorithm, "curve25519-sha256"));
    CHECK(private_key_len == strlen("server-private"));
    CHECK(memcmp(private_key, "server-private", private_key_len) == 0);
    CHECK(peer_public_key_len == strlen("client-ephemeral"));
    CHECK(memcmp(peer_public_key, "client-ephemeral", peer_public_key_len) == 0);
    CHECK(copy_literal(shared_secret, shared_secret_capacity, shared_secret_len, "shared-secret") == SSH_OK);
    return SSH_OK;
}

static int fake_hostkey_public(
    void *ctx,
    ssh_string_view_t hostkey_algorithm,
    uint8_t *hostkey_blob,
    size_t hostkey_blob_capacity,
    size_t *hostkey_blob_len)
{
    (void)ctx;
    CHECK(view_eq(hostkey_algorithm, "ssh-ed25519"));
    CHECK(copy_literal(hostkey_blob, hostkey_blob_capacity, hostkey_blob_len, "host-key") == SSH_OK);
    return SSH_OK;
}

static int fake_hash_exchange(
    void *ctx,
    ssh_string_view_t kex_algorithm,
    const uint8_t *data,
    size_t data_len,
    uint8_t *hash,
    size_t hash_capacity,
    size_t *hash_len)
{
    size_t i;

    (void)ctx;
    CHECK(view_eq(kex_algorithm, "curve25519-sha256"));
    CHECK(data != NULL);
    CHECK(data_len > 0u);
    CHECK(hash_capacity >= 32u);

    for (i = 0u; i < 32u; ++i) {
        hash[i] = (uint8_t)(0x80u + i);
    }
    *hash_len = 32u;
    return SSH_OK;
}

static int fake_hostkey_sign(
    void *ctx,
    ssh_string_view_t hostkey_algorithm,
    const uint8_t *exchange_hash,
    size_t exchange_hash_len,
    uint8_t *signature,
    size_t signature_capacity,
    size_t *signature_len)
{
    (void)ctx;
    CHECK(view_eq(hostkey_algorithm, "ssh-ed25519"));
    CHECK(exchange_hash != NULL);
    CHECK(exchange_hash_len == 32u);
    CHECK(copy_literal(signature, signature_capacity, signature_len, "signature") == SSH_OK);
    return SSH_OK;
}

static int fake_publickey_verify(
    void *ctx,
    ssh_string_view_t publickey_algorithm,
    const uint8_t *publickey_blob,
    size_t publickey_blob_len,
    const uint8_t *signed_data,
    size_t signed_data_len,
    const uint8_t *signature,
    size_t signature_len)
{
    (void)ctx;
    CHECK(view_eq(publickey_algorithm, "ssh-ed25519"));
    CHECK(publickey_blob != NULL);
    CHECK(publickey_blob_len == strlen("dummy-key"));
    CHECK(memcmp(publickey_blob, "dummy-key", publickey_blob_len) == 0);
    CHECK(signed_data != NULL);
    CHECK(signed_data_len > 0u);
    CHECK(signature != NULL);
    CHECK(signature_len == strlen("fake-signature"));
    CHECK(memcmp(signature, "fake-signature", signature_len) == 0);
    return SSH_OK;
}

static int fake_publickey_verify_unsupported(
    void *ctx,
    ssh_string_view_t publickey_algorithm,
    const uint8_t *publickey_blob,
    size_t publickey_blob_len,
    const uint8_t *signed_data,
    size_t signed_data_len,
    const uint8_t *signature,
    size_t signature_len)
{
    (void)ctx;
    (void)publickey_algorithm;
    (void)publickey_blob;
    (void)publickey_blob_len;
    (void)signed_data;
    (void)signed_data_len;
    (void)signature;
    (void)signature_len;
    return SSH_ERR_UNSUPPORTED;
}

static int fake_derive_key(
    void *ctx,
    ssh_string_view_t hash_algorithm,
    const uint8_t *shared_secret,
    size_t shared_secret_len,
    const uint8_t *exchange_hash,
    size_t exchange_hash_len,
    const uint8_t *session_id,
    size_t session_id_len,
    char key_id,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    size_t i;

    (void)ctx;
    CHECK(view_eq(hash_algorithm, "curve25519-sha256"));
    CHECK(shared_secret != NULL);
    CHECK(shared_secret_len == strlen("shared-secret"));
    CHECK(exchange_hash != NULL);
    CHECK(exchange_hash_len == 32u);
    CHECK(session_id != NULL);
    CHECK(session_id_len == 32u);
    CHECK(out != NULL);
    CHECK(out_len != NULL);

    for (i = 0u; i < out_capacity; ++i) {
        out[i] = (uint8_t)((uint8_t)key_id + (uint8_t)i);
    }
    *out_len = out_capacity;
    return SSH_OK;
}

static int fake_cipher_crypt(
    void *ctx,
    ssh_string_view_t cipher_algorithm,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *iv,
    size_t iv_len,
    uint32_t sequence,
    ssh_cipher_direction_t direction,
    uint8_t *data,
    size_t data_len)
{
    size_t i;

    (void)ctx;
    (void)iv;
    (void)iv_len;
    (void)direction;
    CHECK(view_eq(cipher_algorithm, "aes128-ctr"));
    CHECK(key != NULL);
    CHECK(key_len == 16u);
    CHECK(data != NULL || data_len == 0u);

    for (i = 0u; i < data_len; ++i) {
        data[i] ^= (uint8_t)(key[i % key_len] ^ (uint8_t)sequence);
    }
    return SSH_OK;
}

static int fake_mac_compute(
    void *ctx,
    ssh_string_view_t mac_algorithm,
    const uint8_t *key,
    size_t key_len,
    uint32_t sequence,
    const uint8_t *data,
    size_t data_len,
    uint8_t *mac,
    size_t mac_capacity,
    size_t *mac_len)
{
    size_t i;
    uint8_t acc;

    (void)ctx;
    CHECK(view_eq(mac_algorithm, "hmac-sha2-256"));
    CHECK(key != NULL);
    CHECK(key_len == 32u);
    CHECK(data != NULL || data_len == 0u);
    CHECK(mac != NULL);
    CHECK(mac_capacity >= 32u);
    CHECK(mac_len != NULL);

    acc = (uint8_t)sequence;
    for (i = 0u; i < data_len; ++i) {
        acc = (uint8_t)(acc + data[i] + (uint8_t)i);
    }

    for (i = 0u; i < 32u; ++i) {
        mac[i] = (uint8_t)(acc ^ key[i % key_len] ^ (uint8_t)i);
    }
    *mac_len = 32u;
    return SSH_OK;
}

static void fake_secure_zero(void *ctx, void *ptr, size_t len)
{
    (void)ctx;
    if (ptr != NULL) {
        memset(ptr, 0, len);
    }
}

static int build_client_kexinit_payload(uint8_t *out, size_t out_capacity, size_t *out_len)
{
    uint8_t cookie[SSH_KEX_COOKIE_LEN];
    ssh_kexinit_algorithm_set_t algorithms;
    ssh_buffer_t payload;
    size_t i;

    if (out == NULL || out_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    for (i = 0u; i < sizeof(cookie); ++i) {
        cookie[i] = (uint8_t)i;
    }

    ssh_kexinit_algorithm_set_defaults(&algorithms);
    algorithms.kex_algorithms = "curve25519-sha256,ecdh-sha2-nistp256";
    algorithms.server_host_key_algorithms = "ssh-ed25519,ecdsa-sha2-nistp256";

    ssh_buffer_init(&payload, out, out_capacity);
    CHECK(ssh_kexinit_encode(&payload, cookie, &algorithms, 0) == SSH_OK);
    *out_len = ssh_buffer_len(&payload);
    return SSH_OK;
}

static int append_protected_packet(
    ssh_packet_protection_t *protection,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    const uint8_t *payload,
    size_t payload_len,
    const ssh_rng_api_t *rng)
{
    uint8_t packet[EMSSH_MAX_PACKET_SIZE + 4u + EMSSH_MAX_MAC];
    size_t packet_len;
    int status;

    if (protection == NULL || out == NULL || out_len == NULL ||
        (payload == NULL && payload_len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_packet_encode_protected(
        protection,
        packet,
        sizeof(packet),
        &packet_len,
        payload,
        payload_len,
        rng);
    if (status != SSH_OK) {
        return status;
    }
    if (*out_len > out_capacity || packet_len > out_capacity - *out_len) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(out + *out_len, packet, packet_len);
    *out_len += packet_len;
    return SSH_OK;
}

static int build_client_input(uint8_t *out, size_t out_capacity, size_t *out_len)
{
    static const uint8_t client_ident[] = "SSH-2.0-test_client\r\n";
    uint8_t payload_storage[EMSSH_MAX_KEXINIT_PAYLOAD];
    uint8_t packet_storage[EMSSH_MAX_KEXINIT_PAYLOAD + 64u];
    uint8_t ecdh_payload_storage[128];
    uint8_t ecdh_packet_storage[192];
    uint8_t newkeys_payload_storage[8];
    uint8_t newkeys_packet_storage[32];
    ssh_buffer_t ecdh_payload;
    ssh_buffer_t newkeys_payload;
    ssh_rng_api_t rng;
    size_t payload_len;
    size_t packet_len;
    size_t ecdh_packet_len;
    size_t newkeys_packet_len;
    int status;

    if (out == NULL || out_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = build_client_kexinit_payload(payload_storage, sizeof(payload_storage), &payload_len);
    if (status != SSH_OK) {
        return status;
    }

    rng.fill = deterministic_rng;
    rng.ctx = NULL;
    status = ssh_packet_encode_plain(
        packet_storage,
        sizeof(packet_storage),
        &packet_len,
        payload_storage,
        payload_len,
        SSH_PACKET_MIN_BLOCK_SIZE,
        &rng);
    if (status != SSH_OK) {
        return status;
    }

    ssh_buffer_init(&ecdh_payload, ecdh_payload_storage, sizeof(ecdh_payload_storage));
    status = ssh_kex_ecdh_init_encode(
        &ecdh_payload,
        (const uint8_t *)"client-ephemeral",
        strlen("client-ephemeral"));
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_packet_encode_plain(
        ecdh_packet_storage,
        sizeof(ecdh_packet_storage),
        &ecdh_packet_len,
        ecdh_payload_storage,
        ssh_buffer_len(&ecdh_payload),
        SSH_PACKET_MIN_BLOCK_SIZE,
        &rng);
    if (status != SSH_OK) {
        return status;
    }

    ssh_buffer_init(&newkeys_payload, newkeys_payload_storage, sizeof(newkeys_payload_storage));
    status = ssh_kex_newkeys_encode(&newkeys_payload);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_packet_encode_plain(
        newkeys_packet_storage,
        sizeof(newkeys_packet_storage),
        &newkeys_packet_len,
        newkeys_payload_storage,
        ssh_buffer_len(&newkeys_payload),
        SSH_PACKET_MIN_BLOCK_SIZE,
        &rng);
    if (status != SSH_OK) {
        return status;
    }

    if (sizeof(client_ident) - 1u + packet_len + ecdh_packet_len + newkeys_packet_len > out_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(out, client_ident, sizeof(client_ident) - 1u);
    memcpy(out + sizeof(client_ident) - 1u, packet_storage, packet_len);
    memcpy(out + sizeof(client_ident) - 1u + packet_len, ecdh_packet_storage, ecdh_packet_len);
    memcpy(out + sizeof(client_ident) - 1u + packet_len + ecdh_packet_len, newkeys_packet_storage, newkeys_packet_len);
    *out_len = sizeof(client_ident) - 1u + packet_len + ecdh_packet_len + newkeys_packet_len;
    return SSH_OK;
}

int main(void)
{
    static const uint8_t line[] = "SSH-2.0-OpenSSH_9.7 test client\r\n";
    static const uint8_t old_compatible[] = "SSH-1.99-device\r\n";
    static const uint8_t invalid[] = "HTTP/1.1 200 OK\r\n";
    ssh_identification_t ident;
    uint8_t client_input[4096];
    size_t client_input_len;
    memory_conn_t conn;
    ssh_net_api_t net;
    ssh_rng_api_t rng;
    ssh_crypto_api_t crypto;
    ssh_platform_t platform;
    ssh_server_config_t config;
    ssh_server_t server;
    ssh_transport_session_t session;
    size_t reply_offset;
    uint8_t protected_payload[16];
    size_t protected_payload_len;
    uint8_t channel_request_payload[128];
    size_t channel_request_payload_len;
    uint8_t channel_request_packet[256];
    size_t channel_request_packet_len;
    uint8_t channel_message_data[64];
    size_t channel_message_data_len;
    ssh_channel_message_t channel_message;
    uint8_t malformed_first_block[EMSSH_MAX_CIPHER_IV];
    size_t malformed_block_size;
    uint32_t inbound_sequence_before;
    uint32_t outbound_sequence_before;
    static uint8_t large_channel_data[EMSSH_MAX_PAYLOAD_SIZE];
    ssh_packet_view_t reply_packet;
    ssh_buffer_t reply_payload;
    ssh_kex_ecdh_reply_t reply;
    ssh_userauth_request_t auth_request;
    size_t out_len_before;

    CHECK(ssh_identification_parse_line(line, sizeof(line) - 1u, &ident) == SSH_OK);
    CHECK(view_eq(ident.protocol_version, "2.0"));
    CHECK(view_eq(ident.software_version, "OpenSSH_9.7"));
    CHECK(view_eq(ident.comments, "test client"));
    CHECK(ssh_identification_is_ssh2_compatible(&ident));

    CHECK(ssh_identification_parse_line(old_compatible, sizeof(old_compatible) - 1u, &ident) == SSH_OK);
    CHECK(ssh_identification_is_ssh2_compatible(&ident));

    CHECK(ssh_identification_parse_line(invalid, sizeof(invalid) - 1u, &ident) == SSH_ERR_MALFORMED_PACKET);

    CHECK(build_client_input(client_input, sizeof(client_input), &client_input_len) == SSH_OK);

    memset(&conn, 0, sizeof(conn));
    conn.in = client_input;
    conn.in_len = client_input_len;

    net.read = memory_read;
    net.write = memory_write;
    net.close = memory_close;
    net.ctx = NULL;

    rng.fill = deterministic_rng;
    rng.ctx = NULL;

    memset(&crypto, 0, sizeof(crypto));
    crypto.name = "fake-crypto";
    crypto.kex_generate_keypair = fake_kex_generate_keypair;
    crypto.kex_compute_shared_secret = fake_kex_compute_shared_secret;
    crypto.hostkey_public = fake_hostkey_public;
    crypto.hash_exchange = fake_hash_exchange;
    crypto.hostkey_sign = fake_hostkey_sign;
    crypto.publickey_verify = fake_publickey_verify;
    crypto.derive_key = fake_derive_key;
    crypto.cipher_crypt = fake_cipher_crypt;
    crypto.mac_compute = fake_mac_compute;
    crypto.secure_zero = fake_secure_zero;
    crypto.ctx = NULL;

    memset(&platform, 0, sizeof(platform));
    platform.net = &net;
    platform.rng = &rng;
    platform.crypto = &crypto;

    ssh_server_config_defaults(&config);
    config.password_auth = test_password_auth;
    config.publickey_auth = test_publickey_auth;
    config.publickey_signature_algorithms = "ssh-ed25519";
    CHECK(ssh_server_init(&server, &platform, &config) == SSH_OK);
    CHECK(ssh_transport_session_init(&session, &server, NULL) == SSH_OK);

    CHECK(ssh_transport_send_identification(&session, &conn, 1000u) == SSH_OK);
    CHECK(session.state == SSH_TRANSPORT_STATE_IDENT_SENT);
    CHECK(conn.out_len >= strlen("SSH-2.0-emsshd_0.1\r\n"));
    CHECK(memcmp(conn.out, "SSH-2.0-emsshd_0.1\r\n", strlen("SSH-2.0-emsshd_0.1\r\n")) == 0);

    CHECK(ssh_transport_receive_identification(&session, &conn, 1000u) == SSH_OK);
    CHECK(session.state == SSH_TRANSPORT_STATE_IDENT_RECEIVED);
    CHECK(view_eq(session.client_identification.software_version, "test_client"));

    CHECK(ssh_transport_send_kexinit(&session, &conn, 1000u) == SSH_OK);
    CHECK(session.state == SSH_TRANSPORT_STATE_KEXINIT_SENT);
    CHECK(session.server_kexinit_payload_len != 0u);

    CHECK(ssh_transport_receive_kexinit(&session, &conn, 1000u) == SSH_OK);
    CHECK(session.state == SSH_TRANSPORT_STATE_NEGOTIATED);
    CHECK(view_eq(session.negotiation.kex_algorithm, "curve25519-sha256"));
    CHECK(view_eq(session.negotiation.server_host_key_algorithm, "ssh-ed25519"));

    CHECK(ssh_transport_receive_kex_ecdh_init(&session, &conn, 1000u) == SSH_OK);
    CHECK(session.state == SSH_TRANSPORT_STATE_KEX_ECDH_INIT_RECEIVED);
    CHECK(session.client_kex_public_key_len == strlen("client-ephemeral"));
    CHECK(memcmp(session.client_kex_public_key, "client-ephemeral", session.client_kex_public_key_len) == 0);

    reply_offset = conn.out_len;
    CHECK(ssh_transport_send_kex_ecdh_reply(&session, &conn, 1000u) == SSH_OK);
    CHECK(session.state == SSH_TRANSPORT_STATE_KEX_ECDH_REPLY_SENT);
    CHECK(view_eq((ssh_string_view_t){ session.server_host_key, session.server_host_key_len }, "host-key"));
    CHECK(view_eq((ssh_string_view_t){ session.server_kex_public_key, session.server_kex_public_key_len }, "server-ephemeral"));
    CHECK(view_eq((ssh_string_view_t){ session.shared_secret, session.shared_secret_len }, "shared-secret"));
    CHECK(view_eq((ssh_string_view_t){ session.server_signature, session.server_signature_len }, "signature"));

    CHECK(ssh_packet_decode_plain(conn.out + reply_offset, conn.out_len - reply_offset, &reply_packet) == SSH_OK);
    ssh_buffer_wrap(&reply_payload, (uint8_t *)reply_packet.payload, reply_packet.payload_len);
    CHECK(ssh_kex_ecdh_reply_decode(&reply_payload, &reply) == SSH_OK);
    CHECK(view_eq(reply.server_host_key, "host-key"));
    CHECK(view_eq(reply.server_public_key, "server-ephemeral"));
    CHECK(view_eq(reply.signature, "signature"));

    CHECK(ssh_transport_send_newkeys(&session, &conn, 1000u) == SSH_OK);
    CHECK(session.state == SSH_TRANSPORT_STATE_NEWKEYS_SENT);
    CHECK(session.outbound.active);
    CHECK(session.outbound.sequence == 3u);
    CHECK(session.outbound.cipher_key_len == 16u);
    CHECK(session.outbound.mac_key_len == 32u);

    CHECK(ssh_transport_receive_newkeys(&session, &conn, 1000u) == SSH_OK);
    CHECK(session.state == SSH_TRANSPORT_STATE_NEWKEYS_RECEIVED);
    CHECK(session.inbound.active);
    CHECK(session.inbound.sequence == 3u);
    CHECK(session.inbound.cipher_key_len == 16u);
    CHECK(session.inbound.mac_key_len == 32u);

    memset(large_channel_data, 0x5au, sizeof(large_channel_data));
    outbound_sequence_before = session.outbound.sequence;
    CHECK(ssh_transport_send_channel_data(
        &session,
        &conn,
        7u,
        large_channel_data,
        sizeof(large_channel_data),
        1000u) == SSH_OK);
    CHECK(session.outbound.sequence == outbound_sequence_before + 2u);

    CHECK(ssh_transport_set_rekey_limits(&session, 2u, 0u) == SSH_OK);
    CHECK(!ssh_transport_rekey_needed(&session));
    CHECK(ssh_transport_send_protected_payload(&session, &conn, (const uint8_t *)"x", 1u, 1000u) == SSH_OK);
    CHECK(session.outbound_rekey_packets == 1u);
    CHECK(!ssh_transport_rekey_needed(&session));
    CHECK(ssh_transport_send_protected_payload(&session, &conn, (const uint8_t *)"y", 1u, 1000u) == SSH_OK);
    CHECK(session.outbound_rekey_packets == 2u);
    CHECK(ssh_transport_rekey_needed(&session));

    CHECK(ssh_transport_set_rekey_limits(&session, 0u, 1u) == SSH_OK);
    CHECK(!ssh_transport_rekey_needed(&session));
    CHECK(ssh_transport_send_protected_payload(&session, &conn, (const uint8_t *)"z", 1u, 1000u) == SSH_OK);
    CHECK(session.outbound_rekey_bytes > 0u);
    CHECK(ssh_transport_rekey_needed(&session));

    memset(&auth_request, 0, sizeof(auth_request));
    auth_request.username = sv("alice");
    auth_request.service_name = sv(SSH_SERVICE_CONNECTION);
    auth_request.method_name = sv(SSH_AUTH_METHOD_PASSWORD);
    auth_request.password = sv("secret");
    out_len_before = conn.out_len;
    CHECK(ssh_transport_handle_userauth_request(&session, &conn, &auth_request, 1000u) == SSH_OK);
    CHECK(session.state == SSH_TRANSPORT_STATE_USERAUTH_SUCCESS_SENT);
    CHECK(conn.out_len > out_len_before);

    memset(&auth_request, 0, sizeof(auth_request));
    auth_request.username = sv("alice");
    auth_request.service_name = sv(SSH_SERVICE_CONNECTION);
    auth_request.method_name = sv(SSH_AUTH_METHOD_PUBLICKEY);
    auth_request.publickey_has_signature = 0;
    auth_request.publickey_algorithm = sv("ssh-ed25519");
    auth_request.publickey_blob = sv("dummy-key");
    out_len_before = conn.out_len;
    CHECK(ssh_transport_handle_userauth_request(&session, &conn, &auth_request, 1000u) == SSH_OK);
    CHECK(session.state == SSH_TRANSPORT_STATE_USERAUTH_PK_OK_SENT);
    CHECK(conn.out_len > out_len_before);

    memset(&auth_request, 0, sizeof(auth_request));
    auth_request.username = sv("alice");
    auth_request.service_name = sv(SSH_SERVICE_CONNECTION);
    auth_request.method_name = sv(SSH_AUTH_METHOD_PUBLICKEY);
    auth_request.publickey_has_signature = 1;
    auth_request.publickey_algorithm = sv("ssh-ed25519");
    auth_request.publickey_blob = sv("dummy-key");
    auth_request.publickey_signature = sv("fake-signature");
    out_len_before = conn.out_len;
    CHECK(ssh_transport_handle_userauth_request(&session, &conn, &auth_request, 1000u) == SSH_OK);
    CHECK(session.state == SSH_TRANSPORT_STATE_USERAUTH_SUCCESS_SENT);
    CHECK(conn.out_len > out_len_before);

    crypto.publickey_verify = fake_publickey_verify_unsupported;
    memset(&auth_request, 0, sizeof(auth_request));
    auth_request.username = sv("alice");
    auth_request.service_name = sv(SSH_SERVICE_CONNECTION);
    auth_request.method_name = sv(SSH_AUTH_METHOD_PUBLICKEY);
    auth_request.publickey_has_signature = 1;
    auth_request.publickey_algorithm = sv("ssh-ed25519");
    auth_request.publickey_blob = sv("dummy-key");
    auth_request.publickey_signature = sv("fake-signature");
    out_len_before = conn.out_len;
    {
        ssh_packet_protection_t outbound_before = session.outbound;
        uint8_t packet_copy[512];
        size_t packet_len;
        ssh_packet_view_t packet_view;
        ssh_buffer_t packet_buf;
        uint8_t message_id;
        ssh_string_view_t methods;
        int partial_success;

        CHECK(ssh_transport_handle_userauth_request(&session, &conn, &auth_request, 1000u) == SSH_OK);
        CHECK(session.state == SSH_TRANSPORT_STATE_USERAUTH_FAILURE_SENT);
        CHECK(conn.out_len > out_len_before);

        packet_len = conn.out_len - out_len_before;
        CHECK(packet_len <= sizeof(packet_copy));
        memcpy(packet_copy, conn.out + out_len_before, packet_len);
        CHECK(ssh_packet_decode_protected(&outbound_before, packet_copy, packet_len, &packet_view) == SSH_OK);

        ssh_buffer_wrap(&packet_buf, (uint8_t *)packet_view.payload, packet_view.payload_len);
        CHECK(ssh_buffer_get_u8(&packet_buf, &message_id) == SSH_OK);
        CHECK(message_id == SSH_MSG_USERAUTH_FAILURE);
        CHECK(ssh_buffer_get_string_view(&packet_buf, &methods) == SSH_OK);
        CHECK(view_eq(methods, SSH_AUTH_DEFAULT_FAILURE_METHODS));
        CHECK(ssh_buffer_get_bool(&packet_buf, &partial_success) == SSH_OK);
        CHECK(!partial_success);
        CHECK(ssh_buffer_remaining_read(&packet_buf) == 0u);
    }

    server.config.password_auth = NULL;
    {
        ssh_packet_protection_t outbound_before = session.outbound;
        uint8_t packet_copy[512];
        size_t packet_len;
        ssh_packet_view_t packet_view;
        ssh_buffer_t packet_buf;
        uint8_t message_id;
        ssh_string_view_t methods;
        int partial_success;

        out_len_before = conn.out_len;
        CHECK(ssh_transport_handle_userauth_request(&session, &conn, &auth_request, 1000u) == SSH_OK);
        CHECK(session.state == SSH_TRANSPORT_STATE_USERAUTH_FAILURE_SENT);
        CHECK(conn.out_len > out_len_before);

        packet_len = conn.out_len - out_len_before;
        CHECK(packet_len <= sizeof(packet_copy));
        memcpy(packet_copy, conn.out + out_len_before, packet_len);
        CHECK(ssh_packet_decode_protected(&outbound_before, packet_copy, packet_len, &packet_view) == SSH_OK);

        ssh_buffer_wrap(&packet_buf, (uint8_t *)packet_view.payload, packet_view.payload_len);
        CHECK(ssh_buffer_get_u8(&packet_buf, &message_id) == SSH_OK);
        CHECK(message_id == SSH_MSG_USERAUTH_FAILURE);
        CHECK(ssh_buffer_get_string_view(&packet_buf, &methods) == SSH_OK);
        CHECK(view_eq(methods, SSH_AUTH_METHOD_PUBLICKEY));
        CHECK(ssh_buffer_get_bool(&packet_buf, &partial_success) == SSH_OK);
        CHECK(!partial_success);
        CHECK(ssh_buffer_remaining_read(&packet_buf) == 0u);
    }

    {
        ssh_transport_session_t no_session_id = session;
        no_session_id.session_id_len = 0u;
        CHECK(ssh_transport_handle_userauth_request(&no_session_id, &conn, &auth_request, 1000u) == SSH_ERR_INVALID_ARGUMENT);
    }

    memset(&auth_request, 0, sizeof(auth_request));
    auth_request.username = sv("alice");
    auth_request.service_name = sv(SSH_SERVICE_CONNECTION);
    auth_request.method_name = sv(SSH_AUTH_METHOD_PASSWORD);
    auth_request.password_change_request = 1;
    auth_request.password = sv("secret");
    CHECK(ssh_transport_handle_userauth_request(&session, &conn, &auth_request, 1000u) == SSH_ERR_INVALID_ARGUMENT);

    {
        ssh_packet_protection_t inbound_for_encode = session.inbound;
        ssh_buffer_t request_buf;

        ssh_buffer_init(&request_buf, channel_request_payload, sizeof(channel_request_payload));
        CHECK(ssh_buffer_put_u8(&request_buf, SSH_MSG_CHANNEL_REQUEST) == SSH_OK);
        CHECK(ssh_buffer_put_u32(&request_buf, 0u) == SSH_OK);
        CHECK(ssh_buffer_put_cstring(&request_buf, SSH_CHANNEL_REQUEST_SIGNAL) == SSH_OK);
        CHECK(ssh_buffer_put_bool(&request_buf, 1) == SSH_OK);
        CHECK(ssh_buffer_put_cstring(&request_buf, "TERM") == SSH_OK);
        channel_request_payload_len = ssh_buffer_len(&request_buf);

        CHECK(ssh_packet_encode_protected(
            &inbound_for_encode,
            channel_request_packet,
            sizeof(channel_request_packet),
            &channel_request_packet_len,
            channel_request_payload,
            channel_request_payload_len,
            &rng) == SSH_OK);

        conn.in = channel_request_packet;
        conn.in_len = channel_request_packet_len;
        conn.in_pos = 0u;
        channel_message_data_len = 0u;
        memset(&channel_message, 0, sizeof(channel_message));
        CHECK(ssh_transport_receive_channel_message(
            &session,
            &conn,
            &channel_message,
            channel_message_data,
            sizeof(channel_message_data),
            &channel_message_data_len,
            1000u) == SSH_OK);
        CHECK(session.state == SSH_TRANSPORT_STATE_CHANNEL_REQUEST_RECEIVED);
        CHECK(channel_message.message_id == SSH_MSG_CHANNEL_REQUEST);
        CHECK(channel_message.recipient_channel == 0u);
        CHECK(channel_message_data_len == 0u);
        CHECK(view_eq(channel_message.channel_request.request_type, SSH_CHANNEL_REQUEST_SIGNAL));
        CHECK(channel_message.channel_request.want_reply);
        CHECK(view_eq(channel_message.channel_request.signal_name, "TERM"));
    }

    {
        uint8_t rekey_input[4096];
        size_t rekey_input_len;
        uint8_t rekey_kexinit_payload[EMSSH_MAX_KEXINIT_PAYLOAD];
        size_t rekey_kexinit_payload_len;
        uint8_t rekey_ecdh_payload[128];
        size_t rekey_ecdh_payload_len;
        uint8_t rekey_newkeys_payload[8];
        size_t rekey_newkeys_payload_len;
        uint8_t rekey_channel_payload[128];
        size_t rekey_channel_payload_len;
        ssh_packet_protection_t client_to_server;
        ssh_buffer_t rekey_payload;
        size_t server_out_before;
        uint32_t inbound_sequence_start;
        uint32_t outbound_sequence_start;

        CHECK(ssh_transport_set_rekey_limits(&session, 0u, 0u) == SSH_OK);

        client_to_server = session.inbound;
        inbound_sequence_start = session.inbound.sequence;
        outbound_sequence_start = session.outbound.sequence;
        rekey_input_len = 0u;

        CHECK(build_client_kexinit_payload(
            rekey_kexinit_payload,
            sizeof(rekey_kexinit_payload),
            &rekey_kexinit_payload_len) == SSH_OK);
        CHECK(append_protected_packet(
            &client_to_server,
            rekey_input,
            sizeof(rekey_input),
            &rekey_input_len,
            rekey_kexinit_payload,
            rekey_kexinit_payload_len,
            &rng) == SSH_OK);

        ssh_buffer_init(&rekey_payload, rekey_ecdh_payload, sizeof(rekey_ecdh_payload));
        CHECK(ssh_kex_ecdh_init_encode(
            &rekey_payload,
            (const uint8_t *)"client-ephemeral",
            strlen("client-ephemeral")) == SSH_OK);
        rekey_ecdh_payload_len = ssh_buffer_len(&rekey_payload);
        CHECK(append_protected_packet(
            &client_to_server,
            rekey_input,
            sizeof(rekey_input),
            &rekey_input_len,
            rekey_ecdh_payload,
            rekey_ecdh_payload_len,
            &rng) == SSH_OK);

        ssh_buffer_init(&rekey_payload, rekey_newkeys_payload, sizeof(rekey_newkeys_payload));
        CHECK(ssh_kex_newkeys_encode(&rekey_payload) == SSH_OK);
        rekey_newkeys_payload_len = ssh_buffer_len(&rekey_payload);
        CHECK(append_protected_packet(
            &client_to_server,
            rekey_input,
            sizeof(rekey_input),
            &rekey_input_len,
            rekey_newkeys_payload,
            rekey_newkeys_payload_len,
            &rng) == SSH_OK);

        {
            uint8_t rekey_cipher_key[16];
            uint8_t rekey_cipher_iv[16];
            uint8_t rekey_mac_key[32];
            size_t material_len;

            CHECK(fake_derive_key(
                NULL,
                session.negotiation.kex_algorithm,
                session.shared_secret,
                session.shared_secret_len,
                session.exchange_hash,
                session.exchange_hash_len,
                session.session_id,
                session.session_id_len,
                'A',
                rekey_cipher_iv,
                sizeof(rekey_cipher_iv),
                &material_len) == SSH_OK);
            CHECK(material_len == sizeof(rekey_cipher_iv));
            CHECK(fake_derive_key(
                NULL,
                session.negotiation.kex_algorithm,
                session.shared_secret,
                session.shared_secret_len,
                session.exchange_hash,
                session.exchange_hash_len,
                session.session_id,
                session.session_id_len,
                'C',
                rekey_cipher_key,
                sizeof(rekey_cipher_key),
                &material_len) == SSH_OK);
            CHECK(material_len == sizeof(rekey_cipher_key));
            CHECK(fake_derive_key(
                NULL,
                session.negotiation.kex_algorithm,
                session.shared_secret,
                session.shared_secret_len,
                session.exchange_hash,
                session.exchange_hash_len,
                session.session_id,
                session.session_id_len,
                'E',
                rekey_mac_key,
                sizeof(rekey_mac_key),
                &material_len) == SSH_OK);
            CHECK(material_len == sizeof(rekey_mac_key));
            CHECK(ssh_packet_protection_set(
                &client_to_server,
                &crypto,
                session.negotiation.encryption_algorithm_client_to_server,
                session.negotiation.mac_algorithm_client_to_server,
                rekey_cipher_key,
                sizeof(rekey_cipher_key),
                rekey_cipher_iv,
                sizeof(rekey_cipher_iv),
                rekey_mac_key,
                sizeof(rekey_mac_key),
                16u,
                32u) == SSH_OK);
            client_to_server.sequence = inbound_sequence_start + 3u;
        }

        ssh_buffer_init(&rekey_payload, rekey_channel_payload, sizeof(rekey_channel_payload));
        CHECK(ssh_channel_data_encode(
            &rekey_payload,
            0u,
            (const uint8_t *)"after-rekey",
            strlen("after-rekey")) == SSH_OK);
        rekey_channel_payload_len = ssh_buffer_len(&rekey_payload);
        CHECK(append_protected_packet(
            &client_to_server,
            rekey_input,
            sizeof(rekey_input),
            &rekey_input_len,
            rekey_channel_payload,
            rekey_channel_payload_len,
            &rng) == SSH_OK);

        conn.in = rekey_input;
        conn.in_len = rekey_input_len;
        conn.in_pos = 0u;
        server_out_before = conn.out_len;
        channel_message_data_len = 0u;
        memset(&channel_message, 0, sizeof(channel_message));
        CHECK(ssh_transport_receive_channel_message(
            &session,
            &conn,
            &channel_message,
            channel_message_data,
            sizeof(channel_message_data),
            &channel_message_data_len,
            1000u) == SSH_OK);
        CHECK(conn.in_pos == conn.in_len);
        CHECK(conn.out_len > server_out_before);
        CHECK(session.rekey_in_progress == 0);
        CHECK(session.inbound.active);
        CHECK(session.outbound.active);
        CHECK(session.inbound.sequence == inbound_sequence_start + 4u);
        CHECK(session.outbound.sequence == outbound_sequence_start + 3u);
        CHECK(session.state == SSH_TRANSPORT_STATE_CHANNEL_DATA_RECEIVED);
        CHECK(channel_message.message_id == SSH_MSG_CHANNEL_DATA);
        CHECK(channel_message.recipient_channel == 0u);
        CHECK(channel_message_data_len == strlen("after-rekey"));
        CHECK(memcmp(channel_message_data, "after-rekey", channel_message_data_len) == 0);
    }

    malformed_block_size = session.inbound.block_size;
    CHECK(malformed_block_size <= sizeof(malformed_first_block));
    memset(malformed_first_block, 0, malformed_block_size);
    write_u32_be(malformed_first_block, 17u);
    CHECK(session.inbound.crypto->cipher_crypt(
        session.inbound.crypto->ctx,
        session.inbound.cipher_algorithm,
        session.inbound.cipher_key,
        session.inbound.cipher_key_len,
        session.inbound.cipher_iv,
        session.inbound.cipher_iv_len,
        session.inbound.sequence,
        SSH_CIPHER_ENCRYPT,
        malformed_first_block,
        malformed_block_size) == SSH_OK);
    conn.in = malformed_first_block;
    conn.in_len = malformed_block_size;
    conn.in_pos = 0u;
    inbound_sequence_before = session.inbound.sequence;
    CHECK(ssh_transport_receive_protected_payload(
        &session,
        &conn,
        protected_payload,
        sizeof(protected_payload),
        &protected_payload_len,
        1000u) == SSH_ERR_MALFORMED_PACKET);
    CHECK(conn.in_pos == malformed_block_size);
    CHECK(session.inbound.sequence == inbound_sequence_before);
    CHECK(session.inbound_sequence == inbound_sequence_before);

    {
        ssh_transport_session_t detached = session;
        detached.server = NULL;
        CHECK(ssh_transport_handle_userauth_request(&detached, &conn, &auth_request, 1000u) == SSH_ERR_INVALID_ARGUMENT);
        CHECK(ssh_transport_send_ext_info(&detached, &conn, 1000u) == SSH_ERR_INVALID_ARGUMENT);
    }

    ssh_server_deinit(&server);

    return 0;
}
