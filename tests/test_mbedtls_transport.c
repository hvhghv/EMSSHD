#include <stdio.h>
#include <string.h>

#include "emssh/crypto_mbedtls.h"
#include "emssh/sftp.h"
#include "emssh/sftp_server.h"
#include "emssh/ssh_connection.h"
#include "emssh/ssh_crypto.h"
#include "emssh/ssh_error.h"
#include "emssh/ssh_packet.h"
#include "emssh/ssh_server.h"
#include "emssh/ssh_service.h"
#include "emssh/ssh_transport.h"
#include "emssh/ssh_userauth.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

typedef struct memory_conn {
    const uint8_t *in;
    size_t in_len;
    size_t in_pos;
    uint8_t out[8192];
    size_t out_len;
} memory_conn_t;

typedef struct mock_fs {
    char opened_path[EMSSH_SFTP_MAX_PATH];
    uint8_t data[64];
    size_t data_len;
    int close_count;
} mock_fs_t;

static ssh_string_view_t sv(const char *value)
{
    ssh_string_view_t view;
    view.data = (const uint8_t *)value;
    view.len = strlen(value);
    return view;
}

static int view_eq(ssh_string_view_t view, const char *text)
{
    size_t len = strlen(text);
    return view.len == len && memcmp(view.data, text, len) == 0;
}

static int memory_read(void *ctx, void *conn, uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    memory_conn_t *memory = (memory_conn_t *)conn;
    size_t available;
    size_t chunk;

    (void)ctx;
    (void)timeout_ms;

    if (memory == NULL || buf == NULL || len == 0u || memory->in_pos >= memory->in_len) {
        return 0;
    }

    available = memory->in_len - memory->in_pos;
    chunk = len < available ? len : available;
    if (chunk > 7u) {
        chunk = 7u;
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

    if (memory == NULL || (buf == NULL && len != 0u) || memory->out_len >= sizeof(memory->out)) {
        return 0;
    }

    chunk = sizeof(memory->out) - memory->out_len;
    if (chunk > len) {
        chunk = len;
    }
    if (chunk > 11u) {
        chunk = 11u;
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

static int mock_fs_open(void *ctx, const char *path, uint32_t flags, void **handle)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    (void)flags;

    if (fs == NULL || path == NULL || handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    strncpy(fs->opened_path, path, sizeof(fs->opened_path) - 1u);
    fs->opened_path[sizeof(fs->opened_path) - 1u] = '\0';
    *handle = fs;
    return SSH_OK;
}

static int mock_fs_close(void *ctx, void *handle)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || handle != fs) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ++fs->close_count;
    return SSH_OK;
}

static int mock_fs_read_at(void *ctx, void *handle, uint64_t offset, uint8_t *buf, size_t len, size_t *read_len)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;
    size_t available;
    size_t chunk;

    if (fs == NULL || handle != fs || buf == NULL || read_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (offset >= fs->data_len) {
        *read_len = 0u;
        return SSH_OK;
    }

    available = fs->data_len - (size_t)offset;
    chunk = len < available ? len : available;
    memcpy(buf, fs->data + (size_t)offset, chunk);
    *read_len = chunk;
    return SSH_OK;
}

static int append_plain_packet(
    const ssh_rng_api_t *rng,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    const uint8_t *payload,
    size_t payload_len)
{
    size_t packet_len;
    int status;

    status = ssh_packet_encode_plain(
        out + *out_len,
        out_capacity - *out_len,
        &packet_len,
        payload,
        payload_len,
        SSH_PACKET_MIN_BLOCK_SIZE,
        rng);
    if (status != SSH_OK) {
        return status;
    }

    *out_len += packet_len;
    return SSH_OK;
}

static int build_client_input(
    const ssh_crypto_api_t *crypto,
    const ssh_rng_api_t *rng,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    uint8_t *client_private,
    size_t client_private_capacity,
    size_t *client_private_len)
{
    static const uint8_t client_ident[] = "SSH-2.0-mbedtls_test_client\r\n";
    uint8_t cookie[SSH_KEX_COOKIE_LEN];
    uint8_t kexinit_payload[EMSSH_MAX_KEXINIT_PAYLOAD];
    uint8_t ecdh_payload[128];
    uint8_t newkeys_payload[8];
    uint8_t client_public[EMSSH_MAX_KEX_PUBLIC_KEY];
    ssh_kexinit_algorithm_set_t algorithms;
    ssh_buffer_t buf;
    size_t client_public_len;
    size_t i;
    int status;

    if (crypto == NULL || rng == NULL || out == NULL || out_len == NULL ||
        client_private == NULL || client_private_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (sizeof(client_ident) - 1u > out_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(out, client_ident, sizeof(client_ident) - 1u);
    *out_len = sizeof(client_ident) - 1u;

    for (i = 0u; i < sizeof(cookie); ++i) {
        cookie[i] = (uint8_t)(0x20u + i);
    }

    ssh_mbedtls_kexinit_algorithm_set_defaults(&algorithms);
    ssh_buffer_init(&buf, kexinit_payload, sizeof(kexinit_payload));
    status = ssh_kexinit_encode(&buf, cookie, &algorithms, 0);
    if (status != SSH_OK) {
        return status;
    }

    status = append_plain_packet(rng, out, out_capacity, out_len, kexinit_payload, ssh_buffer_len(&buf));
    if (status != SSH_OK) {
        return status;
    }

    status = crypto->kex_generate_keypair(
        crypto->ctx,
        sv("curve25519-sha256"),
        client_public,
        sizeof(client_public),
        &client_public_len,
        client_private,
        client_private_capacity,
        client_private_len);
    if (status != SSH_OK) {
        return status;
    }

    ssh_buffer_init(&buf, ecdh_payload, sizeof(ecdh_payload));
    status = ssh_kex_ecdh_init_encode(&buf, client_public, client_public_len);
    if (status != SSH_OK) {
        return status;
    }

    status = append_plain_packet(rng, out, out_capacity, out_len, ecdh_payload, ssh_buffer_len(&buf));
    if (status != SSH_OK) {
        return status;
    }

    ssh_buffer_init(&buf, newkeys_payload, sizeof(newkeys_payload));
    status = ssh_kex_newkeys_encode(&buf);
    if (status != SSH_OK) {
        return status;
    }

    return append_plain_packet(rng, out, out_capacity, out_len, newkeys_payload, ssh_buffer_len(&buf));
}

static int build_client_receive_protection(
    const ssh_crypto_api_t *crypto,
    const ssh_transport_session_t *session,
    const uint8_t *client_private,
    size_t client_private_len,
    const ssh_kex_ecdh_reply_t *reply,
    ssh_packet_protection_t *protection)
{
    uint8_t shared_secret[EMSSH_MAX_KEX_SHARED_SECRET];
    uint8_t iv[EMSSH_MAX_CIPHER_IV];
    uint8_t cipher_key[EMSSH_MAX_CIPHER_KEY];
    uint8_t mac_key[EMSSH_MAX_MAC_KEY];
    size_t shared_secret_len;
    size_t out_len;
    int status;

    status = crypto->kex_compute_shared_secret(
        crypto->ctx,
        session->negotiation.kex_algorithm,
        client_private,
        client_private_len,
        reply->server_public_key.data,
        reply->server_public_key.len,
        shared_secret,
        sizeof(shared_secret),
        &shared_secret_len);
    if (status != SSH_OK) {
        return status;
    }

    if (shared_secret_len != session->shared_secret_len ||
        memcmp(shared_secret, session->shared_secret, shared_secret_len) != 0) {
        return SSH_ERR_SECURITY;
    }

    status = crypto->derive_key(
        crypto->ctx,
        session->negotiation.kex_algorithm,
        shared_secret,
        shared_secret_len,
        session->exchange_hash,
        session->exchange_hash_len,
        session->session_id,
        session->session_id_len,
        'B',
        iv,
        16u,
        &out_len);
    if (status != SSH_OK || out_len != 16u) {
        return SSH_ERR_PLATFORM;
    }

    status = crypto->derive_key(
        crypto->ctx,
        session->negotiation.kex_algorithm,
        shared_secret,
        shared_secret_len,
        session->exchange_hash,
        session->exchange_hash_len,
        session->session_id,
        session->session_id_len,
        'D',
        cipher_key,
        16u,
        &out_len);
    if (status != SSH_OK || out_len != 16u) {
        return SSH_ERR_PLATFORM;
    }

    status = crypto->derive_key(
        crypto->ctx,
        session->negotiation.kex_algorithm,
        shared_secret,
        shared_secret_len,
        session->exchange_hash,
        session->exchange_hash_len,
        session->session_id,
        session->session_id_len,
        'F',
        mac_key,
        32u,
        &out_len);
    if (status != SSH_OK || out_len != 32u) {
        return SSH_ERR_PLATFORM;
    }

    ssh_packet_protection_init(protection);
    status = ssh_packet_protection_set(
        protection,
        crypto,
        session->negotiation.encryption_algorithm_server_to_client,
        session->negotiation.mac_algorithm_server_to_client,
        cipher_key,
        16u,
        iv,
        16u,
        mac_key,
        32u,
        16u,
        32u);
    if (status == SSH_OK) {
        protection->sequence = 3u;
    }

    crypto->secure_zero(crypto->ctx, shared_secret, sizeof(shared_secret));
    crypto->secure_zero(crypto->ctx, iv, sizeof(iv));
    crypto->secure_zero(crypto->ctx, cipher_key, sizeof(cipher_key));
    crypto->secure_zero(crypto->ctx, mac_key, sizeof(mac_key));
    return status;
}

static int build_client_send_protection(
    const ssh_crypto_api_t *crypto,
    const ssh_transport_session_t *session,
    ssh_packet_protection_t *protection)
{
    uint8_t iv[EMSSH_MAX_CIPHER_IV];
    uint8_t cipher_key[EMSSH_MAX_CIPHER_KEY];
    uint8_t mac_key[EMSSH_MAX_MAC_KEY];
    size_t out_len;
    int status;

    status = crypto->derive_key(
        crypto->ctx,
        session->negotiation.kex_algorithm,
        session->shared_secret,
        session->shared_secret_len,
        session->exchange_hash,
        session->exchange_hash_len,
        session->session_id,
        session->session_id_len,
        'A',
        iv,
        16u,
        &out_len);
    if (status != SSH_OK || out_len != 16u) {
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
        'C',
        cipher_key,
        16u,
        &out_len);
    if (status != SSH_OK || out_len != 16u) {
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
        'E',
        mac_key,
        32u,
        &out_len);
    if (status != SSH_OK || out_len != 32u) {
        return SSH_ERR_PLATFORM;
    }

    ssh_packet_protection_init(protection);
    status = ssh_packet_protection_set(
        protection,
        crypto,
        session->negotiation.encryption_algorithm_client_to_server,
        session->negotiation.mac_algorithm_client_to_server,
        cipher_key,
        16u,
        iv,
        16u,
        mac_key,
        32u,
        16u,
        32u);
    if (status == SSH_OK) {
        protection->sequence = 3u;
    }

    crypto->secure_zero(crypto->ctx, iv, sizeof(iv));
    crypto->secure_zero(crypto->ctx, cipher_key, sizeof(cipher_key));
    crypto->secure_zero(crypto->ctx, mac_key, sizeof(mac_key));
    return status;
}

static int protected_packet_wire_len(
    const ssh_packet_protection_t *protection,
    const uint8_t *packet,
    size_t available_len,
    size_t *wire_len)
{
    uint8_t first_block[EMSSH_MAX_CIPHER_IV];
    uint32_t packet_length;
    size_t encrypted_len;
    int status;

    if (protection == NULL || packet == NULL || wire_len == NULL ||
        !protection->active ||
        protection->block_size < SSH_PACKET_MIN_BLOCK_SIZE ||
        protection->block_size > sizeof(first_block) ||
        available_len < protection->block_size + protection->mac_len) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memcpy(first_block, packet, protection->block_size);
    status = protection->crypto->cipher_crypt(
        protection->crypto->ctx,
        protection->cipher_algorithm,
        protection->cipher_key,
        protection->cipher_key_len,
        protection->cipher_iv,
        protection->cipher_iv_len,
        protection->sequence,
        SSH_CIPHER_DECRYPT,
        first_block,
        protection->block_size);
    if (status != SSH_OK) {
        return SSH_ERR_PLATFORM;
    }

    packet_length = ((uint32_t)first_block[0] << 24) |
                    ((uint32_t)first_block[1] << 16) |
                    ((uint32_t)first_block[2] << 8) |
                    (uint32_t)first_block[3];
    encrypted_len = (size_t)packet_length + 4u;
    if (packet_length == 0u ||
        encrypted_len < protection->block_size ||
        encrypted_len + protection->mac_len > available_len) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    *wire_len = encrypted_len + protection->mac_len;
    return SSH_OK;
}

static int memory_append(memory_conn_t *conn, const uint8_t *data, size_t data_len)
{
    uint8_t *mutable_in;

    if (conn == NULL || data == NULL || data_len == 0u ||
        conn->in_len + data_len > 4096u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    mutable_in = (uint8_t *)conn->in;
    memcpy(mutable_in + conn->in_len, data, data_len);
    conn->in_len += data_len;
    return SSH_OK;
}

static void write_u32_be(uint8_t data[4], uint32_t value)
{
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

static uint32_t read_u32_be(const uint8_t data[4])
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static void finish_sftp_packet(uint8_t *packet, ssh_buffer_t *payload, size_t *packet_len)
{
    write_u32_be(packet, (uint32_t)ssh_buffer_len(payload));
    *packet_len = ssh_buffer_len(payload) + 4u;
}

static int append_client_sftp_packet(
    memory_conn_t *conn,
    ssh_packet_protection_t *client_send,
    const ssh_rng_api_t *rng,
    uint32_t server_channel,
    const uint8_t *sftp_packet,
    size_t sftp_packet_len)
{
    uint8_t channel_payload[512];
    uint8_t encrypted_packet[768];
    ssh_buffer_t buf;
    size_t encrypted_packet_len;
    int status;

    ssh_buffer_init(&buf, channel_payload, sizeof(channel_payload));
    status = ssh_channel_data_encode(&buf, server_channel, sftp_packet, sftp_packet_len);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_packet_encode_protected(
        client_send,
        encrypted_packet,
        sizeof(encrypted_packet),
        &encrypted_packet_len,
        channel_payload,
        ssh_buffer_len(&buf),
        rng);
    if (status != SSH_OK) {
        return status;
    }

    return memory_append(conn, encrypted_packet, encrypted_packet_len);
}

static int append_client_channel_simple(
    memory_conn_t *conn,
    ssh_packet_protection_t *client_send,
    const ssh_rng_api_t *rng,
    uint8_t message_id,
    uint32_t server_channel)
{
    uint8_t channel_payload[32];
    uint8_t encrypted_packet[128];
    ssh_buffer_t buf;
    size_t encrypted_packet_len;
    int status;

    ssh_buffer_init(&buf, channel_payload, sizeof(channel_payload));
    if (message_id == SSH_MSG_CHANNEL_EOF) {
        status = ssh_channel_eof_encode(&buf, server_channel);
    } else if (message_id == SSH_MSG_CHANNEL_CLOSE) {
        status = ssh_channel_close_encode(&buf, server_channel);
    } else {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_packet_encode_protected(
        client_send,
        encrypted_packet,
        sizeof(encrypted_packet),
        &encrypted_packet_len,
        channel_payload,
        ssh_buffer_len(&buf),
        rng);
    if (status != SSH_OK) {
        return status;
    }

    return memory_append(conn, encrypted_packet, encrypted_packet_len);
}

static int append_client_window_adjust(
    memory_conn_t *conn,
    ssh_packet_protection_t *client_send,
    const ssh_rng_api_t *rng,
    uint32_t server_channel,
    uint32_t bytes_to_add)
{
    uint8_t channel_payload[32];
    uint8_t encrypted_packet[128];
    ssh_buffer_t buf;
    size_t encrypted_packet_len;
    int status;

    ssh_buffer_init(&buf, channel_payload, sizeof(channel_payload));
    status = ssh_channel_window_adjust_encode(&buf, server_channel, bytes_to_add);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_packet_encode_protected(
        client_send,
        encrypted_packet,
        sizeof(encrypted_packet),
        &encrypted_packet_len,
        channel_payload,
        ssh_buffer_len(&buf),
        rng);
    if (status != SSH_OK) {
        return status;
    }

    return memory_append(conn, encrypted_packet, encrypted_packet_len);
}

static int append_client_global_request(
    memory_conn_t *conn,
    ssh_packet_protection_t *client_send,
    const ssh_rng_api_t *rng,
    const char *request_name,
    int want_reply)
{
    uint8_t payload[128];
    uint8_t encrypted_packet[192];
    ssh_buffer_t buf;
    size_t encrypted_packet_len;
    int status;

    ssh_buffer_init(&buf, payload, sizeof(payload));
    status = ssh_buffer_put_u8(&buf, SSH_MSG_GLOBAL_REQUEST);
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(&buf, request_name);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_bool(&buf, want_reply);
    }
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_packet_encode_protected(
        client_send,
        encrypted_packet,
        sizeof(encrypted_packet),
        &encrypted_packet_len,
        payload,
        ssh_buffer_len(&buf),
        rng);
    if (status != SSH_OK) {
        return status;
    }

    return memory_append(conn, encrypted_packet, encrypted_packet_len);
}

static int append_client_channel_request(
    memory_conn_t *conn,
    ssh_packet_protection_t *client_send,
    const ssh_rng_api_t *rng,
    uint32_t server_channel,
    const char *request_type,
    int want_reply)
{
    uint8_t payload[128];
    uint8_t encrypted_packet[192];
    ssh_buffer_t buf;
    size_t encrypted_packet_len;
    int status;

    if (request_type == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, payload, sizeof(payload));
    status = ssh_buffer_put_u8(&buf, SSH_MSG_CHANNEL_REQUEST);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(&buf, server_channel);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(&buf, request_type);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_bool(&buf, want_reply);
    }
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_packet_encode_protected(
        client_send,
        encrypted_packet,
        sizeof(encrypted_packet),
        &encrypted_packet_len,
        payload,
        ssh_buffer_len(&buf),
        rng);
    if (status != SSH_OK) {
        return status;
    }

    return memory_append(conn, encrypted_packet, encrypted_packet_len);
}

static int append_client_ignore(
    memory_conn_t *conn,
    ssh_packet_protection_t *client_send,
    const ssh_rng_api_t *rng)
{
    uint8_t payload[16];
    uint8_t encrypted_packet[128];
    ssh_buffer_t buf;
    size_t encrypted_packet_len;
    int status;

    ssh_buffer_init(&buf, payload, sizeof(payload));
    status = ssh_buffer_put_u8(&buf, SSH_MSG_IGNORE);
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(&buf, "noise");
    }
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_packet_encode_protected(
        client_send,
        encrypted_packet,
        sizeof(encrypted_packet),
        &encrypted_packet_len,
        payload,
        ssh_buffer_len(&buf),
        rng);
    if (status != SSH_OK) {
        return status;
    }

    return memory_append(conn, encrypted_packet, encrypted_packet_len);
}

static int append_client_disconnect(
    memory_conn_t *conn,
    ssh_packet_protection_t *client_send,
    const ssh_rng_api_t *rng)
{
    uint8_t payload[64];
    uint8_t encrypted_packet[128];
    ssh_buffer_t buf;
    size_t encrypted_packet_len;
    int status;

    ssh_buffer_init(&buf, payload, sizeof(payload));
    status = ssh_buffer_put_u8(&buf, SSH_MSG_DISCONNECT);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(&buf, 11u);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(&buf, "bye");
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(&buf, "");
    }
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_packet_encode_protected(
        client_send,
        encrypted_packet,
        sizeof(encrypted_packet),
        &encrypted_packet_len,
        payload,
        ssh_buffer_len(&buf),
        rng);
    if (status != SSH_OK) {
        return status;
    }

    return memory_append(conn, encrypted_packet, encrypted_packet_len);
}

static int password_auth(void *ctx, const ssh_password_auth_request_t *request)
{
    (void)ctx;

    return request != NULL &&
           request->username_len == strlen("alice") &&
           memcmp(request->username, "alice", request->username_len) == 0 &&
           request->password_len == strlen("secret") &&
           memcmp(request->password, "secret", request->password_len) == 0 &&
           request->service_name_len == strlen(SSH_SERVICE_CONNECTION) &&
           memcmp(request->service_name, SSH_SERVICE_CONNECTION, request->service_name_len) == 0;
}

static int publickey_auth(void *ctx, const ssh_publickey_auth_request_t *request)
{
    (void)ctx;
    (void)request;
    return 1;
}

static int allow_non_sftp_channel_requests(void *ctx, const ssh_channel_request_t *request)
{
    const int *allow = (const int *)ctx;

    if (allow == NULL || request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    return *allow ? SSH_OK : SSH_ERR_SECURITY;
}

int main(void)
{
    ssh_mbedtls_crypto_t crypto_ctx;
    const ssh_crypto_api_t *crypto;
    const ssh_rng_api_t *rng;
    ssh_kexinit_algorithm_set_t algorithms;
    ssh_net_api_t net;
    ssh_fs_api_t fs;
    ssh_platform_t platform;
    ssh_server_config_t config;
    ssh_server_t server;
    ssh_server_session_options_t server_options;
    ssh_server_sftp_channel_t server_channel;
    ssh_transport_session_t session;
    memory_conn_t conn;
    uint8_t client_input[4096];
    uint8_t client_private[EMSSH_MAX_KEX_PRIVATE_KEY];
    size_t client_input_len;
    size_t client_private_len;
    size_t reply_offset;
    size_t reply_len;
    ssh_packet_view_t reply_packet;
    ssh_buffer_t reply_payload;
    ssh_kex_ecdh_reply_t reply;
    ssh_packet_protection_t client_receive;
    ssh_packet_protection_t client_send;
    uint8_t protected_packet[128];
    uint8_t service_accept_payload[] = { SSH_MSG_SERVICE_ACCEPT, 0, 0, 0, 12, 's', 's', 'h', '-', 'u', 's', 'e', 'r', 'a', 'u', 't', 'h' };
    size_t protected_packet_len;
    ssh_packet_view_t protected_view;
    uint8_t service_request_payload[64];
    uint8_t client_service_packet[128];
    size_t client_service_packet_len;
    ssh_buffer_t service_buf;
    ssh_service_request_t service_request;
    ssh_service_request_t service_accept;
    uint8_t userauth_request_payload[128];
    uint8_t userauth_packet[192];
    size_t userauth_packet_len;
    ssh_userauth_request_t userauth_request;
    uint8_t channel_payload[128];
    uint8_t channel_packet[192];
    size_t channel_packet_len;
    ssh_channel_open_t channel_open;
    ssh_channel_request_t channel_request;
    uint8_t message_id;
    uint32_t value;
    uint8_t sftp_data[128];
    size_t sftp_data_len;
    uint32_t sftp_channel;
    sftp_init_t sftp_init;
    sftp_packet_t sftp_packet;
    ssh_channel_data_t channel_data;
    mock_fs_t fs_ctx;
    sftp_server_session_t sftp_session;
    uint8_t sftp_request_packet[256];
    uint8_t sftp_response_packet[512];
    size_t sftp_request_packet_len;
    size_t sftp_response_packet_len;
    uint8_t sftp_handle[16];
    size_t sftp_handle_len;
    ssh_string_view_t sftp_string;
    uint32_t sftp_request_id;
    uint32_t sftp_status_code;
    ssh_channel_message_t channel_message;
    int allow_non_sftp_channel = 1;

    CHECK(ssh_mbedtls_crypto_init(&crypto_ctx) == SSH_OK);
    CHECK(ssh_mbedtls_crypto_generate_ecdsa_p256_hostkey(&crypto_ctx) == SSH_OK);
    crypto = ssh_mbedtls_crypto_api(&crypto_ctx);
    rng = ssh_mbedtls_rng_api(&crypto_ctx);
    CHECK(crypto != NULL);
    CHECK(rng != NULL);

    CHECK(build_client_input(
        crypto,
        rng,
        client_input,
        sizeof(client_input),
        &client_input_len,
        client_private,
        sizeof(client_private),
        &client_private_len) == SSH_OK);

    memset(&conn, 0, sizeof(conn));
    conn.in = client_input;
    conn.in_len = client_input_len;

    net.read = memory_read;
    net.write = memory_write;
    net.close = memory_close;
    net.ctx = NULL;

    memset(&fs_ctx, 0, sizeof(fs_ctx));
    memcpy(fs_ctx.data, "abcdef", 6u);
    fs_ctx.data_len = 6u;

    memset(&fs, 0, sizeof(fs));
    fs.open = mock_fs_open;
    fs.close = mock_fs_close;
    fs.read_at = mock_fs_read_at;
    fs.ctx = &fs_ctx;

    memset(&platform, 0, sizeof(platform));
    platform.net = &net;
    platform.fs = &fs;
    platform.rng = rng;
    platform.crypto = crypto;

    ssh_server_config_defaults(&config);
    config.password_auth = password_auth;
    CHECK(ssh_server_init(&server, &platform, &config) == SSH_OK);
    ssh_mbedtls_kexinit_algorithm_set_defaults(&algorithms);
    ssh_server_session_options_defaults(&server_options);
    server_options.algorithms = &algorithms;
    server_options.timeout_ms = 1000u;
    server_options.non_sftp_channel_request_policy = allow_non_sftp_channel_requests;
    server_options.non_sftp_channel_request_policy_ctx = &allow_non_sftp_channel;
    CHECK(ssh_server_run_transport_setup(&server, &conn, &session, &server_options) == SSH_OK);
    CHECK(view_eq(session.negotiation.kex_algorithm, "curve25519-sha256"));
    CHECK(view_eq(session.negotiation.server_host_key_algorithm, "ecdsa-sha2-nistp256"));
    CHECK(session.exchange_hash_len == 32u);
    CHECK(session.session_id_len == 32u);
    CHECK(session.outbound.active);
    CHECK(session.inbound.active);

    reply_offset = session.server_identification_len;
    CHECK(reply_offset + 4u <= conn.out_len);
    reply_offset += 4u + (size_t)read_u32_be(conn.out + reply_offset);
    CHECK(reply_offset + 4u <= conn.out_len);
    reply_len = 4u + (size_t)read_u32_be(conn.out + reply_offset);
    CHECK(reply_offset + reply_len <= conn.out_len);
    CHECK(ssh_packet_decode_plain(conn.out + reply_offset, reply_len, &reply_packet) == SSH_OK);
    ssh_buffer_wrap(&reply_payload, (uint8_t *)reply_packet.payload, reply_packet.payload_len);
    CHECK(ssh_kex_ecdh_reply_decode(&reply_payload, &reply) == SSH_OK);
    CHECK(reply.server_host_key.len > strlen("ecdsa-sha2-nistp256"));
    CHECK(reply.signature.len > strlen("ecdsa-sha2-nistp256"));

    CHECK(build_client_receive_protection(crypto, &session, client_private, client_private_len, &reply, &client_receive) == SSH_OK);
    CHECK(build_client_send_protection(crypto, &session, &client_send) == SSH_OK);

    {
        size_t ext_info_offset = conn.out_len;
        size_t ext_info_len;

        session.client_supports_ext_info = 1;
        CHECK(ssh_transport_send_ext_info(&session, &conn, server_options.timeout_ms) == SSH_OK);

        CHECK(protected_packet_wire_len(
            &client_receive,
            conn.out + ext_info_offset,
            conn.out_len - ext_info_offset,
            &ext_info_len) == SSH_OK);
        CHECK(ssh_packet_decode_protected(
            &client_receive,
            conn.out + ext_info_offset,
            ext_info_len,
            &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_buffer_get_u8(&service_buf, &message_id) == SSH_OK);
        CHECK(message_id == SSH_MSG_EXT_INFO);
        CHECK(ssh_buffer_get_u32(&service_buf, &value) == SSH_OK);
        CHECK(value == 0u);
        CHECK(ssh_buffer_remaining_read(&service_buf) == 0u);
    }

    {
        size_t ext_info_offset = conn.out_len;
        size_t ext_info_len;
        ssh_string_view_t ext_name;
        ssh_string_view_t ext_value;
        const char *expected_sig_algs;

        server.config.publickey_auth = publickey_auth;
        expected_sig_algs = ssh_crypto_publickey_signature_algorithms();
        if (expected_sig_algs == NULL) {
            expected_sig_algs = "";
        }
        CHECK(ssh_transport_send_ext_info(&session, &conn, server_options.timeout_ms) == SSH_OK);

        CHECK(protected_packet_wire_len(
            &client_receive,
            conn.out + ext_info_offset,
            conn.out_len - ext_info_offset,
            &ext_info_len) == SSH_OK);
        CHECK(ssh_packet_decode_protected(
            &client_receive,
            conn.out + ext_info_offset,
            ext_info_len,
            &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_buffer_get_u8(&service_buf, &message_id) == SSH_OK);
        CHECK(message_id == SSH_MSG_EXT_INFO);
        CHECK(ssh_buffer_get_u32(&service_buf, &value) == SSH_OK);
        if (expected_sig_algs[0] == '\0') {
            CHECK(value == 0u);
        } else {
            CHECK(value == 1u);
            CHECK(ssh_buffer_get_string_view(&service_buf, &ext_name) == SSH_OK);
            CHECK(view_eq(ext_name, "server-sig-algs"));
            CHECK(ssh_buffer_get_string_view(&service_buf, &ext_value) == SSH_OK);
            CHECK(view_eq(ext_value, expected_sig_algs));
        }
        CHECK(ssh_buffer_remaining_read(&service_buf) == 0u);
    }

    {
        size_t ext_info_offset = conn.out_len;
        size_t ext_info_len;
        server.config.publickey_auth = NULL;
        CHECK(ssh_transport_send_ext_info(&session, &conn, server_options.timeout_ms) == SSH_OK);

        CHECK(protected_packet_wire_len(
            &client_receive,
            conn.out + ext_info_offset,
            conn.out_len - ext_info_offset,
            &ext_info_len) == SSH_OK);
        CHECK(ssh_packet_decode_protected(
            &client_receive,
            conn.out + ext_info_offset,
            ext_info_len,
            &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_buffer_get_u8(&service_buf, &message_id) == SSH_OK);
        CHECK(message_id == SSH_MSG_EXT_INFO);
        CHECK(ssh_buffer_get_u32(&service_buf, &value) == SSH_OK);
        CHECK(value == 0u);
        CHECK(ssh_buffer_remaining_read(&service_buf) == 0u);
    }

    server.config.publickey_auth = publickey_auth;

    CHECK(append_client_ignore(&conn, &client_send, rng) == SSH_OK);

    ssh_buffer_init(&service_buf, service_request_payload, sizeof(service_request_payload));
    CHECK(ssh_service_request_encode(&service_buf, SSH_SERVICE_USERAUTH) == SSH_OK);
    CHECK(ssh_packet_encode_protected(
        &client_send,
        client_service_packet,
        sizeof(client_service_packet),
        &client_service_packet_len,
        service_request_payload,
        ssh_buffer_len(&service_buf),
        rng) == SSH_OK);
    CHECK(memory_append(&conn, client_service_packet, client_service_packet_len) == SSH_OK);

    ssh_buffer_init(&service_buf, userauth_request_payload, sizeof(userauth_request_payload));
    CHECK(ssh_userauth_request_none_encode(&service_buf, "alice", SSH_SERVICE_CONNECTION) == SSH_OK);
    CHECK(ssh_packet_encode_protected(
        &client_send,
        userauth_packet,
        sizeof(userauth_packet),
        &userauth_packet_len,
        userauth_request_payload,
        ssh_buffer_len(&service_buf),
        rng) == SSH_OK);
    CHECK(memory_append(&conn, userauth_packet, userauth_packet_len) == SSH_OK);

    ssh_buffer_init(&service_buf, userauth_request_payload, sizeof(userauth_request_payload));
    CHECK(ssh_buffer_put_u8(&service_buf, SSH_MSG_USERAUTH_REQUEST) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&service_buf, "alice") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&service_buf, SSH_SERVICE_CONNECTION) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&service_buf, SSH_AUTH_METHOD_PUBLICKEY) == SSH_OK);
    CHECK(ssh_buffer_put_bool(&service_buf, 0) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&service_buf, "ssh-ed25519") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&service_buf, "dummy-key") == SSH_OK);
    CHECK(ssh_packet_encode_protected(
        &client_send,
        userauth_packet,
        sizeof(userauth_packet),
        &userauth_packet_len,
        userauth_request_payload,
        ssh_buffer_len(&service_buf),
        rng) == SSH_OK);
    CHECK(memory_append(&conn, userauth_packet, userauth_packet_len) == SSH_OK);

    ssh_buffer_init(&service_buf, userauth_request_payload, sizeof(userauth_request_payload));
    CHECK(ssh_userauth_request_password_encode(&service_buf, "alice", SSH_SERVICE_CONNECTION, "secret") == SSH_OK);
    CHECK(ssh_packet_encode_protected(
        &client_send,
        userauth_packet,
        sizeof(userauth_packet),
        &userauth_packet_len,
        userauth_request_payload,
        ssh_buffer_len(&service_buf),
        rng) == SSH_OK);
    CHECK(memory_append(&conn, userauth_packet, userauth_packet_len) == SSH_OK);

    {
        size_t service_accept_offset = conn.out_len;
        size_t service_accept_len;
        size_t userauth_failure_offset = conn.out_len;
        size_t userauth_failure_len;
        size_t userauth_pk_ok_offset = conn.out_len;
        size_t userauth_pk_ok_len;
        size_t userauth_success_offset = conn.out_len;
        ssh_string_view_t pk_ok_algorithm;
        ssh_string_view_t pk_ok_blob;
        ssh_string_view_t methods;
        int partial_success;

        CHECK(ssh_server_run_userauth(&session, &conn, &server_options) == SSH_OK);
        CHECK(session.state == SSH_TRANSPORT_STATE_USERAUTH_SUCCESS_SENT);

        CHECK(protected_packet_wire_len(&client_receive, conn.out + service_accept_offset, conn.out_len - service_accept_offset, &service_accept_len) == SSH_OK);
        CHECK(ssh_packet_decode_protected(&client_receive, conn.out + service_accept_offset, service_accept_len, &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_service_accept_decode(&service_buf, &service_accept) == SSH_OK);
        CHECK(view_eq(service_accept.service_name, SSH_SERVICE_USERAUTH));

        userauth_failure_offset += service_accept_len;
        CHECK(protected_packet_wire_len(&client_receive, conn.out + userauth_failure_offset, conn.out_len - userauth_failure_offset, &userauth_failure_len) == SSH_OK);
        CHECK(ssh_packet_decode_protected(&client_receive, conn.out + userauth_failure_offset, userauth_failure_len, &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_buffer_get_u8(&service_buf, &message_id) == SSH_OK);
        CHECK(message_id == SSH_MSG_USERAUTH_FAILURE);
        CHECK(ssh_buffer_get_string_view(&service_buf, &methods) == SSH_OK);
        CHECK(view_eq(methods, SSH_AUTH_DEFAULT_FAILURE_METHODS));
        CHECK(ssh_buffer_get_bool(&service_buf, &partial_success) == SSH_OK);
        CHECK(!partial_success);
        CHECK(ssh_buffer_remaining_read(&service_buf) == 0u);

        userauth_pk_ok_offset += service_accept_len + userauth_failure_len;
        CHECK(protected_packet_wire_len(&client_receive, conn.out + userauth_pk_ok_offset, conn.out_len - userauth_pk_ok_offset, &userauth_pk_ok_len) == SSH_OK);
        CHECK(ssh_packet_decode_protected(&client_receive, conn.out + userauth_pk_ok_offset, userauth_pk_ok_len, &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_buffer_get_u8(&service_buf, &message_id) == SSH_OK);
        CHECK(message_id == SSH_MSG_USERAUTH_PK_OK);
        CHECK(ssh_buffer_get_string_view(&service_buf, &pk_ok_algorithm) == SSH_OK);
        CHECK(view_eq(pk_ok_algorithm, "ssh-ed25519"));
        CHECK(ssh_buffer_get_string_view(&service_buf, &pk_ok_blob) == SSH_OK);
        CHECK(view_eq(pk_ok_blob, "dummy-key"));
        CHECK(ssh_buffer_remaining_read(&service_buf) == 0u);

        userauth_success_offset += service_accept_len + userauth_failure_len + userauth_pk_ok_len;
        CHECK(ssh_packet_decode_protected(&client_receive, conn.out + userauth_success_offset, conn.out_len - userauth_success_offset, &protected_view) == SSH_OK);
        CHECK(protected_view.payload_len == 1u);
        CHECK(protected_view.payload[0] == SSH_MSG_USERAUTH_SUCCESS);
    }

    {
        size_t service_accept_offset = conn.out_len;
        size_t service_accept_len;
        size_t failure_offset;
        size_t failure_len;
        size_t i;
        ssh_string_view_t methods;
        int partial_success;

        server.config.password_auth = NULL;
        server.config.publickey_auth = publickey_auth;

        ssh_buffer_init(&service_buf, service_request_payload, sizeof(service_request_payload));
        CHECK(ssh_service_request_encode(&service_buf, SSH_SERVICE_USERAUTH) == SSH_OK);
        CHECK(ssh_packet_encode_protected(
            &client_send,
            client_service_packet,
            sizeof(client_service_packet),
            &client_service_packet_len,
            service_request_payload,
            ssh_buffer_len(&service_buf),
            rng) == SSH_OK);
        CHECK(memory_append(&conn, client_service_packet, client_service_packet_len) == SSH_OK);

        for (i = 0u; i < 3u; ++i) {
            ssh_buffer_init(&service_buf, userauth_request_payload, sizeof(userauth_request_payload));
            CHECK(ssh_userauth_request_none_encode(&service_buf, "alice", SSH_SERVICE_CONNECTION) == SSH_OK);
            CHECK(ssh_packet_encode_protected(
                &client_send,
                userauth_packet,
                sizeof(userauth_packet),
                &userauth_packet_len,
                userauth_request_payload,
                ssh_buffer_len(&service_buf),
                rng) == SSH_OK);
            CHECK(memory_append(&conn, userauth_packet, userauth_packet_len) == SSH_OK);
        }

        CHECK(ssh_server_run_userauth(&session, &conn, &server_options) == SSH_ERR_SECURITY);

        CHECK(protected_packet_wire_len(
            &client_receive,
            conn.out + service_accept_offset,
            conn.out_len - service_accept_offset,
            &service_accept_len) == SSH_OK);
        CHECK(ssh_packet_decode_protected(
            &client_receive,
            conn.out + service_accept_offset,
            service_accept_len,
            &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_service_accept_decode(&service_buf, &service_accept) == SSH_OK);
        CHECK(view_eq(service_accept.service_name, SSH_SERVICE_USERAUTH));

        failure_offset = service_accept_offset + service_accept_len;
        for (i = 0u; i < 3u; ++i) {
            CHECK(protected_packet_wire_len(
                &client_receive,
                conn.out + failure_offset,
                conn.out_len - failure_offset,
                &failure_len) == SSH_OK);
            CHECK(ssh_packet_decode_protected(
                &client_receive,
                conn.out + failure_offset,
                failure_len,
                &protected_view) == SSH_OK);
            ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
            CHECK(ssh_buffer_get_u8(&service_buf, &message_id) == SSH_OK);
            CHECK(message_id == SSH_MSG_USERAUTH_FAILURE);
            CHECK(ssh_buffer_get_string_view(&service_buf, &methods) == SSH_OK);
            CHECK(view_eq(methods, SSH_AUTH_METHOD_PUBLICKEY));
            CHECK(ssh_buffer_get_bool(&service_buf, &partial_success) == SSH_OK);
            CHECK(!partial_success);
            CHECK(ssh_buffer_remaining_read(&service_buf) == 0u);
            failure_offset += failure_len;
        }

        server.config.password_auth = password_auth;
    }

    CHECK(append_client_global_request(&conn, &client_send, rng, "hostkeys-00@openssh.com", 1) == SSH_OK);

    ssh_buffer_init(&service_buf, channel_payload, sizeof(channel_payload));
    CHECK(ssh_channel_open_session_encode(&service_buf, 7u, 65536u, 32768u) == SSH_OK);
    CHECK(ssh_packet_encode_protected(
        &client_send,
        channel_packet,
        sizeof(channel_packet),
        &channel_packet_len,
        channel_payload,
        ssh_buffer_len(&service_buf),
        rng) == SSH_OK);
    CHECK(memory_append(&conn, channel_packet, channel_packet_len) == SSH_OK);

    CHECK(append_client_channel_request(&conn, &client_send, rng, 0u, "exec", 1) == SSH_OK);

    ssh_buffer_init(&service_buf, channel_payload, sizeof(channel_payload));
    CHECK(ssh_channel_request_subsystem_encode(&service_buf, 0u, 1, SSH_SUBSYSTEM_SFTP) == SSH_OK);
    CHECK(ssh_packet_encode_protected(
        &client_send,
        channel_packet,
        sizeof(channel_packet),
        &channel_packet_len,
        channel_payload,
        ssh_buffer_len(&service_buf),
        rng) == SSH_OK);
    CHECK(memory_append(&conn, channel_packet, channel_packet_len) == SSH_OK);

    {
        size_t request_failure_offset = conn.out_len;
        size_t request_failure_len;
        size_t channel_confirm_offset;
        size_t channel_confirm_len;
        size_t channel_failure_offset;
        size_t channel_failure_len;
        size_t channel_success_offset = conn.out_len;

        CHECK(ssh_server_accept_sftp_channel(&session, &conn, &server_channel, &server_options) == SSH_OK);
        CHECK(server_channel.client_channel == 7u);
        CHECK(server_channel.server_channel == 0u);
        CHECK(server_channel.window_size == 65536u);
        CHECK(server_channel.max_packet_size == 32768u);
        CHECK(server_channel.peer_window_size == 65536u);
        CHECK(server_channel.peer_max_packet_size == 32768u);

        CHECK(protected_packet_wire_len(&client_receive, conn.out + request_failure_offset, conn.out_len - request_failure_offset, &request_failure_len) == SSH_OK);
        CHECK(ssh_packet_decode_protected(&client_receive, conn.out + request_failure_offset, request_failure_len, &protected_view) == SSH_OK);
        CHECK(protected_view.payload_len == 1u);
        CHECK(protected_view.payload[0] == SSH_MSG_REQUEST_FAILURE);

        channel_confirm_offset = request_failure_offset + request_failure_len;
        CHECK(protected_packet_wire_len(&client_receive, conn.out + channel_confirm_offset, conn.out_len - channel_confirm_offset, &channel_confirm_len) == SSH_OK);
        CHECK(ssh_packet_decode_protected(&client_receive, conn.out + channel_confirm_offset, channel_confirm_len, &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_buffer_get_u8(&service_buf, &message_id) == SSH_OK);
        CHECK(message_id == SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        CHECK(ssh_buffer_get_u32(&service_buf, &value) == SSH_OK);
        CHECK(value == 7u);
        CHECK(ssh_buffer_get_u32(&service_buf, &value) == SSH_OK);
        CHECK(value == 0u);
        CHECK(ssh_buffer_get_u32(&service_buf, &value) == SSH_OK);
        CHECK(value == 65536u);
        CHECK(ssh_buffer_get_u32(&service_buf, &value) == SSH_OK);
        CHECK(value == 32768u);
        CHECK(ssh_buffer_remaining_read(&service_buf) == 0u);

        channel_failure_offset = request_failure_offset + request_failure_len + channel_confirm_len;
        CHECK(protected_packet_wire_len(&client_receive, conn.out + channel_failure_offset, conn.out_len - channel_failure_offset, &channel_failure_len) == SSH_OK);
        CHECK(ssh_packet_decode_protected(&client_receive, conn.out + channel_failure_offset, channel_failure_len, &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_buffer_get_u8(&service_buf, &message_id) == SSH_OK);
        CHECK(message_id == SSH_MSG_CHANNEL_FAILURE);
        CHECK(ssh_buffer_get_u32(&service_buf, &value) == SSH_OK);
        CHECK(value == 0u);
        CHECK(ssh_buffer_remaining_read(&service_buf) == 0u);

        channel_success_offset += request_failure_len + channel_confirm_len + channel_failure_len;
        CHECK(ssh_packet_decode_protected(&client_receive, conn.out + channel_success_offset, conn.out_len - channel_success_offset, &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_buffer_get_u8(&service_buf, &message_id) == SSH_OK);
        CHECK(message_id == SSH_MSG_CHANNEL_SUCCESS);
        CHECK(ssh_buffer_get_u32(&service_buf, &value) == SSH_OK);
        CHECK(value == 0u);
        CHECK(ssh_buffer_remaining_read(&service_buf) == 0u);
    }

    CHECK(append_client_window_adjust(&conn, &client_send, rng, 0u, 4096u) == SSH_OK);
    CHECK(ssh_server_process_sftp_channel_data(&session, &conn, &server_channel, &server_options) == SSH_OK);
    CHECK(session.state == SSH_TRANSPORT_STATE_CHANNEL_WINDOW_ADJUST_RECEIVED);
    CHECK(server_channel.peer_window_size == 69632u);

    {
        static const uint8_t sftp_init_packet[] = {
            0u, 0u, 0u, 5u,
            SSH_FXP_INIT,
            0u, 0u, 0u, SFTP_VERSION_3
        };

        server_channel.window_size = (uint32_t)sizeof(sftp_init_packet);
        ssh_buffer_init(&service_buf, channel_payload, sizeof(channel_payload));
        CHECK(ssh_channel_data_encode(&service_buf, 0u, sftp_init_packet, sizeof(sftp_init_packet)) == SSH_OK);
        CHECK(ssh_packet_encode_protected(
            &client_send,
            channel_packet,
            sizeof(channel_packet),
            &channel_packet_len,
            channel_payload,
            ssh_buffer_len(&service_buf),
            rng) == SSH_OK);
        CHECK(memory_append(&conn, channel_packet, channel_packet_len) == SSH_OK);
    }

    {
        size_t channel_data_offset = conn.out_len;
        size_t window_adjust_len;

        CHECK(ssh_server_process_sftp_channel_data(&session, &conn, &server_channel, &server_options) == SSH_OK);
        CHECK(session.state == SSH_TRANSPORT_STATE_CHANNEL_DATA_SENT);
        CHECK(server_channel.window_size == server_channel.window_max_size);

        CHECK(protected_packet_wire_len(&client_receive, conn.out + channel_data_offset, conn.out_len - channel_data_offset, &window_adjust_len) == SSH_OK);
        CHECK(ssh_packet_decode_protected(&client_receive, conn.out + channel_data_offset, window_adjust_len, &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_buffer_get_u8(&service_buf, &message_id) == SSH_OK);
        CHECK(message_id == SSH_MSG_CHANNEL_WINDOW_ADJUST);
        CHECK(ssh_buffer_get_u32(&service_buf, &value) == SSH_OK);
        CHECK(value == 7u);
        CHECK(ssh_buffer_get_u32(&service_buf, &value) == SSH_OK);
        CHECK(value == 65536u);
        CHECK(ssh_buffer_remaining_read(&service_buf) == 0u);

        channel_data_offset += window_adjust_len;
        CHECK(ssh_packet_decode_protected(&client_receive, conn.out + channel_data_offset, conn.out_len - channel_data_offset, &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_channel_data_decode(&service_buf, &channel_data) == SSH_OK);
        CHECK(channel_data.recipient_channel == 7u);
        CHECK(sftp_packet_wrap(channel_data.data.data, channel_data.data.len, &sftp_packet) == SSH_OK);
        CHECK(sftp_packet.type == SSH_FXP_VERSION);
        CHECK(sftp_packet.payload.len == 4u);
        CHECK(sftp_packet.payload.data[3] == SFTP_VERSION_3);
    }

    ssh_buffer_init(&service_buf, sftp_request_packet + 4u, sizeof(sftp_request_packet) - 4u);
    CHECK(ssh_buffer_put_u8(&service_buf, SSH_FXP_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&service_buf, 11u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&service_buf, "file.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&service_buf, SSH_FXF_READ) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&service_buf, 0u) == SSH_OK);
    finish_sftp_packet(sftp_request_packet, &service_buf, &sftp_request_packet_len);
    CHECK(append_client_sftp_packet(&conn, &client_send, rng, 0u, sftp_request_packet, sftp_request_packet_len) == SSH_OK);

    {
        size_t sftp_open_offset = conn.out_len;
        CHECK(ssh_server_process_sftp_channel_data(&session, &conn, &server_channel, &server_options) == SSH_OK);
        CHECK(strcmp(fs_ctx.opened_path, "file.txt") == 0);
        CHECK(ssh_packet_decode_protected(&client_receive, conn.out + sftp_open_offset, conn.out_len - sftp_open_offset, &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_channel_data_decode(&service_buf, &channel_data) == SSH_OK);
        CHECK(channel_data.recipient_channel == 7u);
        CHECK(sftp_packet_wrap(channel_data.data.data, channel_data.data.len, &sftp_packet) == SSH_OK);
        CHECK(sftp_packet.type == SSH_FXP_HANDLE);
        ssh_buffer_wrap(&service_buf, (uint8_t *)sftp_packet.payload.data, sftp_packet.payload.len);
        CHECK(ssh_buffer_get_u32(&service_buf, &sftp_request_id) == SSH_OK);
        CHECK(sftp_request_id == 11u);
        CHECK(ssh_buffer_get_string_view(&service_buf, &sftp_string) == SSH_OK);
        CHECK(sftp_string.len <= sizeof(sftp_handle));
        memcpy(sftp_handle, sftp_string.data, sftp_string.len);
        sftp_handle_len = sftp_string.len;
        CHECK(ssh_buffer_remaining_read(&service_buf) == 0u);
    }

    ssh_buffer_init(&service_buf, sftp_request_packet + 4u, sizeof(sftp_request_packet) - 4u);
    CHECK(ssh_buffer_put_u8(&service_buf, SSH_FXP_READ) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&service_buf, 12u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&service_buf, sftp_handle, sftp_handle_len) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&service_buf, 1u) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&service_buf, 3u) == SSH_OK);
    finish_sftp_packet(sftp_request_packet, &service_buf, &sftp_request_packet_len);
    CHECK(append_client_sftp_packet(&conn, &client_send, rng, 0u, sftp_request_packet, sftp_request_packet_len) == SSH_OK);

    {
        size_t sftp_read_offset = conn.out_len;
        CHECK(ssh_server_process_sftp_channel_data(&session, &conn, &server_channel, &server_options) == SSH_OK);
        CHECK(ssh_packet_decode_protected(&client_receive, conn.out + sftp_read_offset, conn.out_len - sftp_read_offset, &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_channel_data_decode(&service_buf, &channel_data) == SSH_OK);
        CHECK(sftp_packet_wrap(channel_data.data.data, channel_data.data.len, &sftp_packet) == SSH_OK);
        CHECK(sftp_packet.type == SSH_FXP_DATA);
        ssh_buffer_wrap(&service_buf, (uint8_t *)sftp_packet.payload.data, sftp_packet.payload.len);
        CHECK(ssh_buffer_get_u32(&service_buf, &sftp_request_id) == SSH_OK);
        CHECK(sftp_request_id == 12u);
        CHECK(ssh_buffer_get_string_view(&service_buf, &sftp_string) == SSH_OK);
        CHECK(sftp_string.len == 3u);
        CHECK(memcmp(sftp_string.data, "bcd", 3u) == 0);
        CHECK(ssh_buffer_remaining_read(&service_buf) == 0u);
    }

    ssh_buffer_init(&service_buf, sftp_request_packet + 4u, sizeof(sftp_request_packet) - 4u);
    CHECK(ssh_buffer_put_u8(&service_buf, SSH_FXP_CLOSE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&service_buf, 13u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&service_buf, sftp_handle, sftp_handle_len) == SSH_OK);
    finish_sftp_packet(sftp_request_packet, &service_buf, &sftp_request_packet_len);
    CHECK(append_client_sftp_packet(&conn, &client_send, rng, 0u, sftp_request_packet, sftp_request_packet_len) == SSH_OK);

    {
        size_t sftp_close_offset = conn.out_len;
        CHECK(ssh_server_process_sftp_channel_data(&session, &conn, &server_channel, &server_options) == SSH_OK);
        CHECK(ssh_packet_decode_protected(&client_receive, conn.out + sftp_close_offset, conn.out_len - sftp_close_offset, &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_channel_data_decode(&service_buf, &channel_data) == SSH_OK);
        CHECK(sftp_packet_wrap(channel_data.data.data, channel_data.data.len, &sftp_packet) == SSH_OK);
        CHECK(sftp_packet.type == SSH_FXP_STATUS);
        ssh_buffer_wrap(&service_buf, (uint8_t *)sftp_packet.payload.data, sftp_packet.payload.len);
        CHECK(ssh_buffer_get_u32(&service_buf, &sftp_request_id) == SSH_OK);
        CHECK(sftp_request_id == 13u);
        CHECK(ssh_buffer_get_u32(&service_buf, &sftp_status_code) == SSH_OK);
        CHECK(sftp_status_code == SSH_FX_OK);
        CHECK(fs_ctx.close_count == 1);
    }

    CHECK(append_client_channel_simple(&conn, &client_send, rng, SSH_MSG_CHANNEL_EOF, 0u) == SSH_OK);
    {
        size_t eof_offset = conn.out_len;
        size_t eof_len;
        size_t close_offset;
        CHECK(ssh_server_process_sftp_channel_data(&session, &conn, &server_channel, &server_options) == SSH_ERR_CLOSED);
        CHECK(server_channel.eof_sent);
        CHECK(server_channel.close_sent);

        CHECK(protected_packet_wire_len(&client_receive, conn.out + eof_offset, conn.out_len - eof_offset, &eof_len) == SSH_OK);
        CHECK(ssh_packet_decode_protected(&client_receive, conn.out + eof_offset, eof_len, &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_buffer_get_u8(&service_buf, &message_id) == SSH_OK);
        CHECK(message_id == SSH_MSG_CHANNEL_EOF);
        CHECK(ssh_buffer_get_u32(&service_buf, &value) == SSH_OK);
        CHECK(value == 7u);
        CHECK(ssh_buffer_remaining_read(&service_buf) == 0u);

        close_offset = eof_offset + eof_len;
        CHECK(ssh_packet_decode_protected(&client_receive, conn.out + close_offset, conn.out_len - close_offset, &protected_view) == SSH_OK);
        ssh_buffer_wrap(&service_buf, (uint8_t *)protected_view.payload, protected_view.payload_len);
        CHECK(ssh_buffer_get_u8(&service_buf, &message_id) == SSH_OK);
        CHECK(message_id == SSH_MSG_CHANNEL_CLOSE);
        CHECK(ssh_buffer_get_u32(&service_buf, &value) == SSH_OK);
        CHECK(value == 7u);
        CHECK(ssh_buffer_remaining_read(&service_buf) == 0u);
    }

    CHECK(append_client_disconnect(&conn, &client_send, rng) == SSH_OK);
    CHECK(ssh_transport_receive_channel_message(
        &session,
        &conn,
        &channel_message,
        sftp_response_packet,
        sizeof(sftp_response_packet),
        &sftp_response_packet_len,
        1000u) == SSH_ERR_CLOSED);

    CHECK(ssh_packet_encode_protected(
        &session.outbound,
        protected_packet,
        sizeof(protected_packet),
        &protected_packet_len,
        service_accept_payload,
        sizeof(service_accept_payload),
        rng) == SSH_OK);
    CHECK(ssh_packet_decode_protected(&client_receive, protected_packet, protected_packet_len, &protected_view) == SSH_OK);
    CHECK(protected_view.payload_len == sizeof(service_accept_payload));
    CHECK(memcmp(protected_view.payload, service_accept_payload, sizeof(service_accept_payload)) == 0);

    ssh_server_sftp_channel_deinit(&server_channel);
    ssh_server_deinit(&server);
    ssh_mbedtls_crypto_free(&crypto_ctx);
    return 0;
}
