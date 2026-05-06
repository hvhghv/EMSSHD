#include <stdio.h>
#include <string.h>

#include "emssh/ssh_error.h"
#include "emssh/ssh_packet.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static int deterministic_rng(void *ctx, uint8_t *buf, size_t len)
{
    size_t i;
    (void)ctx;

    for (i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(0xa0u + i);
    }

    return SSH_OK;
}

static int view_eq(ssh_string_view_t view, const char *text)
{
    size_t len = strlen(text);
    return view.len == len && memcmp(view.data, text, len) == 0;
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
    CHECK(key_len == 32u);
    CHECK(mac_capacity >= 32u);

    acc = (uint8_t)sequence;
    for (i = 0u; i < data_len; ++i) {
        acc = (uint8_t)(acc + data[i] + (uint8_t)i);
    }

    for (i = 0u; i < 32u; ++i) {
        mac[i] = (uint8_t)(acc ^ key[i] ^ (uint8_t)i);
    }
    *mac_len = 32u;
    return SSH_OK;
}

int main(void)
{
    const uint8_t payload[] = { 20u, 1u, 2u, 3u };
    uint8_t encoded[64];
    uint8_t protected_packet[128];
    uint8_t protected_snapshot[128];
    uint8_t key[32];
    uint8_t iv[16];
    size_t encoded_len;
    size_t protected_len;
    ssh_packet_view_t view;
    ssh_rng_api_t rng;
    ssh_crypto_api_t crypto;
    ssh_packet_protection_t send_protection;
    ssh_packet_protection_t recv_protection;
    ssh_string_view_t cipher_algorithm;
    ssh_string_view_t mac_algorithm;
    size_t i;

    rng.fill = deterministic_rng;
    rng.ctx = NULL;

    for (i = 0u; i < sizeof(key); ++i) {
        key[i] = (uint8_t)(0x10u + i);
    }
    for (i = 0u; i < sizeof(iv); ++i) {
        iv[i] = (uint8_t)(0x40u + i);
    }

    memset(&crypto, 0, sizeof(crypto));
    crypto.name = "fake-packet-crypto";
    crypto.cipher_crypt = fake_cipher_crypt;
    crypto.mac_compute = fake_mac_compute;

    CHECK(ssh_packet_encode_plain(
        encoded,
        sizeof(encoded),
        &encoded_len,
        payload,
        sizeof(payload),
        8u,
        &rng) == SSH_OK);

    CHECK(encoded_len == ssh_packet_encoded_len(sizeof(payload), 8u));
    CHECK((encoded_len % 8u) == 0u);

    CHECK(ssh_packet_decode_plain(encoded, encoded_len, &view) == SSH_OK);
    CHECK(view.payload_len == sizeof(payload));
    CHECK(memcmp(view.payload, payload, sizeof(payload)) == 0);

    encoded[4] = 3u;
    CHECK(ssh_packet_decode_plain(encoded, encoded_len, &view) == SSH_ERR_MALFORMED_PACKET);

    cipher_algorithm.data = (const uint8_t *)"aes128-ctr";
    cipher_algorithm.len = strlen("aes128-ctr");
    mac_algorithm.data = (const uint8_t *)"hmac-sha2-256";
    mac_algorithm.len = strlen("hmac-sha2-256");

    ssh_packet_protection_init(&send_protection);
    ssh_packet_protection_init(&recv_protection);
    CHECK(ssh_packet_protection_set(
        &send_protection,
        &crypto,
        cipher_algorithm,
        mac_algorithm,
        key,
        16u,
        iv,
        sizeof(iv),
        key,
        32u,
        16u,
        32u) == SSH_OK);
    CHECK(ssh_packet_protection_set(
        &recv_protection,
        &crypto,
        cipher_algorithm,
        mac_algorithm,
        key,
        16u,
        iv,
        sizeof(iv),
        key,
        32u,
        16u,
        32u) == SSH_OK);

    CHECK(ssh_packet_encode_protected(
        &send_protection,
        protected_packet,
        sizeof(protected_packet),
        &protected_len,
        payload,
        sizeof(payload),
        &rng) == SSH_OK);
    CHECK(send_protection.sequence == 1u);
    CHECK(ssh_packet_decode_protected(&recv_protection, protected_packet, protected_len, &view) == SSH_OK);
    CHECK(recv_protection.sequence == 1u);
    CHECK(view.payload_len == sizeof(payload));
    CHECK(memcmp(view.payload, payload, sizeof(payload)) == 0);

    CHECK(ssh_packet_encode_protected(
        &send_protection,
        protected_packet,
        sizeof(protected_packet),
        &protected_len,
        payload,
        sizeof(payload),
        &rng) == SSH_OK);
    CHECK(ssh_packet_decode_protected(&recv_protection, protected_packet, protected_len - 1u, &view) == SSH_ERR_MALFORMED_PACKET);
    CHECK(recv_protection.sequence == 1u);

    send_protection.sequence = recv_protection.sequence;
    memcpy(send_protection.cipher_iv, recv_protection.cipher_iv, send_protection.cipher_iv_len);
    CHECK(ssh_packet_encode_protected(
        &send_protection,
        protected_packet,
        sizeof(protected_packet),
        &protected_len,
        payload,
        sizeof(payload),
        &rng) == SSH_OK);
    protected_packet[protected_len - 1u] ^= 0x01u;
    memcpy(protected_snapshot, protected_packet, protected_len);
    CHECK(ssh_packet_decode_protected(&recv_protection, protected_packet, protected_len, &view) == SSH_ERR_SECURITY);
    CHECK(recv_protection.sequence == 1u);
    CHECK(memcmp(protected_packet, protected_snapshot, protected_len) == 0);

    return 0;
}
