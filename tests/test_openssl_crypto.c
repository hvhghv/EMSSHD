#include <stdio.h>
#include <string.h>

#include "emssh/crypto_openssl.h"
#include "emssh/ssh_error.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static ssh_string_view_t sv(const char *value)
{
    ssh_string_view_t view;
    view.data = (const uint8_t *)value;
    view.len = strlen(value);
    return view;
}

int main(void)
{
    ssh_openssl_crypto_t crypto_ctx;
    const ssh_crypto_api_t *crypto;
    const ssh_rng_api_t *rng;
    uint8_t random_buf[16];
    uint8_t hash[32];
    uint8_t derived[48];
    uint8_t public_a[EMSSH_MAX_KEX_PUBLIC_KEY];
    uint8_t private_a[EMSSH_MAX_KEX_PRIVATE_KEY];
    uint8_t public_b[EMSSH_MAX_KEX_PUBLIC_KEY];
    uint8_t private_b[EMSSH_MAX_KEX_PRIVATE_KEY];
    uint8_t shared_ab[EMSSH_MAX_KEX_SHARED_SECRET];
    uint8_t shared_ba[EMSSH_MAX_KEX_SHARED_SECRET];
    uint8_t mac[32];
    uint8_t key[16];
    uint8_t iv[16];
    uint8_t packet[16] = {0, 0, 0, 12, 8, 1, 2, 3, 4, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11, 0x22};
    uint8_t original_packet[16];
    size_t hash_len;
    size_t derived_len;
    size_t mac_len;
    size_t public_a_len;
    size_t private_a_len;
    size_t public_b_len;
    size_t private_b_len;
    size_t shared_ab_len;
    size_t shared_ba_len;
    size_t i;

    memset(&crypto_ctx, 0, sizeof(crypto_ctx));
    CHECK(ssh_openssl_crypto_init(&crypto_ctx) == SSH_OK);
    crypto = ssh_openssl_crypto_api(&crypto_ctx);
    rng = ssh_openssl_rng_api(&crypto_ctx);
    CHECK(crypto != NULL);
    CHECK(rng != NULL);
    for (i = 0u; i < sizeof(key); ++i) {
        key[i] = (uint8_t)i;
        iv[i] = (uint8_t)(0x10u + i);
    }

#if defined(EMSSH_USE_OPENSSL_REAL)
    CHECK(rng->fill(rng->ctx, random_buf, sizeof(random_buf)) == SSH_OK);

    CHECK(crypto->hash_exchange(
        crypto->ctx,
        sv("curve25519-sha256"),
        (const uint8_t *)"exchange-data",
        strlen("exchange-data"),
        hash,
        sizeof(hash),
        &hash_len) == SSH_OK);
    CHECK(hash_len == 32u);

    CHECK(crypto->derive_key(
        crypto->ctx,
        sv("curve25519-sha256"),
        (const uint8_t *)"0123456789abcdef",
        16u,
        hash,
        hash_len,
        (const uint8_t *)"session-id",
        strlen("session-id"),
        'A',
        derived,
        sizeof(derived),
        &derived_len) == SSH_OK);
    CHECK(derived_len == sizeof(derived));

    memcpy(original_packet, packet, sizeof(packet));
    CHECK(crypto->cipher_crypt(
        crypto->ctx,
        sv("aes128-ctr"),
        key,
        sizeof(key),
        iv,
        sizeof(iv),
        0u,
        SSH_CIPHER_ENCRYPT,
        packet,
        sizeof(packet)) == SSH_OK);
    CHECK(memcmp(packet, original_packet, sizeof(packet)) != 0);

    CHECK(crypto->cipher_crypt(
        crypto->ctx,
        sv("aes128-ctr"),
        key,
        sizeof(key),
        iv,
        sizeof(iv),
        0u,
        SSH_CIPHER_DECRYPT,
        packet,
        sizeof(packet)) == SSH_OK);
    CHECK(memcmp(packet, original_packet, sizeof(packet)) == 0);

    CHECK(crypto->mac_compute(
        crypto->ctx,
        sv("hmac-sha2-256"),
        (const uint8_t *)"mac-key",
        strlen("mac-key"),
        7u,
        original_packet,
        sizeof(original_packet),
        mac,
        sizeof(mac),
        &mac_len) == SSH_OK);
    CHECK(mac_len == 32u);

    CHECK(crypto->kex_generate_keypair(
        crypto->ctx,
        sv("curve25519-sha256"),
        public_a,
        sizeof(public_a),
        &public_a_len,
        private_a,
        sizeof(private_a),
        &private_a_len) == SSH_OK);
    CHECK(public_a_len == 32u);
    CHECK(private_a_len == 32u);

    CHECK(crypto->kex_generate_keypair(
        crypto->ctx,
        sv("curve25519-sha256"),
        public_b,
        sizeof(public_b),
        &public_b_len,
        private_b,
        sizeof(private_b),
        &private_b_len) == SSH_OK);
    CHECK(public_b_len == 32u);
    CHECK(private_b_len == 32u);

    CHECK(crypto->kex_compute_shared_secret(
        crypto->ctx,
        sv("curve25519-sha256"),
        private_a,
        private_a_len,
        public_b,
        public_b_len,
        shared_ab,
        sizeof(shared_ab),
        &shared_ab_len) == SSH_OK);
    CHECK(crypto->kex_compute_shared_secret(
        crypto->ctx,
        sv("curve25519-sha256"),
        private_b,
        private_b_len,
        public_a,
        public_a_len,
        shared_ba,
        sizeof(shared_ba),
        &shared_ba_len) == SSH_OK);
    CHECK(shared_ab_len == shared_ba_len);
    CHECK(shared_ab_len == 32u);
    CHECK(memcmp(shared_ab, shared_ba, shared_ab_len) == 0);
    for (i = 0u; i < shared_ab_len; ++i) {
        if (shared_ab[i] != 0u) {
            break;
        }
    }
    CHECK(i < shared_ab_len);
#else
    CHECK(rng->fill(rng->ctx, random_buf, sizeof(random_buf)) == SSH_ERR_UNSUPPORTED);
    CHECK(crypto->kex_generate_keypair(
        crypto->ctx,
        sv("curve25519-sha256"),
        public_a,
        sizeof(public_a),
        &public_a_len,
        private_a,
        sizeof(private_a),
        &private_a_len) == SSH_ERR_UNSUPPORTED);
    CHECK(crypto->kex_compute_shared_secret(
        crypto->ctx,
        sv("curve25519-sha256"),
        (const uint8_t *)"private-key",
        strlen("private-key"),
        (const uint8_t *)"public-key",
        strlen("public-key"),
        shared_ab,
        sizeof(shared_ab),
        &shared_ab_len) == SSH_ERR_UNSUPPORTED);
    CHECK(crypto->hash_exchange(
        crypto->ctx,
        sv("curve25519-sha256"),
        (const uint8_t *)"exchange-data",
        strlen("exchange-data"),
        hash,
        sizeof(hash),
        &hash_len) == SSH_ERR_UNSUPPORTED);
    CHECK(crypto->derive_key(
        crypto->ctx,
        sv("curve25519-sha256"),
        (const uint8_t *)"0123456789abcdef",
        16u,
        (const uint8_t *)"hash",
        4u,
        (const uint8_t *)"session-id",
        strlen("session-id"),
        'A',
        derived,
        sizeof(derived),
        &derived_len) == SSH_ERR_UNSUPPORTED);
    CHECK(crypto->cipher_crypt(
        crypto->ctx,
        sv("aes128-ctr"),
        key,
        sizeof(key),
        iv,
        sizeof(iv),
        0u,
        SSH_CIPHER_ENCRYPT,
        packet,
        sizeof(packet)) == SSH_ERR_UNSUPPORTED);
    CHECK(crypto->mac_compute(
        crypto->ctx,
        sv("hmac-sha2-256"),
        (const uint8_t *)"mac-key",
        strlen("mac-key"),
        7u,
        packet,
        sizeof(packet),
        mac,
        sizeof(mac),
        &mac_len) == SSH_ERR_UNSUPPORTED);
#endif

    ssh_openssl_crypto_free(&crypto_ctx);
    return 0;
}
