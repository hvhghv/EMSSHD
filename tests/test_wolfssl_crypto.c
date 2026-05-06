#include <stdio.h>
#include <string.h>

#include "emssh/crypto_wolfssl.h"
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
    ssh_wolfssl_crypto_t crypto_ctx;
    const ssh_crypto_api_t *crypto;
    const ssh_rng_api_t *rng;
    uint8_t random_buf[16];
    uint8_t hash[32];
    uint8_t derived[32];
    uint8_t packet[16] = {0};
    uint8_t public_key[64];
    uint8_t private_key[64];
    uint8_t shared_secret[64];
    size_t hash_len = 0u;
    size_t derived_len = 0u;
    size_t public_key_len = 0u;
    size_t private_key_len = 0u;
    size_t shared_secret_len = 0u;

    memset(&crypto_ctx, 0, sizeof(crypto_ctx));
    CHECK(ssh_wolfssl_crypto_init(&crypto_ctx) == SSH_OK);
    crypto = ssh_wolfssl_crypto_api(&crypto_ctx);
    rng = ssh_wolfssl_rng_api(&crypto_ctx);
    CHECK(crypto != NULL);
    CHECK(rng != NULL);

#if defined(EMSSH_USE_WOLFSSL_REAL)
    {
        int rc;
        rc = rng->fill(rng->ctx, random_buf, sizeof(random_buf));
        CHECK(rc == SSH_OK || rc == SSH_ERR_UNSUPPORTED);
    }
    {
        int rc = crypto->hash_exchange(
            crypto->ctx,
            sv("curve25519-sha256"),
            (const uint8_t *)"exchange-data",
            strlen("exchange-data"),
            hash,
            sizeof(hash),
            &hash_len);
        CHECK(rc == SSH_OK || rc == SSH_ERR_UNSUPPORTED);
    }
    {
        int rc = crypto->derive_key(
            crypto->ctx,
            sv("curve25519-sha256"),
            (const uint8_t *)"shared",
            strlen("shared"),
            (const uint8_t *)"hash",
            4u,
            (const uint8_t *)"session",
            strlen("session"),
            'A',
            derived,
            sizeof(derived),
            &derived_len);
        CHECK(rc == SSH_OK || rc == SSH_ERR_UNSUPPORTED);
    }
    {
        int rc = crypto->cipher_crypt(
            crypto->ctx,
            sv("aes128-ctr"),
            (const uint8_t *)"0123456789abcdef",
            16u,
            (const uint8_t *)"0123456789abcdef",
            16u,
            1u,
            SSH_CIPHER_ENCRYPT,
            packet,
            sizeof(packet));
        CHECK(rc == SSH_OK || rc == SSH_ERR_UNSUPPORTED);
    }
    {
        int rc = crypto->kex_generate_keypair(
            crypto->ctx,
            sv("curve25519-sha256"),
            public_key,
            sizeof(public_key),
            &public_key_len,
            private_key,
            sizeof(private_key),
            &private_key_len);
        CHECK(rc == SSH_OK || rc == SSH_ERR_UNSUPPORTED);
    }
    {
        int rc = crypto->kex_compute_shared_secret(
            crypto->ctx,
            sv("curve25519-sha256"),
            private_key,
            32u,
            public_key,
            32u,
            shared_secret,
            sizeof(shared_secret),
            &shared_secret_len);
        CHECK(rc == SSH_OK || rc == SSH_ERR_UNSUPPORTED);
    }
#else
    CHECK(rng->fill(rng->ctx, random_buf, sizeof(random_buf)) == SSH_ERR_UNSUPPORTED);
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
        (const uint8_t *)"shared",
        strlen("shared"),
        (const uint8_t *)"hash",
        4u,
        (const uint8_t *)"session",
        strlen("session"),
        'A',
        derived,
        sizeof(derived),
        &derived_len) == SSH_ERR_UNSUPPORTED);
    CHECK(crypto->cipher_crypt(
        crypto->ctx,
        sv("aes128-ctr"),
        (const uint8_t *)"0123456789abcdef",
        16u,
        (const uint8_t *)"0123456789abcdef",
        16u,
        1u,
        SSH_CIPHER_ENCRYPT,
        packet,
        sizeof(packet)) == SSH_ERR_UNSUPPORTED);
    CHECK(crypto->kex_generate_keypair(
        crypto->ctx,
        sv("curve25519-sha256"),
        public_key,
        sizeof(public_key),
        &public_key_len,
        private_key,
        sizeof(private_key),
        &private_key_len) == SSH_ERR_UNSUPPORTED);
    CHECK(crypto->kex_compute_shared_secret(
        crypto->ctx,
        sv("curve25519-sha256"),
        private_key,
        32u,
        public_key,
        32u,
        shared_secret,
        sizeof(shared_secret),
        &shared_secret_len) == SSH_ERR_UNSUPPORTED);
#endif

    ssh_wolfssl_crypto_free(&crypto_ctx);
    return 0;
}
