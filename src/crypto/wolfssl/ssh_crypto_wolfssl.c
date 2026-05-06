#include "emssh/crypto_wolfssl.h"

#include <string.h>

#include "emssh/ssh_error.h"

static int wolfssl_unsupported(void)
{
    return SSH_ERR_UNSUPPORTED;
}

static void wolfssl_secure_zero(void *ctx, void *ptr, size_t len)
{
    volatile uint8_t *p;

    (void)ctx;

    if (ptr == NULL) {
        return;
    }

    p = (volatile uint8_t *)ptr;
    while (len-- != 0u) {
        *p++ = 0u;
    }
}

static int wolfssl_rng_fill(void *ctx, uint8_t *buf, size_t len)
{
    (void)ctx;
    (void)buf;
    (void)len;
    return wolfssl_unsupported();
}

static int wolfssl_kex_generate_keypair(
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
    (void)kex_algorithm;
    (void)public_key;
    (void)public_key_capacity;
    (void)public_key_len;
    (void)private_key;
    (void)private_key_capacity;
    (void)private_key_len;
    return wolfssl_unsupported();
}

static int wolfssl_kex_compute_shared_secret(
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
    (void)kex_algorithm;
    (void)private_key;
    (void)private_key_len;
    (void)peer_public_key;
    (void)peer_public_key_len;
    (void)shared_secret;
    (void)shared_secret_capacity;
    (void)shared_secret_len;
    return wolfssl_unsupported();
}

static int wolfssl_hostkey_public(
    void *ctx,
    ssh_string_view_t hostkey_algorithm,
    uint8_t *hostkey_blob,
    size_t hostkey_blob_capacity,
    size_t *hostkey_blob_len)
{
    (void)ctx;
    (void)hostkey_algorithm;
    (void)hostkey_blob;
    (void)hostkey_blob_capacity;
    (void)hostkey_blob_len;
    return wolfssl_unsupported();
}

static int wolfssl_hash_exchange(
    void *ctx,
    ssh_string_view_t kex_algorithm,
    const uint8_t *data,
    size_t data_len,
    uint8_t *hash,
    size_t hash_capacity,
    size_t *hash_len)
{
    (void)ctx;
    (void)kex_algorithm;
    (void)data;
    (void)data_len;
    (void)hash;
    (void)hash_capacity;
    (void)hash_len;
    return wolfssl_unsupported();
}

static int wolfssl_hostkey_sign(
    void *ctx,
    ssh_string_view_t hostkey_algorithm,
    const uint8_t *exchange_hash,
    size_t exchange_hash_len,
    uint8_t *signature,
    size_t signature_capacity,
    size_t *signature_len)
{
    (void)ctx;
    (void)hostkey_algorithm;
    (void)exchange_hash;
    (void)exchange_hash_len;
    (void)signature;
    (void)signature_capacity;
    (void)signature_len;
    return wolfssl_unsupported();
}

static int wolfssl_publickey_verify(
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
    return wolfssl_unsupported();
}

static int wolfssl_derive_key(
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
    (void)ctx;
    (void)hash_algorithm;
    (void)shared_secret;
    (void)shared_secret_len;
    (void)exchange_hash;
    (void)exchange_hash_len;
    (void)session_id;
    (void)session_id_len;
    (void)key_id;
    (void)out;
    (void)out_capacity;
    (void)out_len;
    return wolfssl_unsupported();
}

static int wolfssl_cipher_crypt(
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
    (void)ctx;
    (void)cipher_algorithm;
    (void)key;
    (void)key_len;
    (void)iv;
    (void)iv_len;
    (void)sequence;
    (void)direction;
    (void)data;
    (void)data_len;
    return wolfssl_unsupported();
}

static int wolfssl_mac_compute(
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
    (void)ctx;
    (void)mac_algorithm;
    (void)key;
    (void)key_len;
    (void)sequence;
    (void)data;
    (void)data_len;
    (void)mac;
    (void)mac_capacity;
    (void)mac_len;
    return wolfssl_unsupported();
}

int ssh_wolfssl_crypto_init(ssh_wolfssl_crypto_t *ctx)
{
    if (ctx == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->api.name = "wolfssl";
    ctx->api.kex_generate_keypair = wolfssl_kex_generate_keypair;
    ctx->api.kex_compute_shared_secret = wolfssl_kex_compute_shared_secret;
    ctx->api.hostkey_public = wolfssl_hostkey_public;
    ctx->api.hash_exchange = wolfssl_hash_exchange;
    ctx->api.hostkey_sign = wolfssl_hostkey_sign;
    ctx->api.publickey_verify = wolfssl_publickey_verify;
    ctx->api.derive_key = wolfssl_derive_key;
    ctx->api.cipher_crypt = wolfssl_cipher_crypt;
    ctx->api.mac_compute = wolfssl_mac_compute;
    ctx->api.secure_zero = wolfssl_secure_zero;
    ctx->api.ctx = ctx;
    ctx->rng.fill = wolfssl_rng_fill;
    ctx->rng.ctx = ctx;
    ctx->initialized = 1;
    return SSH_OK;
}

void ssh_wolfssl_crypto_free(ssh_wolfssl_crypto_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(*ctx));
}

const ssh_crypto_api_t *ssh_wolfssl_crypto_api(ssh_wolfssl_crypto_t *ctx)
{
    return (ctx != NULL && ctx->initialized) ? &ctx->api : NULL;
}

const ssh_rng_api_t *ssh_wolfssl_rng_api(ssh_wolfssl_crypto_t *ctx)
{
    return (ctx != NULL && ctx->initialized) ? &ctx->rng : NULL;
}

void ssh_wolfssl_kexinit_algorithm_set_defaults(ssh_kexinit_algorithm_set_t *algorithms)
{
    if (algorithms == NULL) {
        return;
    }

    memset(algorithms, 0, sizeof(*algorithms));
    algorithms->kex_algorithms = "curve25519-sha256";
    algorithms->server_host_key_algorithms = "ecdsa-sha2-nistp256";
    algorithms->encryption_algorithms_client_to_server = "aes128-ctr";
    algorithms->encryption_algorithms_server_to_client = "aes128-ctr";
    algorithms->mac_algorithms_client_to_server = "hmac-sha2-256";
    algorithms->mac_algorithms_server_to_client = "hmac-sha2-256";
    algorithms->compression_algorithms_client_to_server = "none";
    algorithms->compression_algorithms_server_to_client = "none";
    algorithms->languages_client_to_server = "";
    algorithms->languages_server_to_client = "";
}
