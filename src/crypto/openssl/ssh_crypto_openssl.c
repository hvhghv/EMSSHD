#include "emssh/platform_openssl.h"

#include <string.h>

#include "emssh/ssh_buffer.h"
#include "emssh/ssh_config.h"
#include "emssh/ssh_error.h"

#if defined(EMSSH_USE_OPENSSL_REAL)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#endif

static int view_eq(ssh_string_view_t view, const char *value)
{
    size_t len;

    if (value == NULL || view.data == NULL) {
        return 0;
    }

    len = strlen(value);
    return view.len == len && memcmp(view.data, value, len) == 0;
}

static void openssl_secure_zero(void *ctx, void *ptr, size_t len)
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

static size_t openssl_int_max_size(void)
{
    return (size_t)(((unsigned int)~0u) >> 1);
}

#if !defined(EMSSH_USE_OPENSSL_REAL)
static int openssl_unsupported(void)
{
    return SSH_ERR_UNSUPPORTED;
}

static int openssl_rng_fill(void *ctx, uint8_t *buf, size_t len)
{
    (void)ctx;
    (void)buf;
    (void)len;
    return openssl_unsupported();
}

static int openssl_kex_generate_keypair(
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
    return openssl_unsupported();
}

static int openssl_kex_compute_shared_secret(
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
    return openssl_unsupported();
}

static int openssl_hostkey_public(
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
    return openssl_unsupported();
}

static int openssl_hash_exchange(
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
    return openssl_unsupported();
}

static int openssl_hostkey_sign(
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
    return openssl_unsupported();
}

static int openssl_publickey_verify(
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
    return openssl_unsupported();
}

static int openssl_derive_key(
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
    return openssl_unsupported();
}

static int openssl_cipher_crypt(
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
    return openssl_unsupported();
}

static int openssl_mac_compute(
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
    return openssl_unsupported();
}
#else
static int openssl_rng_fill(void *ctx, uint8_t *buf, size_t len)
{
    (void)ctx;

    if ((buf == NULL && len != 0u) || len > openssl_int_max_size()) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (len == 0u) {
        return SSH_OK;
    }

    return RAND_bytes(buf, (int)len) == 1 ? SSH_OK : SSH_ERR_PLATFORM;
}

static int openssl_hash_exchange(
    void *ctx,
    ssh_string_view_t kex_algorithm,
    const uint8_t *data,
    size_t data_len,
    uint8_t *hash,
    size_t hash_capacity,
    size_t *hash_len)
{
    EVP_MD_CTX *md_ctx;
    unsigned int digest_len;

    (void)ctx;

    if (!view_eq(kex_algorithm, "curve25519-sha256") ||
        (data == NULL && data_len != 0u) ||
        hash == NULL || hash_len == NULL || hash_capacity < 32u || data_len > openssl_int_max_size()) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        return SSH_ERR_PLATFORM;
    }

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md_ctx, data, data_len) != 1 ||
        EVP_DigestFinal_ex(md_ctx, hash, &digest_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return SSH_ERR_PLATFORM;
    }

    EVP_MD_CTX_free(md_ctx);
    *hash_len = (size_t)digest_len;
    return *hash_len == 32u ? SSH_OK : SSH_ERR_PLATFORM;
}

static int openssl_kdf_hash_round(
    const uint8_t *shared_secret,
    size_t shared_secret_len,
    const uint8_t *exchange_hash,
    size_t exchange_hash_len,
    const uint8_t *session_id,
    size_t session_id_len,
    char key_id,
    const uint8_t *previous,
    size_t previous_len,
    uint8_t round[32])
{
    uint8_t input[4u + EMSSH_MAX_KEX_SHARED_SECRET + 4u + EMSSH_MAX_EXCHANGE_HASH + 1u + 64u];
    ssh_buffer_t buf;
    EVP_MD_CTX *md_ctx;
    unsigned int digest_len;
    int rc;

    if (shared_secret == NULL || exchange_hash == NULL || session_id == NULL || round == NULL ||
        shared_secret_len > EMSSH_MAX_KEX_SHARED_SECRET ||
        exchange_hash_len > EMSSH_MAX_EXCHANGE_HASH ||
        previous_len > 64u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, input, sizeof(input));
    rc = ssh_buffer_put_string(&buf, shared_secret, shared_secret_len);
    if (rc == SSH_OK) {
        rc = ssh_buffer_put_string(&buf, exchange_hash, exchange_hash_len);
    }
    if (rc == SSH_OK && previous == NULL) {
        rc = ssh_buffer_put_u8(&buf, (uint8_t)key_id);
    }
    if (rc == SSH_OK && previous == NULL) {
        rc = ssh_buffer_put_bytes(&buf, session_id, session_id_len);
    }
    if (rc == SSH_OK && previous != NULL) {
        rc = ssh_buffer_put_bytes(&buf, previous, previous_len);
    }
    if (rc != SSH_OK) {
        openssl_secure_zero(NULL, input, sizeof(input));
        return rc;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        openssl_secure_zero(NULL, input, sizeof(input));
        return SSH_ERR_PLATFORM;
    }
    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md_ctx, input, ssh_buffer_len(&buf)) != 1 ||
        EVP_DigestFinal_ex(md_ctx, round, &digest_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        openssl_secure_zero(NULL, input, sizeof(input));
        openssl_secure_zero(NULL, round, 32u);
        return SSH_ERR_PLATFORM;
    }

    EVP_MD_CTX_free(md_ctx);
    openssl_secure_zero(NULL, input, sizeof(input));
    return digest_len == 32u ? SSH_OK : SSH_ERR_PLATFORM;
}

static int openssl_derive_key(
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
    uint8_t round[32];
    size_t written;
    int rc;

    (void)ctx;

    if (!view_eq(hash_algorithm, "curve25519-sha256") ||
        shared_secret == NULL || exchange_hash == NULL || session_id == NULL ||
        out == NULL || out_len == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    written = 0u;
    rc = openssl_kdf_hash_round(
        shared_secret,
        shared_secret_len,
        exchange_hash,
        exchange_hash_len,
        session_id,
        session_id_len,
        key_id,
        NULL,
        0u,
        round);
    if (rc != SSH_OK) {
        return rc;
    }

    while (written < out_capacity) {
        size_t take = out_capacity - written;
        if (take > sizeof(round)) {
            take = sizeof(round);
        }
        memcpy(out + written, round, take);
        written += take;

        if (written < out_capacity) {
            rc = openssl_kdf_hash_round(
                shared_secret,
                shared_secret_len,
                exchange_hash,
                exchange_hash_len,
                session_id,
                session_id_len,
                key_id,
                out,
                written,
                round);
            if (rc != SSH_OK) {
                openssl_secure_zero(NULL, round, sizeof(round));
                return rc;
            }
        }
    }

    openssl_secure_zero(NULL, round, sizeof(round));
    *out_len = out_capacity;
    return SSH_OK;
}

static int openssl_cipher_crypt(
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
    EVP_CIPHER_CTX *cipher_ctx;
    uint8_t output[EMSSH_MAX_PACKET_SIZE + 4u];
    int out_len;
    int final_len;

    (void)ctx;
    (void)sequence;

    if (!view_eq(cipher_algorithm, "aes128-ctr") ||
        key == NULL || key_len != 16u || iv == NULL || iv_len != 16u ||
        (data == NULL && data_len != 0u) || data_len > sizeof(output) || data_len > openssl_int_max_size()) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (cipher_ctx == NULL) {
        return SSH_ERR_PLATFORM;
    }

    if (EVP_CipherInit_ex(
            cipher_ctx,
            EVP_aes_128_ctr(),
            NULL,
            key,
            iv,
            direction == SSH_CIPHER_ENCRYPT ? 1 : 0) != 1 ||
        EVP_CipherUpdate(cipher_ctx, output, &out_len, data, (int)data_len) != 1 ||
        EVP_CipherFinal_ex(cipher_ctx, output + out_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(cipher_ctx);
        openssl_secure_zero(NULL, output, sizeof(output));
        return SSH_ERR_PLATFORM;
    }

    EVP_CIPHER_CTX_free(cipher_ctx);
    if ((size_t)out_len + (size_t)final_len != data_len) {
        openssl_secure_zero(NULL, output, sizeof(output));
        return SSH_ERR_PLATFORM;
    }

    memcpy(data, output, data_len);
    openssl_secure_zero(NULL, output, sizeof(output));
    return SSH_OK;
}

static int openssl_mac_compute(
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
    uint8_t input[4u + EMSSH_MAX_PACKET_SIZE + 4u];
    unsigned int local_mac_len;

    (void)ctx;

    if (!view_eq(mac_algorithm, "hmac-sha2-256") ||
        key == NULL || key_len == 0u || key_len > openssl_int_max_size() ||
        data == NULL || data_len > EMSSH_MAX_PACKET_SIZE + 4u ||
        mac == NULL || mac_len == NULL || mac_capacity < 32u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    input[0] = (uint8_t)((sequence >> 24) & 0xffu);
    input[1] = (uint8_t)((sequence >> 16) & 0xffu);
    input[2] = (uint8_t)((sequence >> 8) & 0xffu);
    input[3] = (uint8_t)(sequence & 0xffu);
    memcpy(input + 4u, data, data_len);

    if (HMAC(EVP_sha256(), key, (int)key_len, input, (size_t)(data_len + 4u), mac, &local_mac_len) == NULL) {
        openssl_secure_zero(NULL, input, sizeof(input));
        return SSH_ERR_PLATFORM;
    }

    openssl_secure_zero(NULL, input, sizeof(input));
    *mac_len = (size_t)local_mac_len;
    return *mac_len == 32u ? SSH_OK : SSH_ERR_PLATFORM;
}

static int openssl_kex_generate_keypair(
    void *ctx,
    ssh_string_view_t kex_algorithm,
    uint8_t *public_key,
    size_t public_key_capacity,
    size_t *public_key_len,
    uint8_t *private_key,
    size_t private_key_capacity,
    size_t *private_key_len)
{
    EVP_PKEY_CTX *kex_ctx;
    EVP_PKEY *kex_key;
    size_t exported_public_len;
    size_t exported_private_len;
    int rc;

    (void)ctx;

    if (!view_eq(kex_algorithm, "curve25519-sha256")) {
        return SSH_ERR_UNSUPPORTED;
    }
    if (public_key == NULL || public_key_len == NULL ||
        private_key == NULL || private_key_len == NULL ||
        public_key_capacity < 32u || private_key_capacity < 32u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    kex_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (kex_ctx == NULL) {
        return SSH_ERR_PLATFORM;
    }

    rc = SSH_ERR_PLATFORM;
    kex_key = NULL;
    if (EVP_PKEY_keygen_init(kex_ctx) != 1 ||
        EVP_PKEY_keygen(kex_ctx, &kex_key) != 1) {
        EVP_PKEY_CTX_free(kex_ctx);
        return SSH_ERR_PLATFORM;
    }

    exported_public_len = public_key_capacity;
    exported_private_len = private_key_capacity;
    if (EVP_PKEY_get_raw_public_key(kex_key, public_key, &exported_public_len) != 1 ||
        EVP_PKEY_get_raw_private_key(kex_key, private_key, &exported_private_len) != 1 ||
        exported_public_len != 32u || exported_private_len != 32u) {
        openssl_secure_zero(NULL, private_key, private_key_capacity);
        EVP_PKEY_free(kex_key);
        EVP_PKEY_CTX_free(kex_ctx);
        return SSH_ERR_PLATFORM;
    }

    *public_key_len = exported_public_len;
    *private_key_len = exported_private_len;
    rc = SSH_OK;

    EVP_PKEY_free(kex_key);
    EVP_PKEY_CTX_free(kex_ctx);
    return rc;
}

static int openssl_kex_compute_shared_secret(
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
    EVP_PKEY *self_key;
    EVP_PKEY *peer_key;
    EVP_PKEY_CTX *derive_ctx;
    size_t local_shared_len;
    size_t i;
    int all_zero;

    (void)ctx;

    if (!view_eq(kex_algorithm, "curve25519-sha256")) {
        return SSH_ERR_UNSUPPORTED;
    }
    if (private_key == NULL || peer_public_key == NULL ||
        shared_secret == NULL || shared_secret_len == NULL ||
        private_key_len != 32u || peer_public_key_len != 32u ||
        shared_secret_capacity < 32u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    self_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, private_key_len);
    if (self_key == NULL) {
        return SSH_ERR_PLATFORM;
    }

    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_public_key, peer_public_key_len);
    if (peer_key == NULL) {
        EVP_PKEY_free(self_key);
        return SSH_ERR_PLATFORM;
    }

    derive_ctx = EVP_PKEY_CTX_new(self_key, NULL);
    if (derive_ctx == NULL ||
        EVP_PKEY_derive_init(derive_ctx) != 1 ||
        EVP_PKEY_derive_set_peer(derive_ctx, peer_key) != 1) {
        EVP_PKEY_CTX_free(derive_ctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(self_key);
        return SSH_ERR_PLATFORM;
    }

    local_shared_len = shared_secret_capacity;
    if (EVP_PKEY_derive(derive_ctx, NULL, &local_shared_len) != 1 ||
        local_shared_len > shared_secret_capacity ||
        EVP_PKEY_derive(derive_ctx, shared_secret, &local_shared_len) != 1) {
        EVP_PKEY_CTX_free(derive_ctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(self_key);
        return SSH_ERR_PLATFORM;
    }

    all_zero = 1;
    for (i = 0u; i < local_shared_len; ++i) {
        if (shared_secret[i] != 0u) {
            all_zero = 0;
            break;
        }
    }

    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(self_key);

    if (all_zero) {
        openssl_secure_zero(NULL, shared_secret, local_shared_len);
        return SSH_ERR_SECURITY;
    }

    *shared_secret_len = local_shared_len;
    return SSH_OK;
}

static int openssl_hostkey_public(
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
    return SSH_ERR_UNSUPPORTED;
}

static int openssl_hostkey_sign(
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
    return SSH_ERR_UNSUPPORTED;
}

static int openssl_publickey_verify(
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
#endif

int ssh_openssl_crypto_init(ssh_openssl_crypto_t *ctx)
{
    if (ctx == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->api.name = "openssl";
    ctx->api.kex_generate_keypair = openssl_kex_generate_keypair;
    ctx->api.kex_compute_shared_secret = openssl_kex_compute_shared_secret;
    ctx->api.hostkey_public = openssl_hostkey_public;
    ctx->api.hash_exchange = openssl_hash_exchange;
    ctx->api.hostkey_sign = openssl_hostkey_sign;
    ctx->api.publickey_verify = openssl_publickey_verify;
    ctx->api.derive_key = openssl_derive_key;
    ctx->api.cipher_crypt = openssl_cipher_crypt;
    ctx->api.mac_compute = openssl_mac_compute;
    ctx->api.secure_zero = openssl_secure_zero;
    ctx->api.ctx = ctx;
    ctx->rng.fill = openssl_rng_fill;
    ctx->rng.ctx = ctx;
    ctx->initialized = 1;
    return SSH_OK;
}

void ssh_openssl_crypto_free(ssh_openssl_crypto_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(*ctx));
}

const ssh_crypto_api_t *ssh_openssl_crypto_api(ssh_openssl_crypto_t *ctx)
{
    return (ctx != NULL && ctx->initialized) ? &ctx->api : NULL;
}

const ssh_rng_api_t *ssh_openssl_rng_api(ssh_openssl_crypto_t *ctx)
{
    return (ctx != NULL && ctx->initialized) ? &ctx->rng : NULL;
}

void ssh_openssl_kexinit_algorithm_set_defaults(ssh_kexinit_algorithm_set_t *algorithms)
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

int ssh_openssl_platform_init(
    ssh_openssl_platform_t *ctx,
    const ssh_net_api_t *net,
    const ssh_fs_api_t *fs,
    const ssh_term_api_t *term,
    const ssh_mem_api_t *mem,
    const ssh_time_api_t *time,
    const ssh_log_api_t *log)
{
    int status;

    if (ctx == NULL || net == NULL || fs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(ctx, 0, sizeof(*ctx));
    status = ssh_openssl_crypto_init(&ctx->crypto);
    if (status != SSH_OK) {
        return status;
    }

    ctx->platform.net = net;
    ctx->platform.fs = fs;
    ctx->platform.term = term;
    ctx->platform.mem = mem;
    ctx->platform.time = time;
    ctx->platform.log = log;
    ctx->platform.crypto = ssh_openssl_crypto_api(&ctx->crypto);
    ctx->platform.rng = ssh_openssl_rng_api(&ctx->crypto);
    ctx->initialized = 1;
    return SSH_OK;
}

void ssh_openssl_platform_deinit(ssh_openssl_platform_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->initialized) {
        ssh_openssl_crypto_free(&ctx->crypto);
    }
    memset(ctx, 0, sizeof(*ctx));
}

const ssh_platform_t *ssh_openssl_platform_api(ssh_openssl_platform_t *ctx)
{
    if (ctx == NULL || !ctx->initialized) {
        return NULL;
    }
    return &ctx->platform;
}
