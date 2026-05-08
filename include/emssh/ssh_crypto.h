#ifndef EMSSH_SSH_CRYPTO_H
#define EMSSH_SSH_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "emssh/ssh_buffer.h"

#define EMSSH_MAX_KEX_PUBLIC_KEY 256u
#define EMSSH_MAX_KEX_PRIVATE_KEY 256u
#define EMSSH_MAX_KEX_SHARED_SECRET 512u
#define EMSSH_MAX_HOST_KEY_BLOB 512u
#define EMSSH_MAX_SIGNATURE 512u
#define EMSSH_MAX_EXCHANGE_HASH 64u
#define EMSSH_MAX_CIPHER_KEY 64u
#define EMSSH_MAX_CIPHER_IV 32u
#define EMSSH_MAX_MAC_KEY 64u
#define EMSSH_MAX_MAC 64u

typedef struct ssh_rng_api ssh_rng_api_t;
typedef struct ssh_kexinit_algorithm_set ssh_kexinit_algorithm_set_t;
typedef struct ssh_crypto_context ssh_crypto_context_t;

typedef enum ssh_cipher_direction {
    SSH_CIPHER_ENCRYPT = 0,
    SSH_CIPHER_DECRYPT = 1
} ssh_cipher_direction_t;

typedef struct ssh_crypto_api {
    const char *name;

    int (*kex_generate_keypair)(
        void *ctx,
        ssh_string_view_t kex_algorithm,
        uint8_t *public_key,
        size_t public_key_capacity,
        size_t *public_key_len,
        uint8_t *private_key,
        size_t private_key_capacity,
        size_t *private_key_len);

    int (*kex_compute_shared_secret)(
        void *ctx,
        ssh_string_view_t kex_algorithm,
        const uint8_t *private_key,
        size_t private_key_len,
        const uint8_t *peer_public_key,
        size_t peer_public_key_len,
        uint8_t *shared_secret,
        size_t shared_secret_capacity,
        size_t *shared_secret_len);

    int (*hostkey_public)(
        void *ctx,
        ssh_string_view_t hostkey_algorithm,
        uint8_t *hostkey_blob,
        size_t hostkey_blob_capacity,
        size_t *hostkey_blob_len);

    int (*hash_exchange)(
        void *ctx,
        ssh_string_view_t kex_algorithm,
        const uint8_t *data,
        size_t data_len,
        uint8_t *hash,
        size_t hash_capacity,
        size_t *hash_len);

    int (*hostkey_sign)(
        void *ctx,
        ssh_string_view_t hostkey_algorithm,
        const uint8_t *exchange_hash,
        size_t exchange_hash_len,
        uint8_t *signature,
        size_t signature_capacity,
        size_t *signature_len);

    int (*publickey_verify)(
        void *ctx,
        ssh_string_view_t publickey_algorithm,
        const uint8_t *publickey_blob,
        size_t publickey_blob_len,
        const uint8_t *signed_data,
        size_t signed_data_len,
        const uint8_t *signature,
        size_t signature_len);

    int (*derive_key)(
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
        size_t *out_len);

    int (*cipher_crypt)(
        void *ctx,
        ssh_string_view_t cipher_algorithm,
        const uint8_t *key,
        size_t key_len,
        const uint8_t *iv,
        size_t iv_len,
        uint32_t sequence,
        ssh_cipher_direction_t direction,
        uint8_t *data,
        size_t data_len);

    int (*mac_compute)(
        void *ctx,
        ssh_string_view_t mac_algorithm,
        const uint8_t *key,
        size_t key_len,
        uint32_t sequence,
        const uint8_t *data,
        size_t data_len,
        uint8_t *mac,
        size_t mac_capacity,
        size_t *mac_len);

    int (*hostkey_import_private_auto)(
        void *ctx,
        ssh_string_view_t hostkey_algorithm,
        const uint8_t *private_key_data,
        size_t private_key_data_len);

    int (*hostkey_export_private)(
        void *ctx,
        ssh_string_view_t hostkey_algorithm,
        uint8_t *private_key,
        size_t private_key_capacity,
        size_t *private_key_len);

    int (*hostkey_generate)(
        void *ctx,
        ssh_string_view_t hostkey_algorithm);

    void (*kexinit_defaults)(
        void *ctx,
        ssh_kexinit_algorithm_set_t *algorithms);

    void (*secure_zero)(void *ctx, void *ptr, size_t len);

    void *ctx;
} ssh_crypto_api_t;

const char *ssh_crypto_name(void);
const char *ssh_crypto_publickey_signature_algorithms(void);

int ssh_crypto_open(ssh_crypto_context_t *crypto_ctx);
void ssh_crypto_close(ssh_crypto_context_t *crypto_ctx);

const ssh_crypto_api_t *ssh_crypto_api(const ssh_crypto_context_t *crypto_ctx);
const ssh_rng_api_t *ssh_crypto_rng_api(const ssh_crypto_context_t *crypto_ctx);

#endif
