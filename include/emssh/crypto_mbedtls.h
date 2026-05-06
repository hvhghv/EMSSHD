#ifndef EMSSH_CRYPTO_MBEDTLS_H
#define EMSSH_CRYPTO_MBEDTLS_H

#include <stdint.h>

#include "emssh/ssh_crypto.h"
#include "emssh/ssh_kex.h"
#include "emssh/ssh_platform.h"

typedef struct ssh_mbedtls_crypto {
    ssh_crypto_api_t api;
    ssh_rng_api_t rng;
    uint32_t hostkey_id;
    int owns_hostkey;
    void *backend_state;
    int initialized;
} ssh_mbedtls_crypto_t;

int ssh_mbedtls_crypto_init(ssh_mbedtls_crypto_t *ctx);
void ssh_mbedtls_crypto_free(ssh_mbedtls_crypto_t *ctx);

int ssh_mbedtls_crypto_generate_ed25519_hostkey(ssh_mbedtls_crypto_t *ctx);
int ssh_mbedtls_crypto_generate_ecdsa_p256_hostkey(ssh_mbedtls_crypto_t *ctx);

int ssh_mbedtls_crypto_import_ed25519_hostkey(
    ssh_mbedtls_crypto_t *ctx,
    const uint8_t *private_key,
    size_t private_key_len);

int ssh_mbedtls_crypto_import_ecdsa_p256_hostkey(
    ssh_mbedtls_crypto_t *ctx,
    const uint8_t *private_key,
    size_t private_key_len);

int ssh_mbedtls_crypto_export_hostkey_private(
    ssh_mbedtls_crypto_t *ctx,
    uint8_t *private_key,
    size_t private_key_capacity,
    size_t *private_key_len);

int ssh_mbedtls_probe_ed25519_hostkey_support(void);
int ssh_mbedtls_probe_ed25519_publickey_verify_support(void);

const ssh_crypto_api_t *ssh_mbedtls_crypto_api(ssh_mbedtls_crypto_t *ctx);
const ssh_rng_api_t *ssh_mbedtls_rng_api(ssh_mbedtls_crypto_t *ctx);

void ssh_mbedtls_kexinit_algorithm_set_defaults(ssh_kexinit_algorithm_set_t *algorithms);

#endif
