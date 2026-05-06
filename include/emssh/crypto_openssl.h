#ifndef EMSSH_CRYPTO_OPENSSL_H
#define EMSSH_CRYPTO_OPENSSL_H

#include <stdint.h>

#include "emssh/ssh_crypto.h"
#include "emssh/ssh_kex.h"
#include "emssh/ssh_platform.h"

typedef struct ssh_openssl_crypto {
    ssh_crypto_api_t api;
    ssh_rng_api_t rng;
    int initialized;
} ssh_openssl_crypto_t;

int ssh_openssl_crypto_init(ssh_openssl_crypto_t *ctx);
void ssh_openssl_crypto_free(ssh_openssl_crypto_t *ctx);

const ssh_crypto_api_t *ssh_openssl_crypto_api(ssh_openssl_crypto_t *ctx);
const ssh_rng_api_t *ssh_openssl_rng_api(ssh_openssl_crypto_t *ctx);

void ssh_openssl_kexinit_algorithm_set_defaults(ssh_kexinit_algorithm_set_t *algorithms);

#endif
