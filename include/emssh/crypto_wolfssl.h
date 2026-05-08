#ifndef EMSSH_CRYPTO_WOLFSSL_H
#define EMSSH_CRYPTO_WOLFSSL_H

#include <stdint.h>

#include "emssh/ssh_crypto.h"
#include "emssh/ssh_kex.h"
#include "emssh/ssh_platform.h"

typedef struct ssh_wolfssl_crypto {
    ssh_crypto_api_t api;
    ssh_rng_api_t rng;
    int initialized;
} ssh_wolfssl_crypto_t;

typedef struct ssh_crypto_context_wolfssl {
    const ssh_crypto_api_t *crypto;
    const ssh_rng_api_t *rng;
    ssh_wolfssl_crypto_t wolfssl;
} ssh_crypto_context_wolfssl_t;

int ssh_wolfssl_crypto_init(ssh_wolfssl_crypto_t *ctx);
void ssh_wolfssl_crypto_free(ssh_wolfssl_crypto_t *ctx);

const ssh_crypto_api_t *ssh_wolfssl_crypto_api(ssh_wolfssl_crypto_t *ctx);
const ssh_rng_api_t *ssh_wolfssl_rng_api(ssh_wolfssl_crypto_t *ctx);

void ssh_wolfssl_kexinit_algorithm_set_defaults(ssh_kexinit_algorithm_set_t *algorithms);

#endif
