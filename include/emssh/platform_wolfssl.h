#ifndef EMSSH_PLATFORM_WOLFSSL_H
#define EMSSH_PLATFORM_WOLFSSL_H

#include "emssh/crypto_wolfssl.h"
#include "emssh/ssh_platform.h"

typedef struct ssh_wolfssl_platform {
    ssh_wolfssl_crypto_t crypto;
    ssh_platform_t platform;
    int initialized;
} ssh_wolfssl_platform_t;

int ssh_wolfssl_platform_init(
    ssh_wolfssl_platform_t *ctx,
    const ssh_net_api_t *net,
    const ssh_fs_api_t *fs,
    const ssh_term_api_t *term,
    const ssh_mem_api_t *mem,
    const ssh_time_api_t *time,
    const ssh_log_api_t *log);
void ssh_wolfssl_platform_deinit(ssh_wolfssl_platform_t *ctx);
const ssh_platform_t *ssh_wolfssl_platform_api(ssh_wolfssl_platform_t *ctx);

#endif
