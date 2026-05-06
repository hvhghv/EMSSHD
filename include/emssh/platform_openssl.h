#ifndef EMSSH_PLATFORM_OPENSSL_H
#define EMSSH_PLATFORM_OPENSSL_H

#include "emssh/crypto_openssl.h"
#include "emssh/ssh_platform.h"

typedef struct ssh_openssl_platform {
    ssh_openssl_crypto_t crypto;
    ssh_platform_t platform;
    int initialized;
} ssh_openssl_platform_t;

int ssh_openssl_platform_init(
    ssh_openssl_platform_t *ctx,
    const ssh_net_api_t *net,
    const ssh_fs_api_t *fs,
    const ssh_term_api_t *term,
    const ssh_mem_api_t *mem,
    const ssh_time_api_t *time,
    const ssh_log_api_t *log);
void ssh_openssl_platform_deinit(ssh_openssl_platform_t *ctx);
const ssh_platform_t *ssh_openssl_platform_api(ssh_openssl_platform_t *ctx);

#endif
