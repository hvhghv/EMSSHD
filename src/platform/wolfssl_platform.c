#include "emssh/platform_wolfssl.h"

#include <string.h>

#include "emssh/ssh_error.h"

int ssh_wolfssl_platform_init(
    ssh_wolfssl_platform_t *ctx,
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
    status = ssh_wolfssl_crypto_init(&ctx->crypto);
    if (status != SSH_OK) {
        return status;
    }

    ctx->platform.net = net;
    ctx->platform.fs = fs;
    ctx->platform.term = term;
    ctx->platform.mem = mem;
    ctx->platform.time = time;
    ctx->platform.log = log;
    ctx->platform.crypto = ssh_wolfssl_crypto_api(&ctx->crypto);
    ctx->platform.rng = ssh_wolfssl_rng_api(&ctx->crypto);
    ctx->initialized = 1;
    return SSH_OK;
}

void ssh_wolfssl_platform_deinit(ssh_wolfssl_platform_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->initialized) {
        ssh_wolfssl_crypto_free(&ctx->crypto);
    }
    memset(ctx, 0, sizeof(*ctx));
}

const ssh_platform_t *ssh_wolfssl_platform_api(ssh_wolfssl_platform_t *ctx)
{
    if (ctx == NULL || !ctx->initialized) {
        return NULL;
    }
    return &ctx->platform;
}
