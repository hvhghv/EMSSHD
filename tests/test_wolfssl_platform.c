#include <stdio.h>
#include <string.h>

#include "emssh/platform_wolfssl.h"
#include "emssh/ssh_error.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

int main(void)
{
    ssh_wolfssl_platform_t ctx;
    ssh_net_api_t net;
    ssh_fs_api_t fs;
    ssh_term_api_t term;
    ssh_mem_api_t mem;
    ssh_time_api_t time_api;
    ssh_log_api_t log;
    const ssh_platform_t *platform;

    memset(&ctx, 0, sizeof(ctx));
    memset(&net, 0, sizeof(net));
    memset(&fs, 0, sizeof(fs));
    memset(&term, 0, sizeof(term));
    memset(&mem, 0, sizeof(mem));
    memset(&time_api, 0, sizeof(time_api));
    memset(&log, 0, sizeof(log));

    CHECK(ssh_wolfssl_platform_init(NULL, &net, &fs, &term, &mem, &time_api, &log) == SSH_ERR_INVALID_ARGUMENT);
    CHECK(ssh_wolfssl_platform_init(&ctx, NULL, &fs, &term, &mem, &time_api, &log) == SSH_ERR_INVALID_ARGUMENT);
    CHECK(ssh_wolfssl_platform_init(&ctx, &net, NULL, &term, &mem, &time_api, &log) == SSH_ERR_INVALID_ARGUMENT);

    CHECK(ssh_wolfssl_platform_init(&ctx, &net, &fs, &term, &mem, &time_api, &log) == SSH_OK);
    platform = ssh_wolfssl_platform_api(&ctx);
    CHECK(platform != NULL);
    CHECK(platform->net == &net);
    CHECK(platform->fs == &fs);
    CHECK(platform->term == &term);
    CHECK(platform->mem == &mem);
    CHECK(platform->time == &time_api);
    CHECK(platform->log == &log);
    CHECK(platform->crypto != NULL);
    CHECK(platform->rng != NULL);
    CHECK(platform->crypto->name != NULL);
    CHECK(strcmp(platform->crypto->name, "wolfssl") == 0);

    ssh_wolfssl_platform_deinit(&ctx);
    CHECK(ssh_wolfssl_platform_api(&ctx) == NULL);

    return 0;
}
