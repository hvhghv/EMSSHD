#include <stdio.h>
#include <string.h>

#include "emssh/platform_posix_term.h"
#include "emssh/ssh_error.h"

#ifndef _WIN32
#include <sys/select.h>

static void wait_one_millisecond(void)
{
    struct timeval timeout;

    timeout.tv_sec = 0;
    timeout.tv_usec = 1000;
    (void)select(0, NULL, NULL, NULL, &timeout);
}
#endif

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

int main(void)
{
    ssh_posix_term_platform_t term;
    const ssh_term_api_t *api;
    void *handle;
    uint8_t output[32];
    uint8_t read_buf[16];
    size_t output_len;
    size_t read_len;
    int status;
    int exited;
    uint32_t exit_code;
    unsigned tries;

    memset(&term, 0, sizeof(term));
    {
        int null_status = ssh_posix_term_platform_init(NULL);
        CHECK(null_status == SSH_ERR_INVALID_ARGUMENT || null_status == SSH_ERR_UNSUPPORTED);
    }

#ifdef _WIN32
    CHECK(ssh_posix_term_platform_init(&term) == SSH_ERR_UNSUPPORTED);
    return 0;
#else
    CHECK(ssh_posix_term_platform_init(&term) == SSH_OK);
    api = ssh_posix_term_api(&term);
    CHECK(api != NULL);
    CHECK(api->spawn_exec != NULL);
    CHECK(api->wait_exit != NULL);
    CHECK(api->close != NULL);

    handle = NULL;
    status = api->spawn_exec(api->ctx, NULL, "true", "xterm-256color", 80u, 24u, 0u, 0u, &handle);
    CHECK(status == SSH_OK);
    CHECK(handle != NULL);

    exited = 0;
    exit_code = 0u;
    for (tries = 0u; tries < 200u; ++tries) {
        status = api->wait_exit(api->ctx, handle, &exited, &exit_code);
        CHECK(status == SSH_OK);
        if (exited) {
            break;
        }
        wait_one_millisecond();
    }
    CHECK(exited);
    CHECK(exit_code == 0u);
    read_len = 0u;
    CHECK(api->read(api->ctx, handle, read_buf, sizeof(read_buf), &read_len) == SSH_OK);

    CHECK(api->close(api->ctx, handle) == SSH_OK);

    handle = NULL;
    status = api->spawn_exec(api->ctx, NULL, "printf 'a\\nb\\n'", NULL, 0u, 0u, 0u, 0u, &handle);
    CHECK(status == SSH_OK);
    CHECK(handle != NULL);

    output_len = 0u;
    exited = 0;
    exit_code = 0u;
    for (tries = 0u; tries < 100000u; ++tries) {
        read_len = 0u;
        status = api->read(api->ctx, handle, read_buf, sizeof(read_buf), &read_len);
        CHECK(status == SSH_OK);
        CHECK(read_len <= sizeof(output) - output_len);
        if (read_len != 0u) {
            memcpy(output + output_len, read_buf, read_len);
            output_len += read_len;
        }

        status = api->wait_exit(api->ctx, handle, &exited, &exit_code);
        CHECK(status == SSH_OK);
        if (exited && output_len == strlen("a\nb\n")) {
            break;
        }
        wait_one_millisecond();
    }
    CHECK(exited);
    CHECK(exit_code == 0u);
    CHECK(output_len == strlen("a\nb\n"));
    CHECK(memcmp(output, "a\nb\n", output_len) == 0);
    CHECK(api->close(api->ctx, handle) == SSH_OK);

    ssh_posix_term_platform_deinit(&term);
    CHECK(ssh_posix_term_api(&term) == NULL);
    return 0;
#endif
}
