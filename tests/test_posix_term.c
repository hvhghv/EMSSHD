#include <stdio.h>
#include <string.h>

#include "emssh/platform_posix_term.h"
#include "emssh/ssh_error.h"

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
    status = api->spawn_exec(api->ctx, "tester", "true", "xterm-256color", 80u, 24u, 0u, 0u, &handle);
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
    }
    CHECK(exited);
    CHECK(exit_code == 0u);

    CHECK(api->close(api->ctx, handle) == SSH_OK);
    ssh_posix_term_platform_deinit(&term);
    CHECK(ssh_posix_term_api(&term) == NULL);
    return 0;
#endif
}
