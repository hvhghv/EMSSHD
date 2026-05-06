#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "emssh/platform_posix_runtime.h"
#include "emssh/ssh_error.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

#if defined(_WIN32) && !defined(__CYGWIN__) && !defined(__MINGW32__) && !defined(__MINGW64__)
#define EMSSH_TEST_NATIVE_WIN32 1
#else
#define EMSSH_TEST_NATIVE_WIN32 0
#endif

typedef struct log_capture {
    int calls;
    ssh_log_level_t last_level;
    char last_message[128];
} log_capture_t;

static void capture_sink(void *ctx, ssh_log_level_t level, const char *message)
{
    log_capture_t *capture = (log_capture_t *)ctx;
    size_t len;

    if (capture == NULL || message == NULL) {
        return;
    }

    capture->calls++;
    capture->last_level = level;
    len = strlen(message);
    if (len >= sizeof(capture->last_message)) {
        len = sizeof(capture->last_message) - 1u;
    }
    memcpy(capture->last_message, message, len);
    capture->last_message[len] = '\0';
}

int main(void)
{
    ssh_posix_runtime_t runtime;
    log_capture_t capture;
    const ssh_mem_api_t *mem;
    const ssh_time_api_t *time_api;
    const ssh_log_api_t *log_api;
    void *p;
    uint64_t t0;
    uint64_t t1;
    uint8_t bytes[8];
    uint8_t zero[8];

    memset(&runtime, 0, sizeof(runtime));
    memset(&capture, 0, sizeof(capture));
    memset(zero, 0, sizeof(zero));

    CHECK(ssh_posix_runtime_init(NULL, capture_sink, &capture) == SSH_ERR_INVALID_ARGUMENT);

#if EMSSH_TEST_NATIVE_WIN32
    CHECK(ssh_posix_runtime_init(&runtime, capture_sink, &capture) == SSH_ERR_UNSUPPORTED);
    CHECK(ssh_posix_mem_api(&runtime) == NULL);
    CHECK(ssh_posix_time_api(&runtime) == NULL);
    CHECK(ssh_posix_log_api(&runtime) == NULL);
    ssh_posix_runtime_deinit(&runtime);
#else
    CHECK(ssh_posix_runtime_init(&runtime, capture_sink, &capture) == SSH_OK);

    mem = ssh_posix_mem_api(&runtime);
    time_api = ssh_posix_time_api(&runtime);
    log_api = ssh_posix_log_api(&runtime);
    CHECK(mem != NULL);
    CHECK(time_api != NULL);
    CHECK(log_api != NULL);
    CHECK(mem->alloc != NULL);
    CHECK(mem->free != NULL);
    CHECK(mem->secure_zero != NULL);
    CHECK(time_api->monotonic_ms != NULL);
    CHECK(log_api->write != NULL);

    p = mem->alloc(mem->ctx, sizeof(bytes));
    CHECK(p != NULL);
    memset(p, 0xa5, sizeof(bytes));
    mem->secure_zero(mem->ctx, p, sizeof(bytes));
    CHECK(memcmp(p, zero, sizeof(zero)) == 0);
    mem->free(mem->ctx, p);

    t0 = time_api->monotonic_ms(time_api->ctx);
    t1 = time_api->monotonic_ms(time_api->ctx);
    CHECK(t1 >= t0);

    log_api->write(log_api->ctx, SSH_LOG_INFO, "posix runtime ok");
    CHECK(capture.calls == 1);
    CHECK(capture.last_level == SSH_LOG_INFO);
    CHECK(strcmp(capture.last_message, "posix runtime ok") == 0);

    ssh_posix_runtime_deinit(&runtime);
    CHECK(ssh_posix_mem_api(&runtime) == NULL);
    CHECK(ssh_posix_time_api(&runtime) == NULL);
    CHECK(ssh_posix_log_api(&runtime) == NULL);
#endif

    return 0;
}
