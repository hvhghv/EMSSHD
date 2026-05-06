#include "emssh/platform_posix_runtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "emssh/ssh_error.h"

static void *posix_alloc(void *ctx, size_t size)
{
    (void)ctx;
    if (size == 0u) {
        return NULL;
    }
    return malloc(size);
}

static void posix_free(void *ctx, void *ptr)
{
    (void)ctx;
    free(ptr);
}

static void posix_secure_zero(void *ctx, void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    size_t i;

    (void)ctx;
    if (p == NULL) {
        return;
    }

    for (i = 0u; i < len; ++i) {
        p[i] = 0u;
    }
}

static uint64_t posix_monotonic_ms(void *ctx)
{
    struct timespec ts;

    (void)ctx;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0u;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000u);
}

static const char *posix_log_level_name(ssh_log_level_t level)
{
    switch (level) {
    case SSH_LOG_ERROR:
        return "ERROR";
    case SSH_LOG_WARN:
        return "WARN";
    case SSH_LOG_INFO:
        return "INFO";
    case SSH_LOG_DEBUG:
        return "DEBUG";
    case SSH_LOG_TRACE:
        return "TRACE";
    default:
        return "UNKNOWN";
    }
}

static void posix_log_write(void *ctx, ssh_log_level_t level, const char *message)
{
    ssh_posix_runtime_t *runtime = (ssh_posix_runtime_t *)ctx;

    if (runtime == NULL || !runtime->initialized || message == NULL) {
        return;
    }

    if (runtime->sink != NULL) {
        runtime->sink(runtime->sink_ctx, level, message);
        return;
    }

    fprintf(stderr, "[emssh][%s] %s\n", posix_log_level_name(level), message);
}

int ssh_posix_runtime_init(
    ssh_posix_runtime_t *runtime,
    ssh_posix_log_sink_fn sink,
    void *sink_ctx)
{
    if (runtime == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(runtime, 0, sizeof(*runtime));
    runtime->sink = sink;
    runtime->sink_ctx = sink_ctx;

    runtime->mem.alloc = posix_alloc;
    runtime->mem.free = posix_free;
    runtime->mem.secure_zero = posix_secure_zero;
    runtime->mem.ctx = runtime;

    runtime->time.monotonic_ms = posix_monotonic_ms;
    runtime->time.ctx = runtime;

    runtime->log.write = posix_log_write;
    runtime->log.ctx = runtime;

    runtime->initialized = 1;
    return SSH_OK;
}

void ssh_posix_runtime_deinit(ssh_posix_runtime_t *runtime)
{
    if (runtime == NULL) {
        return;
    }
    memset(runtime, 0, sizeof(*runtime));
}

const ssh_mem_api_t *ssh_posix_mem_api(ssh_posix_runtime_t *runtime)
{
    if (runtime == NULL || !runtime->initialized) {
        return NULL;
    }
    return &runtime->mem;
}

const ssh_time_api_t *ssh_posix_time_api(ssh_posix_runtime_t *runtime)
{
    if (runtime == NULL || !runtime->initialized) {
        return NULL;
    }
    return &runtime->time;
}

const ssh_log_api_t *ssh_posix_log_api(ssh_posix_runtime_t *runtime)
{
    if (runtime == NULL || !runtime->initialized) {
        return NULL;
    }
    return &runtime->log;
}
