#include "emssh/platform_freertos.h"

#include <string.h>

#include "emssh/ssh_error.h"

#include "FreeRTOS.h"
#include "task.h"

static void *freertos_alloc(void *ctx, size_t size)
{
    (void)ctx;
    if (size == 0u) {
        return NULL;
    }
    return pvPortMalloc(size);
}

static void freertos_free(void *ctx, void *ptr)
{
    (void)ctx;
    if (ptr == NULL) {
        return;
    }
    vPortFree(ptr);
}

static void freertos_secure_zero(void *ctx, void *ptr, size_t len)
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

static uint64_t freertos_monotonic_ms(void *ctx)
{
    TickType_t ticks;
    uint64_t tick_ms;

    (void)ctx;
    ticks = xTaskGetTickCount();
#if (portTICK_PERIOD_MS > 0)
    tick_ms = (uint64_t)portTICK_PERIOD_MS;
#else
    tick_ms = 1u;
#endif
    return ((uint64_t)ticks) * tick_ms;
}

static const char *freertos_level_name(ssh_log_level_t level)
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

static void freertos_log_write(void *ctx, ssh_log_level_t level, const char *message)
{
    ssh_freertos_runtime_t *runtime = (ssh_freertos_runtime_t *)ctx;

    if (runtime == NULL || !runtime->initialized || message == NULL) {
        return;
    }

    if (runtime->sink != NULL) {
        runtime->sink(runtime->sink_ctx, level, message);
        return;
    }

}

int ssh_freertos_runtime_init(
    ssh_freertos_runtime_t *runtime,
    ssh_freertos_log_sink_fn sink,
    void *sink_ctx)
{
    if (runtime == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(runtime, 0, sizeof(*runtime));
    runtime->sink = sink;
    runtime->sink_ctx = sink_ctx;

    runtime->mem.alloc = freertos_alloc;
    runtime->mem.free = freertos_free;
    runtime->mem.secure_zero = freertos_secure_zero;
    runtime->mem.ctx = runtime;

    runtime->time.monotonic_ms = freertos_monotonic_ms;
    runtime->time.ctx = runtime;

    runtime->log.write = freertos_log_write;
    runtime->log.ctx = runtime;
    runtime->initialized = 1;
    return SSH_OK;
}

void ssh_freertos_runtime_deinit(ssh_freertos_runtime_t *runtime)
{
    if (runtime == NULL) {
        return;
    }
    memset(runtime, 0, sizeof(*runtime));
}

const ssh_mem_api_t *ssh_freertos_mem_api(ssh_freertos_runtime_t *runtime)
{
    if (runtime == NULL || !runtime->initialized) {
        return NULL;
    }
    return &runtime->mem;
}

const ssh_time_api_t *ssh_freertos_time_api(ssh_freertos_runtime_t *runtime)
{
    if (runtime == NULL || !runtime->initialized) {
        return NULL;
    }
    return &runtime->time;
}

const ssh_log_api_t *ssh_freertos_log_api(ssh_freertos_runtime_t *runtime)
{
    if (runtime == NULL || !runtime->initialized) {
        return NULL;
    }
    return &runtime->log;
}
