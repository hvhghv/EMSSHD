#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#include "emssh/platform_freertos.h"
#include "emssh/ssh_error.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

typedef struct log_capture {
    int calls;
    ssh_log_level_t last_level;
    char last_message[128];
} log_capture_t;

static size_t g_alloc_calls = 0u;
static size_t g_free_calls = 0u;
static TickType_t g_tick_count = 0;

void *pvPortMalloc(size_t xSize)
{
    g_alloc_calls++;
    return malloc(xSize);
}

void vPortFree(void *pv)
{
    g_free_calls++;
    free(pv);
}

TickType_t xTaskGetTickCount(void)
{
    return g_tick_count;
}

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
    ssh_freertos_runtime_t runtime;
    log_capture_t capture;
    const ssh_mem_api_t *mem;
    const ssh_time_api_t *time_api;
    const ssh_log_api_t *log_api;
    uint8_t *p;
    uint8_t zero[8];
    uint64_t expected_ms;

    memset(&runtime, 0, sizeof(runtime));
    memset(&capture, 0, sizeof(capture));
    memset(zero, 0, sizeof(zero));

    CHECK(ssh_freertos_runtime_init(NULL, capture_sink, &capture) == SSH_ERR_INVALID_ARGUMENT);
    CHECK(ssh_freertos_runtime_init(&runtime, capture_sink, &capture) == SSH_OK);

    mem = ssh_freertos_mem_api(&runtime);
    time_api = ssh_freertos_time_api(&runtime);
    log_api = ssh_freertos_log_api(&runtime);
    CHECK(mem != NULL);
    CHECK(time_api != NULL);
    CHECK(log_api != NULL);

    p = (uint8_t *)mem->alloc(mem->ctx, 8u);
    CHECK(p != NULL);
    memset(p, 0xa5, 8u);
    mem->secure_zero(mem->ctx, p, 8u);
    CHECK(memcmp(p, zero, 8u) == 0);
    mem->free(mem->ctx, p);
    CHECK(g_alloc_calls == 1u);
    CHECK(g_free_calls == 1u);

    g_tick_count = (TickType_t)123;
#if (portTICK_PERIOD_MS > 0)
    expected_ms = (uint64_t)g_tick_count * (uint64_t)portTICK_PERIOD_MS;
#else
    expected_ms = (uint64_t)g_tick_count;
#endif
    CHECK(time_api->monotonic_ms(time_api->ctx) == expected_ms);

    log_api->write(log_api->ctx, SSH_LOG_WARN, "freertos runtime ok");
    CHECK(capture.calls == 1);
    CHECK(capture.last_level == SSH_LOG_WARN);
    CHECK(strcmp(capture.last_message, "freertos runtime ok") == 0);

    ssh_freertos_runtime_deinit(&runtime);
    CHECK(ssh_freertos_mem_api(&runtime) == NULL);
    CHECK(ssh_freertos_time_api(&runtime) == NULL);
    CHECK(ssh_freertos_log_api(&runtime) == NULL);

    return 0;
}
