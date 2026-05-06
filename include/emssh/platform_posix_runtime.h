#ifndef EMSSH_PLATFORM_POSIX_RUNTIME_H
#define EMSSH_PLATFORM_POSIX_RUNTIME_H

#include "emssh/ssh_platform.h"

typedef void (*ssh_posix_log_sink_fn)(void *ctx, ssh_log_level_t level, const char *message);

typedef struct ssh_posix_runtime {
    ssh_mem_api_t mem;
    ssh_time_api_t time;
    ssh_log_api_t log;
    ssh_posix_log_sink_fn sink;
    void *sink_ctx;
    int initialized;
} ssh_posix_runtime_t;

int ssh_posix_runtime_init(
    ssh_posix_runtime_t *runtime,
    ssh_posix_log_sink_fn sink,
    void *sink_ctx);
void ssh_posix_runtime_deinit(ssh_posix_runtime_t *runtime);

const ssh_mem_api_t *ssh_posix_mem_api(ssh_posix_runtime_t *runtime);
const ssh_time_api_t *ssh_posix_time_api(ssh_posix_runtime_t *runtime);
const ssh_log_api_t *ssh_posix_log_api(ssh_posix_runtime_t *runtime);

#endif
