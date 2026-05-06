#ifndef EMSSH_PLATFORM_LITTLEFS_ADAPTER_H
#define EMSSH_PLATFORM_LITTLEFS_ADAPTER_H

#include "emssh/platform_littlefs.h"

typedef struct lfs lfs_t;

typedef struct ssh_littlefs_adapter {
    ssh_littlefs_t fs;
    ssh_littlefs_ops_t ops;
    lfs_t *lfs;
    int initialized;
} ssh_littlefs_adapter_t;

int ssh_littlefs_adapter_init(ssh_littlefs_adapter_t *adapter, lfs_t *lfs);
void ssh_littlefs_adapter_deinit(ssh_littlefs_adapter_t *adapter);
const ssh_fs_api_t *ssh_littlefs_adapter_api(ssh_littlefs_adapter_t *adapter);

#endif
