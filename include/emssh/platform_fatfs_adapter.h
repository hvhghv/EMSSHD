#ifndef EMSSH_PLATFORM_FATFS_ADAPTER_H
#define EMSSH_PLATFORM_FATFS_ADAPTER_H

#include "emssh/platform_fatfs.h"

#ifndef EMSSH_FATFS_ADAPTER_PATH_MAX
#define EMSSH_FATFS_ADAPTER_PATH_MAX 256u
#endif

typedef struct ssh_fatfs_adapter {
    ssh_fatfs_t fs;
    ssh_fatfs_ops_t ops;
    char path_prefix[EMSSH_FATFS_ADAPTER_PATH_MAX];
    int initialized;
} ssh_fatfs_adapter_t;

int ssh_fatfs_adapter_init(ssh_fatfs_adapter_t *adapter, const char *path_prefix);
void ssh_fatfs_adapter_deinit(ssh_fatfs_adapter_t *adapter);
const ssh_fs_api_t *ssh_fatfs_adapter_api(ssh_fatfs_adapter_t *adapter);

#endif
