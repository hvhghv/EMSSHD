#ifndef EMSSH_PLATFORM_FATFS_H
#define EMSSH_PLATFORM_FATFS_H

#include "emssh/platform_portable_fs.h"

typedef ssh_portable_fs_ops_t ssh_fatfs_ops_t;
typedef ssh_portable_fs_t ssh_fatfs_t;

static inline int ssh_fatfs_init(
    ssh_fatfs_t *fs,
    const ssh_fatfs_ops_t *ops,
    void *backend_ctx)
{
    return ssh_portable_fs_init(fs, ops, backend_ctx);
}

static inline void ssh_fatfs_deinit(ssh_fatfs_t *fs)
{
    ssh_portable_fs_deinit(fs);
}

static inline const ssh_fs_api_t *ssh_fatfs_api(ssh_fatfs_t *fs)
{
    return ssh_portable_fs_api(fs);
}

#endif
