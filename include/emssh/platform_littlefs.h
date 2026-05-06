#ifndef EMSSH_PLATFORM_LITTLEFS_H
#define EMSSH_PLATFORM_LITTLEFS_H

#include "emssh/platform_portable_fs.h"

typedef ssh_portable_fs_ops_t ssh_littlefs_ops_t;
typedef ssh_portable_fs_t ssh_littlefs_t;

static inline int ssh_littlefs_init(
    ssh_littlefs_t *fs,
    const ssh_littlefs_ops_t *ops,
    void *backend_ctx)
{
    return ssh_portable_fs_init(fs, ops, backend_ctx);
}

static inline void ssh_littlefs_deinit(ssh_littlefs_t *fs)
{
    ssh_portable_fs_deinit(fs);
}

static inline const ssh_fs_api_t *ssh_littlefs_api(ssh_littlefs_t *fs)
{
    return ssh_portable_fs_api(fs);
}

#endif
