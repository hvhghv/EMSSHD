#ifndef EMSSH_PLATFORM_PORTABLE_FS_H
#define EMSSH_PLATFORM_PORTABLE_FS_H

#include "emssh/ssh_platform.h"

typedef struct ssh_portable_fs_ops {
    int (*open)(void *ctx, const char *path, uint32_t flags, void **handle);
    int (*close)(void *ctx, void *handle);
    int (*read)(void *ctx, void *handle, uint8_t *buf, size_t len, size_t *read_len);
    int (*write)(void *ctx, void *handle, const uint8_t *buf, size_t len, size_t *written_len);
    int (*read_at)(void *ctx, void *handle, uint64_t offset, uint8_t *buf, size_t len, size_t *read_len);
    int (*write_at)(void *ctx, void *handle, uint64_t offset, const uint8_t *buf, size_t len, size_t *written_len);
    int (*stat)(void *ctx, const char *path, ssh_fs_attrs_t *attrs);
    int (*lstat)(void *ctx, const char *path, ssh_fs_attrs_t *attrs);
    int (*setstat)(void *ctx, const char *path, const ssh_fs_attrs_t *attrs);
    int (*fsetstat)(void *ctx, void *handle, const ssh_fs_attrs_t *attrs);
    int (*opendir)(void *ctx, const char *path, void **handle);
    int (*readdir)(void *ctx, void *handle, ssh_fs_dirent_t *entry, int *eof);
    int (*closedir)(void *ctx, void *handle);
    int (*mkdir)(void *ctx, const char *path, const ssh_fs_attrs_t *attrs);
    int (*rmdir)(void *ctx, const char *path);
    int (*remove)(void *ctx, const char *path);
    int (*rename)(void *ctx, const char *old_path, const char *new_path);
    int (*posix_rename)(void *ctx, const char *old_path, const char *new_path);
    int (*fsync)(void *ctx, void *handle);
    int (*hardlink)(void *ctx, const char *old_path, const char *new_path);
    int (*statvfs)(void *ctx, const char *path, ssh_fs_statvfs_t *stats);
    int (*fstatvfs)(void *ctx, void *handle, ssh_fs_statvfs_t *stats);
} ssh_portable_fs_ops_t;

typedef struct ssh_portable_fs {
    const ssh_portable_fs_ops_t *ops;
    void *backend_ctx;
    ssh_fs_api_t api;
} ssh_portable_fs_t;

int ssh_portable_fs_init(
    ssh_portable_fs_t *fs,
    const ssh_portable_fs_ops_t *ops,
    void *backend_ctx);
void ssh_portable_fs_deinit(ssh_portable_fs_t *fs);
const ssh_fs_api_t *ssh_portable_fs_api(ssh_portable_fs_t *fs);

#endif
