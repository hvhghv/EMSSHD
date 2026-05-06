#include "emssh/platform_portable_fs.h"

#include <string.h>

#include "emssh/ssh_error.h"

static int portable_open(void *ctx, const char *path, uint32_t flags, void **handle)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->open == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->open(fs->backend_ctx, path, flags, handle);
}

static int portable_close(void *ctx, void *handle)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->close == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->close(fs->backend_ctx, handle);
}

static int portable_read(void *ctx, void *handle, uint8_t *buf, size_t len, size_t *read_len)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->read == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->read(fs->backend_ctx, handle, buf, len, read_len);
}

static int portable_write(void *ctx, void *handle, const uint8_t *buf, size_t len, size_t *written_len)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->write == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->write(fs->backend_ctx, handle, buf, len, written_len);
}

static int portable_read_at(
    void *ctx,
    void *handle,
    uint64_t offset,
    uint8_t *buf,
    size_t len,
    size_t *read_len)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->read_at == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->read_at(fs->backend_ctx, handle, offset, buf, len, read_len);
}

static int portable_write_at(
    void *ctx,
    void *handle,
    uint64_t offset,
    const uint8_t *buf,
    size_t len,
    size_t *written_len)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->write_at == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->write_at(fs->backend_ctx, handle, offset, buf, len, written_len);
}

static int portable_stat(void *ctx, const char *path, ssh_fs_attrs_t *attrs)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->stat == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->stat(fs->backend_ctx, path, attrs);
}

static int portable_lstat(void *ctx, const char *path, ssh_fs_attrs_t *attrs)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->lstat == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->lstat(fs->backend_ctx, path, attrs);
}

static int portable_setstat(void *ctx, const char *path, const ssh_fs_attrs_t *attrs)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->setstat == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->setstat(fs->backend_ctx, path, attrs);
}

static int portable_fsetstat(void *ctx, void *handle, const ssh_fs_attrs_t *attrs)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->fsetstat == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->fsetstat(fs->backend_ctx, handle, attrs);
}

static int portable_opendir(void *ctx, const char *path, void **handle)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->opendir == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->opendir(fs->backend_ctx, path, handle);
}

static int portable_readdir(void *ctx, void *handle, ssh_fs_dirent_t *entry, int *eof)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->readdir == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->readdir(fs->backend_ctx, handle, entry, eof);
}

static int portable_closedir(void *ctx, void *handle)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->closedir == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->closedir(fs->backend_ctx, handle);
}

static int portable_mkdir(void *ctx, const char *path, const ssh_fs_attrs_t *attrs)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->mkdir == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->mkdir(fs->backend_ctx, path, attrs);
}

static int portable_rmdir(void *ctx, const char *path)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->rmdir == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->rmdir(fs->backend_ctx, path);
}

static int portable_remove(void *ctx, const char *path)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->remove == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->remove(fs->backend_ctx, path);
}

static int portable_rename(void *ctx, const char *old_path, const char *new_path)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->rename == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->rename(fs->backend_ctx, old_path, new_path);
}

static int portable_posix_rename(void *ctx, const char *old_path, const char *new_path)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->posix_rename == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->posix_rename(fs->backend_ctx, old_path, new_path);
}

static int portable_fsync(void *ctx, void *handle)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->fsync == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->fsync(fs->backend_ctx, handle);
}

static int portable_hardlink(void *ctx, const char *old_path, const char *new_path)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->hardlink == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->hardlink(fs->backend_ctx, old_path, new_path);
}

static int portable_statvfs(void *ctx, const char *path, ssh_fs_statvfs_t *stats)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->statvfs == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->statvfs(fs->backend_ctx, path, stats);
}

static int portable_fstatvfs(void *ctx, void *handle, ssh_fs_statvfs_t *stats)
{
    ssh_portable_fs_t *fs = (ssh_portable_fs_t *)ctx;
    if (fs == NULL || fs->ops == NULL || fs->ops->fstatvfs == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    return fs->ops->fstatvfs(fs->backend_ctx, handle, stats);
}

int ssh_portable_fs_init(
    ssh_portable_fs_t *fs,
    const ssh_portable_fs_ops_t *ops,
    void *backend_ctx)
{
    if (fs == NULL || ops == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(fs, 0, sizeof(*fs));
    fs->ops = ops;
    fs->backend_ctx = backend_ctx;
    fs->api.open = portable_open;
    fs->api.close = portable_close;
    fs->api.read = portable_read;
    fs->api.write = portable_write;
    fs->api.read_at = portable_read_at;
    fs->api.write_at = portable_write_at;
    fs->api.stat = portable_stat;
    fs->api.lstat = portable_lstat;
    fs->api.setstat = portable_setstat;
    fs->api.fsetstat = portable_fsetstat;
    fs->api.opendir = portable_opendir;
    fs->api.readdir = portable_readdir;
    fs->api.closedir = portable_closedir;
    fs->api.mkdir = portable_mkdir;
    fs->api.rmdir = portable_rmdir;
    fs->api.remove = portable_remove;
    fs->api.rename = portable_rename;
    fs->api.posix_rename = portable_posix_rename;
    fs->api.fsync = portable_fsync;
    fs->api.hardlink = portable_hardlink;
    fs->api.statvfs = portable_statvfs;
    fs->api.fstatvfs = portable_fstatvfs;
    fs->api.ctx = fs;
    return SSH_OK;
}

void ssh_portable_fs_deinit(ssh_portable_fs_t *fs)
{
    if (fs == NULL) {
        return;
    }
    memset(fs, 0, sizeof(*fs));
}

const ssh_fs_api_t *ssh_portable_fs_api(ssh_portable_fs_t *fs)
{
    if (fs == NULL || fs->ops == NULL) {
        return NULL;
    }
    return &fs->api;
}
