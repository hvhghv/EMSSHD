#include "emssh/platform_littlefs_adapter.h"

#include <stdlib.h>
#include <string.h>

#include "emssh/sftp.h"
#include "emssh/ssh_error.h"

#include "lfs.h"

typedef struct littlefs_file_handle {
    lfs_file_t file;
} littlefs_file_handle_t;

typedef struct littlefs_dir_handle {
    lfs_dir_t dir;
    struct lfs_info info;
    char longname[LFS_NAME_MAX + 1];
} littlefs_dir_handle_t;

static int littlefs_status_from_lfs_error(int code)
{
    switch (code) {
    case LFS_ERR_OK:
        return SSH_OK;
    case LFS_ERR_NOENT:
    case LFS_ERR_NOTDIR:
        return SSH_ERR_NOT_FOUND;
    case LFS_ERR_EXIST:
        return SSH_ERR_ALREADY_EXISTS;
    case LFS_ERR_NOTEMPTY:
        return SSH_ERR_DIR_NOT_EMPTY;
    case LFS_ERR_INVAL:
        return SSH_ERR_INVALID_ARGUMENT;
    case LFS_ERR_NOSPC:
    case LFS_ERR_NOMEM:
    case LFS_ERR_NAMETOOLONG:
        return SSH_ERR_PLATFORM;
    case LFS_ERR_ISDIR:
    case LFS_ERR_BADF:
        return SSH_ERR_SECURITY;
    case LFS_ERR_FBIG:
    case LFS_ERR_NOATTR:
    case LFS_ERR_CORRUPT:
    case LFS_ERR_IO:
    default:
        return SSH_ERR_PLATFORM;
    }
}

static const char *littlefs_normalize_path(const char *path, char *scratch, size_t scratch_capacity)
{
    const char *normalized;
    size_t len;

    if (path == NULL || scratch == NULL || scratch_capacity == 0u) {
        return NULL;
    }

    normalized = path;
    while (*normalized == '/') {
        ++normalized;
    }

    if (*normalized == '\0') {
        if (scratch_capacity < 2u) {
            return NULL;
        }
        scratch[0] = '.';
        scratch[1] = '\0';
        return scratch;
    }

    len = strlen(normalized);
    if (len + 1u > scratch_capacity) {
        return NULL;
    }
    memcpy(scratch, normalized, len + 1u);
    return scratch;
}

static int littlefs_fill_attrs(const struct lfs_info *info, ssh_fs_attrs_t *attrs)
{
    if (info == NULL || attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(attrs, 0, sizeof(*attrs));
    attrs->flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS;
    attrs->size = info->size;
    attrs->permissions = info->type == LFS_TYPE_DIR ? 0755u : 0644u;
    return SSH_OK;
}

static int littlefs_open_cb(void *ctx, const char *path, uint32_t flags, void **handle)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    littlefs_file_handle_t *file_handle;
    int lfs_flags;
    int rc;
    char path_scratch[LFS_NAME_MAX + 64];
    const char *normalized;

    if (adapter == NULL || adapter->lfs == NULL || path == NULL || handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if ((flags & (SSH_FXF_READ | SSH_FXF_WRITE)) == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    normalized = littlefs_normalize_path(path, path_scratch, sizeof(path_scratch));
    if (normalized == NULL) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    if ((flags & SSH_FXF_READ) != 0u && (flags & SSH_FXF_WRITE) != 0u) {
        lfs_flags = LFS_O_RDWR;
    } else if ((flags & SSH_FXF_WRITE) != 0u) {
        lfs_flags = LFS_O_WRONLY;
    } else {
        lfs_flags = LFS_O_RDONLY;
    }
    if ((flags & SSH_FXF_CREAT) != 0u) {
        lfs_flags |= LFS_O_CREAT;
    }
    if ((flags & SSH_FXF_TRUNC) != 0u) {
        lfs_flags |= LFS_O_TRUNC;
    }
    if ((flags & SSH_FXF_EXCL) != 0u) {
        lfs_flags |= LFS_O_EXCL;
    }
    if ((flags & SSH_FXF_APPEND) != 0u) {
        lfs_flags |= LFS_O_APPEND;
    }

    file_handle = (littlefs_file_handle_t *)malloc(sizeof(*file_handle));
    if (file_handle == NULL) {
        return SSH_ERR_PLATFORM;
    }
    memset(file_handle, 0, sizeof(*file_handle));

    rc = lfs_file_open(adapter->lfs, &file_handle->file, normalized, lfs_flags);
    if (rc < 0) {
        free(file_handle);
        return littlefs_status_from_lfs_error(rc);
    }

    *handle = file_handle;
    return SSH_OK;
}

static int littlefs_close_cb(void *ctx, void *handle)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    littlefs_file_handle_t *file_handle = (littlefs_file_handle_t *)handle;
    int rc;

    if (adapter == NULL || adapter->lfs == NULL || file_handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    rc = lfs_file_close(adapter->lfs, &file_handle->file);
    free(file_handle);
    return littlefs_status_from_lfs_error(rc);
}

static int littlefs_read_cb(void *ctx, void *handle, uint8_t *buf, size_t len, size_t *read_len)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    littlefs_file_handle_t *file_handle = (littlefs_file_handle_t *)handle;
    lfs_ssize_t n;

    if (adapter == NULL || adapter->lfs == NULL || file_handle == NULL || read_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    n = lfs_file_read(adapter->lfs, &file_handle->file, buf, (lfs_size_t)len);
    if (n < 0) {
        return littlefs_status_from_lfs_error((int)n);
    }
    *read_len = (size_t)n;
    return SSH_OK;
}

static int littlefs_write_cb(void *ctx, void *handle, const uint8_t *buf, size_t len, size_t *written_len)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    littlefs_file_handle_t *file_handle = (littlefs_file_handle_t *)handle;
    lfs_ssize_t n;

    if (adapter == NULL || adapter->lfs == NULL || file_handle == NULL || written_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    n = lfs_file_write(adapter->lfs, &file_handle->file, buf, (lfs_size_t)len);
    if (n < 0) {
        return littlefs_status_from_lfs_error((int)n);
    }
    *written_len = (size_t)n;
    return SSH_OK;
}

static int littlefs_read_at_cb(
    void *ctx,
    void *handle,
    uint64_t offset,
    uint8_t *buf,
    size_t len,
    size_t *read_len)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    littlefs_file_handle_t *file_handle = (littlefs_file_handle_t *)handle;
    lfs_soff_t seek_rc;

    if (adapter == NULL || adapter->lfs == NULL || file_handle == NULL || read_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (offset > (uint64_t)0x7fffffff) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    seek_rc = lfs_file_seek(adapter->lfs, &file_handle->file, (lfs_soff_t)offset, LFS_SEEK_SET);
    if (seek_rc < 0) {
        return littlefs_status_from_lfs_error((int)seek_rc);
    }
    return littlefs_read_cb(ctx, handle, buf, len, read_len);
}

static int littlefs_write_at_cb(
    void *ctx,
    void *handle,
    uint64_t offset,
    const uint8_t *buf,
    size_t len,
    size_t *written_len)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    littlefs_file_handle_t *file_handle = (littlefs_file_handle_t *)handle;
    lfs_soff_t seek_rc;

    if (adapter == NULL || adapter->lfs == NULL || file_handle == NULL || written_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (offset > (uint64_t)0x7fffffff) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    seek_rc = lfs_file_seek(adapter->lfs, &file_handle->file, (lfs_soff_t)offset, LFS_SEEK_SET);
    if (seek_rc < 0) {
        return littlefs_status_from_lfs_error((int)seek_rc);
    }
    return littlefs_write_cb(ctx, handle, buf, len, written_len);
}

static int littlefs_stat_path(ssh_littlefs_adapter_t *adapter, const char *path, ssh_fs_attrs_t *attrs)
{
    struct lfs_info info;
    int rc;
    char path_scratch[LFS_NAME_MAX + 64];
    const char *normalized;

    normalized = littlefs_normalize_path(path, path_scratch, sizeof(path_scratch));
    if (normalized == NULL) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memset(&info, 0, sizeof(info));
    rc = lfs_stat(adapter->lfs, normalized, &info);
    if (rc < 0) {
        return littlefs_status_from_lfs_error(rc);
    }
    return littlefs_fill_attrs(&info, attrs);
}

static int littlefs_stat_cb(void *ctx, const char *path, ssh_fs_attrs_t *attrs)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    if (adapter == NULL || adapter->lfs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    return littlefs_stat_path(adapter, path, attrs);
}

static int littlefs_lstat_cb(void *ctx, const char *path, ssh_fs_attrs_t *attrs)
{
    return littlefs_stat_cb(ctx, path, attrs);
}

static int littlefs_setstat_cb(void *ctx, const char *path, const ssh_fs_attrs_t *attrs)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    littlefs_file_handle_t file_handle;
    int flags;
    int rc;
    char path_scratch[LFS_NAME_MAX + 64];
    const char *normalized;

    if (adapter == NULL || adapter->lfs == NULL || path == NULL || attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if ((attrs->flags & SSH_FILEXFER_ATTR_SIZE) == 0u) {
        return SSH_ERR_UNSUPPORTED;
    }
    if (attrs->size > (uint64_t)0x7fffffff) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    normalized = littlefs_normalize_path(path, path_scratch, sizeof(path_scratch));
    if (normalized == NULL) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memset(&file_handle, 0, sizeof(file_handle));
    flags = LFS_O_WRONLY;
    rc = lfs_file_open(adapter->lfs, &file_handle.file, normalized, flags);
    if (rc < 0) {
        return littlefs_status_from_lfs_error(rc);
    }
    rc = lfs_file_truncate(adapter->lfs, &file_handle.file, (lfs_off_t)attrs->size);
    (void)lfs_file_close(adapter->lfs, &file_handle.file);
    return littlefs_status_from_lfs_error(rc);
}

static int littlefs_fsetstat_cb(void *ctx, void *handle, const ssh_fs_attrs_t *attrs)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    littlefs_file_handle_t *file_handle = (littlefs_file_handle_t *)handle;
    int rc;

    if (adapter == NULL || adapter->lfs == NULL || file_handle == NULL || attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if ((attrs->flags & SSH_FILEXFER_ATTR_SIZE) == 0u) {
        return SSH_ERR_UNSUPPORTED;
    }
    if (attrs->size > (uint64_t)0x7fffffff) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    rc = lfs_file_truncate(adapter->lfs, &file_handle->file, (lfs_off_t)attrs->size);
    return littlefs_status_from_lfs_error(rc);
}

static int littlefs_opendir_cb(void *ctx, const char *path, void **handle)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    littlefs_dir_handle_t *dir_handle;
    int rc;
    char path_scratch[LFS_NAME_MAX + 64];
    const char *normalized;

    if (adapter == NULL || adapter->lfs == NULL || path == NULL || handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    normalized = littlefs_normalize_path(path, path_scratch, sizeof(path_scratch));
    if (normalized == NULL) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    dir_handle = (littlefs_dir_handle_t *)malloc(sizeof(*dir_handle));
    if (dir_handle == NULL) {
        return SSH_ERR_PLATFORM;
    }
    memset(dir_handle, 0, sizeof(*dir_handle));

    rc = lfs_dir_open(adapter->lfs, &dir_handle->dir, normalized);
    if (rc < 0) {
        free(dir_handle);
        return littlefs_status_from_lfs_error(rc);
    }

    *handle = dir_handle;
    return SSH_OK;
}

static int littlefs_readdir_cb(void *ctx, void *handle, ssh_fs_dirent_t *entry, int *eof)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    littlefs_dir_handle_t *dir_handle = (littlefs_dir_handle_t *)handle;
    int rc;
    size_t name_len;

    if (adapter == NULL || adapter->lfs == NULL || dir_handle == NULL || entry == NULL || eof == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(&dir_handle->info, 0, sizeof(dir_handle->info));
    rc = lfs_dir_read(adapter->lfs, &dir_handle->dir, &dir_handle->info);
    if (rc < 0) {
        return littlefs_status_from_lfs_error(rc);
    }
    if (rc == 0) {
        *eof = 1;
        return SSH_OK;
    }

    name_len = strlen(dir_handle->info.name);
    if (name_len + 1u > sizeof(dir_handle->longname)) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(dir_handle->longname, dir_handle->info.name, name_len + 1u);

    memset(entry, 0, sizeof(*entry));
    entry->filename = dir_handle->info.name;
    entry->longname = dir_handle->longname;
    littlefs_fill_attrs(&dir_handle->info, &entry->attrs);
    *eof = 0;
    return SSH_OK;
}

static int littlefs_closedir_cb(void *ctx, void *handle)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    littlefs_dir_handle_t *dir_handle = (littlefs_dir_handle_t *)handle;
    int rc;

    if (adapter == NULL || adapter->lfs == NULL || dir_handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    rc = lfs_dir_close(adapter->lfs, &dir_handle->dir);
    free(dir_handle);
    return littlefs_status_from_lfs_error(rc);
}

static int littlefs_mkdir_cb(void *ctx, const char *path, const ssh_fs_attrs_t *attrs)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    int rc;
    char path_scratch[LFS_NAME_MAX + 64];
    const char *normalized;

    (void)attrs;

    if (adapter == NULL || adapter->lfs == NULL || path == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    normalized = littlefs_normalize_path(path, path_scratch, sizeof(path_scratch));
    if (normalized == NULL) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    rc = lfs_mkdir(adapter->lfs, normalized);
    return littlefs_status_from_lfs_error(rc);
}

static int littlefs_rmdir_cb(void *ctx, const char *path)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    int rc;
    char path_scratch[LFS_NAME_MAX + 64];
    const char *normalized;

    if (adapter == NULL || adapter->lfs == NULL || path == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    normalized = littlefs_normalize_path(path, path_scratch, sizeof(path_scratch));
    if (normalized == NULL) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    rc = lfs_remove(adapter->lfs, normalized);
    return littlefs_status_from_lfs_error(rc);
}

static int littlefs_remove_cb(void *ctx, const char *path)
{
    return littlefs_rmdir_cb(ctx, path);
}

static int littlefs_rename_cb(void *ctx, const char *old_path, const char *new_path)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    int rc;
    char old_scratch[LFS_NAME_MAX + 64];
    char new_scratch[LFS_NAME_MAX + 64];
    const char *old_normalized;
    const char *new_normalized;

    if (adapter == NULL || adapter->lfs == NULL || old_path == NULL || new_path == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    old_normalized = littlefs_normalize_path(old_path, old_scratch, sizeof(old_scratch));
    new_normalized = littlefs_normalize_path(new_path, new_scratch, sizeof(new_scratch));
    if (old_normalized == NULL || new_normalized == NULL) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    rc = lfs_rename(adapter->lfs, old_normalized, new_normalized);
    return littlefs_status_from_lfs_error(rc);
}

static int littlefs_posix_rename_cb(void *ctx, const char *old_path, const char *new_path)
{
    return littlefs_rename_cb(ctx, old_path, new_path);
}

static int littlefs_fsync_cb(void *ctx, void *handle)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    littlefs_file_handle_t *file_handle = (littlefs_file_handle_t *)handle;
    int rc;

    if (adapter == NULL || adapter->lfs == NULL || file_handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    rc = lfs_file_sync(adapter->lfs, &file_handle->file);
    return littlefs_status_from_lfs_error(rc);
}

static int littlefs_hardlink_cb(void *ctx, const char *old_path, const char *new_path)
{
    (void)ctx;
    (void)old_path;
    (void)new_path;
    return SSH_ERR_UNSUPPORTED;
}

static int littlefs_statvfs_cb(void *ctx, const char *path, ssh_fs_statvfs_t *stats)
{
    ssh_littlefs_adapter_t *adapter = (ssh_littlefs_adapter_t *)ctx;
    struct lfs_fsinfo info;
    int rc;

    (void)path;

    if (adapter == NULL || adapter->lfs == NULL || stats == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(&info, 0, sizeof(info));
    rc = lfs_fs_stat(adapter->lfs, &info);
    if (rc < 0) {
        return littlefs_status_from_lfs_error(rc);
    }

    memset(stats, 0, sizeof(*stats));
    stats->bsize = info.block_size;
    stats->frsize = info.block_size;
    stats->blocks = info.block_count;
    stats->namemax = info.name_max;
    return SSH_OK;
}

static int littlefs_fstatvfs_cb(void *ctx, void *handle, ssh_fs_statvfs_t *stats)
{
    (void)handle;
    return littlefs_statvfs_cb(ctx, "/", stats);
}

int ssh_littlefs_adapter_init(ssh_littlefs_adapter_t *adapter, lfs_t *lfs)
{
    int status;

    if (adapter == NULL || lfs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(adapter, 0, sizeof(*adapter));
    adapter->lfs = lfs;

    memset(&adapter->ops, 0, sizeof(adapter->ops));
    adapter->ops.open = littlefs_open_cb;
    adapter->ops.close = littlefs_close_cb;
    adapter->ops.read = littlefs_read_cb;
    adapter->ops.write = littlefs_write_cb;
    adapter->ops.read_at = littlefs_read_at_cb;
    adapter->ops.write_at = littlefs_write_at_cb;
    adapter->ops.stat = littlefs_stat_cb;
    adapter->ops.lstat = littlefs_lstat_cb;
    adapter->ops.setstat = littlefs_setstat_cb;
    adapter->ops.fsetstat = littlefs_fsetstat_cb;
    adapter->ops.opendir = littlefs_opendir_cb;
    adapter->ops.readdir = littlefs_readdir_cb;
    adapter->ops.closedir = littlefs_closedir_cb;
    adapter->ops.mkdir = littlefs_mkdir_cb;
    adapter->ops.rmdir = littlefs_rmdir_cb;
    adapter->ops.remove = littlefs_remove_cb;
    adapter->ops.rename = littlefs_rename_cb;
    adapter->ops.posix_rename = littlefs_posix_rename_cb;
    adapter->ops.fsync = littlefs_fsync_cb;
    adapter->ops.hardlink = littlefs_hardlink_cb;
    adapter->ops.statvfs = littlefs_statvfs_cb;
    adapter->ops.fstatvfs = littlefs_fstatvfs_cb;

    status = ssh_littlefs_init(&adapter->fs, &adapter->ops, adapter);
    if (status != SSH_OK) {
        return status;
    }

    adapter->initialized = 1;
    return SSH_OK;
}

void ssh_littlefs_adapter_deinit(ssh_littlefs_adapter_t *adapter)
{
    if (adapter == NULL) {
        return;
    }
    if (adapter->initialized) {
        ssh_littlefs_deinit(&adapter->fs);
    }
    memset(adapter, 0, sizeof(*adapter));
}

const ssh_fs_api_t *ssh_littlefs_adapter_api(ssh_littlefs_adapter_t *adapter)
{
    if (adapter == NULL || !adapter->initialized) {
        return NULL;
    }
    return ssh_littlefs_api(&adapter->fs);
}
