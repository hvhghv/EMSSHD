#include "emssh/platform_fatfs_adapter.h"

#include <stdlib.h>
#include <string.h>

#include "emssh/sftp.h"
#include "emssh/ssh_error.h"

#if defined(_MSC_VER) && !defined(__attribute__)
#define __attribute__(x)
#define EMSSH_FATFS_UNDEF_ATTRIBUTE
#endif

#if defined(_WIN32)
#define EMSSH_FATFS_RESTORE_WIN32 _WIN32
#undef _WIN32
#define EMSSH_FATFS_UNDEF_WIN32
#endif

#include "ff.h"

#if defined(EMSSH_FATFS_UNDEF_WIN32)
#define _WIN32 EMSSH_FATFS_RESTORE_WIN32
#undef EMSSH_FATFS_RESTORE_WIN32
#undef EMSSH_FATFS_UNDEF_WIN32
#endif

#if defined(EMSSH_FATFS_UNDEF_ATTRIBUTE)
#undef __attribute__
#undef EMSSH_FATFS_UNDEF_ATTRIBUTE
#endif

typedef struct fatfs_file_handle {
    FIL file;
} fatfs_file_handle_t;

typedef struct fatfs_dir_handle {
    DIR dir;
    FILINFO info;
    char name[EMSSH_FATFS_ADAPTER_PATH_MAX];
    char longname[EMSSH_FATFS_ADAPTER_PATH_MAX];
} fatfs_dir_handle_t;

static int fatfs_status_from_fresult(FRESULT fr)
{
    switch (fr) {
    case FR_OK:
        return SSH_OK;
    case FR_NO_FILE:
    case FR_NO_PATH:
    case FR_INVALID_NAME:
        return SSH_ERR_NOT_FOUND;
    case FR_EXIST:
        return SSH_ERR_ALREADY_EXISTS;
    case FR_DENIED:
    case FR_WRITE_PROTECTED:
        return SSH_ERR_SECURITY;
    case FR_INVALID_PARAMETER:
        return SSH_ERR_INVALID_ARGUMENT;
    case FR_NOT_READY:
    case FR_DISK_ERR:
    case FR_INT_ERR:
    case FR_INVALID_OBJECT:
    case FR_INVALID_DRIVE:
    case FR_NOT_ENABLED:
    case FR_NO_FILESYSTEM:
    case FR_TIMEOUT:
    case FR_LOCKED:
    case FR_NOT_ENOUGH_CORE:
    case FR_TOO_MANY_OPEN_FILES:
    case FR_MKFS_ABORTED:
    default:
        return SSH_ERR_PLATFORM;
    }
}

static int fatfs_copy_tchar_to_char(char *dst, size_t dst_capacity, const TCHAR *src)
{
    size_t len;

    if (dst == NULL || dst_capacity == 0u || src == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

#if (FF_LFN_UNICODE == 1) || (FF_LFN_UNICODE == 3)
    (void)len;
    (void)src;
    dst[0] = '\0';
    return SSH_ERR_UNSUPPORTED;
#else
    len = strlen((const char *)src);
    if (len + 1u > dst_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(dst, src, len + 1u);
    return SSH_OK;
#endif
}

static int fatfs_build_path(
    const ssh_fatfs_adapter_t *adapter,
    const char *path,
    char *out,
    size_t out_capacity)
{
    const char *relative;
    size_t prefix_len;
    size_t relative_len;
    size_t needed;

    if (adapter == NULL || path == NULL || out == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    relative = path;
    while (*relative == '/') {
        ++relative;
    }

    prefix_len = strlen(adapter->path_prefix);
    relative_len = strlen(relative);
    if (prefix_len == 0u) {
        if (relative_len == 0u) {
            if (out_capacity < 2u) {
                return SSH_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = '/';
            out[1] = '\0';
            return SSH_OK;
        }
        if (relative_len + 1u > out_capacity) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(out, relative, relative_len + 1u);
        return SSH_OK;
    }

    needed = prefix_len + 1u + (relative_len == 0u ? 0u : relative_len) + 1u;
    if (needed > out_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(out, adapter->path_prefix, prefix_len);
    if (adapter->path_prefix[prefix_len - 1u] == '/') {
        if (relative_len == 0u) {
            out[prefix_len] = '\0';
            return SSH_OK;
        }
        memcpy(out + prefix_len, relative, relative_len + 1u);
        return SSH_OK;
    }

    out[prefix_len] = '/';
    if (relative_len == 0u) {
        out[prefix_len + 1u] = '\0';
        return SSH_OK;
    }
    memcpy(out + prefix_len + 1u, relative, relative_len + 1u);
    return SSH_OK;
}

static int fatfs_translate_attrs(const FILINFO *info, ssh_fs_attrs_t *attrs)
{
    uint32_t perms;

    if (info == NULL || attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(attrs, 0, sizeof(*attrs));
    attrs->flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS;
    attrs->size = info->fsize;

    if ((info->fattrib & AM_DIR) != 0u) {
        perms = 0755u;
    } else {
        perms = 0644u;
    }
    if ((info->fattrib & AM_RDO) != 0u) {
        perms &= ~(uint32_t)0222u;
    }
    attrs->permissions = perms;
    return SSH_OK;
}

static int fatfs_open_cb(void *ctx, const char *path, uint32_t flags, void **handle)
{
    ssh_fatfs_adapter_t *adapter = (ssh_fatfs_adapter_t *)ctx;
    fatfs_file_handle_t *file_handle;
    BYTE mode;
    FRESULT fr;
    int status;
    char full_path[EMSSH_FATFS_ADAPTER_PATH_MAX];

    if (adapter == NULL || path == NULL || handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if ((flags & (SSH_FXF_READ | SSH_FXF_WRITE)) == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = fatfs_build_path(adapter, path, full_path, sizeof(full_path));
    if (status != SSH_OK) {
        return status;
    }

    mode = 0u;
    if ((flags & SSH_FXF_READ) != 0u) {
        mode |= FA_READ;
    }
    if ((flags & SSH_FXF_WRITE) != 0u) {
        mode |= FA_WRITE;
    }

    if ((flags & SSH_FXF_CREAT) != 0u && (flags & SSH_FXF_EXCL) != 0u) {
        mode |= FA_CREATE_NEW;
    } else if ((flags & SSH_FXF_CREAT) != 0u && (flags & SSH_FXF_TRUNC) != 0u) {
        mode |= FA_CREATE_ALWAYS;
    } else if ((flags & SSH_FXF_CREAT) != 0u) {
        mode |= FA_OPEN_ALWAYS;
    } else {
        mode |= FA_OPEN_EXISTING;
    }

    file_handle = (fatfs_file_handle_t *)malloc(sizeof(*file_handle));
    if (file_handle == NULL) {
        return SSH_ERR_PLATFORM;
    }
    memset(file_handle, 0, sizeof(*file_handle));

    fr = f_open(&file_handle->file, (const TCHAR *)full_path, mode);
    if (fr != FR_OK) {
        free(file_handle);
        return fatfs_status_from_fresult(fr);
    }

    if ((flags & SSH_FXF_TRUNC) != 0u && (flags & SSH_FXF_CREAT) == 0u) {
        fr = f_lseek(&file_handle->file, 0u);
        if (fr == FR_OK) {
            fr = f_truncate(&file_handle->file);
        }
        if (fr != FR_OK) {
            (void)f_close(&file_handle->file);
            free(file_handle);
            return fatfs_status_from_fresult(fr);
        }
    }

    if ((flags & SSH_FXF_APPEND) != 0u) {
        fr = f_lseek(&file_handle->file, f_size(&file_handle->file));
        if (fr != FR_OK) {
            (void)f_close(&file_handle->file);
            free(file_handle);
            return fatfs_status_from_fresult(fr);
        }
    }

    *handle = file_handle;
    return SSH_OK;
}

static int fatfs_close_cb(void *ctx, void *handle)
{
    fatfs_file_handle_t *file_handle = (fatfs_file_handle_t *)handle;
    FRESULT fr;

    (void)ctx;

    if (file_handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    fr = f_close(&file_handle->file);
    free(file_handle);
    return fatfs_status_from_fresult(fr);
}

static int fatfs_read_cb(void *ctx, void *handle, uint8_t *buf, size_t len, size_t *read_len)
{
    fatfs_file_handle_t *file_handle = (fatfs_file_handle_t *)handle;
    UINT bytes_read;
    FRESULT fr;

    (void)ctx;

    if (file_handle == NULL || (buf == NULL && len != 0u) || read_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    fr = f_read(&file_handle->file, buf, (UINT)len, &bytes_read);
    if (fr != FR_OK) {
        return fatfs_status_from_fresult(fr);
    }
    *read_len = (size_t)bytes_read;
    return SSH_OK;
}

static int fatfs_write_cb(void *ctx, void *handle, const uint8_t *buf, size_t len, size_t *written_len)
{
    fatfs_file_handle_t *file_handle = (fatfs_file_handle_t *)handle;
    UINT bytes_written;
    FRESULT fr;

    (void)ctx;

    if (file_handle == NULL || (buf == NULL && len != 0u) || written_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    fr = f_write(&file_handle->file, buf, (UINT)len, &bytes_written);
    if (fr != FR_OK) {
        return fatfs_status_from_fresult(fr);
    }
    *written_len = (size_t)bytes_written;
    return SSH_OK;
}

static int fatfs_read_at_cb(
    void *ctx,
    void *handle,
    uint64_t offset,
    uint8_t *buf,
    size_t len,
    size_t *read_len)
{
    fatfs_file_handle_t *file_handle = (fatfs_file_handle_t *)handle;
    FRESULT fr;

    (void)ctx;

    if (file_handle == NULL || read_len == NULL || offset > (uint64_t)0xffffffffu) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    fr = f_lseek(&file_handle->file, (FSIZE_t)offset);
    if (fr != FR_OK) {
        return fatfs_status_from_fresult(fr);
    }

    return fatfs_read_cb(ctx, handle, buf, len, read_len);
}

static int fatfs_write_at_cb(
    void *ctx,
    void *handle,
    uint64_t offset,
    const uint8_t *buf,
    size_t len,
    size_t *written_len)
{
    fatfs_file_handle_t *file_handle = (fatfs_file_handle_t *)handle;
    FRESULT fr;

    (void)ctx;

    if (file_handle == NULL || written_len == NULL || offset > (uint64_t)0xffffffffu) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    fr = f_lseek(&file_handle->file, (FSIZE_t)offset);
    if (fr != FR_OK) {
        return fatfs_status_from_fresult(fr);
    }

    return fatfs_write_cb(ctx, handle, buf, len, written_len);
}

static int fatfs_stat_path(ssh_fatfs_adapter_t *adapter, const char *path, ssh_fs_attrs_t *attrs)
{
    FILINFO info;
    FRESULT fr;
    int status;
    char full_path[EMSSH_FATFS_ADAPTER_PATH_MAX];

    status = fatfs_build_path(adapter, path, full_path, sizeof(full_path));
    if (status != SSH_OK) {
        return status;
    }

    memset(&info, 0, sizeof(info));
    fr = f_stat((const TCHAR *)full_path, &info);
    if (fr != FR_OK) {
        return fatfs_status_from_fresult(fr);
    }
    return fatfs_translate_attrs(&info, attrs);
}

static int fatfs_stat_cb(void *ctx, const char *path, ssh_fs_attrs_t *attrs)
{
    return fatfs_stat_path((ssh_fatfs_adapter_t *)ctx, path, attrs);
}

static int fatfs_lstat_cb(void *ctx, const char *path, ssh_fs_attrs_t *attrs)
{
    return fatfs_stat_path((ssh_fatfs_adapter_t *)ctx, path, attrs);
}

static int fatfs_setstat_cb(void *ctx, const char *path, const ssh_fs_attrs_t *attrs)
{
    ssh_fatfs_adapter_t *adapter = (ssh_fatfs_adapter_t *)ctx;
    FRESULT fr;
    FIL file;
    char full_path[EMSSH_FATFS_ADAPTER_PATH_MAX];
    int status;

    if (adapter == NULL || path == NULL || attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if ((attrs->flags & SSH_FILEXFER_ATTR_SIZE) == 0u) {
        return SSH_ERR_UNSUPPORTED;
    }
    if (attrs->size > (uint64_t)0xffffffffu) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = fatfs_build_path(adapter, path, full_path, sizeof(full_path));
    if (status != SSH_OK) {
        return status;
    }

    memset(&file, 0, sizeof(file));
    fr = f_open(&file, (const TCHAR *)full_path, FA_WRITE | FA_OPEN_EXISTING);
    if (fr != FR_OK) {
        return fatfs_status_from_fresult(fr);
    }
    fr = f_lseek(&file, (FSIZE_t)attrs->size);
    if (fr == FR_OK) {
        fr = f_truncate(&file);
    }
    (void)f_close(&file);
    return fatfs_status_from_fresult(fr);
}

static int fatfs_fsetstat_cb(void *ctx, void *handle, const ssh_fs_attrs_t *attrs)
{
    fatfs_file_handle_t *file_handle = (fatfs_file_handle_t *)handle;
    FRESULT fr;

    (void)ctx;

    if (file_handle == NULL || attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if ((attrs->flags & SSH_FILEXFER_ATTR_SIZE) == 0u) {
        return SSH_ERR_UNSUPPORTED;
    }
    if (attrs->size > (uint64_t)0xffffffffu) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    fr = f_lseek(&file_handle->file, (FSIZE_t)attrs->size);
    if (fr == FR_OK) {
        fr = f_truncate(&file_handle->file);
    }
    return fatfs_status_from_fresult(fr);
}

static int fatfs_opendir_cb(void *ctx, const char *path, void **handle)
{
    ssh_fatfs_adapter_t *adapter = (ssh_fatfs_adapter_t *)ctx;
    fatfs_dir_handle_t *dir_handle;
    FRESULT fr;
    int status;
    char full_path[EMSSH_FATFS_ADAPTER_PATH_MAX];

    if (adapter == NULL || path == NULL || handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = fatfs_build_path(adapter, path, full_path, sizeof(full_path));
    if (status != SSH_OK) {
        return status;
    }

    dir_handle = (fatfs_dir_handle_t *)malloc(sizeof(*dir_handle));
    if (dir_handle == NULL) {
        return SSH_ERR_PLATFORM;
    }
    memset(dir_handle, 0, sizeof(*dir_handle));

    fr = f_opendir(&dir_handle->dir, (const TCHAR *)full_path);
    if (fr != FR_OK) {
        free(dir_handle);
        return fatfs_status_from_fresult(fr);
    }

    *handle = dir_handle;
    return SSH_OK;
}

static int fatfs_readdir_cb(void *ctx, void *handle, ssh_fs_dirent_t *entry, int *eof)
{
    fatfs_dir_handle_t *dir_handle = (fatfs_dir_handle_t *)handle;
    int status;
    FRESULT fr;

    (void)ctx;

    if (dir_handle == NULL || entry == NULL || eof == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(&dir_handle->info, 0, sizeof(dir_handle->info));
    fr = f_readdir(&dir_handle->dir, &dir_handle->info);
    if (fr != FR_OK) {
        return fatfs_status_from_fresult(fr);
    }

    if (dir_handle->info.fname[0] == (TCHAR)0) {
        *eof = 1;
        return SSH_OK;
    }

    status = fatfs_copy_tchar_to_char(dir_handle->name, sizeof(dir_handle->name), dir_handle->info.fname);
    if (status != SSH_OK) {
        return status;
    }

#if FF_USE_LFN
    if (dir_handle->info.altname[0] != (TCHAR)0) {
        status = fatfs_copy_tchar_to_char(
            dir_handle->longname,
            sizeof(dir_handle->longname),
            dir_handle->info.altname);
        if (status != SSH_OK) {
            return status;
        }
    } else
#endif
    {
        size_t len = strlen(dir_handle->name);
        if (len + 1u > sizeof(dir_handle->longname)) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(dir_handle->longname, dir_handle->name, len + 1u);
    }

    memset(entry, 0, sizeof(*entry));
    entry->filename = dir_handle->name;
    entry->longname = dir_handle->longname;
    status = fatfs_translate_attrs(&dir_handle->info, &entry->attrs);
    if (status != SSH_OK) {
        return status;
    }
    *eof = 0;
    return SSH_OK;
}

static int fatfs_closedir_cb(void *ctx, void *handle)
{
    fatfs_dir_handle_t *dir_handle = (fatfs_dir_handle_t *)handle;
    FRESULT fr;

    (void)ctx;

    if (dir_handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    fr = f_closedir(&dir_handle->dir);
    free(dir_handle);
    return fatfs_status_from_fresult(fr);
}

static int fatfs_mkdir_cb(void *ctx, const char *path, const ssh_fs_attrs_t *attrs)
{
    ssh_fatfs_adapter_t *adapter = (ssh_fatfs_adapter_t *)ctx;
    FRESULT fr;
    int status;
    char full_path[EMSSH_FATFS_ADAPTER_PATH_MAX];

    (void)attrs;

    if (adapter == NULL || path == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = fatfs_build_path(adapter, path, full_path, sizeof(full_path));
    if (status != SSH_OK) {
        return status;
    }

    fr = f_mkdir((const TCHAR *)full_path);
    return fatfs_status_from_fresult(fr);
}

static int fatfs_rmdir_cb(void *ctx, const char *path)
{
    ssh_fatfs_adapter_t *adapter = (ssh_fatfs_adapter_t *)ctx;
    FRESULT fr;
    int status;
    char full_path[EMSSH_FATFS_ADAPTER_PATH_MAX];

    if (adapter == NULL || path == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = fatfs_build_path(adapter, path, full_path, sizeof(full_path));
    if (status != SSH_OK) {
        return status;
    }

    fr = f_rmdir((const TCHAR *)full_path);
    return fatfs_status_from_fresult(fr);
}

static int fatfs_remove_cb(void *ctx, const char *path)
{
    ssh_fatfs_adapter_t *adapter = (ssh_fatfs_adapter_t *)ctx;
    FRESULT fr;
    int status;
    char full_path[EMSSH_FATFS_ADAPTER_PATH_MAX];

    if (adapter == NULL || path == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = fatfs_build_path(adapter, path, full_path, sizeof(full_path));
    if (status != SSH_OK) {
        return status;
    }

    fr = f_unlink((const TCHAR *)full_path);
    return fatfs_status_from_fresult(fr);
}

static int fatfs_rename_internal(void *ctx, const char *old_path, const char *new_path)
{
    ssh_fatfs_adapter_t *adapter = (ssh_fatfs_adapter_t *)ctx;
    FRESULT fr;
    int status;
    char full_old_path[EMSSH_FATFS_ADAPTER_PATH_MAX];
    char full_new_path[EMSSH_FATFS_ADAPTER_PATH_MAX];

    if (adapter == NULL || old_path == NULL || new_path == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = fatfs_build_path(adapter, old_path, full_old_path, sizeof(full_old_path));
    if (status != SSH_OK) {
        return status;
    }
    status = fatfs_build_path(adapter, new_path, full_new_path, sizeof(full_new_path));
    if (status != SSH_OK) {
        return status;
    }

    fr = f_rename((const TCHAR *)full_old_path, (const TCHAR *)full_new_path);
    return fatfs_status_from_fresult(fr);
}

static int fatfs_rename_cb(void *ctx, const char *old_path, const char *new_path)
{
    return fatfs_rename_internal(ctx, old_path, new_path);
}

static int fatfs_posix_rename_cb(void *ctx, const char *old_path, const char *new_path)
{
    return fatfs_rename_internal(ctx, old_path, new_path);
}

static int fatfs_fsync_cb(void *ctx, void *handle)
{
    fatfs_file_handle_t *file_handle = (fatfs_file_handle_t *)handle;
    FRESULT fr;

    (void)ctx;

    if (file_handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    fr = f_sync(&file_handle->file);
    return fatfs_status_from_fresult(fr);
}

static int fatfs_hardlink_cb(void *ctx, const char *old_path, const char *new_path)
{
    (void)ctx;
    (void)old_path;
    (void)new_path;
    return SSH_ERR_UNSUPPORTED;
}

static int fatfs_statvfs_cb(void *ctx, const char *path, ssh_fs_statvfs_t *stats)
{
    ssh_fatfs_adapter_t *adapter = (ssh_fatfs_adapter_t *)ctx;
    FATFS *fatfs;
    DWORD free_clusters;
    DWORD total_clusters;
    FRESULT fr;
    char query_path[EMSSH_FATFS_ADAPTER_PATH_MAX];
    int status;

    if (adapter == NULL || path == NULL || stats == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = fatfs_build_path(adapter, path, query_path, sizeof(query_path));
    if (status != SSH_OK) {
        return status;
    }

    fr = f_getfree((const TCHAR *)query_path, &free_clusters, &fatfs);
    if (fr != FR_OK) {
        return fatfs_status_from_fresult(fr);
    }

    total_clusters = fatfs->n_fatent > 2u ? fatfs->n_fatent - 2u : 0u;
    memset(stats, 0, sizeof(*stats));
    stats->bsize = FF_MIN_SS;
    stats->frsize = (uint64_t)FF_MIN_SS * (uint64_t)fatfs->csize;
    stats->blocks = total_clusters;
    stats->bfree = free_clusters;
    stats->bavail = free_clusters;
    stats->namemax = FF_LFN_BUF;
    return SSH_OK;
}

static int fatfs_fstatvfs_cb(void *ctx, void *handle, ssh_fs_statvfs_t *stats)
{
    (void)handle;
    return fatfs_statvfs_cb(ctx, "/", stats);
}

int ssh_fatfs_adapter_init(ssh_fatfs_adapter_t *adapter, const char *path_prefix)
{
    int status;
    size_t prefix_len;

    if (adapter == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(adapter, 0, sizeof(*adapter));
    prefix_len = path_prefix != NULL ? strlen(path_prefix) : 0u;
    if (prefix_len >= sizeof(adapter->path_prefix)) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    if (prefix_len != 0u) {
        memcpy(adapter->path_prefix, path_prefix, prefix_len + 1u);
    } else {
        adapter->path_prefix[0] = '\0';
    }

    memset(&adapter->ops, 0, sizeof(adapter->ops));
    adapter->ops.open = fatfs_open_cb;
    adapter->ops.close = fatfs_close_cb;
    adapter->ops.read = fatfs_read_cb;
    adapter->ops.write = fatfs_write_cb;
    adapter->ops.read_at = fatfs_read_at_cb;
    adapter->ops.write_at = fatfs_write_at_cb;
    adapter->ops.stat = fatfs_stat_cb;
    adapter->ops.lstat = fatfs_lstat_cb;
    adapter->ops.setstat = fatfs_setstat_cb;
    adapter->ops.fsetstat = fatfs_fsetstat_cb;
    adapter->ops.opendir = fatfs_opendir_cb;
    adapter->ops.readdir = fatfs_readdir_cb;
    adapter->ops.closedir = fatfs_closedir_cb;
    adapter->ops.mkdir = fatfs_mkdir_cb;
    adapter->ops.rmdir = fatfs_rmdir_cb;
    adapter->ops.remove = fatfs_remove_cb;
    adapter->ops.rename = fatfs_rename_cb;
    adapter->ops.posix_rename = fatfs_posix_rename_cb;
    adapter->ops.fsync = fatfs_fsync_cb;
    adapter->ops.hardlink = fatfs_hardlink_cb;
    adapter->ops.statvfs = fatfs_statvfs_cb;
    adapter->ops.fstatvfs = fatfs_fstatvfs_cb;

    status = ssh_fatfs_init(&adapter->fs, &adapter->ops, adapter);
    if (status != SSH_OK) {
        return status;
    }

    adapter->initialized = 1;
    return SSH_OK;
}

void ssh_fatfs_adapter_deinit(ssh_fatfs_adapter_t *adapter)
{
    if (adapter == NULL) {
        return;
    }
    if (adapter->initialized) {
        ssh_fatfs_deinit(&adapter->fs);
    }
    memset(adapter, 0, sizeof(*adapter));
}

const ssh_fs_api_t *ssh_fatfs_adapter_api(ssh_fatfs_adapter_t *adapter)
{
    if (adapter == NULL || !adapter->initialized) {
        return NULL;
    }
    return ssh_fatfs_api(&adapter->fs);
}
