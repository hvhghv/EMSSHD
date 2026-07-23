#include "emssh/platform_stdio_fs.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <sys/stat.h>
#include <sys/utime.h>
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <utime.h>
#include <unistd.h>
#endif

#include "emssh/sftp.h"
#include "emssh/ssh_error.h"

typedef struct stdio_file_handle {
    FILE *file;
    char path[EMSSH_STDIO_FS_MAX_PATH];
    int append;
} stdio_file_handle_t;

typedef struct stdio_dir_handle {
#ifdef _WIN32
    intptr_t find_handle;
    struct _finddata_t find_data;
    int first_ready;
#else
    DIR *dir;
#endif
    char path[EMSSH_STDIO_FS_MAX_PATH];
    char name[EMSSH_STDIO_FS_MAX_PATH];
    char longname[EMSSH_STDIO_FS_MAX_PATH];
} stdio_dir_handle_t;

static int error_to_status(void)
{
#ifdef ENOSPC
    if (errno == ENOSPC) {
        return SSH_ERR_BUFFER_OVERFLOW;
    }
#endif
#ifdef EDQUOT
    if (errno == EDQUOT) {
        return SSH_ERR_BUFFER_OVERFLOW;
    }
#endif
#ifdef EFBIG
    if (errno == EFBIG) {
        return SSH_ERR_BUFFER_OVERFLOW;
    }
#endif
    if (errno == ENOENT
#ifdef ENOTDIR
        || errno == ENOTDIR
#endif
    ) {
        return SSH_ERR_NOT_FOUND;
    }
    if (errno == EEXIST) {
        return SSH_ERR_ALREADY_EXISTS;
    }
#ifdef ENOTEMPTY
    if (errno == ENOTEMPTY) {
        return SSH_ERR_DIR_NOT_EMPTY;
    }
#endif
#ifdef EROFS
    if (errno == EROFS) {
        return SSH_ERR_READ_ONLY;
    }
#endif
    if (errno == EACCES || errno == EPERM) {
        return SSH_ERR_SECURITY;
    }
    return SSH_ERR_PLATFORM;
}

#ifdef _WIN32
static int windows_error_to_status(DWORD error)
{
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
        return SSH_ERR_NOT_FOUND;
    }
    if (error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS) {
        return SSH_ERR_ALREADY_EXISTS;
    }
    if (error == ERROR_DIR_NOT_EMPTY) {
        return SSH_ERR_DIR_NOT_EMPTY;
    }
    if (error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION) {
        return SSH_ERR_SECURITY;
    }
    return SSH_ERR_PLATFORM;
}
#endif

static int path_is_safe(const char *path)
{
    const char *p;
    int segment_start;

    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    if (path[0] == '\\' || strchr(path, ':') != NULL) {
        return 0;
    }

    p = path;
    segment_start = 1;
    while (*p != '\0') {
        if (*p == '\\') {
            return 0;
        }
        if (segment_start && p[0] == '.' && p[1] == '.' && (p[2] == '\0' || p[2] == '/')) {
            return 0;
        }
        segment_start = *p == '/';
        ++p;
    }

    return 1;
}

static int resolve_path(ssh_stdio_fs_t *fs, const char *path, char out[EMSSH_STDIO_FS_MAX_PATH])
{
    const char *relative;
    size_t root_len;
    size_t rel_len;
    int needs_sep;
    int written;

    if (fs == NULL || path == NULL || out == NULL || !path_is_safe(path)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    relative = path;
    while (*relative == '/') {
        ++relative;
    }
    if (relative[0] == '\0' || (relative[0] == '.' && relative[1] == '\0')) {
        relative = "";
    }

    root_len = strlen(fs->root);
    rel_len = strlen(relative);
    needs_sep = root_len != 0u && rel_len != 0u &&
                fs->root[root_len - 1u] != '/' && fs->root[root_len - 1u] != '\\';

    written = snprintf(out, EMSSH_STDIO_FS_MAX_PATH, "%s%s%s", fs->root, needs_sep ? "/" : "", relative);
    if (written < 0 || (size_t)written >= EMSSH_STDIO_FS_MAX_PATH) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    return SSH_OK;
}

static int stat_path(const char *path, ssh_fs_attrs_t *attrs)
{
#ifdef _WIN32
    struct _stat64 st;
    if (_stat64(path, &st) != 0) {
        return error_to_status();
    }
#else
    struct stat st;
    if (stat(path, &st) != 0) {
        return error_to_status();
    }
#endif

    memset(attrs, 0, sizeof(*attrs));
    attrs->flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME;
    attrs->size = (uint64_t)st.st_size;
#ifndef _WIN32
    attrs->flags |= SSH_FILEXFER_ATTR_UIDGID;
    attrs->uid = (uint32_t)st.st_uid;
    attrs->gid = (uint32_t)st.st_gid;
#endif
    attrs->permissions = (uint32_t)st.st_mode;
    attrs->atime = (uint32_t)st.st_atime;
    attrs->mtime = (uint32_t)st.st_mtime;
    return SSH_OK;
}

#ifndef _WIN32
static int lstat_path(const char *path, ssh_fs_attrs_t *attrs)
{
    struct stat st;

    if (lstat(path, &st) != 0) {
        return error_to_status();
    }

    memset(attrs, 0, sizeof(*attrs));
    attrs->flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID |
                   SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME;
    attrs->size = (uint64_t)st.st_size;
    attrs->uid = (uint32_t)st.st_uid;
    attrs->gid = (uint32_t)st.st_gid;
    attrs->permissions = (uint32_t)st.st_mode;
    attrs->atime = (uint32_t)st.st_atime;
    attrs->mtime = (uint32_t)st.st_mtime;
    return SSH_OK;
}
#endif

static int join_path_child(
    const char *parent,
    const char *child,
    char out[EMSSH_STDIO_FS_MAX_PATH])
{
    size_t parent_len;
    int needs_sep;
    int written;

    if (parent == NULL || child == NULL || out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    parent_len = strlen(parent);
    needs_sep = parent_len != 0u && parent[parent_len - 1u] != '/' && parent[parent_len - 1u] != '\\';
    written = snprintf(out, EMSSH_STDIO_FS_MAX_PATH, "%s%s%s", parent, needs_sep ? "/" : "", child);
    if (written < 0 || (size_t)written >= EMSSH_STDIO_FS_MAX_PATH) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    return SSH_OK;
}

static int resolved_path_exists(const char *path)
{
#ifdef _WIN32
    struct _stat st;
    return _stat(path, &st) == 0;
#else
    struct stat st;
    return stat(path, &st) == 0;
#endif
}

static int statvfs_path(const char *path, ssh_fs_statvfs_t *stats)
{
    if (path == NULL || stats == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(stats, 0, sizeof(*stats));
#ifdef _WIN32
    {
        char volume[EMSSH_STDIO_FS_MAX_PATH];
        ULARGE_INTEGER free_available;
        ULARGE_INTEGER total_bytes;
        ULARGE_INTEGER free_total;
        DWORD sectors_per_cluster;
        DWORD bytes_per_sector;
        DWORD free_clusters;
        DWORD total_clusters;
        DWORD max_component_len;
        DWORD fs_flags;
        uint64_t block_size;

        if (!GetVolumePathNameA(path, volume, (DWORD)sizeof(volume))) {
            return windows_error_to_status(GetLastError());
        }
        if (!GetDiskFreeSpaceA(volume, &sectors_per_cluster, &bytes_per_sector, &free_clusters, &total_clusters)) {
            return windows_error_to_status(GetLastError());
        }
        if (!GetDiskFreeSpaceExA(volume, &free_available, &total_bytes, &free_total)) {
            return windows_error_to_status(GetLastError());
        }

        block_size = (uint64_t)sectors_per_cluster * (uint64_t)bytes_per_sector;
        if (block_size == 0u) {
            return SSH_ERR_PLATFORM;
        }

        stats->bsize = block_size;
        stats->frsize = block_size;
        stats->blocks = total_bytes.QuadPart / block_size;
        stats->bfree = free_total.QuadPart / block_size;
        stats->bavail = free_available.QuadPart / block_size;
        stats->fsid = 0u;
        stats->flag = 0u;
        stats->namemax = 255u;
        if (GetVolumeInformationA(volume, NULL, 0u, NULL, &max_component_len, &fs_flags, NULL, 0u)) {
            stats->namemax = max_component_len;
            if ((fs_flags & FILE_READ_ONLY_VOLUME) != 0u) {
                stats->flag |= 1u;
            }
        }
    }
#else
    {
        struct statvfs st;
        if (statvfs(path, &st) != 0) {
            return error_to_status();
        }

        stats->bsize = (uint64_t)st.f_bsize;
        stats->frsize = (uint64_t)st.f_frsize;
        stats->blocks = (uint64_t)st.f_blocks;
        stats->bfree = (uint64_t)st.f_bfree;
        stats->bavail = (uint64_t)st.f_bavail;
        stats->files = (uint64_t)st.f_files;
        stats->ffree = (uint64_t)st.f_ffree;
        stats->favail = (uint64_t)st.f_favail;
        stats->fsid = (uint64_t)st.f_fsid;
        stats->flag = (uint64_t)st.f_flag;
        stats->namemax = (uint64_t)st.f_namemax;
    }
#endif
    return SSH_OK;
}

static int open_flags_are_valid(uint32_t flags)
{
    uint32_t known_flags = SSH_FXF_READ | SSH_FXF_WRITE | SSH_FXF_APPEND | SSH_FXF_CREAT | SSH_FXF_TRUNC | SSH_FXF_EXCL;
    uint32_t write_only_flags = SSH_FXF_APPEND | SSH_FXF_CREAT | SSH_FXF_TRUNC | SSH_FXF_EXCL;

    if ((flags & ~known_flags) != 0u) {
        return 0;
    }
    if ((flags & (SSH_FXF_READ | SSH_FXF_WRITE)) == 0u) {
        return 0;
    }
    if ((flags & write_only_flags) != 0u && (flags & SSH_FXF_WRITE) == 0u) {
        return 0;
    }
    if ((flags & SSH_FXF_EXCL) != 0u && (flags & SSH_FXF_CREAT) == 0u) {
        return 0;
    }

    return 1;
}

static int stdio_open(void *ctx, const char *path, uint32_t flags, void **handle)
{
    ssh_stdio_fs_t *fs = (ssh_stdio_fs_t *)ctx;
    stdio_file_handle_t *file_handle;
    char resolved[EMSSH_STDIO_FS_MAX_PATH];
    const char *mode = NULL;
    int create;
    int truncate;
    int excl;
    int append;
    ssh_fs_attrs_t existing_attrs;
    int status;

    if (handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *handle = NULL;
    status = resolve_path(fs, path, resolved);
    if (status != SSH_OK) {
        return status;
    }
    if (!open_flags_are_valid(flags)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    create = (flags & SSH_FXF_CREAT) != 0u;
    truncate = (flags & SSH_FXF_TRUNC) != 0u;
    excl = (flags & SSH_FXF_EXCL) != 0u;
    append = (flags & SSH_FXF_APPEND) != 0u;

    if (excl && !create) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (excl) {
        status = stat_path(resolved, &existing_attrs);
        if (status == SSH_OK) {
            return SSH_ERR_ALREADY_EXISTS;
        }
        if (status != SSH_ERR_NOT_FOUND) {
            return status;
        }
    }

    if (truncate) {
        mode = "w+b";
    } else if ((flags & SSH_FXF_WRITE) != 0u) {
        mode = "r+b";
    } else {
        mode = "rb";
    }

    file_handle = (stdio_file_handle_t *)calloc(1u, sizeof(*file_handle));
    if (file_handle == NULL) {
        return SSH_ERR_PLATFORM;
    }

    file_handle->file = fopen(resolved, mode);
    if (file_handle->file == NULL && create && !truncate && errno == ENOENT) {
        file_handle->file = fopen(resolved, "w+b");
    }
    if (file_handle->file == NULL) {
        free(file_handle);
        return error_to_status();
    }

    snprintf(file_handle->path, sizeof(file_handle->path), "%s", resolved);
    file_handle->append = append;
    *handle = file_handle;
    return SSH_OK;
}

static int stdio_close(void *ctx, void *handle)
{
    stdio_file_handle_t *file_handle = (stdio_file_handle_t *)handle;
    int status = SSH_OK;

    (void)ctx;

    if (file_handle == NULL || file_handle->file == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (fclose(file_handle->file) != 0) {
        status = error_to_status();
    }
    free(file_handle);
    return status;
}

static int stdio_fsync(void *ctx, void *handle)
{
    stdio_file_handle_t *file_handle = (stdio_file_handle_t *)handle;
    int fd;

    (void)ctx;

    if (file_handle == NULL || file_handle->file == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (fflush(file_handle->file) != 0) {
        return error_to_status();
    }

#ifdef _WIN32
    fd = _fileno(file_handle->file);
    if (fd < 0) {
        return error_to_status();
    }
    return _commit(fd) == 0 ? SSH_OK : error_to_status();
#else
    fd = fileno(file_handle->file);
    if (fd < 0) {
        return error_to_status();
    }
    return fsync(fd) == 0 ? SSH_OK : error_to_status();
#endif
}

static int seek_file(FILE *file, uint64_t offset)
{
#ifdef _WIN32
    return _fseeki64(file, (__int64)offset, SEEK_SET) == 0 ? SSH_OK : error_to_status();
#else
    return fseeko(file, (off_t)offset, SEEK_SET) == 0 ? SSH_OK : error_to_status();
#endif
}

static int stdio_read_at(void *ctx, void *handle, uint64_t offset, uint8_t *buf, size_t len, size_t *read_len);
static int stdio_write_at(void *ctx, void *handle, uint64_t offset, const uint8_t *buf, size_t len, size_t *written_len);

static int tell_file(FILE *file, uint64_t *offset)
{
#ifdef _WIN32
    __int64 pos;
#else
    off_t pos;
#endif

    if (file == NULL || offset == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

#ifdef _WIN32
    pos = _ftelli64(file);
    if (pos < 0) {
        return error_to_status();
    }
    *offset = (uint64_t)pos;
#else
    pos = ftello(file);
    if (pos < (off_t)0) {
        return error_to_status();
    }
    *offset = (uint64_t)pos;
#endif
    return SSH_OK;
}

static int stdio_read(void *ctx, void *handle, uint8_t *buf, size_t len, size_t *read_len)
{
    stdio_file_handle_t *file_handle = (stdio_file_handle_t *)handle;
    uint64_t offset = 0u;
    int status;

    (void)ctx;

    if (file_handle == NULL || file_handle->file == NULL || buf == NULL || read_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = tell_file(file_handle->file, &offset);
    if (status != SSH_OK) {
        return status;
    }
    return stdio_read_at(ctx, handle, offset, buf, len, read_len);
}

static int stdio_write(void *ctx, void *handle, const uint8_t *buf, size_t len, size_t *written_len)
{
    stdio_file_handle_t *file_handle = (stdio_file_handle_t *)handle;
    uint64_t offset = 0u;
    int status;

    (void)ctx;

    if (file_handle == NULL || file_handle->file == NULL || (buf == NULL && len != 0u) || written_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = tell_file(file_handle->file, &offset);
    if (status != SSH_OK) {
        return status;
    }
    return stdio_write_at(ctx, handle, offset, buf, len, written_len);
}

static int stdio_read_at(void *ctx, void *handle, uint64_t offset, uint8_t *buf, size_t len, size_t *read_len)
{
    stdio_file_handle_t *file_handle = (stdio_file_handle_t *)handle;

    (void)ctx;

    if (file_handle == NULL || file_handle->file == NULL || buf == NULL || read_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (seek_file(file_handle->file, offset) != SSH_OK) {
        return SSH_ERR_PLATFORM;
    }

    *read_len = fread(buf, 1u, len, file_handle->file);
    if (*read_len < len && ferror(file_handle->file)) {
        return error_to_status();
    }
    return SSH_OK;
}

static int stdio_write_at(void *ctx, void *handle, uint64_t offset, const uint8_t *buf, size_t len, size_t *written_len)
{
    stdio_file_handle_t *file_handle = (stdio_file_handle_t *)handle;

    (void)ctx;

    if (file_handle == NULL || file_handle->file == NULL || (buf == NULL && len != 0u) || written_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (file_handle->append) {
        if (fseek(file_handle->file, 0, SEEK_END) != 0) {
            return error_to_status();
        }
    } else if (seek_file(file_handle->file, offset) != SSH_OK) {
        return SSH_ERR_PLATFORM;
    }

    *written_len = fwrite(buf, 1u, len, file_handle->file);
    if (*written_len != len) {
        return error_to_status();
    }
    return SSH_OK;
}

static int stdio_stat(void *ctx, const char *path, ssh_fs_attrs_t *attrs)
{
    ssh_stdio_fs_t *fs = (ssh_stdio_fs_t *)ctx;
    char resolved[EMSSH_STDIO_FS_MAX_PATH];
    int status;

    if (attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = resolve_path(fs, path, resolved);
    if (status != SSH_OK) {
        return status;
    }
    return stat_path(resolved, attrs);
}

static int stdio_statvfs(void *ctx, const char *path, ssh_fs_statvfs_t *stats)
{
    ssh_stdio_fs_t *fs = (ssh_stdio_fs_t *)ctx;
    char resolved[EMSSH_STDIO_FS_MAX_PATH];
    ssh_fs_attrs_t attrs;
    int status;

    status = resolve_path(fs, path, resolved);
    if (status != SSH_OK) {
        return status;
    }
    status = stat_path(resolved, &attrs);
    if (status != SSH_OK) {
        return status;
    }

    return statvfs_path(resolved, stats);
}

static int stdio_fstatvfs(void *ctx, void *handle, ssh_fs_statvfs_t *stats)
{
    stdio_file_handle_t *file_handle = (stdio_file_handle_t *)handle;

    (void)ctx;

    if (file_handle == NULL || file_handle->file == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    return statvfs_path(file_handle->path, stats);
}

static int truncate_path(const char *path, uint64_t size)
{
#ifdef _WIN32
    int fd;
    int status;

    if (size > INT64_MAX) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    fd = _open(path, _O_RDWR | _O_BINARY);
    if (fd < 0) {
        return error_to_status();
    }

    status = _chsize_s(fd, size) == 0 ? SSH_OK : error_to_status();
    (void)_close(fd);
    return status;
#else
    if (sizeof(off_t) < sizeof(uint64_t) && size > (uint64_t)((off_t)-1)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    return truncate(path, (off_t)size) == 0 ? SSH_OK : error_to_status();
#endif
}

static int truncate_file(FILE *file, uint64_t size)
{
    int fd;

    if (file == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (fflush(file) != 0) {
        return error_to_status();
    }

#ifdef _WIN32
    if (size > INT64_MAX) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    fd = _fileno(file);
    if (fd < 0) {
        return error_to_status();
    }
    return _chsize_s(fd, size) == 0 ? SSH_OK : error_to_status();
#else
    if (sizeof(off_t) < sizeof(uint64_t) && size > (uint64_t)((off_t)-1)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    fd = fileno(file);
    if (fd < 0) {
        return error_to_status();
    }
    return ftruncate(fd, (off_t)size) == 0 ? SSH_OK : error_to_status();
#endif
}

static int set_path_permissions(const char *path, uint32_t permissions)
{
#ifdef _WIN32
    return _chmod(path, (int)permissions) == 0 ? SSH_OK : error_to_status();
#else
    return chmod(path, (mode_t)permissions) == 0 ? SSH_OK : error_to_status();
#endif
}

static int set_path_times(const char *path, uint32_t atime, uint32_t mtime)
{
#ifdef _WIN32
    struct __utimbuf64 times;
    times.actime = (__time64_t)atime;
    times.modtime = (__time64_t)mtime;
    return _utime64(path, &times) == 0 ? SSH_OK : error_to_status();
#else
    struct utimbuf times;
    times.actime = (time_t)atime;
    times.modtime = (time_t)mtime;
    return utime(path, &times) == 0 ? SSH_OK : error_to_status();
#endif
}

static int apply_path_attrs(const char *path, const ssh_fs_attrs_t *attrs)
{
    int status;

    if (path == NULL || attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if ((attrs->flags & SSH_FILEXFER_ATTR_UIDGID) != 0u) {
        return SSH_ERR_UNSUPPORTED;
    }

    if ((attrs->flags & SSH_FILEXFER_ATTR_SIZE) != 0u) {
        status = truncate_path(path, attrs->size);
        if (status != SSH_OK) {
            return status;
        }
    }
    if ((attrs->flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0u) {
        status = set_path_permissions(path, attrs->permissions);
        if (status != SSH_OK) {
            return status;
        }
    }
    if ((attrs->flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0u) {
        status = set_path_times(path, attrs->atime, attrs->mtime);
        if (status != SSH_OK) {
            return status;
        }
    }

    return SSH_OK;
}

static int validate_dir_attrs(const ssh_fs_attrs_t *attrs)
{
    if (attrs == NULL || attrs->flags == 0u) {
        return SSH_OK;
    }
    if ((attrs->flags & (SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID)) != 0u) {
        return SSH_ERR_UNSUPPORTED;
    }
    return SSH_OK;
}

static int apply_dir_attrs(const char *path, const ssh_fs_attrs_t *attrs)
{
    int status;

    if (path == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    status = validate_dir_attrs(attrs);
    if (status != SSH_OK || attrs == NULL || attrs->flags == 0u) {
        return status;
    }

    if ((attrs->flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0u) {
        status = set_path_permissions(path, attrs->permissions);
        if (status != SSH_OK) {
            return status;
        }
    }
    if ((attrs->flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0u) {
        status = set_path_times(path, attrs->atime, attrs->mtime);
        if (status != SSH_OK) {
            return status;
        }
    }

    return SSH_OK;
}

static int apply_file_attrs(stdio_file_handle_t *file_handle, const ssh_fs_attrs_t *attrs)
{
    int status;

    if (file_handle == NULL || file_handle->file == NULL || attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if ((attrs->flags & SSH_FILEXFER_ATTR_UIDGID) != 0u) {
        return SSH_ERR_UNSUPPORTED;
    }

    if ((attrs->flags & SSH_FILEXFER_ATTR_SIZE) != 0u) {
        status = truncate_file(file_handle->file, attrs->size);
        if (status != SSH_OK) {
            return status;
        }
    }
    if ((attrs->flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0u) {
        status = set_path_permissions(file_handle->path, attrs->permissions);
        if (status != SSH_OK) {
            return status;
        }
    }
    if ((attrs->flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0u) {
        status = set_path_times(file_handle->path, attrs->atime, attrs->mtime);
        if (status != SSH_OK) {
            return status;
        }
    }

    return SSH_OK;
}

static int stdio_setstat(void *ctx, const char *path, const ssh_fs_attrs_t *attrs)
{
    ssh_stdio_fs_t *fs = (ssh_stdio_fs_t *)ctx;
    char resolved[EMSSH_STDIO_FS_MAX_PATH];
    int status;

    if (attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = resolve_path(fs, path, resolved);
    if (status != SSH_OK) {
        return status;
    }

    return apply_path_attrs(resolved, attrs);
}

static int stdio_fsetstat(void *ctx, void *handle, const ssh_fs_attrs_t *attrs)
{
    (void)ctx;
    return apply_file_attrs((stdio_file_handle_t *)handle, attrs);
}

static int stdio_opendir(void *ctx, const char *path, void **handle)
{
    ssh_stdio_fs_t *fs = (ssh_stdio_fs_t *)ctx;
    stdio_dir_handle_t *dir_handle;
    char resolved[EMSSH_STDIO_FS_MAX_PATH];
    int status;

    if (handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *handle = NULL;
    status = resolve_path(fs, path, resolved);
    if (status != SSH_OK) {
        return status;
    }

    dir_handle = (stdio_dir_handle_t *)calloc(1u, sizeof(*dir_handle));
    if (dir_handle == NULL) {
        return SSH_ERR_PLATFORM;
    }
    snprintf(dir_handle->path, sizeof(dir_handle->path), "%s", resolved);

#ifdef _WIN32
    {
        char pattern[EMSSH_STDIO_FS_MAX_PATH];
        int written = snprintf(pattern, sizeof(pattern), "%s/*", resolved);
        if (written < 0 || (size_t)written >= sizeof(pattern)) {
            free(dir_handle);
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        dir_handle->find_handle = _findfirst(pattern, &dir_handle->find_data);
        if (dir_handle->find_handle == -1) {
            free(dir_handle);
            return error_to_status();
        }
        dir_handle->first_ready = 1;
    }
#else
    dir_handle->dir = opendir(resolved);
    if (dir_handle->dir == NULL) {
        free(dir_handle);
        return error_to_status();
    }
#endif

    *handle = dir_handle;
    return SSH_OK;
}

static int stdio_readdir(void *ctx, void *handle, ssh_fs_dirent_t *entry, int *eof)
{
    stdio_dir_handle_t *dir_handle = (stdio_dir_handle_t *)handle;
    char entry_path[EMSSH_STDIO_FS_MAX_PATH];
    int status;

    (void)ctx;

    if (dir_handle == NULL || entry == NULL || eof == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    for (;;) {
        memset(entry, 0, sizeof(*entry));
#ifdef _WIN32
        if (dir_handle->first_ready) {
            dir_handle->first_ready = 0;
        } else if (_findnext(dir_handle->find_handle, &dir_handle->find_data) != 0) {
            *eof = 1;
            return SSH_OK;
        }
        snprintf(dir_handle->name, sizeof(dir_handle->name), "%s", dir_handle->find_data.name);
        entry->attrs.flags = SSH_FILEXFER_ATTR_SIZE;
        entry->attrs.size = (uint64_t)dir_handle->find_data.size;
#else
        {
            struct dirent *dirent;

            errno = 0;
            dirent = readdir(dir_handle->dir);
            if (dirent == NULL) {
                if (errno != 0) {
                    return error_to_status();
                }
                *eof = 1;
                return SSH_OK;
            }
            snprintf(dir_handle->name, sizeof(dir_handle->name), "%s", dirent->d_name);
        }
#endif

        snprintf(dir_handle->longname, sizeof(dir_handle->longname), "%s", dir_handle->name);
        status = join_path_child(dir_handle->path, dir_handle->name, entry_path);
        if (status != SSH_OK) {
            return status;
        }
#ifdef _WIN32
        status = stat_path(entry_path, &entry->attrs);
#else
        status = lstat_path(entry_path, &entry->attrs);
        if (status != SSH_OK) {
            status = stat_path(entry_path, &entry->attrs);
        }
#endif
        if (status != SSH_OK) {
            /* Skip entries we cannot stat (broken links/permission races). */
            continue;
        }

        entry->filename = dir_handle->name;
        entry->longname = dir_handle->longname;
        *eof = 0;
        return SSH_OK;
    }
}

static int stdio_closedir(void *ctx, void *handle)
{
    stdio_dir_handle_t *dir_handle = (stdio_dir_handle_t *)handle;

    (void)ctx;

    if (dir_handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
#ifdef _WIN32
    if (dir_handle->find_handle != -1) {
        (void)_findclose(dir_handle->find_handle);
    }
#else
    if (dir_handle->dir != NULL) {
        (void)closedir(dir_handle->dir);
    }
#endif
    free(dir_handle);
    return SSH_OK;
}

static int stdio_mkdir(void *ctx, const char *path, const ssh_fs_attrs_t *attrs)
{
    ssh_stdio_fs_t *fs = (ssh_stdio_fs_t *)ctx;
    char resolved[EMSSH_STDIO_FS_MAX_PATH];
    int status;

    status = resolve_path(fs, path, resolved);
    if (status != SSH_OK) {
        return status;
    }
    status = validate_dir_attrs(attrs);
    if (status != SSH_OK) {
        return status;
    }
#ifdef _WIN32
    status = _mkdir(resolved) == 0 ? SSH_OK : error_to_status();
#else
    status = mkdir(resolved, 0777) == 0 ? SSH_OK : error_to_status();
#endif
    if (status != SSH_OK) {
        return status;
    }

    status = apply_dir_attrs(resolved, attrs);
    if (status != SSH_OK) {
#ifdef _WIN32
        (void)_rmdir(resolved);
#else
        (void)rmdir(resolved);
#endif
    }

    return status;
}

static int stdio_rmdir(void *ctx, const char *path)
{
    ssh_stdio_fs_t *fs = (ssh_stdio_fs_t *)ctx;
    char resolved[EMSSH_STDIO_FS_MAX_PATH];
    int status;

    status = resolve_path(fs, path, resolved);
    if (status != SSH_OK) {
        return status;
    }
#ifdef _WIN32
    return _rmdir(resolved) == 0 ? SSH_OK : error_to_status();
#else
    return rmdir(resolved) == 0 ? SSH_OK : error_to_status();
#endif
}

static int stdio_remove(void *ctx, const char *path)
{
    ssh_stdio_fs_t *fs = (ssh_stdio_fs_t *)ctx;
    char resolved[EMSSH_STDIO_FS_MAX_PATH];
    int status;

    status = resolve_path(fs, path, resolved);
    if (status != SSH_OK) {
        return status;
    }
    return remove(resolved) == 0 ? SSH_OK : error_to_status();
}

static int stdio_rename(void *ctx, const char *old_path, const char *new_path)
{
    ssh_stdio_fs_t *fs = (ssh_stdio_fs_t *)ctx;
    char old_resolved[EMSSH_STDIO_FS_MAX_PATH];
    char new_resolved[EMSSH_STDIO_FS_MAX_PATH];
    int status;

    status = resolve_path(fs, old_path, old_resolved);
    if (status != SSH_OK) {
        return status;
    }
    status = resolve_path(fs, new_path, new_resolved);
    if (status != SSH_OK) {
        return status;
    }
    if (resolved_path_exists(new_resolved)) {
        return SSH_ERR_ALREADY_EXISTS;
    }
    return rename(old_resolved, new_resolved) == 0 ? SSH_OK : error_to_status();
}

static int stdio_posix_rename(void *ctx, const char *old_path, const char *new_path)
{
    ssh_stdio_fs_t *fs = (ssh_stdio_fs_t *)ctx;
    char old_resolved[EMSSH_STDIO_FS_MAX_PATH];
    char new_resolved[EMSSH_STDIO_FS_MAX_PATH];
    int status;

    status = resolve_path(fs, old_path, old_resolved);
    if (status != SSH_OK) {
        return status;
    }
    status = resolve_path(fs, new_path, new_resolved);
    if (status != SSH_OK) {
        return status;
    }
#ifdef _WIN32
    return MoveFileExA(old_resolved, new_resolved, MOVEFILE_REPLACE_EXISTING) ? SSH_OK : windows_error_to_status(GetLastError());
#else
    return rename(old_resolved, new_resolved) == 0 ? SSH_OK : error_to_status();
#endif
}

static int stdio_hardlink(void *ctx, const char *old_path, const char *new_path)
{
    ssh_stdio_fs_t *fs = (ssh_stdio_fs_t *)ctx;
    char old_resolved[EMSSH_STDIO_FS_MAX_PATH];
    char new_resolved[EMSSH_STDIO_FS_MAX_PATH];
    int status;

    status = resolve_path(fs, old_path, old_resolved);
    if (status != SSH_OK) {
        return status;
    }
    status = resolve_path(fs, new_path, new_resolved);
    if (status != SSH_OK) {
        return status;
    }
#ifdef _WIN32
    return CreateHardLinkA(new_resolved, old_resolved, NULL) ? SSH_OK : windows_error_to_status(GetLastError());
#else
    return link(old_resolved, new_resolved) == 0 ? SSH_OK : error_to_status();
#endif
}

int ssh_stdio_fs_init(ssh_stdio_fs_t *fs, const char *root)
{
    int written;

    if (fs == NULL || root == NULL || root[0] == '\0') {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(fs, 0, sizeof(*fs));
    written = snprintf(fs->root, sizeof(fs->root), "%s", root);
    if (written < 0 || (size_t)written >= sizeof(fs->root)) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    fs->api.open = stdio_open;
    fs->api.close = stdio_close;
    fs->api.read = stdio_read;
    fs->api.write = stdio_write;
    fs->api.read_at = stdio_read_at;
    fs->api.write_at = stdio_write_at;
    fs->api.stat = stdio_stat;
    fs->api.lstat = stdio_stat;
    fs->api.setstat = stdio_setstat;
    fs->api.fsetstat = stdio_fsetstat;
    fs->api.opendir = stdio_opendir;
    fs->api.readdir = stdio_readdir;
    fs->api.closedir = stdio_closedir;
    fs->api.mkdir = stdio_mkdir;
    fs->api.rmdir = stdio_rmdir;
    fs->api.remove = stdio_remove;
    fs->api.rename = stdio_rename;
    fs->api.posix_rename = stdio_posix_rename;
    fs->api.fsync = stdio_fsync;
    fs->api.hardlink = stdio_hardlink;
    fs->api.statvfs = stdio_statvfs;
    fs->api.fstatvfs = stdio_fstatvfs;
    fs->api.ctx = fs;
    return SSH_OK;
}

void ssh_stdio_fs_deinit(ssh_stdio_fs_t *fs)
{
    if (fs != NULL) {
        memset(fs, 0, sizeof(*fs));
    }
}

const ssh_fs_api_t *ssh_stdio_fs_api(ssh_stdio_fs_t *fs)
{
    return fs != NULL ? &fs->api : NULL;
}
