#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "emssh/platform_stdio_fs.h"
#include "emssh/sftp.h"
#include "emssh/ssh_error.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static int make_dir(const char *path)
{
#ifdef _WIN32
    return _mkdir(path) == 0 ? SSH_OK : SSH_ERR_PLATFORM;
#else
    return mkdir(path, 0777) == 0 ? SSH_OK : SSH_ERR_PLATFORM;
#endif
}

static int remove_dir(const char *path)
{
#ifdef _WIN32
    return _rmdir(path) == 0 ? SSH_OK : SSH_ERR_PLATFORM;
#else
    return rmdir(path) == 0 ? SSH_OK : SSH_ERR_PLATFORM;
#endif
}

static void cleanup_root(void)
{
    (void)remove("stdio_fs_root/append.txt");
    (void)remove("stdio_fs_root/created.txt");
    (void)remove("stdio_fs_root/keep.txt");
    (void)remove("stdio_fs_root/existing.txt");
    (void)remove("stdio_fs_root/hardlink_source.txt");
    (void)remove("stdio_fs_root/hardlink_target.txt");
    (void)remove("stdio_fs_root/rename_source.txt");
    (void)remove("stdio_fs_root/posix_source.txt");
    (void)remove("stdio_fs_root/renamed.txt");
    (void)remove("stdio_fs_root/file.txt");
    (void)remove_dir("stdio_fs_root/attrdir");
    (void)remove_dir("stdio_fs_root/baddir");
    (void)remove_dir("stdio_fs_root/newdir");
    (void)remove_dir("stdio_fs_root");
}

int main(void)
{
    ssh_stdio_fs_t fs_ctx;
    const ssh_fs_api_t *fs;
    ssh_fs_attrs_t attrs;
    ssh_fs_statvfs_t vfs_stats;
    ssh_fs_dirent_t entry;
    FILE *seed;
    void *handle;
    void *dir;
    uint8_t data[16];
    size_t len;
    int eof;
    int saw_file;

    cleanup_root();
    CHECK(make_dir("stdio_fs_root") == SSH_OK);

    seed = fopen("stdio_fs_root/file.txt", "wb");
    CHECK(seed != NULL);
    CHECK(fwrite("abcdef", 1u, 6u, seed) == 6u);
    CHECK(fclose(seed) == 0);

    CHECK(ssh_stdio_fs_init(&fs_ctx, "stdio_fs_root") == SSH_OK);
    fs = ssh_stdio_fs_api(&fs_ctx);
    CHECK(fs != NULL);

    CHECK(fs->stat(fs->ctx, "file.txt", &attrs) == SSH_OK);
    CHECK((attrs.flags & SSH_FILEXFER_ATTR_SIZE) != 0u);
    CHECK(attrs.size == 6u);
    CHECK(fs->stat(fs->ctx, "missing.txt", &attrs) == SSH_ERR_NOT_FOUND);

    handle = NULL;
    CHECK(fs->open(fs->ctx, "file.txt", 0u, &handle) == SSH_ERR_INVALID_ARGUMENT);
    CHECK(handle == NULL);
    handle = NULL;
    CHECK(fs->open(fs->ctx, "file.txt", SSH_FXF_READ | SSH_FXF_CREAT, &handle) == SSH_ERR_INVALID_ARGUMENT);
    CHECK(handle == NULL);
    handle = NULL;
    CHECK(fs->open(fs->ctx, "file.txt", SSH_FXF_WRITE | SSH_FXF_EXCL, &handle) == SSH_ERR_INVALID_ARGUMENT);
    CHECK(handle == NULL);
    handle = NULL;
    CHECK(fs->open(fs->ctx, "file.txt", SSH_FXF_READ | 0x00000100u, &handle) == SSH_ERR_INVALID_ARGUMENT);
    CHECK(handle == NULL);

    handle = NULL;
    CHECK(fs->open(fs->ctx, "file.txt", SSH_FXF_READ | SSH_FXF_WRITE, &handle) == SSH_OK);
    CHECK(handle != NULL);
    len = 0u;
    CHECK(fs->read_at(fs->ctx, handle, 1u, data, 3u, &len) == SSH_OK);
    CHECK(len == 3u);
    CHECK(memcmp(data, "bcd", 3u) == 0);
    CHECK(fs->write_at(fs->ctx, handle, 2u, (const uint8_t *)"XY", 2u, &len) == SSH_OK);
    CHECK(len == 2u);
    CHECK(fs->fsync != NULL);
    CHECK(fs->fsync(fs->ctx, handle) == SSH_OK);
    CHECK(fs->fstatvfs != NULL);
    CHECK(fs->fstatvfs(fs->ctx, handle, &vfs_stats) == SSH_OK);
    CHECK(vfs_stats.bsize != 0u);
    CHECK(vfs_stats.frsize != 0u);
    CHECK(fs->close(fs->ctx, handle) == SSH_OK);

    CHECK(fs->statvfs != NULL);
    CHECK(fs->statvfs(fs->ctx, "file.txt", &vfs_stats) == SSH_OK);
    CHECK(vfs_stats.bsize != 0u);
    CHECK(vfs_stats.namemax != 0u);

    seed = fopen("stdio_fs_root/keep.txt", "wb");
    CHECK(seed != NULL);
    CHECK(fwrite("keep", 1u, 4u, seed) == 4u);
    CHECK(fclose(seed) == 0);

    handle = NULL;
    CHECK(fs->open(fs->ctx, "keep.txt", SSH_FXF_WRITE | SSH_FXF_CREAT, &handle) == SSH_OK);
    CHECK(fs->close(fs->ctx, handle) == SSH_OK);
    CHECK(fs->stat(fs->ctx, "keep.txt", &attrs) == SSH_OK);
    CHECK(attrs.size == 4u);

    handle = NULL;
    CHECK(fs->open(fs->ctx, "keep.txt", SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_EXCL, &handle) == SSH_ERR_ALREADY_EXISTS);

    handle = NULL;
    CHECK(fs->open(fs->ctx, "keep.txt", SSH_FXF_WRITE | SSH_FXF_TRUNC, &handle) == SSH_OK);
    CHECK(fs->close(fs->ctx, handle) == SSH_OK);
    CHECK(fs->stat(fs->ctx, "keep.txt", &attrs) == SSH_OK);
    CHECK(attrs.size == 0u);

    handle = NULL;
    CHECK(fs->open(fs->ctx, "created.txt", SSH_FXF_WRITE | SSH_FXF_CREAT, &handle) == SSH_OK);
    CHECK(fs->write_at(fs->ctx, handle, 0u, (const uint8_t *)"new", 3u, &len) == SSH_OK);
    CHECK(len == 3u);
    CHECK(fs->close(fs->ctx, handle) == SSH_OK);
    CHECK(fs->stat(fs->ctx, "created.txt", &attrs) == SSH_OK);
    CHECK(attrs.size == 3u);

    seed = fopen("stdio_fs_root/append.txt", "wb");
    CHECK(seed != NULL);
    CHECK(fwrite("ab", 1u, 2u, seed) == 2u);
    CHECK(fclose(seed) == 0);

    handle = NULL;
    CHECK(fs->open(fs->ctx, "append.txt", SSH_FXF_WRITE | SSH_FXF_APPEND, &handle) == SSH_OK);
    CHECK(fs->write_at(fs->ctx, handle, 0u, (const uint8_t *)"XY", 2u, &len) == SSH_OK);
    CHECK(len == 2u);
    CHECK(fs->close(fs->ctx, handle) == SSH_OK);

    handle = NULL;
    CHECK(fs->open(fs->ctx, "append.txt", SSH_FXF_READ, &handle) == SSH_OK);
    CHECK(fs->read_at(fs->ctx, handle, 0u, data, 4u, &len) == SSH_OK);
    CHECK(len == 4u);
    CHECK(memcmp(data, "abXY", 4u) == 0);
    CHECK(fs->close(fs->ctx, handle) == SSH_OK);

    handle = NULL;
    CHECK(fs->open(fs->ctx, "file.txt", SSH_FXF_READ, &handle) == SSH_OK);
    CHECK(fs->read_at(fs->ctx, handle, 0u, data, 6u, &len) == SSH_OK);
    CHECK(len == 6u);
    CHECK(memcmp(data, "abXYef", 6u) == 0);
    CHECK(fs->close(fs->ctx, handle) == SSH_OK);

    memset(&attrs, 0, sizeof(attrs));
    attrs.flags = SSH_FILEXFER_ATTR_SIZE;
    attrs.size = 4u;
    CHECK(fs->setstat(fs->ctx, "file.txt", &attrs) == SSH_OK);
    CHECK(fs->stat(fs->ctx, "file.txt", &attrs) == SSH_OK);
    CHECK(attrs.size == 4u);

    handle = NULL;
    CHECK(fs->open(fs->ctx, "file.txt", SSH_FXF_READ | SSH_FXF_WRITE, &handle) == SSH_OK);
    memset(&attrs, 0, sizeof(attrs));
    attrs.flags = SSH_FILEXFER_ATTR_SIZE;
    attrs.size = 2u;
    CHECK(fs->fsetstat(fs->ctx, handle, &attrs) == SSH_OK);
    CHECK(fs->close(fs->ctx, handle) == SSH_OK);
    CHECK(fs->stat(fs->ctx, "file.txt", &attrs) == SSH_OK);
    CHECK(attrs.size == 2u);

    memset(&attrs, 0, sizeof(attrs));
    attrs.flags = SSH_FILEXFER_ATTR_UIDGID;
    CHECK(fs->setstat(fs->ctx, "file.txt", &attrs) == SSH_ERR_UNSUPPORTED);

    dir = NULL;
    CHECK(fs->opendir(fs->ctx, ".", &dir) == SSH_OK);
    saw_file = 0;
    for (;;) {
        CHECK(fs->readdir(fs->ctx, dir, &entry, &eof) == SSH_OK);
        if (eof) {
            break;
        }
        if (entry.filename != NULL && strcmp(entry.filename, "file.txt") == 0) {
            saw_file = 1;
            CHECK((entry.attrs.flags & SSH_FILEXFER_ATTR_SIZE) != 0u);
            CHECK((entry.attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0u);
            CHECK((entry.attrs.flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0u);
            CHECK(entry.attrs.size == 2u);
        }
    }
    CHECK(saw_file);
    CHECK(fs->closedir(fs->ctx, dir) == SSH_OK);

    CHECK(fs->mkdir(fs->ctx, "newdir", NULL) == SSH_OK);
    CHECK(fs->rmdir(fs->ctx, "newdir") == SSH_OK);

    memset(&attrs, 0, sizeof(attrs));
    attrs.flags = SSH_FILEXFER_ATTR_PERMISSIONS;
    attrs.permissions = 0040750u;
    CHECK(fs->mkdir(fs->ctx, "attrdir", &attrs) == SSH_OK);
    CHECK(fs->stat(fs->ctx, "attrdir", &attrs) == SSH_OK);
#ifndef _WIN32
    CHECK((attrs.permissions & 0777u) == 0750u);
#endif
    CHECK(fs->rmdir(fs->ctx, "attrdir") == SSH_OK);

    memset(&attrs, 0, sizeof(attrs));
    attrs.flags = SSH_FILEXFER_ATTR_UIDGID;
    CHECK(fs->mkdir(fs->ctx, "baddir", &attrs) == SSH_ERR_UNSUPPORTED);
    CHECK(fs->stat(fs->ctx, "baddir", &attrs) == SSH_ERR_NOT_FOUND);

    CHECK(fs->rename(fs->ctx, "file.txt", "renamed.txt") == SSH_OK);
    CHECK(fs->remove(fs->ctx, "renamed.txt") == SSH_OK);

    seed = fopen("stdio_fs_root/existing.txt", "wb");
    CHECK(seed != NULL);
    CHECK(fwrite("existing", 1u, 8u, seed) == 8u);
    CHECK(fclose(seed) == 0);
    seed = fopen("stdio_fs_root/rename_source.txt", "wb");
    CHECK(seed != NULL);
    CHECK(fwrite("src", 1u, 3u, seed) == 3u);
    CHECK(fclose(seed) == 0);
    CHECK(fs->rename(fs->ctx, "rename_source.txt", "existing.txt") == SSH_ERR_ALREADY_EXISTS);
    CHECK(fs->stat(fs->ctx, "rename_source.txt", &attrs) == SSH_OK);
    CHECK(fs->stat(fs->ctx, "existing.txt", &attrs) == SSH_OK);
    CHECK(attrs.size == 8u);

    seed = fopen("stdio_fs_root/posix_source.txt", "wb");
    CHECK(seed != NULL);
    CHECK(fwrite("new", 1u, 3u, seed) == 3u);
    CHECK(fclose(seed) == 0);
    CHECK(fs->posix_rename != NULL);
    CHECK(fs->posix_rename(fs->ctx, "posix_source.txt", "existing.txt") == SSH_OK);
    CHECK(fs->stat(fs->ctx, "posix_source.txt", &attrs) == SSH_ERR_NOT_FOUND);
    CHECK(fs->stat(fs->ctx, "existing.txt", &attrs) == SSH_OK);
    CHECK(attrs.size == 3u);
    CHECK(fs->remove(fs->ctx, "existing.txt") == SSH_OK);
    CHECK(fs->remove(fs->ctx, "rename_source.txt") == SSH_OK);

    seed = fopen("stdio_fs_root/hardlink_source.txt", "wb");
    CHECK(seed != NULL);
    CHECK(fwrite("hardlink", 1u, 8u, seed) == 8u);
    CHECK(fclose(seed) == 0);
    CHECK(fs->hardlink != NULL);
    CHECK(fs->hardlink(fs->ctx, "hardlink_source.txt", "hardlink_target.txt") == SSH_OK);
    CHECK(fs->stat(fs->ctx, "hardlink_source.txt", &attrs) == SSH_OK);
    CHECK(attrs.size == 8u);
    CHECK(fs->stat(fs->ctx, "hardlink_target.txt", &attrs) == SSH_OK);
    CHECK(attrs.size == 8u);
    CHECK(fs->hardlink(fs->ctx, "hardlink_source.txt", "hardlink_target.txt") == SSH_ERR_ALREADY_EXISTS);
    CHECK(fs->remove(fs->ctx, "hardlink_target.txt") == SSH_OK);
    CHECK(fs->remove(fs->ctx, "hardlink_source.txt") == SSH_OK);

    CHECK(fs->remove(fs->ctx, "missing.txt") == SSH_ERR_NOT_FOUND);
    CHECK(fs->open(fs->ctx, "../escape.txt", SSH_FXF_READ, &handle) == SSH_ERR_INVALID_ARGUMENT);

    ssh_stdio_fs_deinit(&fs_ctx);
    cleanup_root();
    return 0;
}
