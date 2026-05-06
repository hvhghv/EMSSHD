#ifndef EMSSH_SSH_PLATFORM_H
#define EMSSH_SSH_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

#include "emssh/ssh_crypto.h"

typedef enum ssh_log_level {
    SSH_LOG_ERROR = 0,
    SSH_LOG_WARN,
    SSH_LOG_INFO,
    SSH_LOG_DEBUG,
    SSH_LOG_TRACE
} ssh_log_level_t;

typedef struct ssh_mem_api {
    void *(*alloc)(void *ctx, size_t size);
    void (*free)(void *ctx, void *ptr);
    void (*secure_zero)(void *ctx, void *ptr, size_t len);
    void *ctx;
} ssh_mem_api_t;

typedef struct ssh_rng_api {
    int (*fill)(void *ctx, uint8_t *buf, size_t len);
    void *ctx;
} ssh_rng_api_t;

typedef struct ssh_time_api {
    uint64_t (*monotonic_ms)(void *ctx);
    void *ctx;
} ssh_time_api_t;

typedef struct ssh_log_api {
    void (*write)(void *ctx, ssh_log_level_t level, const char *message);
    void *ctx;
} ssh_log_api_t;

typedef struct ssh_net_api {
    int (*read)(void *ctx, void *conn, uint8_t *buf, size_t len, uint32_t timeout_ms);
    int (*write)(void *ctx, void *conn, const uint8_t *buf, size_t len, uint32_t timeout_ms);
    int (*close)(void *ctx, void *conn);
    void *ctx;
} ssh_net_api_t;

typedef struct ssh_fs_attrs {
    uint32_t flags;
    uint64_t size;
    uint32_t uid;
    uint32_t gid;
    uint32_t permissions;
    uint32_t atime;
    uint32_t mtime;
} ssh_fs_attrs_t;

typedef struct ssh_fs_dirent {
    const char *filename;
    const char *longname;
    ssh_fs_attrs_t attrs;
} ssh_fs_dirent_t;

typedef struct ssh_fs_statvfs {
    uint64_t bsize;
    uint64_t frsize;
    uint64_t blocks;
    uint64_t bfree;
    uint64_t bavail;
    uint64_t files;
    uint64_t ffree;
    uint64_t favail;
    uint64_t fsid;
    uint64_t flag;
    uint64_t namemax;
} ssh_fs_statvfs_t;

typedef struct ssh_fs_api {
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
    void *ctx;
} ssh_fs_api_t;

typedef struct ssh_term_api {
    int (*spawn_shell)(
        void *ctx,
        const char *username,
        const char *term_type,
        uint32_t cols,
        uint32_t rows,
        uint32_t width_px,
        uint32_t height_px,
        void **handle);
    int (*spawn_exec)(
        void *ctx,
        const char *username,
        const char *command,
        const char *term_type,
        uint32_t cols,
        uint32_t rows,
        uint32_t width_px,
        uint32_t height_px,
        void **handle);
    int (*write)(void *ctx, void *handle, const uint8_t *buf, size_t len, size_t *written_len);
    int (*read)(void *ctx, void *handle, uint8_t *buf, size_t len, size_t *read_len);
    int (*resize)(void *ctx, void *handle, uint32_t cols, uint32_t rows, uint32_t width_px, uint32_t height_px);
    int (*signal)(void *ctx, void *handle, const char *signal_name);
    int (*wait_exit)(void *ctx, void *handle, int *exited, uint32_t *exit_status);
    int (*close)(void *ctx, void *handle);
    void *ctx;
} ssh_term_api_t;

typedef struct ssh_platform {
    const ssh_mem_api_t *mem;
    const ssh_net_api_t *net;
    const ssh_fs_api_t *fs;
    const ssh_term_api_t *term;
    const ssh_crypto_api_t *crypto;
    const ssh_rng_api_t *rng;
    const ssh_time_api_t *time;
    const ssh_log_api_t *log;
} ssh_platform_t;

#endif
