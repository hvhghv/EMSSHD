#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "emssh/platform_fatfs.h"
#include "emssh/platform_littlefs.h"
#include "emssh/ssh_error.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

typedef struct fs_probe_ctx {
    int open_calls;
    int stat_calls;
    int close_calls;
} fs_probe_ctx_t;

static int probe_open(void *ctx, const char *path, uint32_t flags, void **handle)
{
    fs_probe_ctx_t *probe = (fs_probe_ctx_t *)ctx;
    (void)flags;
    if (probe == NULL || path == NULL || handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    probe->open_calls++;
    *handle = (void *)path;
    return SSH_OK;
}

static int probe_close(void *ctx, void *handle)
{
    fs_probe_ctx_t *probe = (fs_probe_ctx_t *)ctx;
    (void)handle;
    if (probe == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    probe->close_calls++;
    return SSH_OK;
}

static int probe_stat(void *ctx, const char *path, ssh_fs_attrs_t *attrs)
{
    fs_probe_ctx_t *probe = (fs_probe_ctx_t *)ctx;
    if (probe == NULL || path == NULL || attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    probe->stat_calls++;
    memset(attrs, 0, sizeof(*attrs));
    attrs->flags = 1u;
    attrs->size = 123u;
    return SSH_OK;
}

static int test_littlefs_alias(void)
{
    ssh_littlefs_t lfs;
    ssh_littlefs_ops_t ops;
    fs_probe_ctx_t probe;
    const ssh_fs_api_t *api;
    void *handle;
    ssh_fs_attrs_t attrs;

    memset(&ops, 0, sizeof(ops));
    memset(&probe, 0, sizeof(probe));
    ops.open = probe_open;
    ops.close = probe_close;
    ops.stat = probe_stat;

    CHECK(ssh_littlefs_init(&lfs, &ops, &probe) == SSH_OK);
    api = ssh_littlefs_api(&lfs);
    CHECK(api != NULL);

    CHECK(api->open(api->ctx, "a.txt", 0u, &handle) == SSH_OK);
    CHECK(api->stat(api->ctx, "a.txt", &attrs) == SSH_OK);
    CHECK(attrs.size == 123u);
    CHECK(api->close(api->ctx, handle) == SSH_OK);
    CHECK(api->read(api->ctx, handle, NULL, 0u, NULL) == SSH_ERR_UNSUPPORTED);

    CHECK(probe.open_calls == 1);
    CHECK(probe.stat_calls == 1);
    CHECK(probe.close_calls == 1);

    ssh_littlefs_deinit(&lfs);
    CHECK(ssh_littlefs_api(&lfs) == NULL);
    return 0;
}

static int test_fatfs_alias(void)
{
    ssh_fatfs_t fat;
    ssh_fatfs_ops_t ops;
    fs_probe_ctx_t probe;
    const ssh_fs_api_t *api;
    void *handle;

    memset(&ops, 0, sizeof(ops));
    memset(&probe, 0, sizeof(probe));
    ops.open = probe_open;
    ops.close = probe_close;

    CHECK(ssh_fatfs_init(&fat, &ops, &probe) == SSH_OK);
    api = ssh_fatfs_api(&fat);
    CHECK(api != NULL);
    CHECK(api->open(api->ctx, "b.txt", 0u, &handle) == SSH_OK);
    CHECK(api->close(api->ctx, handle) == SSH_OK);
    CHECK(api->statvfs(api->ctx, "/", NULL) == SSH_ERR_UNSUPPORTED);

    CHECK(probe.open_calls == 1);
    CHECK(probe.close_calls == 1);

    ssh_fatfs_deinit(&fat);
    return 0;
}

int main(void)
{
    if (test_littlefs_alias() != 0) {
        return 1;
    }
    if (test_fatfs_alias() != 0) {
        return 1;
    }
    return 0;
}
