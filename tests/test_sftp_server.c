#include <stdio.h>
#include <string.h>

#include "emssh/sftp.h"
#include "emssh/sftp_server.h"
#include "emssh/ssh_error.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

typedef struct mock_fs {
    char opened_path[EMSSH_SFTP_MAX_PATH];
    char removed_path[EMSSH_SFTP_MAX_PATH];
    char renamed_old_path[EMSSH_SFTP_MAX_PATH];
    char renamed_new_path[EMSSH_SFTP_MAX_PATH];
    char posix_renamed_old_path[EMSSH_SFTP_MAX_PATH];
    char posix_renamed_new_path[EMSSH_SFTP_MAX_PATH];
    char hardlinked_old_path[EMSSH_SFTP_MAX_PATH];
    char hardlinked_new_path[EMSSH_SFTP_MAX_PATH];
    char stat_path[EMSSH_SFTP_MAX_PATH];
    char opendir_path[EMSSH_SFTP_MAX_PATH];
    char mkdir_path[EMSSH_SFTP_MAX_PATH];
    char rmdir_path[EMSSH_SFTP_MAX_PATH];
    char setstat_path[EMSSH_SFTP_MAX_PATH];
    ssh_fs_attrs_t mkdir_attrs;
    ssh_fs_attrs_t setstat_attrs;
    ssh_fs_attrs_t fsetstat_attrs;
    uint8_t data[64];
    size_t data_len;
    unsigned dir_index;
    int close_count;
    int closedir_count;
    int fsync_count;
    int statvfs_count;
    int fstatvfs_count;
    int stat_missing_txt;
    int fsetstat_count;
    size_t generated_read_len;
} mock_fs_t;

typedef struct test_policy_ctx {
    const char *deny_path;
    uint64_t max_write_end;
    sftp_policy_operation_t last_operation;
    char last_path[EMSSH_SFTP_MAX_PATH];
    char last_new_path[EMSSH_SFTP_MAX_PATH];
    uint64_t last_offset;
    size_t last_length;
} test_policy_ctx_t;

static void write_u32_be(uint8_t data[4], uint32_t value)
{
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

static void finish_packet(uint8_t *packet, ssh_buffer_t *payload, size_t *packet_len)
{
    write_u32_be(packet, (uint32_t)ssh_buffer_len(payload));
    *packet_len = ssh_buffer_len(payload) + 4u;
}

static int mock_open(void *ctx, const char *path, uint32_t flags, void **handle)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    (void)flags;

    if (fs == NULL || path == NULL || handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    strncpy(fs->opened_path, path, sizeof(fs->opened_path) - 1u);
    fs->opened_path[sizeof(fs->opened_path) - 1u] = '\0';
    *handle = fs;
    return SSH_OK;
}

static int mock_close(void *ctx, void *handle)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || handle != fs) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ++fs->close_count;
    return SSH_OK;
}

static int mock_fsync(void *ctx, void *handle)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || handle != fs) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ++fs->fsync_count;
    return SSH_OK;
}

static void fill_mock_statvfs(ssh_fs_statvfs_t *stats)
{
    memset(stats, 0, sizeof(*stats));
    stats->bsize = 4096u;
    stats->frsize = 4096u;
    stats->blocks = 1000u;
    stats->bfree = 500u;
    stats->bavail = 400u;
    stats->files = 200u;
    stats->ffree = 100u;
    stats->favail = 80u;
    stats->fsid = 7u;
    stats->flag = 0u;
    stats->namemax = 255u;
}

static int mock_statvfs(void *ctx, const char *path, ssh_fs_statvfs_t *stats)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || path == NULL || stats == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (strcmp(path, "missing.txt") == 0) {
        return SSH_ERR_NOT_FOUND;
    }

    ++fs->statvfs_count;
    fill_mock_statvfs(stats);
    return SSH_OK;
}

static int mock_fstatvfs(void *ctx, void *handle, ssh_fs_statvfs_t *stats)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || handle != fs || stats == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ++fs->fstatvfs_count;
    fill_mock_statvfs(stats);
    return SSH_OK;
}

static int mock_read_at(void *ctx, void *handle, uint64_t offset, uint8_t *buf, size_t len, size_t *read_len)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;
    size_t available;
    size_t chunk;

    if (fs == NULL || handle != fs || buf == NULL || read_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (fs->generated_read_len != 0u) {
        size_t i;

        if (offset >= fs->generated_read_len) {
            *read_len = 0u;
            return SSH_OK;
        }
        available = fs->generated_read_len - (size_t)offset;
        chunk = len < available ? len : available;
        for (i = 0u; i < chunk; ++i) {
            buf[i] = (uint8_t)(((size_t)offset + i) & 0xffu);
        }
        *read_len = chunk;
        return SSH_OK;
    }

    if (offset >= fs->data_len) {
        *read_len = 0u;
        return SSH_OK;
    }

    available = fs->data_len - (size_t)offset;
    chunk = len < available ? len : available;
    memcpy(buf, fs->data + (size_t)offset, chunk);
    *read_len = chunk;
    return SSH_OK;
}

static int mock_write_at(void *ctx, void *handle, uint64_t offset, const uint8_t *buf, size_t len, size_t *written_len)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || handle != fs || (buf == NULL && len != 0u) || written_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (offset > sizeof(fs->data) || len > sizeof(fs->data) - (size_t)offset) {
        return SSH_ERR_BUFFER_OVERFLOW;
    }

    if (len != 0u) {
        memcpy(fs->data + (size_t)offset, buf, len);
    }
    if (len != 0u && (size_t)offset + len > fs->data_len) {
        fs->data_len = (size_t)offset + len;
    }
    *written_len = len;
    return SSH_OK;
}

static int mock_stat(void *ctx, const char *path, ssh_fs_attrs_t *attrs)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || path == NULL || attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    strncpy(fs->stat_path, path, sizeof(fs->stat_path) - 1u);
    fs->stat_path[sizeof(fs->stat_path) - 1u] = '\0';
    if (fs->stat_missing_txt && strcmp(path, "missing.txt") == 0) {
        return SSH_ERR_NOT_FOUND;
    }
    memset(attrs, 0, sizeof(*attrs));
    attrs->flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS;
    attrs->size = fs->data_len;
    attrs->permissions = 0100644u;
    return SSH_OK;
}

static int mock_lstat(void *ctx, const char *path, ssh_fs_attrs_t *attrs)
{
    return mock_stat(ctx, path, attrs);
}

static int mock_setstat(void *ctx, const char *path, const ssh_fs_attrs_t *attrs)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || path == NULL || attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    strncpy(fs->setstat_path, path, sizeof(fs->setstat_path) - 1u);
    fs->setstat_path[sizeof(fs->setstat_path) - 1u] = '\0';
    fs->setstat_attrs = *attrs;
    if ((attrs->flags & SSH_FILEXFER_ATTR_SIZE) != 0u) {
        if (attrs->size > sizeof(fs->data)) {
            return SSH_ERR_BUFFER_OVERFLOW;
        }
        if (attrs->size > fs->data_len) {
            memset(fs->data + fs->data_len, 0, (size_t)attrs->size - fs->data_len);
        }
        fs->data_len = (size_t)attrs->size;
    }
    return SSH_OK;
}

static int mock_fsetstat(void *ctx, void *handle, const ssh_fs_attrs_t *attrs)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || handle != fs || attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ++fs->fsetstat_count;
    fs->fsetstat_attrs = *attrs;
    if ((attrs->flags & SSH_FILEXFER_ATTR_SIZE) != 0u) {
        if (attrs->size > sizeof(fs->data)) {
            return SSH_ERR_BUFFER_OVERFLOW;
        }
        if (attrs->size > fs->data_len) {
            memset(fs->data + fs->data_len, 0, (size_t)attrs->size - fs->data_len);
        }
        fs->data_len = (size_t)attrs->size;
    }
    return SSH_OK;
}

static int mock_opendir(void *ctx, const char *path, void **handle)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || path == NULL || handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    strncpy(fs->opendir_path, path, sizeof(fs->opendir_path) - 1u);
    fs->opendir_path[sizeof(fs->opendir_path) - 1u] = '\0';
    fs->dir_index = 0u;
    *handle = fs;
    return SSH_OK;
}

static int mock_readdir(void *ctx, void *handle, ssh_fs_dirent_t *entry, int *eof)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || handle != fs || entry == NULL || eof == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (fs->dir_index > 0u) {
        *eof = 1;
        return SSH_OK;
    }

    memset(entry, 0, sizeof(*entry));
    entry->filename = "entry.txt";
    entry->longname = "entry.txt";
    entry->attrs.flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS;
    entry->attrs.size = 6u;
    entry->attrs.permissions = 0100644u;
    ++fs->dir_index;
    *eof = 0;
    return SSH_OK;
}

static int mock_closedir(void *ctx, void *handle)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || handle != fs) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ++fs->closedir_count;
    return SSH_OK;
}

static int mock_mkdir(void *ctx, const char *path, const ssh_fs_attrs_t *attrs)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    (void)attrs;

    if (fs == NULL || path == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (strcmp(path, "existsdir") == 0) {
        return SSH_ERR_ALREADY_EXISTS;
    }

    if (attrs != NULL) {
        fs->mkdir_attrs = *attrs;
    }
    strncpy(fs->mkdir_path, path, sizeof(fs->mkdir_path) - 1u);
    fs->mkdir_path[sizeof(fs->mkdir_path) - 1u] = '\0';
    return SSH_OK;
}

static int mock_rmdir(void *ctx, const char *path)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || path == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (strcmp(path, "notempty") == 0) {
        return SSH_ERR_DIR_NOT_EMPTY;
    }

    strncpy(fs->rmdir_path, path, sizeof(fs->rmdir_path) - 1u);
    fs->rmdir_path[sizeof(fs->rmdir_path) - 1u] = '\0';
    return SSH_OK;
}

static int mock_remove(void *ctx, const char *path)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || path == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (strcmp(path, "readonly.txt") == 0) {
        return SSH_ERR_READ_ONLY;
    }

    strncpy(fs->removed_path, path, sizeof(fs->removed_path) - 1u);
    fs->removed_path[sizeof(fs->removed_path) - 1u] = '\0';
    return SSH_OK;
}

static int mock_rename(void *ctx, const char *old_path, const char *new_path)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || old_path == NULL || new_path == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    strncpy(fs->renamed_old_path, old_path, sizeof(fs->renamed_old_path) - 1u);
    fs->renamed_old_path[sizeof(fs->renamed_old_path) - 1u] = '\0';
    strncpy(fs->renamed_new_path, new_path, sizeof(fs->renamed_new_path) - 1u);
    fs->renamed_new_path[sizeof(fs->renamed_new_path) - 1u] = '\0';
    return SSH_OK;
}

static int mock_posix_rename(void *ctx, const char *old_path, const char *new_path)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || old_path == NULL || new_path == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    strncpy(fs->posix_renamed_old_path, old_path, sizeof(fs->posix_renamed_old_path) - 1u);
    fs->posix_renamed_old_path[sizeof(fs->posix_renamed_old_path) - 1u] = '\0';
    strncpy(fs->posix_renamed_new_path, new_path, sizeof(fs->posix_renamed_new_path) - 1u);
    fs->posix_renamed_new_path[sizeof(fs->posix_renamed_new_path) - 1u] = '\0';
    return SSH_OK;
}

static int mock_hardlink(void *ctx, const char *old_path, const char *new_path)
{
    mock_fs_t *fs = (mock_fs_t *)ctx;

    if (fs == NULL || old_path == NULL || new_path == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    strncpy(fs->hardlinked_old_path, old_path, sizeof(fs->hardlinked_old_path) - 1u);
    fs->hardlinked_old_path[sizeof(fs->hardlinked_old_path) - 1u] = '\0';
    strncpy(fs->hardlinked_new_path, new_path, sizeof(fs->hardlinked_new_path) - 1u);
    fs->hardlinked_new_path[sizeof(fs->hardlinked_new_path) - 1u] = '\0';
    return SSH_OK;
}

static int decode_status(const uint8_t *packet_data, size_t packet_len, uint32_t *request_id, uint32_t *status_code)
{
    sftp_packet_t packet;
    ssh_buffer_t payload;

    if (sftp_packet_wrap(packet_data, packet_len, &packet) != SSH_OK || packet.type != SSH_FXP_STATUS) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    if (ssh_buffer_get_u32(&payload, request_id) != SSH_OK) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return ssh_buffer_get_u32(&payload, status_code);
}

static int decode_status_message(
    const uint8_t *packet_data,
    size_t packet_len,
    uint32_t *request_id,
    uint32_t *status_code,
    ssh_string_view_t *message)
{
    sftp_packet_t packet;
    ssh_buffer_t payload;

    if (message == NULL ||
        sftp_packet_wrap(packet_data, packet_len, &packet) != SSH_OK ||
        packet.type != SSH_FXP_STATUS) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    if (ssh_buffer_get_u32(&payload, request_id) != SSH_OK ||
        ssh_buffer_get_u32(&payload, status_code) != SSH_OK) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return ssh_buffer_get_string_view(&payload, message);
}

static int status_message_equals(ssh_string_view_t message, const char *expected)
{
    size_t expected_len = strlen(expected);

    return message.len == expected_len &&
           message.data != NULL &&
           memcmp(message.data, expected, expected_len) == 0;
}

static int test_policy(void *ctx, const sftp_policy_request_t *request)
{
    test_policy_ctx_t *policy = (test_policy_ctx_t *)ctx;

    if (policy == NULL || request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    policy->last_operation = request->operation;
    policy->last_offset = request->offset;
    policy->last_length = request->length;
    policy->last_path[0] = '\0';
    policy->last_new_path[0] = '\0';
    if (request->path != NULL) {
        strncpy(policy->last_path, request->path, sizeof(policy->last_path) - 1u);
        policy->last_path[sizeof(policy->last_path) - 1u] = '\0';
    }
    if (request->new_path != NULL) {
        strncpy(policy->last_new_path, request->new_path, sizeof(policy->last_new_path) - 1u);
        policy->last_new_path[sizeof(policy->last_new_path) - 1u] = '\0';
    }

    if (policy->deny_path != NULL &&
        request->path != NULL &&
        strcmp(policy->deny_path, request->path) == 0) {
        return SSH_ERR_SECURITY;
    }
    if (request->operation == SFTP_POLICY_WRITE &&
        policy->max_write_end != 0u &&
        request->offset <= UINT64_MAX - (uint64_t)request->length &&
        request->offset + (uint64_t)request->length > policy->max_write_end) {
        return SSH_ERR_SECURITY;
    }

    return SSH_OK;
}

int main(void)
{
    mock_fs_t fs_ctx;
    test_policy_ctx_t policy_ctx;
    ssh_fs_api_t fs;
    sftp_server_session_t session;
    uint8_t request[256];
    uint8_t response[256];
    static uint8_t large_response[EMSSH_MAX_PACKET_SIZE];
    uint8_t handle[8];
    size_t request_len;
    size_t response_len;
    size_t handle_len;
    sftp_packet_t packet;
    ssh_buffer_t payload;
    ssh_string_view_t view;
    uint64_t size_value;
    uint32_t value;
    uint32_t status_code;
    size_t i;

    memset(&fs_ctx, 0, sizeof(fs_ctx));
    memcpy(fs_ctx.data, "abcdef", 6u);
    fs_ctx.data_len = 6u;
    memset(&policy_ctx, 0, sizeof(policy_ctx));

    memset(&fs, 0, sizeof(fs));
    fs.open = mock_open;
    fs.close = mock_close;
    fs.read_at = mock_read_at;
    fs.write_at = mock_write_at;
    fs.stat = mock_stat;
    fs.lstat = mock_lstat;
    fs.setstat = mock_setstat;
    fs.fsetstat = mock_fsetstat;
    fs.opendir = mock_opendir;
    fs.readdir = mock_readdir;
    fs.closedir = mock_closedir;
    fs.mkdir = mock_mkdir;
    fs.rmdir = mock_rmdir;
    fs.remove = mock_remove;
    fs.rename = mock_rename;
    fs.posix_rename = mock_posix_rename;
    fs.fsync = mock_fsync;
    fs.hardlink = mock_hardlink;
    fs.statvfs = mock_statvfs;
    fs.fstatvfs = mock_fstatvfs;
    fs.ctx = &fs_ctx;

    CHECK(sftp_server_session_init(&session, &fs) == SSH_OK);

    request[0] = 0u;
    request[1] = 0u;
    request[2] = 0u;
    request[3] = 5u;
    request[4] = SSH_FXP_INIT;
    request[5] = 0u;
    request[6] = 0u;
    request[7] = 0u;
    request[8] = SFTP_VERSION_3;
    CHECK(sftp_server_handle_packet(&session, request, 9u, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_VERSION);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_REALPATH) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 1u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, ".") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_NAME);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 1u);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 1u);
    CHECK(ssh_buffer_get_string_view(&payload, &view) == SSH_OK);
    CHECK(view.len == 1u && view.data[0] == '/');

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_REALPATH) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 2u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "/mnt/host/..") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_NAME);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 2u);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 1u);
    CHECK(ssh_buffer_get_string_view(&payload, &view) == SSH_OK);
    CHECK(view.len == strlen("/mnt") && memcmp(view.data, "/mnt", view.len) == 0);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_STAT) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 10u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "file.txt") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(strcmp(fs_ctx.stat_path, "file.txt") == 0);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_ATTRS);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 10u);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == (SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS));

    fs_ctx.stat_missing_txt = 1;
    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_STAT) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 11u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "missing.txt") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(strcmp(fs_ctx.stat_path, "missing.txt") == 0);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 11u);
    CHECK(status_code == SSH_FX_NO_SUCH_FILE);
    fs_ctx.stat_missing_txt = 0;

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 45u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "bad-flags.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0u) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 45u);
    CHECK(status_code == SSH_FX_BAD_MESSAGE);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 46u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "bad-flags.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FXF_READ | SSH_FXF_CREAT) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 46u);
    CHECK(status_code == SSH_FX_BAD_MESSAGE);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 47u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "bad-flags.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FXF_WRITE | SSH_FXF_EXCL) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 47u);
    CHECK(status_code == SSH_FX_BAD_MESSAGE);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 48u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "bad-flags.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FXF_READ | 0x00000100u) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 48u);
    CHECK(status_code == SSH_FX_BAD_MESSAGE);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 49u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "readonly-attrs.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FXF_READ) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FILEXFER_ATTR_PERMISSIONS) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0100600u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 49u);
    CHECK(status_code == SSH_FX_PERMISSION_DENIED);

    fs_ctx.data_len = 0u;
    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 70u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "winscp-ascii-edit.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FILEXFER_ATTR_SIZE) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&payload, 18u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_HANDLE);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 70u);
    CHECK(ssh_buffer_get_string_view(&payload, &view) == SSH_OK);
    CHECK(view.len <= sizeof(handle));
    memcpy(handle, view.data, view.len);
    handle_len = view.len;
    CHECK(fs_ctx.fsetstat_count == 0);
    CHECK(fs_ctx.data_len == 0u);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_WRITE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 71u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&payload, 0u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "line1\nline2\n") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 71u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(fs_ctx.data_len == strlen("line1\nline2\n"));
    CHECK(memcmp(fs_ctx.data, "line1\nline2\n", fs_ctx.data_len) == 0);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_CLOSE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 72u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 72u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(fs_ctx.close_count == 1);
    fs_ctx.close_count = 0;
    memcpy(fs_ctx.data, "abcdef", 6u);
    fs_ctx.data_len = 6u;

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 31u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "attr-open.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FXF_READ | SSH_FXF_WRITE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FILEXFER_ATTR_PERMISSIONS) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0100600u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(strcmp(fs_ctx.opened_path, "attr-open.txt") == 0);
    CHECK(fs_ctx.fsetstat_attrs.flags == SSH_FILEXFER_ATTR_PERMISSIONS);
    CHECK(fs_ctx.fsetstat_attrs.permissions == 0100600u);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_HANDLE);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 31u);
    CHECK(ssh_buffer_get_string_view(&payload, &view) == SSH_OK);
    CHECK(view.len <= sizeof(handle));
    memcpy(handle, view.data, view.len);
    handle_len = view.len;

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_CLOSE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 32u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 32u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(fs_ctx.close_count == 1);
    fs_ctx.close_count = 0;

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 38u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "readonly-handle.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FXF_READ) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_HANDLE);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 38u);
    CHECK(ssh_buffer_get_string_view(&payload, &view) == SSH_OK);
    CHECK(view.len <= sizeof(handle));
    memcpy(handle, view.data, view.len);
    handle_len = view.len;

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_WRITE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 39u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&payload, 0u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "Z") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 39u);
    CHECK(status_code == SSH_FX_PERMISSION_DENIED);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_FSETSTAT) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 44u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FILEXFER_ATTR_SIZE) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&payload, 1u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 44u);
    CHECK(status_code == SSH_FX_PERMISSION_DENIED);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_CLOSE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 40u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 40u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(fs_ctx.close_count == 1);
    fs_ctx.close_count = 0;

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 41u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "writeonly-handle.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FXF_WRITE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_HANDLE);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 41u);
    CHECK(ssh_buffer_get_string_view(&payload, &view) == SSH_OK);
    CHECK(view.len <= sizeof(handle));
    memcpy(handle, view.data, view.len);
    handle_len = view.len;

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_READ) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 42u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&payload, 0u) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 1u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 42u);
    CHECK(status_code == SSH_FX_PERMISSION_DENIED);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_CLOSE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 43u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 43u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(fs_ctx.close_count == 1);
    fs_ctx.close_count = 0;

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 2u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "file.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FXF_READ | SSH_FXF_WRITE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(strcmp(fs_ctx.opened_path, "file.txt") == 0);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_HANDLE);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 2u);
    CHECK(ssh_buffer_get_string_view(&payload, &view) == SSH_OK);
    CHECK(view.len <= sizeof(handle));
    memcpy(handle, view.data, view.len);
    handle_len = view.len;

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_FSTAT) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 24u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_ATTRS);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 24u);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == (SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS));
    CHECK(ssh_buffer_get_u64(&payload, &size_value) == SSH_OK);
    CHECK(size_value == 6u);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_EXTENDED) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 56u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "fsync@openssh.com") == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 56u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(fs_ctx.fsync_count == 1);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_EXTENDED) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 58u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "statvfs@openssh.com") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "file.txt") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_EXTENDED_REPLY);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 58u);
    CHECK(ssh_buffer_get_u64(&payload, &size_value) == SSH_OK);
    CHECK(size_value == 4096u);
    CHECK(ssh_buffer_get_u64(&payload, &size_value) == SSH_OK);
    CHECK(size_value == 4096u);
    CHECK(ssh_buffer_get_u64(&payload, &size_value) == SSH_OK);
    CHECK(size_value == 1000u);
    CHECK(fs_ctx.statvfs_count == 1);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_EXTENDED) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 59u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "fstatvfs@openssh.com") == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_EXTENDED_REPLY);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 59u);
    CHECK(ssh_buffer_get_u64(&payload, &size_value) == SSH_OK);
    CHECK(size_value == 4096u);
    CHECK(fs_ctx.fstatvfs_count == 1);

    policy_ctx.deny_path = "file.txt";
    policy_ctx.max_write_end = 0u;
    CHECK(sftp_server_session_set_policy(&session, test_policy, &policy_ctx) == SSH_OK);
    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_EXTENDED) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 67u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "fstatvfs@openssh.com") == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 67u);
    CHECK(status_code == SSH_FX_PERMISSION_DENIED);
    CHECK(policy_ctx.last_operation == SFTP_POLICY_FSTATVFS);
    CHECK(strcmp(policy_ctx.last_path, "file.txt") == 0);
    CHECK(fs_ctx.fstatvfs_count == 1);

    policy_ctx.deny_path = NULL;
    CHECK(sftp_server_session_set_policy(&session, test_policy, &policy_ctx) == SSH_OK);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_FSETSTAT) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 36u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0x00000010u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 36u);
    CHECK(status_code == SSH_FX_OP_UNSUPPORTED);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_FSETSTAT) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 27u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FILEXFER_ATTR_SIZE) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&payload, 3u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 27u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(fs_ctx.fsetstat_attrs.flags == SSH_FILEXFER_ATTR_SIZE);
    CHECK(fs_ctx.fsetstat_attrs.size == 3u);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_FSTAT) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 35u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_ATTRS);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 35u);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == (SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS));
    CHECK(ssh_buffer_get_u64(&payload, &size_value) == SSH_OK);
    CHECK(size_value == 3u);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 0100644u);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_READ) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 3u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&payload, 1u) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 3u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_DATA);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 3u);
    CHECK(ssh_buffer_get_string_view(&payload, &view) == SSH_OK);
    CHECK(view.len == 2u);
    CHECK(memcmp(view.data, "bc", 2u) == 0);

    fs_ctx.generated_read_len = 32752u;
    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_READ) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 69u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&payload, 0u) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 32752u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, large_response, sizeof(large_response), &response_len) == SSH_OK);
    CHECK(response_len == 32752u + 13u);
    CHECK(sftp_packet_wrap(large_response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_DATA);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 69u);
    CHECK(ssh_buffer_get_string_view(&payload, &view) == SSH_OK);
    CHECK(view.len == 32752u);
    for (i = 0u; i < view.len; ++i) {
        CHECK(view.data[i] == (uint8_t)(i & 0xffu));
    }
    fs_ctx.generated_read_len = 0u;

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_WRITE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 4u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&payload, 2u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "XY") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 4u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(fs_ctx.data_len == 4u);
    CHECK(memcmp(fs_ctx.data, "abXY", 4u) == 0);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_FSTAT) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 34u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_ATTRS);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 34u);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == (SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS));
    CHECK(ssh_buffer_get_u64(&payload, &size_value) == SSH_OK);
    CHECK(size_value == 4u);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 0100644u);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_WRITE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 50u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&payload, 10u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 50u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(fs_ctx.data_len == 4u);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_FSTAT) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 51u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_ATTRS);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 51u);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == (SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS));
    CHECK(ssh_buffer_get_u64(&payload, &size_value) == SSH_OK);
    CHECK(size_value == 4u);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_WRITE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 64u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&payload, 63u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "XY") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status_message(response, response_len, &value, &status_code, &view) == SSH_OK);
    CHECK(value == 64u);
    CHECK(status_code == SSH_FX_FAILURE);
    CHECK(status_message_equals(view, "buffer overflow"));

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_SETSTAT) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 52u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "file.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FILEXFER_ATTR_SIZE) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&payload, 2u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 52u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(strcmp(fs_ctx.setstat_path, "file.txt") == 0);
    CHECK(fs_ctx.setstat_attrs.flags == SSH_FILEXFER_ATTR_SIZE);
    CHECK(fs_ctx.setstat_attrs.size == 2u);
    CHECK(fs_ctx.data_len == 2u);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_FSTAT) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 53u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_ATTRS);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 53u);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == (SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS));
    CHECK(ssh_buffer_get_u64(&payload, &size_value) == SSH_OK);
    CHECK(size_value == 2u);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_CLOSE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 5u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 5u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(fs_ctx.close_count == 1);

    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 5u);
    CHECK(status_code == SSH_FX_FAILURE);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_MKDIR) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 25u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "newdir") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FILEXFER_ATTR_PERMISSIONS) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0040755u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 25u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(strcmp(fs_ctx.mkdir_path, "newdir") == 0);
    CHECK(fs_ctx.mkdir_attrs.flags == SSH_FILEXFER_ATTR_PERMISSIONS);
    CHECK(fs_ctx.mkdir_attrs.permissions == 0040755u);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_MKDIR) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 65u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "existsdir") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status_message(response, response_len, &value, &status_code, &view) == SSH_OK);
    CHECK(value == 65u);
    CHECK(status_code == SSH_FX_FAILURE);
    CHECK(status_message_equals(view, "already exists"));

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_RMDIR) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 26u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "newdir") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 26u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(strcmp(fs_ctx.rmdir_path, "newdir") == 0);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_RMDIR) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 66u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "notempty") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status_message(response, response_len, &value, &status_code, &view) == SSH_OK);
    CHECK(value == 66u);
    CHECK(status_code == SSH_FX_FAILURE);
    CHECK(status_message_equals(view, "directory not empty"));

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_SETSTAT) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 28u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "file.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FILEXFER_ATTR_PERMISSIONS) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0100600u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 28u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(strcmp(fs_ctx.setstat_path, "file.txt") == 0);
    CHECK(fs_ctx.setstat_attrs.flags == SSH_FILEXFER_ATTR_PERMISSIONS);
    CHECK(fs_ctx.setstat_attrs.permissions == 0100600u);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_SETSTAT) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 37u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "file.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0x00000010u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 37u);
    CHECK(status_code == SSH_FX_OP_UNSUPPORTED);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_REMOVE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 6u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "delete.txt") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 6u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(strcmp(fs_ctx.removed_path, "delete.txt") == 0);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_REMOVE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 33u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "readonly.txt") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 33u);
    CHECK(status_code == SSH_FX_PERMISSION_DENIED);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_RENAME) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 7u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "old.txt") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "new.txt") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 7u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(strcmp(fs_ctx.renamed_old_path, "old.txt") == 0);
    CHECK(strcmp(fs_ctx.renamed_new_path, "new.txt") == 0);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_EXTENDED) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 54u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "posix-rename@openssh.com") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "old-posix.txt") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "new-posix.txt") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 54u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(strcmp(fs_ctx.posix_renamed_old_path, "old-posix.txt") == 0);
    CHECK(strcmp(fs_ctx.posix_renamed_new_path, "new-posix.txt") == 0);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_EXTENDED) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 57u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "hardlink@openssh.com") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "old-hardlink.txt") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "new-hardlink.txt") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 57u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(strcmp(fs_ctx.hardlinked_old_path, "old-hardlink.txt") == 0);
    CHECK(strcmp(fs_ctx.hardlinked_new_path, "new-hardlink.txt") == 0);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_EXTENDED) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 55u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "unknown@example.com") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 55u);
    CHECK(status_code == SSH_FX_OP_UNSUPPORTED);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 8u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "../secret.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FXF_READ) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 8u);
    CHECK(status_code == SSH_FX_PERMISSION_DENIED);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_REMOVE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 9u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "C:\\secret.txt") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 9u);
    CHECK(status_code == SSH_FX_PERMISSION_DENIED);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_OPENDIR) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 20u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, ".") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(strcmp(fs_ctx.opendir_path, ".") == 0);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_HANDLE);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 20u);
    CHECK(ssh_buffer_get_string_view(&payload, &view) == SSH_OK);
    CHECK(view.len <= sizeof(handle));
    memcpy(handle, view.data, view.len);
    handle_len = view.len;

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_READ) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 29u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&payload, 0u) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 1u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 29u);
    CHECK(status_code == SSH_FX_FAILURE);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_WRITE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 30u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&payload, 0u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "Z") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 30u);
    CHECK(status_code == SSH_FX_FAILURE);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_READDIR) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 21u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_NAME);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 21u);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 1u);
    CHECK(ssh_buffer_get_string_view(&payload, &view) == SSH_OK);
    CHECK(view.len == strlen("entry.txt"));
    CHECK(memcmp(view.data, "entry.txt", view.len) == 0);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_READDIR) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 22u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 22u);
    CHECK(status_code == SSH_FX_EOF);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_CLOSE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 23u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 23u);
    CHECK(status_code == SSH_FX_OK);
    CHECK(fs_ctx.closedir_count == 1);

    policy_ctx.deny_path = "blocked.txt";
    CHECK(sftp_server_session_set_policy(&session, test_policy, &policy_ctx) == SSH_OK);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 60u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "blocked.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FXF_READ) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 60u);
    CHECK(status_code == SSH_FX_PERMISSION_DENIED);
    CHECK(policy_ctx.last_operation == SFTP_POLICY_OPEN);
    CHECK(strcmp(policy_ctx.last_path, "blocked.txt") == 0);
    CHECK(strcmp(fs_ctx.opened_path, "blocked.txt") != 0);

    policy_ctx.deny_path = NULL;
    policy_ctx.max_write_end = 4u;

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 61u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "limited.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, SSH_FXF_WRITE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 0u) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(sftp_packet_wrap(response, response_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_HANDLE);
    ssh_buffer_wrap(&payload, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&payload, &value) == SSH_OK);
    CHECK(value == 61u);
    CHECK(ssh_buffer_get_string_view(&payload, &view) == SSH_OK);
    CHECK(view.len <= sizeof(handle));
    memcpy(handle, view.data, view.len);
    handle_len = view.len;
    CHECK(policy_ctx.last_operation == SFTP_POLICY_OPEN);
    CHECK(strcmp(policy_ctx.last_path, "limited.txt") == 0);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_WRITE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 62u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&payload, 2u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&payload, "XYZ") == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 62u);
    CHECK(status_code == SSH_FX_PERMISSION_DENIED);
    CHECK(policy_ctx.last_operation == SFTP_POLICY_WRITE);
    CHECK(strcmp(policy_ctx.last_path, "limited.txt") == 0);
    CHECK(policy_ctx.last_offset == 2u);
    CHECK(policy_ctx.last_length == 3u);

    ssh_buffer_init(&payload, request + 4u, sizeof(request) - 4u);
    CHECK(ssh_buffer_put_u8(&payload, SSH_FXP_CLOSE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&payload, 63u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&payload, handle, handle_len) == SSH_OK);
    finish_packet(request, &payload, &request_len);
    CHECK(sftp_server_handle_packet(&session, request, request_len, response, sizeof(response), &response_len) == SSH_OK);
    CHECK(decode_status(response, response_len, &value, &status_code) == SSH_OK);
    CHECK(value == 63u);
    CHECK(status_code == SSH_FX_OK);

    sftp_server_session_deinit(&session);
    return 0;
}
