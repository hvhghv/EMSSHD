#include <stdio.h>
#include <string.h>

#include "emssh/sftp.h"
#include "emssh/ssh_error.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

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

int main(void)
{
    uint8_t init_packet[] = {
        0u, 0u, 0u, 5u,
        SSH_FXP_INIT,
        0u, 0u, 0u, SFTP_VERSION_3
    };
    uint8_t out[128];
    size_t out_len;
    sftp_packet_t packet;
    sftp_init_t init;
    ssh_buffer_t buf;
    uint32_t value;
    uint64_t offset;
    ssh_string_view_t message;
    ssh_string_view_t language;
    ssh_string_view_t attrs_view;
    sftp_request_t request;
    sftp_path_request_t path_request;
    sftp_open_request_t open_request;
    sftp_handle_request_t handle_request;
    sftp_read_request_t read_request;
    sftp_write_request_t write_request;
    sftp_rename_request_t rename_request;
    sftp_mkdir_request_t mkdir_request;
    sftp_setstat_request_t setstat_request;
    sftp_fsetstat_request_t fsetstat_request;
    sftp_extended_request_t extended_request;
    uint8_t handle[] = { 'h', '1' };
    ssh_fs_attrs_t attrs;

    CHECK(sftp_packet_wrap(init_packet, sizeof(init_packet), &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_INIT);
    CHECK(packet.payload.len == 4u);

    CHECK(sftp_init_decode(init_packet, sizeof(init_packet), &init) == SSH_OK);
    CHECK(init.version == SFTP_VERSION_3);
    CHECK(init.extension_data.len == 0u);

    CHECK(sftp_version_encode(out, sizeof(out), &out_len, SFTP_VERSION_3) == SSH_OK);
    CHECK(out_len == 9u);
    CHECK(sftp_packet_wrap(out, out_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_VERSION);
    CHECK(packet.payload.len == 4u);
    CHECK(packet.payload.data[3] == SFTP_VERSION_3);

    CHECK(sftp_status_encode(out, sizeof(out), &out_len, 42u, SSH_FX_OP_UNSUPPORTED, "unsupported", "") == SSH_OK);
    CHECK(sftp_packet_wrap(out, out_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_STATUS);
    ssh_buffer_wrap(&buf, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&buf, &value) == SSH_OK);
    CHECK(value == 42u);
    CHECK(ssh_buffer_get_u32(&buf, &value) == SSH_OK);
    CHECK(value == SSH_FX_OP_UNSUPPORTED);
    CHECK(ssh_buffer_get_string_view(&buf, &message) == SSH_OK);
    CHECK(message.len == strlen("unsupported"));
    CHECK(memcmp(message.data, "unsupported", message.len) == 0);
    CHECK(ssh_buffer_get_string_view(&buf, &language) == SSH_OK);
    CHECK(language.len == 0u);
    CHECK(ssh_buffer_remaining_read(&buf) == 0u);

    CHECK(sftp_packet_wrap(out, out_len - 1u, &packet) == SSH_ERR_MALFORMED_PACKET);
    CHECK(sftp_init_decode(out, out_len, &init) == SSH_ERR_MALFORMED_PACKET);

    ssh_buffer_init(&buf, out + 4u, sizeof(out) - 4u);
    CHECK(ssh_buffer_put_u8(&buf, SSH_FXP_REALPATH) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 7u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, ".") == SSH_OK);
    finish_packet(out, &buf, &out_len);
    CHECK(sftp_request_decode(out, out_len, &request) == SSH_OK);
    CHECK(request.type == SSH_FXP_REALPATH);
    CHECK(request.id == 7u);
    CHECK(sftp_realpath_request_decode(out, out_len, &path_request) == SSH_OK);
    CHECK(path_request.id == 7u);
    CHECK(path_request.path.len == 1u);
    CHECK(path_request.path.data[0] == '.');

    ssh_buffer_init(&buf, out + 4u, sizeof(out) - 4u);
    CHECK(ssh_buffer_put_u8(&buf, SSH_FXP_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 8u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "file.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, SSH_FXF_READ) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 0u) == SSH_OK);
    finish_packet(out, &buf, &out_len);
    CHECK(sftp_open_request_decode(out, out_len, &open_request) == SSH_OK);
    CHECK(open_request.id == 8u);
    CHECK(open_request.filename.len == strlen("file.txt"));
    CHECK(memcmp(open_request.filename.data, "file.txt", open_request.filename.len) == 0);
    CHECK(open_request.pflags == SSH_FXF_READ);
    CHECK(open_request.attrs.len == 4u);

    ssh_buffer_init(&buf, out + 4u, sizeof(out) - 4u);
    CHECK(ssh_buffer_put_u8(&buf, SSH_FXP_READ) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 9u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&buf, handle, sizeof(handle)) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&buf, 0x0102030405060708ull) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 4096u) == SSH_OK);
    finish_packet(out, &buf, &out_len);
    CHECK(sftp_read_request_decode(out, out_len, &read_request) == SSH_OK);
    CHECK(read_request.id == 9u);
    CHECK(read_request.handle.len == sizeof(handle));
    CHECK(read_request.offset == 0x0102030405060708ull);
    CHECK(read_request.len == 4096u);

    ssh_buffer_init(&buf, out + 4u, sizeof(out) - 4u);
    CHECK(ssh_buffer_put_u8(&buf, SSH_FXP_WRITE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 10u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&buf, handle, sizeof(handle)) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&buf, 5u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "data") == SSH_OK);
    finish_packet(out, &buf, &out_len);
    CHECK(sftp_write_request_decode(out, out_len, &write_request) == SSH_OK);
    CHECK(write_request.id == 10u);
    CHECK(write_request.offset == 5u);
    CHECK(write_request.data.len == strlen("data"));
    CHECK(memcmp(write_request.data.data, "data", write_request.data.len) == 0);

    ssh_buffer_init(&buf, out + 4u, sizeof(out) - 4u);
    CHECK(ssh_buffer_put_u8(&buf, SSH_FXP_CLOSE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 11u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&buf, handle, sizeof(handle)) == SSH_OK);
    finish_packet(out, &buf, &out_len);
    CHECK(sftp_close_request_decode(out, out_len, &handle_request) == SSH_OK);
    CHECK(handle_request.id == 11u);
    CHECK(handle_request.handle.len == sizeof(handle));

    ssh_buffer_init(&buf, out + 4u, sizeof(out) - 4u);
    CHECK(ssh_buffer_put_u8(&buf, SSH_FXP_REMOVE) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 12u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "old.txt") == SSH_OK);
    finish_packet(out, &buf, &out_len);
    CHECK(sftp_remove_request_decode(out, out_len, &path_request) == SSH_OK);
    CHECK(path_request.id == 12u);
    CHECK(path_request.path.len == strlen("old.txt"));

    ssh_buffer_init(&buf, out + 4u, sizeof(out) - 4u);
    CHECK(ssh_buffer_put_u8(&buf, SSH_FXP_MKDIR) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 16u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "newdir") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 0u) == SSH_OK);
    finish_packet(out, &buf, &out_len);
    CHECK(sftp_mkdir_request_decode(out, out_len, &mkdir_request) == SSH_OK);
    CHECK(mkdir_request.id == 16u);
    CHECK(mkdir_request.path.len == strlen("newdir"));
    CHECK(mkdir_request.attrs.len == 4u);

    ssh_buffer_init(&buf, out + 4u, sizeof(out) - 4u);
    CHECK(ssh_buffer_put_u8(&buf, SSH_FXP_RMDIR) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 17u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "newdir") == SSH_OK);
    finish_packet(out, &buf, &out_len);
    CHECK(sftp_rmdir_request_decode(out, out_len, &path_request) == SSH_OK);
    CHECK(path_request.id == 17u);
    CHECK(path_request.path.len == strlen("newdir"));

    ssh_buffer_init(&buf, out + 4u, sizeof(out) - 4u);
    CHECK(ssh_buffer_put_u8(&buf, SSH_FXP_RENAME) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 13u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "old.txt") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "new.txt") == SSH_OK);
    finish_packet(out, &buf, &out_len);
    CHECK(sftp_rename_request_decode(out, out_len, &rename_request) == SSH_OK);
    CHECK(rename_request.id == 13u);
    CHECK(rename_request.old_path.len == strlen("old.txt"));
    CHECK(rename_request.new_path.len == strlen("new.txt"));

    ssh_buffer_init(&buf, out + 4u, sizeof(out) - 4u);
    CHECK(ssh_buffer_put_u8(&buf, SSH_FXP_EXTENDED) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 18u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "posix-rename@openssh.com") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "old.txt") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "new.txt") == SSH_OK);
    finish_packet(out, &buf, &out_len);
    CHECK(sftp_extended_request_decode(out, out_len, &extended_request) == SSH_OK);
    CHECK(extended_request.id == 18u);
    CHECK(extended_request.name.len == strlen("posix-rename@openssh.com"));
    CHECK(memcmp(extended_request.name.data, "posix-rename@openssh.com", extended_request.name.len) == 0);
    ssh_buffer_wrap(&buf, (uint8_t *)extended_request.payload.data, extended_request.payload.len);
    CHECK(ssh_buffer_get_string_view(&buf, &message) == SSH_OK);
    CHECK(message.len == strlen("old.txt"));
    CHECK(ssh_buffer_get_string_view(&buf, &language) == SSH_OK);
    CHECK(language.len == strlen("new.txt"));
    CHECK(ssh_buffer_remaining_read(&buf) == 0u);

    CHECK(sftp_handle_encode(out, sizeof(out), &out_len, 8u, handle, sizeof(handle)) == SSH_OK);
    CHECK(sftp_packet_wrap(out, out_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_HANDLE);
    ssh_buffer_wrap(&buf, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&buf, &value) == SSH_OK);
    CHECK(value == 8u);
    CHECK(ssh_buffer_get_string_view(&buf, &message) == SSH_OK);
    CHECK(message.len == sizeof(handle));

    CHECK(sftp_data_encode(out, sizeof(out), &out_len, 9u, (const uint8_t *)"abc", 3u) == SSH_OK);
    CHECK(sftp_packet_wrap(out, out_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_DATA);
    ssh_buffer_wrap(&buf, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&buf, &value) == SSH_OK);
    CHECK(value == 9u);
    CHECK(ssh_buffer_get_string_view(&buf, &message) == SSH_OK);
    CHECK(message.len == 3u);
    CHECK(memcmp(message.data, "abc", 3u) == 0);

    CHECK(sftp_name_one_encode(out, sizeof(out), &out_len, 7u, "/", NULL) == SSH_OK);
    CHECK(sftp_packet_wrap(out, out_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_NAME);
    ssh_buffer_wrap(&buf, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&buf, &value) == SSH_OK);
    CHECK(value == 7u);
    CHECK(ssh_buffer_get_u32(&buf, &value) == SSH_OK);
    CHECK(value == 1u);
    CHECK(ssh_buffer_get_string_view(&buf, &message) == SSH_OK);
    CHECK(message.len == 1u && message.data[0] == '/');
    CHECK(ssh_buffer_get_string_view(&buf, &language) == SSH_OK);
    CHECK(language.len == 1u && language.data[0] == '/');
    CHECK(ssh_buffer_get_u32(&buf, &value) == SSH_OK);
    CHECK(value == 0u);
    CHECK(ssh_buffer_remaining_read(&buf) == 0u);

    memset(&attrs, 0, sizeof(attrs));
    attrs.flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS;
    attrs.size = 1234u;
    attrs.permissions = 0100644u;
    CHECK(sftp_attrs_encode(out, sizeof(out), &out_len, 14u, &attrs) == SSH_OK);
    CHECK(sftp_packet_wrap(out, out_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_ATTRS);
    ssh_buffer_wrap(&buf, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&buf, &value) == SSH_OK);
    CHECK(value == 14u);
    CHECK(ssh_buffer_get_u32(&buf, &value) == SSH_OK);
    CHECK(value == (SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS));
    CHECK(ssh_buffer_get_u64(&buf, &offset) == SSH_OK);
    CHECK(offset == 1234u);
    CHECK(ssh_buffer_get_u32(&buf, &value) == SSH_OK);
    CHECK(value == 0100644u);
    CHECK(ssh_buffer_remaining_read(&buf) == 0u);

    CHECK(sftp_name_one_attrs_encode(out, sizeof(out), &out_len, 15u, "file.txt", NULL, &attrs) == SSH_OK);
    CHECK(sftp_packet_wrap(out, out_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_NAME);

    ssh_buffer_init(&buf, out, sizeof(out));
    CHECK(ssh_buffer_put_u32(&buf, SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_EXTENDED) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 0100600u) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 1u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "vendor@example.com") == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "ignored") == SSH_OK);
    attrs_view.data = out;
    attrs_view.len = ssh_buffer_len(&buf);
    memset(&attrs, 0, sizeof(attrs));
    CHECK(sftp_attrs_decode(attrs_view, &attrs) == SSH_OK);
    CHECK(attrs.flags == SSH_FILEXFER_ATTR_PERMISSIONS);
    CHECK(attrs.permissions == 0100600u);

    memset(&attrs, 0, sizeof(attrs));
    attrs.flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_EXTENDED;
    attrs.size = 55u;
    CHECK(sftp_attrs_encode(out, sizeof(out), &out_len, 20u, &attrs) == SSH_OK);
    CHECK(sftp_packet_wrap(out, out_len, &packet) == SSH_OK);
    CHECK(packet.type == SSH_FXP_ATTRS);
    ssh_buffer_wrap(&buf, (uint8_t *)packet.payload.data, packet.payload.len);
    CHECK(ssh_buffer_get_u32(&buf, &value) == SSH_OK);
    CHECK(value == 20u);
    CHECK(ssh_buffer_get_u32(&buf, &value) == SSH_OK);
    CHECK(value == SSH_FILEXFER_ATTR_SIZE);
    CHECK(ssh_buffer_get_u64(&buf, &offset) == SSH_OK);
    CHECK(offset == 55u);
    CHECK(ssh_buffer_remaining_read(&buf) == 0u);

    ssh_buffer_init(&buf, out + 4u, sizeof(out) - 4u);
    CHECK(ssh_buffer_put_u8(&buf, SSH_FXP_SETSTAT) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 18u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "file.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, SSH_FILEXFER_ATTR_PERMISSIONS) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 0100600u) == SSH_OK);
    finish_packet(out, &buf, &out_len);
    CHECK(sftp_setstat_request_decode(out, out_len, &setstat_request) == SSH_OK);
    CHECK(setstat_request.id == 18u);
    CHECK(setstat_request.path.len == strlen("file.txt"));
    CHECK(setstat_request.attrs.flags == SSH_FILEXFER_ATTR_PERMISSIONS);
    CHECK(setstat_request.attrs.permissions == 0100600u);

    ssh_buffer_init(&buf, out + 4u, sizeof(out) - 4u);
    CHECK(ssh_buffer_put_u8(&buf, SSH_FXP_FSETSTAT) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 19u) == SSH_OK);
    CHECK(ssh_buffer_put_string(&buf, handle, sizeof(handle)) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, SSH_FILEXFER_ATTR_SIZE) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&buf, 7u) == SSH_OK);
    finish_packet(out, &buf, &out_len);
    CHECK(sftp_fsetstat_request_decode(out, out_len, &fsetstat_request) == SSH_OK);
    CHECK(fsetstat_request.id == 19u);
    CHECK(fsetstat_request.handle.len == sizeof(handle));
    CHECK(fsetstat_request.attrs.flags == SSH_FILEXFER_ATTR_SIZE);
    CHECK(fsetstat_request.attrs.size == 7u);

    CHECK(ssh_buffer_get_u64(NULL, &offset) == SSH_ERR_INVALID_ARGUMENT);

    return 0;
}
