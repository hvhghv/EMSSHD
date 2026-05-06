#include "emssh/sftp.h"

#include <string.h>

#include "emssh/ssh_error.h"

#define SFTP_SUPPORTED_ATTR_FLAGS \
    (SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID | SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME)

static uint32_t read_u32_be(const uint8_t data[4])
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static void write_u32_be(uint8_t data[4], uint32_t value)
{
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

static int packet_payload_init(uint8_t *out, size_t out_capacity, ssh_buffer_t *payload)
{
    if (out == NULL || payload == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (out_capacity < 4u) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    ssh_buffer_init(payload, out + 4u, out_capacity - 4u);
    return SSH_OK;
}

static int packet_finish(uint8_t *out, ssh_buffer_t *payload, size_t *out_len)
{
    size_t payload_len;

    if (out == NULL || payload == NULL || out_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    payload_len = ssh_buffer_len(payload);
    if (payload_len > UINT32_MAX) {
        return SSH_ERR_BUFFER_OVERFLOW;
    }

    write_u32_be(out, (uint32_t)payload_len);
    *out_len = payload_len + 4u;
    return SSH_OK;
}

static int decode_path_request(
    const uint8_t *packet,
    size_t packet_len,
    uint8_t expected_type,
    sftp_path_request_t *request)
{
    sftp_request_t generic;
    ssh_buffer_t payload;
    int status;

    if (request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(request, 0, sizeof(*request));
    status = sftp_request_decode(packet, packet_len, &generic);
    if (status != SSH_OK) {
        return status;
    }
    if (generic.type != expected_type) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    ssh_buffer_wrap(&payload, (uint8_t *)generic.payload.data, generic.payload.len);
    status = ssh_buffer_get_string_view(&payload, &request->path);
    if (status != SSH_OK) {
        return status;
    }
    if (ssh_buffer_remaining_read(&payload) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    request->id = generic.id;
    return SSH_OK;
}

int sftp_packet_wrap(const uint8_t *packet, size_t packet_len, sftp_packet_t *wrapped)
{
    uint32_t packet_length;

    if (packet == NULL || wrapped == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (packet_len < 5u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    packet_length = read_u32_be(packet);
    if (packet_length == 0u || (size_t)packet_length + 4u != packet_len) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    wrapped->type = packet[4];
    wrapped->payload.data = packet + 5u;
    wrapped->payload.len = (size_t)packet_length - 1u;
    return SSH_OK;
}

int sftp_request_decode(const uint8_t *packet, size_t packet_len, sftp_request_t *request)
{
    sftp_packet_t wrapped;
    int status;

    if (request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(request, 0, sizeof(*request));

    status = sftp_packet_wrap(packet, packet_len, &wrapped);
    if (status != SSH_OK) {
        return status;
    }
    if (wrapped.payload.len < 4u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    request->type = wrapped.type;
    request->id = read_u32_be(wrapped.payload.data);
    request->payload.data = wrapped.payload.data + 4u;
    request->payload.len = wrapped.payload.len - 4u;
    return SSH_OK;
}

int sftp_attrs_decode(ssh_string_view_t encoded, ssh_fs_attrs_t *attrs)
{
    ssh_buffer_t payload;
    ssh_string_view_t extension_name;
    ssh_string_view_t extension_data;
    uint32_t flags;
    uint32_t extended_count;
    uint32_t i;
    int status;

    if (attrs == NULL || encoded.data == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(attrs, 0, sizeof(*attrs));
    ssh_buffer_wrap(&payload, (uint8_t *)encoded.data, encoded.len);

    status = ssh_buffer_get_u32(&payload, &flags);
    if (status != SSH_OK) {
        return status;
    }
    if ((flags & ~(SFTP_SUPPORTED_ATTR_FLAGS | SSH_FILEXFER_ATTR_EXTENDED)) != 0u) {
        return SSH_ERR_UNSUPPORTED;
    }

    attrs->flags = flags & SFTP_SUPPORTED_ATTR_FLAGS;
    if ((attrs->flags & SSH_FILEXFER_ATTR_SIZE) != 0u) {
        status = ssh_buffer_get_u64(&payload, &attrs->size);
    }
    if (status == SSH_OK && (attrs->flags & SSH_FILEXFER_ATTR_UIDGID) != 0u) {
        status = ssh_buffer_get_u32(&payload, &attrs->uid);
    }
    if (status == SSH_OK && (attrs->flags & SSH_FILEXFER_ATTR_UIDGID) != 0u) {
        status = ssh_buffer_get_u32(&payload, &attrs->gid);
    }
    if (status == SSH_OK && (attrs->flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0u) {
        status = ssh_buffer_get_u32(&payload, &attrs->permissions);
    }
    if (status == SSH_OK && (attrs->flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0u) {
        status = ssh_buffer_get_u32(&payload, &attrs->atime);
    }
    if (status == SSH_OK && (attrs->flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0u) {
        status = ssh_buffer_get_u32(&payload, &attrs->mtime);
    }
    if (status == SSH_OK && (flags & SSH_FILEXFER_ATTR_EXTENDED) != 0u) {
        status = ssh_buffer_get_u32(&payload, &extended_count);
        for (i = 0u; status == SSH_OK && i < extended_count; ++i) {
            status = ssh_buffer_get_string_view(&payload, &extension_name);
            if (status == SSH_OK) {
                status = ssh_buffer_get_string_view(&payload, &extension_data);
            }
        }
    }
    if (status != SSH_OK) {
        return status;
    }

    return ssh_buffer_remaining_read(&payload) == 0u ? SSH_OK : SSH_ERR_MALFORMED_PACKET;
}

int sftp_init_decode(const uint8_t *packet, size_t packet_len, sftp_init_t *init)
{
    sftp_packet_t wrapped;
    int status;

    if (init == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(init, 0, sizeof(*init));

    status = sftp_packet_wrap(packet, packet_len, &wrapped);
    if (status != SSH_OK) {
        return status;
    }
    if (wrapped.type != SSH_FXP_INIT || wrapped.payload.len < 4u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    init->version = read_u32_be(wrapped.payload.data);
    init->extension_data.data = wrapped.payload.data + 4u;
    init->extension_data.len = wrapped.payload.len - 4u;
    return SSH_OK;
}

int sftp_realpath_request_decode(const uint8_t *packet, size_t packet_len, sftp_path_request_t *request)
{
    return decode_path_request(packet, packet_len, SSH_FXP_REALPATH, request);
}

int sftp_lstat_request_decode(const uint8_t *packet, size_t packet_len, sftp_path_request_t *request)
{
    return decode_path_request(packet, packet_len, SSH_FXP_LSTAT, request);
}

int sftp_stat_request_decode(const uint8_t *packet, size_t packet_len, sftp_path_request_t *request)
{
    return decode_path_request(packet, packet_len, SSH_FXP_STAT, request);
}

int sftp_opendir_request_decode(const uint8_t *packet, size_t packet_len, sftp_path_request_t *request)
{
    return decode_path_request(packet, packet_len, SSH_FXP_OPENDIR, request);
}

int sftp_open_request_decode(const uint8_t *packet, size_t packet_len, sftp_open_request_t *request)
{
    sftp_request_t generic;
    ssh_buffer_t payload;
    size_t attrs_len;
    int status;

    if (request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(request, 0, sizeof(*request));
    status = sftp_request_decode(packet, packet_len, &generic);
    if (status != SSH_OK) {
        return status;
    }
    if (generic.type != SSH_FXP_OPEN) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    ssh_buffer_wrap(&payload, (uint8_t *)generic.payload.data, generic.payload.len);
    status = ssh_buffer_get_string_view(&payload, &request->filename);
    if (status == SSH_OK) {
        status = ssh_buffer_get_u32(&payload, &request->pflags);
    }
    if (status != SSH_OK) {
        return status;
    }

    attrs_len = ssh_buffer_remaining_read(&payload);
    if (attrs_len < 4u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    request->id = generic.id;
    request->attrs.data = payload.data + payload.pos;
    request->attrs.len = attrs_len;
    payload.pos += attrs_len;
    return SSH_OK;
}

int sftp_close_request_decode(const uint8_t *packet, size_t packet_len, sftp_handle_request_t *request)
{
    sftp_request_t generic;
    ssh_buffer_t payload;
    int status;

    if (request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(request, 0, sizeof(*request));
    status = sftp_request_decode(packet, packet_len, &generic);
    if (status != SSH_OK) {
        return status;
    }
    if (generic.type != SSH_FXP_CLOSE) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    ssh_buffer_wrap(&payload, (uint8_t *)generic.payload.data, generic.payload.len);
    status = ssh_buffer_get_string_view(&payload, &request->handle);
    if (status != SSH_OK) {
        return status;
    }
    if (ssh_buffer_remaining_read(&payload) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    request->id = generic.id;
    return SSH_OK;
}

int sftp_fstat_request_decode(const uint8_t *packet, size_t packet_len, sftp_handle_request_t *request)
{
    sftp_request_t generic;
    ssh_buffer_t payload;
    int status;

    if (request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(request, 0, sizeof(*request));
    status = sftp_request_decode(packet, packet_len, &generic);
    if (status != SSH_OK) {
        return status;
    }
    if (generic.type != SSH_FXP_FSTAT) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    ssh_buffer_wrap(&payload, (uint8_t *)generic.payload.data, generic.payload.len);
    status = ssh_buffer_get_string_view(&payload, &request->handle);
    if (status != SSH_OK) {
        return status;
    }
    if (ssh_buffer_remaining_read(&payload) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    request->id = generic.id;
    return SSH_OK;
}

int sftp_readdir_request_decode(const uint8_t *packet, size_t packet_len, sftp_handle_request_t *request)
{
    sftp_request_t generic;
    ssh_buffer_t payload;
    int status;

    if (request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(request, 0, sizeof(*request));
    status = sftp_request_decode(packet, packet_len, &generic);
    if (status != SSH_OK) {
        return status;
    }
    if (generic.type != SSH_FXP_READDIR) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    ssh_buffer_wrap(&payload, (uint8_t *)generic.payload.data, generic.payload.len);
    status = ssh_buffer_get_string_view(&payload, &request->handle);
    if (status != SSH_OK) {
        return status;
    }
    if (ssh_buffer_remaining_read(&payload) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    request->id = generic.id;
    return SSH_OK;
}

int sftp_read_request_decode(const uint8_t *packet, size_t packet_len, sftp_read_request_t *request)
{
    sftp_request_t generic;
    ssh_buffer_t payload;
    int status;

    if (request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(request, 0, sizeof(*request));
    status = sftp_request_decode(packet, packet_len, &generic);
    if (status != SSH_OK) {
        return status;
    }
    if (generic.type != SSH_FXP_READ) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    ssh_buffer_wrap(&payload, (uint8_t *)generic.payload.data, generic.payload.len);
    status = ssh_buffer_get_string_view(&payload, &request->handle);
    if (status == SSH_OK) {
        status = ssh_buffer_get_u64(&payload, &request->offset);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_u32(&payload, &request->len);
    }
    if (status != SSH_OK) {
        return status;
    }
    if (ssh_buffer_remaining_read(&payload) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    request->id = generic.id;
    return SSH_OK;
}

int sftp_write_request_decode(const uint8_t *packet, size_t packet_len, sftp_write_request_t *request)
{
    sftp_request_t generic;
    ssh_buffer_t payload;
    int status;

    if (request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(request, 0, sizeof(*request));
    status = sftp_request_decode(packet, packet_len, &generic);
    if (status != SSH_OK) {
        return status;
    }
    if (generic.type != SSH_FXP_WRITE) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    ssh_buffer_wrap(&payload, (uint8_t *)generic.payload.data, generic.payload.len);
    status = ssh_buffer_get_string_view(&payload, &request->handle);
    if (status == SSH_OK) {
        status = ssh_buffer_get_u64(&payload, &request->offset);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&payload, &request->data);
    }
    if (status != SSH_OK) {
        return status;
    }
    if (ssh_buffer_remaining_read(&payload) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    request->id = generic.id;
    return SSH_OK;
}

int sftp_remove_request_decode(const uint8_t *packet, size_t packet_len, sftp_path_request_t *request)
{
    return decode_path_request(packet, packet_len, SSH_FXP_REMOVE, request);
}

int sftp_mkdir_request_decode(const uint8_t *packet, size_t packet_len, sftp_mkdir_request_t *request)
{
    sftp_request_t generic;
    ssh_buffer_t payload;
    size_t attrs_len;
    int status;

    if (request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(request, 0, sizeof(*request));
    status = sftp_request_decode(packet, packet_len, &generic);
    if (status != SSH_OK) {
        return status;
    }
    if (generic.type != SSH_FXP_MKDIR) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    ssh_buffer_wrap(&payload, (uint8_t *)generic.payload.data, generic.payload.len);
    status = ssh_buffer_get_string_view(&payload, &request->path);
    if (status != SSH_OK) {
        return status;
    }

    attrs_len = ssh_buffer_remaining_read(&payload);
    if (attrs_len < 4u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    request->id = generic.id;
    request->attrs.data = payload.data + payload.pos;
    request->attrs.len = attrs_len;
    payload.pos += attrs_len;
    return SSH_OK;
}

int sftp_rmdir_request_decode(const uint8_t *packet, size_t packet_len, sftp_path_request_t *request)
{
    return decode_path_request(packet, packet_len, SSH_FXP_RMDIR, request);
}

int sftp_rename_request_decode(const uint8_t *packet, size_t packet_len, sftp_rename_request_t *request)
{
    sftp_request_t generic;
    ssh_buffer_t payload;
    int status;

    if (request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(request, 0, sizeof(*request));
    status = sftp_request_decode(packet, packet_len, &generic);
    if (status != SSH_OK) {
        return status;
    }
    if (generic.type != SSH_FXP_RENAME) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    ssh_buffer_wrap(&payload, (uint8_t *)generic.payload.data, generic.payload.len);
    status = ssh_buffer_get_string_view(&payload, &request->old_path);
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&payload, &request->new_path);
    }
    if (status != SSH_OK) {
        return status;
    }
    if (ssh_buffer_remaining_read(&payload) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    request->id = generic.id;
    return SSH_OK;
}

int sftp_setstat_request_decode(const uint8_t *packet, size_t packet_len, sftp_setstat_request_t *request)
{
    sftp_request_t generic;
    ssh_buffer_t payload;
    ssh_string_view_t attrs_view;
    int status;

    if (request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(request, 0, sizeof(*request));
    status = sftp_request_decode(packet, packet_len, &generic);
    if (status != SSH_OK) {
        return status;
    }
    if (generic.type != SSH_FXP_SETSTAT) {
        return SSH_ERR_MALFORMED_PACKET;
    }
    request->id = generic.id;

    ssh_buffer_wrap(&payload, (uint8_t *)generic.payload.data, generic.payload.len);
    status = ssh_buffer_get_string_view(&payload, &request->path);
    if (status != SSH_OK) {
        return status;
    }

    attrs_view.data = payload.data + payload.pos;
    attrs_view.len = ssh_buffer_remaining_read(&payload);
    status = sftp_attrs_decode(attrs_view, &request->attrs);
    if (status != SSH_OK) {
        return status;
    }

    return SSH_OK;
}

int sftp_fsetstat_request_decode(const uint8_t *packet, size_t packet_len, sftp_fsetstat_request_t *request)
{
    sftp_request_t generic;
    ssh_buffer_t payload;
    ssh_string_view_t attrs_view;
    int status;

    if (request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(request, 0, sizeof(*request));
    status = sftp_request_decode(packet, packet_len, &generic);
    if (status != SSH_OK) {
        return status;
    }
    if (generic.type != SSH_FXP_FSETSTAT) {
        return SSH_ERR_MALFORMED_PACKET;
    }
    request->id = generic.id;

    ssh_buffer_wrap(&payload, (uint8_t *)generic.payload.data, generic.payload.len);
    status = ssh_buffer_get_string_view(&payload, &request->handle);
    if (status != SSH_OK) {
        return status;
    }

    attrs_view.data = payload.data + payload.pos;
    attrs_view.len = ssh_buffer_remaining_read(&payload);
    status = sftp_attrs_decode(attrs_view, &request->attrs);
    if (status != SSH_OK) {
        return status;
    }

    return SSH_OK;
}

int sftp_extended_request_decode(const uint8_t *packet, size_t packet_len, sftp_extended_request_t *request)
{
    sftp_request_t generic;
    ssh_buffer_t payload;
    int status;

    if (request == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(request, 0, sizeof(*request));
    status = sftp_request_decode(packet, packet_len, &generic);
    if (status != SSH_OK) {
        return status;
    }
    if (generic.type != SSH_FXP_EXTENDED) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    ssh_buffer_wrap(&payload, (uint8_t *)generic.payload.data, generic.payload.len);
    status = ssh_buffer_get_string_view(&payload, &request->name);
    if (status != SSH_OK) {
        return status;
    }

    request->id = generic.id;
    request->payload.data = payload.data + payload.pos;
    request->payload.len = ssh_buffer_remaining_read(&payload);
    return SSH_OK;
}

int sftp_version_encode(uint8_t *out, size_t out_capacity, size_t *out_len, uint32_t version)
{
    if (out == NULL || out_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (out_capacity < 9u) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    write_u32_be(out, 5u);
    out[4] = SSH_FXP_VERSION;
    write_u32_be(out + 5u, version);
    *out_len = 9u;
    return SSH_OK;
}

int sftp_status_encode(
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    uint32_t request_id,
    uint32_t status_code,
    const char *message,
    const char *language)
{
    ssh_buffer_t payload;
    int status;

    if (out == NULL || out_len == NULL || message == NULL || language == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = packet_payload_init(out, out_capacity, &payload);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_u8(&payload, SSH_FXP_STATUS);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(&payload, request_id);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(&payload, status_code);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(&payload, message);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(&payload, language);
    }
    if (status != SSH_OK) {
        return status;
    }

    return packet_finish(out, &payload, out_len);
}

int sftp_handle_encode(
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    uint32_t request_id,
    const uint8_t *handle,
    size_t handle_len)
{
    ssh_buffer_t payload;
    int status;

    if (out == NULL || out_len == NULL || (handle == NULL && handle_len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = packet_payload_init(out, out_capacity, &payload);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_u8(&payload, SSH_FXP_HANDLE);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(&payload, request_id);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(&payload, handle, handle_len);
    }
    if (status != SSH_OK) {
        return status;
    }

    return packet_finish(out, &payload, out_len);
}

int sftp_data_encode(
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    uint32_t request_id,
    const uint8_t *data,
    size_t data_len)
{
    ssh_buffer_t payload;
    int status;

    if (out == NULL || out_len == NULL || (data == NULL && data_len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = packet_payload_init(out, out_capacity, &payload);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_u8(&payload, SSH_FXP_DATA);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(&payload, request_id);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(&payload, data, data_len);
    }
    if (status != SSH_OK) {
        return status;
    }

    return packet_finish(out, &payload, out_len);
}

static int put_attrs(ssh_buffer_t *payload, const ssh_fs_attrs_t *attrs)
{
    uint32_t flags;
    int status;

    if (payload == NULL || attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    flags = attrs->flags & SFTP_SUPPORTED_ATTR_FLAGS;
    status = ssh_buffer_put_u32(payload, flags);
    if (status == SSH_OK && (flags & SSH_FILEXFER_ATTR_SIZE) != 0u) {
        status = ssh_buffer_put_u64(payload, attrs->size);
    }
    if (status == SSH_OK && (flags & SSH_FILEXFER_ATTR_UIDGID) != 0u) {
        status = ssh_buffer_put_u32(payload, attrs->uid);
    }
    if (status == SSH_OK && (flags & SSH_FILEXFER_ATTR_UIDGID) != 0u) {
        status = ssh_buffer_put_u32(payload, attrs->gid);
    }
    if (status == SSH_OK && (flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0u) {
        status = ssh_buffer_put_u32(payload, attrs->permissions);
    }
    if (status == SSH_OK && (flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0u) {
        status = ssh_buffer_put_u32(payload, attrs->atime);
    }
    if (status == SSH_OK && (flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0u) {
        status = ssh_buffer_put_u32(payload, attrs->mtime);
    }

    return status;
}

int sftp_attrs_encode(
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    uint32_t request_id,
    const ssh_fs_attrs_t *attrs)
{
    ssh_buffer_t payload;
    int status;

    if (out == NULL || out_len == NULL || attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = packet_payload_init(out, out_capacity, &payload);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_u8(&payload, SSH_FXP_ATTRS);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(&payload, request_id);
    }
    if (status == SSH_OK) {
        status = put_attrs(&payload, attrs);
    }
    if (status != SSH_OK) {
        return status;
    }

    return packet_finish(out, &payload, out_len);
}

int sftp_name_one_attrs_encode(
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    uint32_t request_id,
    const char *filename,
    const char *longname,
    const ssh_fs_attrs_t *attrs)
{
    ssh_buffer_t payload;
    const char *entry_longname;
    int status;

    if (out == NULL || out_len == NULL || filename == NULL || attrs == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    entry_longname = longname != NULL ? longname : filename;
    status = packet_payload_init(out, out_capacity, &payload);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_u8(&payload, SSH_FXP_NAME);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(&payload, request_id);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(&payload, 1u);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(&payload, filename);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(&payload, entry_longname);
    }
    if (status == SSH_OK) {
        status = put_attrs(&payload, attrs);
    }
    if (status != SSH_OK) {
        return status;
    }

    return packet_finish(out, &payload, out_len);
}

int sftp_name_one_encode(
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    uint32_t request_id,
    const char *filename,
    const char *longname)
{
    ssh_fs_attrs_t empty_attrs;

    memset(&empty_attrs, 0, sizeof(empty_attrs));
    return sftp_name_one_attrs_encode(
        out,
        out_capacity,
        out_len,
        request_id,
        filename,
        longname,
        &empty_attrs);
}
