#include "emssh/sftp_server.h"

#include <string.h>

#include "emssh/sftp.h"
#include "emssh/ssh_error.h"

static void write_u32_be(uint8_t data[4], uint32_t value)
{
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

static uint32_t status_from_error(int status)
{
    if (status == SSH_OK) {
        return SSH_FX_OK;
    }
    if (status == SSH_ERR_UNSUPPORTED) {
        return SSH_FX_OP_UNSUPPORTED;
    }
    if (status == SSH_ERR_SECURITY) {
        return SSH_FX_PERMISSION_DENIED;
    }
    if (status == SSH_ERR_READ_ONLY) {
        return SSH_FX_PERMISSION_DENIED;
    }
    if (status == SSH_ERR_NOT_FOUND) {
        return SSH_FX_NO_SUCH_FILE;
    }
    if (status == SSH_ERR_MALFORMED_PACKET || status == SSH_ERR_INVALID_ARGUMENT) {
        return SSH_FX_BAD_MESSAGE;
    }

    return SSH_FX_FAILURE;
}

static const char *status_message_from_error(int status, const char *fallback)
{
    switch (status) {
    case SSH_OK:
        return "ok";
    case SSH_ERR_UNSUPPORTED:
        return "unsupported";
    case SSH_ERR_SECURITY:
        return "permission denied";
    case SSH_ERR_READ_ONLY:
        return "read only";
    case SSH_ERR_NOT_FOUND:
        return "not found";
    case SSH_ERR_ALREADY_EXISTS:
        return "already exists";
    case SSH_ERR_DIR_NOT_EMPTY:
        return "directory not empty";
    case SSH_ERR_BUFFER_TOO_SMALL:
        return "buffer too small";
    case SSH_ERR_BUFFER_OVERFLOW:
        return "buffer overflow";
    case SSH_ERR_MALFORMED_PACKET:
    case SSH_ERR_INVALID_ARGUMENT:
        return "bad request";
    case SSH_ERR_PLATFORM:
        return "platform error";
    default:
        return fallback != NULL ? fallback : "failure";
    }
}

static int normalize_path_view(ssh_string_view_t path, char out[EMSSH_SFTP_MAX_PATH])
{
    size_t i;
    size_t out_pos;
    size_t segment_starts[EMSSH_SFTP_MAX_PATH];
    size_t segment_count;
    int absolute;
    int has_segment;

    if (path.data == NULL || path.len == 0u || out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    absolute = path.data[0] == '/';
    out_pos = 0u;
    has_segment = 0;
    segment_count = 0u;
    if (absolute) {
        if (out_pos + 1u >= EMSSH_SFTP_MAX_PATH) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        out[out_pos++] = '/';
    }

    i = 0u;
    while (i < path.len) {
        size_t seg_start;
        size_t seg_len;
        const uint8_t *seg;
        size_t j;

        while (i < path.len && path.data[i] == '/') {
            ++i;
        }
        if (i >= path.len) {
            break;
        }

        seg_start = i;
        while (i < path.len && path.data[i] != '/') {
            ++i;
        }
        seg_len = i - seg_start;
        seg = path.data + seg_start;
        if (seg_len == 0u) {
            continue;
        }

        if (seg_len == 1u && seg[0] == '.') {
            continue;
        }
        if (seg_len == 2u && seg[0] == '.' && seg[1] == '.') {
            if (segment_count > 0u) {
                out_pos = segment_starts[segment_count - 1u];
                --segment_count;
                has_segment = segment_count > 0u;
                continue;
            }
            if (absolute) {
                continue;
            }
            return SSH_ERR_SECURITY;
        }

        for (j = 0u; j < seg_len; ++j) {
            uint8_t c = seg[j];
            if (c == '\0' || c == '\\' || c == ':') {
                return SSH_ERR_SECURITY;
            }
        }

        {
            size_t segment_base = out_pos;

        if (has_segment || absolute) {
            if (out_pos > 0u && out[out_pos - 1u] != '/') {
                if (out_pos + 1u >= EMSSH_SFTP_MAX_PATH) {
                    return SSH_ERR_BUFFER_TOO_SMALL;
                }
                out[out_pos++] = '/';
            }
        }

        if (out_pos + seg_len >= EMSSH_SFTP_MAX_PATH) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        segment_starts[segment_count++] = segment_base;
        memcpy(out + out_pos, seg, seg_len);
        out_pos += seg_len;
        has_segment = 1;
        }
    }

    if (!has_segment) {
        if (absolute) {
            out[0] = '/';
            out[1] = '\0';
        } else {
            out[0] = '.';
            out[1] = '\0';
        }
        return SSH_OK;
    }

    out[out_pos] = '\0';
    return SSH_OK;
}

static int copy_path(ssh_string_view_t path, char out[EMSSH_SFTP_MAX_PATH])
{
    return normalize_path_view(path, out);
}

static int open_pflags_are_valid(uint32_t pflags)
{
    uint32_t known_flags = SSH_FXF_READ | SSH_FXF_WRITE | SSH_FXF_APPEND | SSH_FXF_CREAT | SSH_FXF_TRUNC | SSH_FXF_EXCL;
    uint32_t write_only_flags = SSH_FXF_APPEND | SSH_FXF_CREAT | SSH_FXF_TRUNC | SSH_FXF_EXCL;

    if ((pflags & ~known_flags) != 0u) {
        return 0;
    }
    if ((pflags & (SSH_FXF_READ | SSH_FXF_WRITE)) == 0u) {
        return 0;
    }
    if ((pflags & write_only_flags) != 0u && (pflags & SSH_FXF_WRITE) == 0u) {
        return 0;
    }
    if ((pflags & SSH_FXF_EXCL) != 0u && (pflags & SSH_FXF_CREAT) == 0u) {
        return 0;
    }

    return 1;
}

static int handle_equals(const sftp_handle_entry_t *entry, ssh_string_view_t handle)
{
    return entry != NULL &&
           entry->in_use &&
           entry->wire_handle_len == handle.len &&
           handle.data != NULL &&
           memcmp(entry->wire_handle, handle.data, handle.len) == 0;
}

static sftp_handle_entry_t *find_handle(sftp_server_session_t *session, ssh_string_view_t handle)
{
    size_t i;

    if (session == NULL) {
        return NULL;
    }

    for (i = 0u; i < EMSSH_SFTP_MAX_HANDLES; ++i) {
        if (handle_equals(&session->handles[i], handle)) {
            return &session->handles[i];
        }
    }

    return NULL;
}

static sftp_handle_entry_t *alloc_handle(
    sftp_server_session_t *session,
    void *fs_handle,
    sftp_handle_kind_t kind,
    uint32_t pflags,
    const char *path,
    const ssh_fs_attrs_t *attrs)
{
    size_t i;
    size_t path_len;

    if (session == NULL || fs_handle == NULL) {
        return NULL;
    }
    path_len = path != NULL ? strlen(path) : 0u;
    if (path_len >= EMSSH_SFTP_MAX_PATH) {
        return NULL;
    }

    for (i = 0u; i < EMSSH_SFTP_MAX_HANDLES; ++i) {
        if (!session->handles[i].in_use) {
            sftp_handle_entry_t *entry = &session->handles[i];
            uint32_t id = session->next_handle_id++;
            if (session->next_handle_id == 0u) {
                session->next_handle_id = 1u;
            }

            memset(entry, 0, sizeof(*entry));
            entry->in_use = 1;
            entry->kind = kind;
            entry->wire_handle_len = sizeof(entry->wire_handle);
            entry->fs_handle = fs_handle;
            entry->pflags = pflags;
            if (path != NULL) {
                memcpy(entry->path, path, path_len + 1u);
            }
            if (attrs != NULL) {
                entry->attrs = *attrs;
            }
            write_u32_be(entry->wire_handle, id);
            return entry;
        }
    }

    return NULL;
}

static int close_entry(sftp_server_session_t *session, sftp_handle_entry_t *entry)
{
    int status = SSH_OK;

    if (session == NULL || entry == NULL || !entry->in_use) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (session->fs != NULL && entry->kind == SFTP_HANDLE_KIND_DIR && session->fs->closedir != NULL) {
        status = session->fs->closedir(session->fs->ctx, entry->fs_handle);
    } else if (session->fs != NULL && entry->kind == SFTP_HANDLE_KIND_FILE && session->fs->close != NULL) {
        status = session->fs->close(session->fs->ctx, entry->fs_handle);
    }

    memset(entry, 0, sizeof(*entry));
    return status;
}

static void update_file_size_after_write(sftp_handle_entry_t *entry, uint64_t offset, size_t written_len)
{
    uint64_t end_offset;

    if (entry == NULL || written_len == 0u || written_len > UINT64_MAX - offset) {
        return;
    }

    end_offset = offset + (uint64_t)written_len;
    if ((entry->attrs.flags & SSH_FILEXFER_ATTR_SIZE) == 0u || end_offset > entry->attrs.size) {
        entry->attrs.flags |= SSH_FILEXFER_ATTR_SIZE;
        entry->attrs.size = end_offset;
    }
}

static void merge_attrs(ssh_fs_attrs_t *dst, const ssh_fs_attrs_t *src)
{
    if (dst == NULL || src == NULL) {
        return;
    }

    if ((src->flags & SSH_FILEXFER_ATTR_SIZE) != 0u) {
        dst->size = src->size;
    }
    if ((src->flags & SSH_FILEXFER_ATTR_UIDGID) != 0u) {
        dst->uid = src->uid;
        dst->gid = src->gid;
    }
    if ((src->flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0u) {
        dst->permissions = src->permissions;
    }
    if ((src->flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0u) {
        dst->atime = src->atime;
        dst->mtime = src->mtime;
    }
    dst->flags |= src->flags;
}

static int policy_check(
    sftp_server_session_t *session,
    sftp_policy_operation_t operation,
    const char *path,
    const char *new_path,
    uint32_t pflags,
    uint64_t offset,
    size_t length,
    const ssh_fs_attrs_t *attrs)
{
    sftp_policy_request_t request;

    if (session == NULL || session->policy == NULL) {
        return SSH_OK;
    }

    memset(&request, 0, sizeof(request));
    request.operation = operation;
    request.path = path;
    request.new_path = new_path;
    request.pflags = pflags;
    request.offset = offset;
    request.length = length;
    request.attrs = attrs;
    return session->policy(session->policy_ctx, &request);
}

static int encode_status(
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len,
    uint32_t request_id,
    uint32_t status_code,
    const char *message)
{
    return sftp_status_encode(response, response_capacity, response_len, request_id, status_code, message, "");
}

static int view_equals_cstring(ssh_string_view_t view, const char *text)
{
    size_t text_len;

    if (view.data == NULL || text == NULL) {
        return 0;
    }

    text_len = strlen(text);
    return view.len == text_len && memcmp(view.data, text, text_len) == 0;
}

static int encode_server_version(
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len,
    int advertise_posix_rename,
    int advertise_fsync,
    int advertise_hardlink,
    int advertise_statvfs,
    int advertise_fstatvfs)
{
    ssh_buffer_t payload;
    int status;

    if (response == NULL || response_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (response_capacity < 4u) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    ssh_buffer_init(&payload, response + 4u, response_capacity - 4u);
    status = ssh_buffer_put_u8(&payload, SSH_FXP_VERSION);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(&payload, SFTP_VERSION_3);
    }
    if (status == SSH_OK && advertise_posix_rename) {
        status = ssh_buffer_put_cstring(&payload, "posix-rename@openssh.com");
    }
    if (status == SSH_OK && advertise_posix_rename) {
        status = ssh_buffer_put_cstring(&payload, "1");
    }
    if (status == SSH_OK && advertise_fsync) {
        status = ssh_buffer_put_cstring(&payload, "fsync@openssh.com");
    }
    if (status == SSH_OK && advertise_fsync) {
        status = ssh_buffer_put_cstring(&payload, "1");
    }
    if (status == SSH_OK && advertise_hardlink) {
        status = ssh_buffer_put_cstring(&payload, "hardlink@openssh.com");
    }
    if (status == SSH_OK && advertise_hardlink) {
        status = ssh_buffer_put_cstring(&payload, "1");
    }
    if (status == SSH_OK && advertise_statvfs) {
        status = ssh_buffer_put_cstring(&payload, "statvfs@openssh.com");
    }
    if (status == SSH_OK && advertise_statvfs) {
        status = ssh_buffer_put_cstring(&payload, "2");
    }
    if (status == SSH_OK && advertise_fstatvfs) {
        status = ssh_buffer_put_cstring(&payload, "fstatvfs@openssh.com");
    }
    if (status == SSH_OK && advertise_fstatvfs) {
        status = ssh_buffer_put_cstring(&payload, "2");
    }
    if (status != SSH_OK) {
        return status;
    }

    write_u32_be(response, (uint32_t)ssh_buffer_len(&payload));
    *response_len = ssh_buffer_len(&payload) + 4u;
    return SSH_OK;
}

static int encode_statvfs_reply(
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len,
    uint32_t request_id,
    const ssh_fs_statvfs_t *stats)
{
    ssh_buffer_t payload;
    int status;

    if (response == NULL || response_len == NULL || stats == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (response_capacity < 4u) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    ssh_buffer_init(&payload, response + 4u, response_capacity - 4u);
    status = ssh_buffer_put_u8(&payload, SSH_FXP_EXTENDED_REPLY);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(&payload, request_id);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u64(&payload, stats->bsize);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u64(&payload, stats->frsize);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u64(&payload, stats->blocks);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u64(&payload, stats->bfree);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u64(&payload, stats->bavail);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u64(&payload, stats->files);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u64(&payload, stats->ffree);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u64(&payload, stats->favail);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u64(&payload, stats->fsid);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u64(&payload, stats->flag);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u64(&payload, stats->namemax);
    }
    if (status != SSH_OK) {
        return status;
    }

    write_u32_be(response, (uint32_t)ssh_buffer_len(&payload));
    *response_len = ssh_buffer_len(&payload) + 4u;
    return SSH_OK;
}

static int handle_init(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_init_t init;
    int status;

    status = sftp_init_decode(request, request_len, &init);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, 0u, SSH_FX_BAD_MESSAGE, "bad init");
    }

    return encode_server_version(
        response,
        response_capacity,
        response_len,
        session != NULL && session->fs != NULL && session->fs->posix_rename != NULL,
        session != NULL && session->fs != NULL && session->fs->fsync != NULL,
        session != NULL && session->fs != NULL && session->fs->hardlink != NULL,
        session != NULL && session->fs != NULL && session->fs->statvfs != NULL,
        session != NULL && session->fs != NULL && session->fs->fstatvfs != NULL);
}

static int handle_realpath(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_path_request_t realpath;
    char path[EMSSH_SFTP_MAX_PATH];
    int status;

    status = sftp_realpath_request_decode(request, request_len, &realpath);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, 0u, SSH_FX_BAD_MESSAGE, "bad realpath");
    }

    status = copy_path(realpath.path, path);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, realpath.id, status_from_error(status), "bad path");
    }
    status = policy_check(session, SFTP_POLICY_REALPATH, path, NULL, 0u, 0u, 0u, NULL);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, realpath.id, status_from_error(status), "realpath denied");
    }

    return sftp_name_one_encode(response, response_capacity, response_len, realpath.id, path, path);
}

static int handle_path_attrs(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t packet_type,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_path_request_t attrs_request;
    ssh_fs_attrs_t attrs;
    char path[EMSSH_SFTP_MAX_PATH];
    int status;

    if (packet_type == SSH_FXP_LSTAT) {
        status = sftp_lstat_request_decode(request, request_len, &attrs_request);
    } else {
        status = sftp_stat_request_decode(request, request_len, &attrs_request);
    }
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, 0u, SSH_FX_BAD_MESSAGE, "bad stat");
    }
    if (session->fs == NULL ||
        (packet_type == SSH_FXP_LSTAT && session->fs->lstat == NULL) ||
        (packet_type == SSH_FXP_STAT && session->fs->stat == NULL)) {
        return encode_status(response, response_capacity, response_len, attrs_request.id, SSH_FX_OP_UNSUPPORTED, "stat unsupported");
    }

    status = copy_path(attrs_request.path, path);
    if (status == SSH_OK) {
        status = policy_check(session, SFTP_POLICY_STAT, path, NULL, 0u, 0u, 0u, NULL);
    }
    if (status == SSH_OK) {
        if (packet_type == SSH_FXP_LSTAT) {
            status = session->fs->lstat(session->fs->ctx, path, &attrs);
        } else {
            status = session->fs->stat(session->fs->ctx, path, &attrs);
        }
    }
    if (status != SSH_OK) {
        return encode_status(
            response,
            response_capacity,
            response_len,
            attrs_request.id,
            status_from_error(status),
            status_message_from_error(status, "stat failed"));
    }

    return sftp_attrs_encode(response, response_capacity, response_len, attrs_request.id, &attrs);
}

static int handle_open(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_open_request_t open_request;
    sftp_handle_entry_t *entry = NULL;
    char path[EMSSH_SFTP_MAX_PATH];
    void *fs_handle;
    ssh_fs_attrs_t attrs;
    ssh_fs_attrs_t requested_attrs;
    int status;

    status = sftp_open_request_decode(request, request_len, &open_request);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, 0u, SSH_FX_BAD_MESSAGE, "bad open");
    }
    if (session->fs == NULL || session->fs->open == NULL) {
        return encode_status(response, response_capacity, response_len, open_request.id, SSH_FX_OP_UNSUPPORTED, "open unsupported");
    }

    status = copy_path(open_request.filename, path);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, open_request.id, status_from_error(status), "bad path");
    }
    if (!open_pflags_are_valid(open_request.pflags)) {
        return encode_status(response, response_capacity, response_len, open_request.id, SSH_FX_BAD_MESSAGE, "bad open flags");
    }

    status = sftp_attrs_decode(open_request.attrs, &requested_attrs);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, open_request.id, status_from_error(status), "bad attrs");
    }
    if (requested_attrs.flags != 0u && (open_request.pflags & SSH_FXF_WRITE) == 0u) {
        return encode_status(response, response_capacity, response_len, open_request.id, SSH_FX_PERMISSION_DENIED, "open attrs denied");
    }
    if (requested_attrs.flags != 0u && session->fs->fsetstat == NULL) {
        return encode_status(response, response_capacity, response_len, open_request.id, SSH_FX_OP_UNSUPPORTED, "open attrs unsupported");
    }
    status = policy_check(
        session,
        SFTP_POLICY_OPEN,
        path,
        NULL,
        open_request.pflags,
        0u,
        0u,
        &requested_attrs);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, open_request.id, status_from_error(status), "open denied");
    }

    fs_handle = NULL;
    status = session->fs->open(session->fs->ctx, path, open_request.pflags, &fs_handle);
    if (status != SSH_OK) {
        return encode_status(
            response,
            response_capacity,
            response_len,
            open_request.id,
            status_from_error(status),
            status_message_from_error(status, "open failed"));
    }

    attrs = requested_attrs;
    if (requested_attrs.flags != 0u) {
        status = session->fs->fsetstat(session->fs->ctx, fs_handle, &requested_attrs);
        if (status != SSH_OK) {
            if (session->fs->close != NULL) {
                (void)session->fs->close(session->fs->ctx, fs_handle);
            }
            return encode_status(
                response,
                response_capacity,
                response_len,
                open_request.id,
                status_from_error(status),
                status_message_from_error(status, "open attrs failed"));
        }
    }

    if (session->fs->stat != NULL) {
        (void)session->fs->stat(session->fs->ctx, path, &attrs);
    }

    entry = alloc_handle(session, fs_handle, SFTP_HANDLE_KIND_FILE, open_request.pflags, path, &attrs);
    if (entry == NULL) {
        if (session->fs->close != NULL) {
            (void)session->fs->close(session->fs->ctx, fs_handle);
        }
        return encode_status(response, response_capacity, response_len, open_request.id, SSH_FX_FAILURE, "no handles");
    }

    return sftp_handle_encode(
        response,
        response_capacity,
        response_len,
        open_request.id,
        entry->wire_handle,
        entry->wire_handle_len);
}

static int handle_close(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_handle_request_t close_request;
    sftp_handle_entry_t *entry = NULL;
    int status;

    status = sftp_close_request_decode(request, request_len, &close_request);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, 0u, SSH_FX_BAD_MESSAGE, "bad close");
    }

    entry = find_handle(session, close_request.handle);
    if (entry == NULL) {
        return encode_status(response, response_capacity, response_len, close_request.id, SSH_FX_FAILURE, "bad handle");
    }

    status = close_entry(session, entry);
    return encode_status(
        response,
        response_capacity,
        response_len,
        close_request.id,
        status_from_error(status),
        status_message_from_error(status, "close failed"));
}

static int handle_fstat(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_handle_request_t fstat_request;
    sftp_handle_entry_t *entry;
    int status;

    status = sftp_fstat_request_decode(request, request_len, &fstat_request);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, 0u, SSH_FX_BAD_MESSAGE, "bad fstat");
    }

    entry = find_handle(session, fstat_request.handle);
    if (entry == NULL) {
        return encode_status(response, response_capacity, response_len, fstat_request.id, SSH_FX_FAILURE, "bad handle");
    }
    status = policy_check(session, SFTP_POLICY_FSTAT, entry->path, NULL, 0u, 0u, 0u, NULL);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, fstat_request.id, status_from_error(status), "fstat denied");
    }
    if (session->fs != NULL && session->fs->stat != NULL && entry->path[0] != '\0') {
        ssh_fs_attrs_t refreshed_attrs;
        if (session->fs->stat(session->fs->ctx, entry->path, &refreshed_attrs) == SSH_OK) {
            entry->attrs = refreshed_attrs;
        }
    }
    if (entry->attrs.flags == 0u) {
        return encode_status(response, response_capacity, response_len, fstat_request.id, SSH_FX_OP_UNSUPPORTED, "fstat unsupported");
    }

    return sftp_attrs_encode(response, response_capacity, response_len, fstat_request.id, &entry->attrs);
}

static int handle_setstat(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_setstat_request_t setstat_request;
    char path[EMSSH_SFTP_MAX_PATH];
    int status;

    status = sftp_setstat_request_decode(request, request_len, &setstat_request);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, setstat_request.id, status_from_error(status), "bad setstat");
    }
    if (session->fs == NULL || session->fs->setstat == NULL) {
        return encode_status(response, response_capacity, response_len, setstat_request.id, SSH_FX_OP_UNSUPPORTED, "setstat unsupported");
    }

    status = copy_path(setstat_request.path, path);
    if (status == SSH_OK) {
        status = policy_check(
            session,
            SFTP_POLICY_SETSTAT,
            path,
            NULL,
            0u,
            0u,
            0u,
            &setstat_request.attrs);
    }
    if (status == SSH_OK) {
        status = session->fs->setstat(session->fs->ctx, path, &setstat_request.attrs);
    }

    return encode_status(
        response,
        response_capacity,
        response_len,
        setstat_request.id,
        status_from_error(status),
        status_message_from_error(status, "setstat failed"));
}

static int handle_fsetstat(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_fsetstat_request_t fsetstat_request;
    sftp_handle_entry_t *entry;
    int status;

    status = sftp_fsetstat_request_decode(request, request_len, &fsetstat_request);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, fsetstat_request.id, status_from_error(status), "bad fsetstat");
    }
    if (session->fs == NULL || session->fs->fsetstat == NULL) {
        return encode_status(response, response_capacity, response_len, fsetstat_request.id, SSH_FX_OP_UNSUPPORTED, "fsetstat unsupported");
    }

    entry = find_handle(session, fsetstat_request.handle);
    if (entry == NULL || entry->kind != SFTP_HANDLE_KIND_FILE) {
        return encode_status(response, response_capacity, response_len, fsetstat_request.id, SSH_FX_FAILURE, "bad handle");
    }
    if ((entry->pflags & SSH_FXF_WRITE) == 0u) {
        return encode_status(response, response_capacity, response_len, fsetstat_request.id, SSH_FX_PERMISSION_DENIED, "fsetstat denied");
    }

    status = policy_check(
        session,
        SFTP_POLICY_FSETSTAT,
        entry->path,
        NULL,
        entry->pflags,
        0u,
        0u,
        &fsetstat_request.attrs);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, fsetstat_request.id, status_from_error(status), "fsetstat denied");
    }

    status = session->fs->fsetstat(session->fs->ctx, entry->fs_handle, &fsetstat_request.attrs);
    if (status == SSH_OK) {
        merge_attrs(&entry->attrs, &fsetstat_request.attrs);
    }

    return encode_status(
        response,
        response_capacity,
        response_len,
        fsetstat_request.id,
        status_from_error(status),
        status_message_from_error(status, "fsetstat failed"));
}

static int handle_read(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_read_request_t read_request;
    sftp_handle_entry_t *entry;
    uint8_t data[EMSSH_SFTP_MAX_IO];
    size_t wanted;
    size_t read_len;
    int status;

    status = sftp_read_request_decode(request, request_len, &read_request);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, 0u, SSH_FX_BAD_MESSAGE, "bad read");
    }
    if (session->fs == NULL || (session->fs->read == NULL && session->fs->read_at == NULL)) {
        return encode_status(response, response_capacity, response_len, read_request.id, SSH_FX_OP_UNSUPPORTED, "read unsupported");
    }

    entry = find_handle(session, read_request.handle);
    if (entry == NULL || entry->kind != SFTP_HANDLE_KIND_FILE) {
        return encode_status(response, response_capacity, response_len, read_request.id, SSH_FX_FAILURE, "bad handle");
    }
    if ((entry->pflags & SSH_FXF_READ) == 0u) {
        return encode_status(response, response_capacity, response_len, read_request.id, SSH_FX_PERMISSION_DENIED, "read denied");
    }

    wanted = read_request.len < EMSSH_SFTP_MAX_IO ? read_request.len : EMSSH_SFTP_MAX_IO;
    status = policy_check(
        session,
        SFTP_POLICY_READ,
        entry->path,
        NULL,
        entry->pflags,
        read_request.offset,
        wanted,
        NULL);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, read_request.id, status_from_error(status), "read denied");
    }

    read_len = 0u;
    if (session->fs->read_at != NULL) {
        status = session->fs->read_at(session->fs->ctx, entry->fs_handle, read_request.offset, data, wanted, &read_len);
    } else {
        status = session->fs->read(session->fs->ctx, entry->fs_handle, data, wanted, &read_len);
    }
    if (status != SSH_OK) {
        return encode_status(
            response,
            response_capacity,
            response_len,
            read_request.id,
            status_from_error(status),
            status_message_from_error(status, "read failed"));
    }
    if (read_len == 0u) {
        return encode_status(response, response_capacity, response_len, read_request.id, SSH_FX_EOF, "eof");
    }

    return sftp_data_encode(response, response_capacity, response_len, read_request.id, data, read_len);
}

static int handle_opendir(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_path_request_t opendir_request;
    sftp_handle_entry_t *entry;
    char path[EMSSH_SFTP_MAX_PATH];
    void *fs_handle;
    ssh_fs_attrs_t attrs;
    int status;

    status = sftp_opendir_request_decode(request, request_len, &opendir_request);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, 0u, SSH_FX_BAD_MESSAGE, "bad opendir");
    }
    if (session->fs == NULL || session->fs->opendir == NULL) {
        return encode_status(response, response_capacity, response_len, opendir_request.id, SSH_FX_OP_UNSUPPORTED, "opendir unsupported");
    }

    status = copy_path(opendir_request.path, path);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, opendir_request.id, status_from_error(status), "bad path");
    }
    status = policy_check(session, SFTP_POLICY_OPENDIR, path, NULL, 0u, 0u, 0u, NULL);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, opendir_request.id, status_from_error(status), "opendir denied");
    }

    fs_handle = NULL;
    status = session->fs->opendir(session->fs->ctx, path, &fs_handle);
    if (status != SSH_OK) {
        return encode_status(
            response,
            response_capacity,
            response_len,
            opendir_request.id,
            status_from_error(status),
            status_message_from_error(status, "opendir failed"));
    }

    memset(&attrs, 0, sizeof(attrs));
    if (session->fs->stat != NULL) {
        (void)session->fs->stat(session->fs->ctx, path, &attrs);
    }

    entry = alloc_handle(session, fs_handle, SFTP_HANDLE_KIND_DIR, 0u, path, &attrs);
    if (entry == NULL) {
        if (session->fs->closedir != NULL) {
            (void)session->fs->closedir(session->fs->ctx, fs_handle);
        }
        return encode_status(response, response_capacity, response_len, opendir_request.id, SSH_FX_FAILURE, "no handles");
    }

    return sftp_handle_encode(
        response,
        response_capacity,
        response_len,
        opendir_request.id,
        entry->wire_handle,
        entry->wire_handle_len);
}

static int handle_readdir(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_handle_request_t readdir_request;
    sftp_handle_entry_t *entry;
    ssh_fs_dirent_t dirent;
    int eof;
    int status;

    status = sftp_readdir_request_decode(request, request_len, &readdir_request);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, 0u, SSH_FX_BAD_MESSAGE, "bad readdir");
    }
    if (session->fs == NULL || session->fs->readdir == NULL) {
        return encode_status(response, response_capacity, response_len, readdir_request.id, SSH_FX_OP_UNSUPPORTED, "readdir unsupported");
    }

    entry = find_handle(session, readdir_request.handle);
    if (entry == NULL || entry->kind != SFTP_HANDLE_KIND_DIR) {
        return encode_status(response, response_capacity, response_len, readdir_request.id, SSH_FX_FAILURE, "bad handle");
    }
    status = policy_check(session, SFTP_POLICY_READDIR, entry->path, NULL, 0u, 0u, 0u, NULL);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, readdir_request.id, status_from_error(status), "readdir denied");
    }

    memset(&dirent, 0, sizeof(dirent));
    eof = 0;
    status = session->fs->readdir(session->fs->ctx, entry->fs_handle, &dirent, &eof);
    if (status != SSH_OK) {
        return encode_status(
            response,
            response_capacity,
            response_len,
            readdir_request.id,
            status_from_error(status),
            status_message_from_error(status, "readdir failed"));
    }
    if (eof) {
        return encode_status(response, response_capacity, response_len, readdir_request.id, SSH_FX_EOF, "eof");
    }
    if (dirent.filename == NULL) {
        return encode_status(response, response_capacity, response_len, readdir_request.id, SSH_FX_FAILURE, "bad dirent");
    }

    return sftp_name_one_attrs_encode(
        response,
        response_capacity,
        response_len,
        readdir_request.id,
        dirent.filename,
        dirent.longname,
        &dirent.attrs);
}

static int handle_write(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_write_request_t write_request;
    sftp_handle_entry_t *entry;
    size_t written_len;
    int used_write_at;
    int status;

    status = sftp_write_request_decode(request, request_len, &write_request);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, 0u, SSH_FX_BAD_MESSAGE, "bad write");
    }
    if (session->fs == NULL || (session->fs->write == NULL && session->fs->write_at == NULL)) {
        return encode_status(response, response_capacity, response_len, write_request.id, SSH_FX_OP_UNSUPPORTED, "write unsupported");
    }

    entry = find_handle(session, write_request.handle);
    if (entry == NULL || entry->kind != SFTP_HANDLE_KIND_FILE) {
        return encode_status(response, response_capacity, response_len, write_request.id, SSH_FX_FAILURE, "bad handle");
    }
    if ((entry->pflags & SSH_FXF_WRITE) == 0u) {
        return encode_status(response, response_capacity, response_len, write_request.id, SSH_FX_PERMISSION_DENIED, "write denied");
    }

    status = policy_check(
        session,
        SFTP_POLICY_WRITE,
        entry->path,
        NULL,
        entry->pflags,
        write_request.offset,
        write_request.data.len,
        NULL);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, write_request.id, status_from_error(status), "write denied");
    }

    written_len = 0u;
    used_write_at = session->fs->write_at != NULL;
    if (session->fs->write_at != NULL) {
        status = session->fs->write_at(
            session->fs->ctx,
            entry->fs_handle,
            write_request.offset,
            write_request.data.data,
            write_request.data.len,
            &written_len);
    } else {
        status = session->fs->write(
            session->fs->ctx,
            entry->fs_handle,
            write_request.data.data,
            write_request.data.len,
            &written_len);
    }
    if (status != SSH_OK || written_len != write_request.data.len) {
        return encode_status(
            response,
            response_capacity,
            response_len,
            write_request.id,
            status != SSH_OK ? status_from_error(status) : SSH_FX_FAILURE,
            status != SSH_OK ? status_message_from_error(status, "write failed") : "short write");
    }
    if (used_write_at) {
        update_file_size_after_write(entry, write_request.offset, written_len);
    }

    return encode_status(response, response_capacity, response_len, write_request.id, SSH_FX_OK, "ok");
}

static int handle_remove(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_path_request_t remove_request;
    char path[EMSSH_SFTP_MAX_PATH];
    int status;

    status = sftp_remove_request_decode(request, request_len, &remove_request);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, 0u, SSH_FX_BAD_MESSAGE, "bad remove");
    }
    if (session->fs == NULL || session->fs->remove == NULL) {
        return encode_status(response, response_capacity, response_len, remove_request.id, SSH_FX_OP_UNSUPPORTED, "remove unsupported");
    }

    status = copy_path(remove_request.path, path);
    if (status == SSH_OK) {
        status = policy_check(session, SFTP_POLICY_REMOVE, path, NULL, 0u, 0u, 0u, NULL);
    }
    if (status == SSH_OK) {
        status = session->fs->remove(session->fs->ctx, path);
    }

    return encode_status(
        response,
        response_capacity,
        response_len,
        remove_request.id,
        status_from_error(status),
        status_message_from_error(status, "remove failed"));
}

static int handle_mkdir(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_mkdir_request_t mkdir_request;
    ssh_fs_attrs_t attrs;
    char path[EMSSH_SFTP_MAX_PATH];
    int status;

    status = sftp_mkdir_request_decode(request, request_len, &mkdir_request);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, 0u, SSH_FX_BAD_MESSAGE, "bad mkdir");
    }
    if (session->fs == NULL || session->fs->mkdir == NULL) {
        return encode_status(response, response_capacity, response_len, mkdir_request.id, SSH_FX_OP_UNSUPPORTED, "mkdir unsupported");
    }

    status = copy_path(mkdir_request.path, path);
    if (status == SSH_OK) {
        status = sftp_attrs_decode(mkdir_request.attrs, &attrs);
    }
    if (status == SSH_OK) {
        status = policy_check(session, SFTP_POLICY_MKDIR, path, NULL, 0u, 0u, 0u, &attrs);
    }
    if (status == SSH_OK) {
        status = session->fs->mkdir(session->fs->ctx, path, &attrs);
    }

    return encode_status(
        response,
        response_capacity,
        response_len,
        mkdir_request.id,
        status_from_error(status),
        status_message_from_error(status, "mkdir failed"));
}

static int handle_rmdir(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_path_request_t rmdir_request;
    char path[EMSSH_SFTP_MAX_PATH];
    int status;

    status = sftp_rmdir_request_decode(request, request_len, &rmdir_request);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, 0u, SSH_FX_BAD_MESSAGE, "bad rmdir");
    }
    if (session->fs == NULL || session->fs->rmdir == NULL) {
        return encode_status(response, response_capacity, response_len, rmdir_request.id, SSH_FX_OP_UNSUPPORTED, "rmdir unsupported");
    }

    status = copy_path(rmdir_request.path, path);
    if (status == SSH_OK) {
        status = policy_check(session, SFTP_POLICY_RMDIR, path, NULL, 0u, 0u, 0u, NULL);
    }
    if (status == SSH_OK) {
        status = session->fs->rmdir(session->fs->ctx, path);
    }

    return encode_status(
        response,
        response_capacity,
        response_len,
        rmdir_request.id,
        status_from_error(status),
        status_message_from_error(status, "rmdir failed"));
}

static int handle_rename(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_rename_request_t rename_request;
    char old_path[EMSSH_SFTP_MAX_PATH];
    char new_path[EMSSH_SFTP_MAX_PATH];
    int status;

    status = sftp_rename_request_decode(request, request_len, &rename_request);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, 0u, SSH_FX_BAD_MESSAGE, "bad rename");
    }
    if (session->fs == NULL || session->fs->rename == NULL) {
        return encode_status(response, response_capacity, response_len, rename_request.id, SSH_FX_OP_UNSUPPORTED, "rename unsupported");
    }

    status = copy_path(rename_request.old_path, old_path);
    if (status == SSH_OK) {
        status = copy_path(rename_request.new_path, new_path);
    }
    if (status == SSH_OK) {
        status = policy_check(session, SFTP_POLICY_RENAME, old_path, new_path, 0u, 0u, 0u, NULL);
    }
    if (status == SSH_OK) {
        status = session->fs->rename(session->fs->ctx, old_path, new_path);
        if (status == SSH_ERR_ALREADY_EXISTS && session->fs->posix_rename != NULL) {
            status = session->fs->posix_rename(session->fs->ctx, old_path, new_path);
        }
    }

    return encode_status(
        response,
        response_capacity,
        response_len,
        rename_request.id,
        status_from_error(status),
        status_message_from_error(status, "rename failed"));
}

static int handle_extended(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_extended_request_t extended_request;
    ssh_buffer_t payload;
    ssh_fs_statvfs_t vfs_stats;
    ssh_string_view_t handle_view = { 0 };
    ssh_string_view_t old_path_view = { 0 };
    ssh_string_view_t new_path_view = { 0 };
    sftp_handle_entry_t *entry = NULL;
    char old_path[EMSSH_SFTP_MAX_PATH];
    char new_path[EMSSH_SFTP_MAX_PATH];
    int status;

    status = sftp_extended_request_decode(request, request_len, &extended_request);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, 0u, SSH_FX_BAD_MESSAGE, "bad extended");
    }
    if (view_equals_cstring(extended_request.name, "fsync@openssh.com")) {
        if (session->fs == NULL || session->fs->fsync == NULL) {
            return encode_status(response, response_capacity, response_len, extended_request.id, SSH_FX_OP_UNSUPPORTED, "fsync unsupported");
        }

        ssh_buffer_wrap(&payload, (uint8_t *)extended_request.payload.data, extended_request.payload.len);
        status = ssh_buffer_get_string_view(&payload, &handle_view);
        if (status == SSH_OK && ssh_buffer_remaining_read(&payload) != 0u) {
            status = SSH_ERR_MALFORMED_PACKET;
        }
        if (status == SSH_OK) {
            entry = find_handle(session, handle_view);
            if (entry == NULL || entry->kind != SFTP_HANDLE_KIND_FILE) {
                status = SSH_ERR_INVALID_ARGUMENT;
            }
        }
        if (status == SSH_OK) {
            status = policy_check(session, SFTP_POLICY_FSYNC, entry->path, NULL, entry->pflags, 0u, 0u, NULL);
        }
        if (status == SSH_OK) {
            status = session->fs->fsync(session->fs->ctx, entry->fs_handle);
        }

        return encode_status(
            response,
            response_capacity,
            response_len,
            extended_request.id,
            status_from_error(status),
            status_message_from_error(status, "fsync failed"));
    }
    if (view_equals_cstring(extended_request.name, "statvfs@openssh.com")) {
        if (session->fs == NULL || session->fs->statvfs == NULL) {
            return encode_status(response, response_capacity, response_len, extended_request.id, SSH_FX_OP_UNSUPPORTED, "statvfs unsupported");
        }

        ssh_buffer_wrap(&payload, (uint8_t *)extended_request.payload.data, extended_request.payload.len);
        status = ssh_buffer_get_string_view(&payload, &old_path_view);
        if (status == SSH_OK && ssh_buffer_remaining_read(&payload) != 0u) {
            status = SSH_ERR_MALFORMED_PACKET;
        }
        if (status == SSH_OK) {
            status = copy_path(old_path_view, old_path);
        }
        if (status == SSH_OK) {
            status = policy_check(session, SFTP_POLICY_STATVFS, old_path, NULL, 0u, 0u, 0u, NULL);
        }
        if (status == SSH_OK) {
            status = session->fs->statvfs(session->fs->ctx, old_path, &vfs_stats);
        }
        if (status != SSH_OK) {
            return encode_status(
                response,
                response_capacity,
                response_len,
                extended_request.id,
                status_from_error(status),
                status_message_from_error(status, "statvfs failed"));
        }

        return encode_statvfs_reply(response, response_capacity, response_len, extended_request.id, &vfs_stats);
    }
    if (view_equals_cstring(extended_request.name, "fstatvfs@openssh.com")) {
        if (session->fs == NULL || session->fs->fstatvfs == NULL) {
            return encode_status(response, response_capacity, response_len, extended_request.id, SSH_FX_OP_UNSUPPORTED, "fstatvfs unsupported");
        }

        ssh_buffer_wrap(&payload, (uint8_t *)extended_request.payload.data, extended_request.payload.len);
        status = ssh_buffer_get_string_view(&payload, &handle_view);
        if (status == SSH_OK && ssh_buffer_remaining_read(&payload) != 0u) {
            status = SSH_ERR_MALFORMED_PACKET;
        }
        if (status == SSH_OK) {
            entry = find_handle(session, handle_view);
            if (entry == NULL || entry->kind != SFTP_HANDLE_KIND_FILE) {
                status = SSH_ERR_INVALID_ARGUMENT;
            }
        }
        if (status == SSH_OK) {
            status = policy_check(session, SFTP_POLICY_FSTATVFS, entry->path, NULL, entry->pflags, 0u, 0u, NULL);
        }
        if (status == SSH_OK) {
            status = session->fs->fstatvfs(session->fs->ctx, entry->fs_handle, &vfs_stats);
        }
        if (status != SSH_OK) {
            return encode_status(
                response,
                response_capacity,
                response_len,
                extended_request.id,
                status_from_error(status),
                status_message_from_error(status, "fstatvfs failed"));
        }

        return encode_statvfs_reply(response, response_capacity, response_len, extended_request.id, &vfs_stats);
    }
    if (view_equals_cstring(extended_request.name, "hardlink@openssh.com")) {
        if (session->fs == NULL || session->fs->hardlink == NULL) {
            return encode_status(response, response_capacity, response_len, extended_request.id, SSH_FX_OP_UNSUPPORTED, "hardlink unsupported");
        }

        ssh_buffer_wrap(&payload, (uint8_t *)extended_request.payload.data, extended_request.payload.len);
        status = ssh_buffer_get_string_view(&payload, &old_path_view);
        if (status == SSH_OK) {
            status = ssh_buffer_get_string_view(&payload, &new_path_view);
        }
        if (status == SSH_OK && ssh_buffer_remaining_read(&payload) != 0u) {
            status = SSH_ERR_MALFORMED_PACKET;
        }
        if (status == SSH_OK) {
            status = copy_path(old_path_view, old_path);
        }
        if (status == SSH_OK) {
            status = copy_path(new_path_view, new_path);
        }
        if (status == SSH_OK) {
            status = policy_check(session, SFTP_POLICY_HARDLINK, old_path, new_path, 0u, 0u, 0u, NULL);
        }
        if (status == SSH_OK) {
            status = session->fs->hardlink(session->fs->ctx, old_path, new_path);
        }

        return encode_status(
            response,
            response_capacity,
            response_len,
            extended_request.id,
            status_from_error(status),
            status_message_from_error(status, "hardlink failed"));
    }
    if (!view_equals_cstring(extended_request.name, "posix-rename@openssh.com")) {
        return encode_status(response, response_capacity, response_len, extended_request.id, SSH_FX_OP_UNSUPPORTED, "extension unsupported");
    }
    if (session->fs == NULL || session->fs->posix_rename == NULL) {
        return encode_status(response, response_capacity, response_len, extended_request.id, SSH_FX_OP_UNSUPPORTED, "posix rename unsupported");
    }

    ssh_buffer_wrap(&payload, (uint8_t *)extended_request.payload.data, extended_request.payload.len);
    status = ssh_buffer_get_string_view(&payload, &old_path_view);
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&payload, &new_path_view);
    }
    if (status == SSH_OK && ssh_buffer_remaining_read(&payload) != 0u) {
        status = SSH_ERR_MALFORMED_PACKET;
    }
    if (status == SSH_OK) {
        status = copy_path(old_path_view, old_path);
    }
    if (status == SSH_OK) {
        status = copy_path(new_path_view, new_path);
    }
    if (status == SSH_OK) {
        status = policy_check(session, SFTP_POLICY_RENAME, old_path, new_path, 0u, 0u, 0u, NULL);
    }
    if (status == SSH_OK) {
        status = session->fs->posix_rename(session->fs->ctx, old_path, new_path);
    }

    return encode_status(
        response,
        response_capacity,
        response_len,
        extended_request.id,
        status_from_error(status),
        status_message_from_error(status, "posix rename failed"));
}

int sftp_server_session_init(sftp_server_session_t *session, const ssh_fs_api_t *fs)
{
    if (session == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(session, 0, sizeof(*session));
    session->fs = fs;
    session->next_handle_id = 1u;
    return SSH_OK;
}

int sftp_server_session_set_policy(sftp_server_session_t *session, sftp_policy_fn policy, void *ctx)
{
    if (session == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    session->policy = policy;
    session->policy_ctx = ctx;
    return SSH_OK;
}

void sftp_server_session_deinit(sftp_server_session_t *session)
{
    size_t i;

    if (session == NULL) {
        return;
    }

    for (i = 0u; i < EMSSH_SFTP_MAX_HANDLES; ++i) {
        if (session->handles[i].in_use) {
            (void)close_entry(session, &session->handles[i]);
        }
    }

    memset(session, 0, sizeof(*session));
}

int sftp_server_handle_packet(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len)
{
    sftp_packet_t packet;
    sftp_request_t generic;
    int status;

    if (session == NULL || request == NULL || response == NULL || response_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = sftp_packet_wrap(request, request_len, &packet);
    if (status != SSH_OK) {
        return encode_status(response, response_capacity, response_len, 0u, SSH_FX_BAD_MESSAGE, "bad packet");
    }

    if (packet.type == SSH_FXP_INIT) {
        return handle_init(session, request, request_len, response, response_capacity, response_len);
    }
    if (packet.type == SSH_FXP_REALPATH) {
        return handle_realpath(session, request, request_len, response, response_capacity, response_len);
    }
    if (packet.type == SSH_FXP_LSTAT || packet.type == SSH_FXP_STAT) {
        return handle_path_attrs(session, request, request_len, packet.type, response, response_capacity, response_len);
    }
    if (packet.type == SSH_FXP_OPEN) {
        return handle_open(session, request, request_len, response, response_capacity, response_len);
    }
    if (packet.type == SSH_FXP_CLOSE) {
        return handle_close(session, request, request_len, response, response_capacity, response_len);
    }
    if (packet.type == SSH_FXP_FSTAT) {
        return handle_fstat(session, request, request_len, response, response_capacity, response_len);
    }
    if (packet.type == SSH_FXP_SETSTAT) {
        return handle_setstat(session, request, request_len, response, response_capacity, response_len);
    }
    if (packet.type == SSH_FXP_FSETSTAT) {
        return handle_fsetstat(session, request, request_len, response, response_capacity, response_len);
    }
    if (packet.type == SSH_FXP_OPENDIR) {
        return handle_opendir(session, request, request_len, response, response_capacity, response_len);
    }
    if (packet.type == SSH_FXP_READDIR) {
        return handle_readdir(session, request, request_len, response, response_capacity, response_len);
    }
    if (packet.type == SSH_FXP_READ) {
        return handle_read(session, request, request_len, response, response_capacity, response_len);
    }
    if (packet.type == SSH_FXP_WRITE) {
        return handle_write(session, request, request_len, response, response_capacity, response_len);
    }
    if (packet.type == SSH_FXP_REMOVE) {
        return handle_remove(session, request, request_len, response, response_capacity, response_len);
    }
    if (packet.type == SSH_FXP_MKDIR) {
        return handle_mkdir(session, request, request_len, response, response_capacity, response_len);
    }
    if (packet.type == SSH_FXP_RMDIR) {
        return handle_rmdir(session, request, request_len, response, response_capacity, response_len);
    }
    if (packet.type == SSH_FXP_RENAME) {
        return handle_rename(session, request, request_len, response, response_capacity, response_len);
    }
    if (packet.type == SSH_FXP_EXTENDED) {
        return handle_extended(session, request, request_len, response, response_capacity, response_len);
    }

    status = sftp_request_decode(request, request_len, &generic);
    return encode_status(
        response,
        response_capacity,
        response_len,
        status == SSH_OK ? generic.id : 0u,
        status == SSH_OK ? SSH_FX_OP_UNSUPPORTED : SSH_FX_BAD_MESSAGE,
        status == SSH_OK ? "unsupported" : "bad request");
}
