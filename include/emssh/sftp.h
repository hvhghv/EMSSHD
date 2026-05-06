#ifndef EMSSH_SFTP_H
#define EMSSH_SFTP_H

#include <stddef.h>
#include <stdint.h>

#include "emssh/ssh_buffer.h"
#include "emssh/ssh_platform.h"

#define SSH_FXP_INIT 1u
#define SSH_FXP_VERSION 2u
#define SSH_FXP_OPEN 3u
#define SSH_FXP_CLOSE 4u
#define SSH_FXP_READ 5u
#define SSH_FXP_WRITE 6u
#define SSH_FXP_LSTAT 7u
#define SSH_FXP_FSTAT 8u
#define SSH_FXP_SETSTAT 9u
#define SSH_FXP_FSETSTAT 10u
#define SSH_FXP_OPENDIR 11u
#define SSH_FXP_READDIR 12u
#define SSH_FXP_REMOVE 13u
#define SSH_FXP_MKDIR 14u
#define SSH_FXP_RMDIR 15u
#define SSH_FXP_REALPATH 16u
#define SSH_FXP_STAT 17u
#define SSH_FXP_RENAME 18u
#define SSH_FXP_STATUS 101u
#define SSH_FXP_HANDLE 102u
#define SSH_FXP_DATA 103u
#define SSH_FXP_NAME 104u
#define SSH_FXP_ATTRS 105u
#define SSH_FXP_EXTENDED 200u
#define SSH_FXP_EXTENDED_REPLY 201u

#define SFTP_VERSION_3 3u

#define SSH_FXF_READ 0x00000001u
#define SSH_FXF_WRITE 0x00000002u
#define SSH_FXF_APPEND 0x00000004u
#define SSH_FXF_CREAT 0x00000008u
#define SSH_FXF_TRUNC 0x00000010u
#define SSH_FXF_EXCL 0x00000020u

#define SSH_FILEXFER_ATTR_SIZE 0x00000001u
#define SSH_FILEXFER_ATTR_UIDGID 0x00000002u
#define SSH_FILEXFER_ATTR_PERMISSIONS 0x00000004u
#define SSH_FILEXFER_ATTR_ACMODTIME 0x00000008u
#define SSH_FILEXFER_ATTR_EXTENDED 0x80000000u

typedef enum sftp_status_code {
    SSH_FX_OK = 0,
    SSH_FX_EOF = 1,
    SSH_FX_NO_SUCH_FILE = 2,
    SSH_FX_PERMISSION_DENIED = 3,
    SSH_FX_FAILURE = 4,
    SSH_FX_BAD_MESSAGE = 5,
    SSH_FX_NO_CONNECTION = 6,
    SSH_FX_CONNECTION_LOST = 7,
    SSH_FX_OP_UNSUPPORTED = 8
} sftp_status_code_t;

typedef struct sftp_init {
    uint32_t version;
    ssh_string_view_t extension_data;
} sftp_init_t;

typedef struct sftp_packet {
    uint8_t type;
    ssh_string_view_t payload;
} sftp_packet_t;

typedef struct sftp_request {
    uint8_t type;
    uint32_t id;
    ssh_string_view_t payload;
} sftp_request_t;

typedef struct sftp_path_request {
    uint32_t id;
    ssh_string_view_t path;
} sftp_path_request_t;

typedef struct sftp_open_request {
    uint32_t id;
    ssh_string_view_t filename;
    uint32_t pflags;
    ssh_string_view_t attrs;
} sftp_open_request_t;

typedef struct sftp_handle_request {
    uint32_t id;
    ssh_string_view_t handle;
} sftp_handle_request_t;

typedef struct sftp_read_request {
    uint32_t id;
    ssh_string_view_t handle;
    uint64_t offset;
    uint32_t len;
} sftp_read_request_t;

typedef struct sftp_write_request {
    uint32_t id;
    ssh_string_view_t handle;
    uint64_t offset;
    ssh_string_view_t data;
} sftp_write_request_t;

typedef struct sftp_rename_request {
    uint32_t id;
    ssh_string_view_t old_path;
    ssh_string_view_t new_path;
} sftp_rename_request_t;

typedef struct sftp_mkdir_request {
    uint32_t id;
    ssh_string_view_t path;
    ssh_string_view_t attrs;
} sftp_mkdir_request_t;

typedef struct sftp_setstat_request {
    uint32_t id;
    ssh_string_view_t path;
    ssh_fs_attrs_t attrs;
} sftp_setstat_request_t;

typedef struct sftp_fsetstat_request {
    uint32_t id;
    ssh_string_view_t handle;
    ssh_fs_attrs_t attrs;
} sftp_fsetstat_request_t;

typedef struct sftp_extended_request {
    uint32_t id;
    ssh_string_view_t name;
    ssh_string_view_t payload;
} sftp_extended_request_t;

int sftp_packet_wrap(const uint8_t *packet, size_t packet_len, sftp_packet_t *wrapped);
int sftp_request_decode(const uint8_t *packet, size_t packet_len, sftp_request_t *request);
int sftp_attrs_decode(ssh_string_view_t encoded, ssh_fs_attrs_t *attrs);
int sftp_init_decode(const uint8_t *packet, size_t packet_len, sftp_init_t *init);
int sftp_realpath_request_decode(const uint8_t *packet, size_t packet_len, sftp_path_request_t *request);
int sftp_lstat_request_decode(const uint8_t *packet, size_t packet_len, sftp_path_request_t *request);
int sftp_stat_request_decode(const uint8_t *packet, size_t packet_len, sftp_path_request_t *request);
int sftp_opendir_request_decode(const uint8_t *packet, size_t packet_len, sftp_path_request_t *request);
int sftp_open_request_decode(const uint8_t *packet, size_t packet_len, sftp_open_request_t *request);
int sftp_close_request_decode(const uint8_t *packet, size_t packet_len, sftp_handle_request_t *request);
int sftp_fstat_request_decode(const uint8_t *packet, size_t packet_len, sftp_handle_request_t *request);
int sftp_readdir_request_decode(const uint8_t *packet, size_t packet_len, sftp_handle_request_t *request);
int sftp_read_request_decode(const uint8_t *packet, size_t packet_len, sftp_read_request_t *request);
int sftp_write_request_decode(const uint8_t *packet, size_t packet_len, sftp_write_request_t *request);
int sftp_remove_request_decode(const uint8_t *packet, size_t packet_len, sftp_path_request_t *request);
int sftp_mkdir_request_decode(const uint8_t *packet, size_t packet_len, sftp_mkdir_request_t *request);
int sftp_rmdir_request_decode(const uint8_t *packet, size_t packet_len, sftp_path_request_t *request);
int sftp_rename_request_decode(const uint8_t *packet, size_t packet_len, sftp_rename_request_t *request);
int sftp_setstat_request_decode(const uint8_t *packet, size_t packet_len, sftp_setstat_request_t *request);
int sftp_fsetstat_request_decode(const uint8_t *packet, size_t packet_len, sftp_fsetstat_request_t *request);
int sftp_extended_request_decode(const uint8_t *packet, size_t packet_len, sftp_extended_request_t *request);
int sftp_version_encode(uint8_t *out, size_t out_capacity, size_t *out_len, uint32_t version);
int sftp_status_encode(
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    uint32_t request_id,
    uint32_t status_code,
    const char *message,
    const char *language);
int sftp_handle_encode(
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    uint32_t request_id,
    const uint8_t *handle,
    size_t handle_len);
int sftp_data_encode(
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    uint32_t request_id,
    const uint8_t *data,
    size_t data_len);
int sftp_attrs_encode(
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    uint32_t request_id,
    const ssh_fs_attrs_t *attrs);
int sftp_name_one_encode(
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    uint32_t request_id,
    const char *filename,
    const char *longname);
int sftp_name_one_attrs_encode(
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    uint32_t request_id,
    const char *filename,
    const char *longname,
    const ssh_fs_attrs_t *attrs);

#endif
