#ifndef EMSSH_SFTP_SERVER_H
#define EMSSH_SFTP_SERVER_H

#include <stddef.h>
#include <stdint.h>

#include "emssh/ssh_config.h"
#include "emssh/ssh_platform.h"

#ifndef EMSSH_SFTP_MAX_PATH
#define EMSSH_SFTP_MAX_PATH 256u
#endif

#ifndef EMSSH_SFTP_MAX_IO
#define EMSSH_SFTP_MAX_IO 8192u
#endif

typedef enum sftp_policy_operation {
    SFTP_POLICY_REALPATH = 1,
    SFTP_POLICY_STAT = 2,
    SFTP_POLICY_OPEN = 3,
    SFTP_POLICY_READ = 4,
    SFTP_POLICY_WRITE = 5,
    SFTP_POLICY_SETSTAT = 6,
    SFTP_POLICY_OPENDIR = 7,
    SFTP_POLICY_READDIR = 8,
    SFTP_POLICY_REMOVE = 9,
    SFTP_POLICY_MKDIR = 10,
    SFTP_POLICY_RMDIR = 11,
    SFTP_POLICY_RENAME = 12,
    SFTP_POLICY_FSTAT = 13,
    SFTP_POLICY_FSETSTAT = 14,
    SFTP_POLICY_FSYNC = 15,
    SFTP_POLICY_HARDLINK = 16,
    SFTP_POLICY_STATVFS = 17,
    SFTP_POLICY_FSTATVFS = 18
} sftp_policy_operation_t;

typedef struct sftp_policy_request {
    sftp_policy_operation_t operation;
    const char *path;
    const char *new_path;
    uint32_t pflags;
    uint64_t offset;
    size_t length;
    const ssh_fs_attrs_t *attrs;
} sftp_policy_request_t;

typedef int (*sftp_policy_fn)(void *ctx, const sftp_policy_request_t *request);

typedef enum sftp_handle_kind {
    SFTP_HANDLE_KIND_FILE = 1,
    SFTP_HANDLE_KIND_DIR = 2
} sftp_handle_kind_t;

typedef struct sftp_handle_entry {
    int in_use;
    sftp_handle_kind_t kind;
    uint8_t wire_handle[4];
    size_t wire_handle_len;
    void *fs_handle;
    uint32_t pflags;
    char path[EMSSH_SFTP_MAX_PATH];
    ssh_fs_attrs_t attrs;
} sftp_handle_entry_t;

typedef struct sftp_server_session {
    const ssh_fs_api_t *fs;
    sftp_policy_fn policy;
    void *policy_ctx;
    uint32_t next_handle_id;
    sftp_handle_entry_t handles[EMSSH_SFTP_MAX_HANDLES];
} sftp_server_session_t;

int sftp_server_session_init(sftp_server_session_t *session, const ssh_fs_api_t *fs);
int sftp_server_session_set_policy(sftp_server_session_t *session, sftp_policy_fn policy, void *ctx);
void sftp_server_session_deinit(sftp_server_session_t *session);

int sftp_server_handle_packet(
    sftp_server_session_t *session,
    const uint8_t *request,
    size_t request_len,
    uint8_t *response,
    size_t response_capacity,
    size_t *response_len);

#endif
