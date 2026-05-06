#ifndef EMSSH_PLATFORM_POSIX_PASSWD_AUTH_H
#define EMSSH_PLATFORM_POSIX_PASSWD_AUTH_H

#include "emssh/ssh_server.h"

typedef struct ssh_posix_passwd_auth {
    const ssh_fs_api_t *fs;
    const char *passwd_path;
    const char *shadow_path;
    int initialized;
} ssh_posix_passwd_auth_t;

int ssh_posix_passwd_auth_init(
    ssh_posix_passwd_auth_t *auth,
    const ssh_fs_api_t *fs,
    const char *passwd_path,
    const char *shadow_path);
void ssh_posix_passwd_auth_deinit(ssh_posix_passwd_auth_t *auth);

int ssh_posix_passwd_auth_cb(void *ctx, const ssh_password_auth_request_t *request);

#endif
