#ifndef EMSSH_PLATFORM_STDIO_FS_H
#define EMSSH_PLATFORM_STDIO_FS_H

#include "emssh/ssh_platform.h"

#ifndef EMSSH_STDIO_FS_MAX_PATH
#define EMSSH_STDIO_FS_MAX_PATH 512u
#endif

typedef struct ssh_stdio_fs {
    char root[EMSSH_STDIO_FS_MAX_PATH];
    ssh_fs_api_t api;
} ssh_stdio_fs_t;

int ssh_stdio_fs_init(ssh_stdio_fs_t *fs, const char *root);
void ssh_stdio_fs_deinit(ssh_stdio_fs_t *fs);
const ssh_fs_api_t *ssh_stdio_fs_api(ssh_stdio_fs_t *fs);

#endif
