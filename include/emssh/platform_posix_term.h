#ifndef EMSSH_PLATFORM_POSIX_TERM_H
#define EMSSH_PLATFORM_POSIX_TERM_H

#include "emssh/ssh_platform.h"

typedef struct ssh_posix_term_platform {
    ssh_term_api_t api;
    int initialized;
} ssh_posix_term_platform_t;

int ssh_posix_term_platform_init(ssh_posix_term_platform_t *term);
void ssh_posix_term_platform_deinit(ssh_posix_term_platform_t *term);
const ssh_term_api_t *ssh_posix_term_api(ssh_posix_term_platform_t *term);

#endif
