#ifndef EMSSH_PLATFORM_POSIX_NET_H
#define EMSSH_PLATFORM_POSIX_NET_H

#include <stdint.h>

#include "emssh/ssh_platform.h"

typedef struct ssh_posix_net_platform {
    ssh_net_api_t api;
    int initialized;
} ssh_posix_net_platform_t;

typedef struct ssh_posix_listener {
    int socket_fd;
    int open;
} ssh_posix_listener_t;

typedef struct ssh_posix_conn {
    int socket_fd;
    char peer_address[64];
    int open;
} ssh_posix_conn_t;

int ssh_posix_net_platform_init(ssh_posix_net_platform_t *net);
void ssh_posix_net_platform_deinit(ssh_posix_net_platform_t *net);
const ssh_net_api_t *ssh_posix_net_api(ssh_posix_net_platform_t *net);

int ssh_posix_listen(
    ssh_posix_net_platform_t *net,
    const char *host,
    uint16_t port,
    int backlog,
    ssh_posix_listener_t *listener);

int ssh_posix_accept(
    ssh_posix_net_platform_t *net,
    ssh_posix_listener_t *listener,
    ssh_posix_conn_t *conn,
    uint32_t timeout_ms);

int ssh_posix_listener_close(ssh_posix_net_platform_t *net, ssh_posix_listener_t *listener);
int ssh_posix_conn_close(ssh_posix_net_platform_t *net, ssh_posix_conn_t *conn);
int ssh_posix_listener_port(ssh_posix_net_platform_t *net, const ssh_posix_listener_t *listener, uint16_t *port);
const char *ssh_posix_conn_peer_address(const ssh_posix_conn_t *conn);

#endif
