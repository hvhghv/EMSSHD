#ifndef EMSSH_PLATFORM_LWIP_H
#define EMSSH_PLATFORM_LWIP_H

#include <stdint.h>

#include "emssh/ssh_platform.h"

typedef struct ssh_lwip_platform {
    ssh_net_api_t api;
    int initialized;
} ssh_lwip_platform_t;

typedef struct ssh_lwip_listener {
    int socket_fd;
    int open;
} ssh_lwip_listener_t;

typedef struct ssh_lwip_conn {
    int socket_fd;
    char peer_address[64];
    int open;
} ssh_lwip_conn_t;

int ssh_lwip_platform_init(ssh_lwip_platform_t *net);
void ssh_lwip_platform_deinit(ssh_lwip_platform_t *net);
const ssh_net_api_t *ssh_lwip_net_api(ssh_lwip_platform_t *net);

int ssh_lwip_listen(
    ssh_lwip_platform_t *net,
    const char *host,
    uint16_t port,
    int backlog,
    ssh_lwip_listener_t *listener);

int ssh_lwip_accept(
    ssh_lwip_platform_t *net,
    ssh_lwip_listener_t *listener,
    ssh_lwip_conn_t *conn,
    uint32_t timeout_ms);

int ssh_lwip_listener_close(ssh_lwip_platform_t *net, ssh_lwip_listener_t *listener);
int ssh_lwip_conn_close(ssh_lwip_platform_t *net, ssh_lwip_conn_t *conn);
int ssh_lwip_listener_port(ssh_lwip_platform_t *net, const ssh_lwip_listener_t *listener, uint16_t *port);
const char *ssh_lwip_conn_peer_address(const ssh_lwip_conn_t *conn);

#endif
