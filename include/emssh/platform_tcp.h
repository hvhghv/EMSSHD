#ifndef EMSSH_PLATFORM_TCP_H
#define EMSSH_PLATFORM_TCP_H

#include <stdint.h>

#include "emssh/ssh_platform.h"

typedef struct ssh_tcp_platform {
    ssh_net_api_t api;
    int initialized;
} ssh_tcp_platform_t;

typedef struct ssh_tcp_listener {
    uintptr_t socket_handle;
    int open;
} ssh_tcp_listener_t;

typedef struct ssh_tcp_conn {
    uintptr_t socket_handle;
    char peer_address[64];
    int open;
} ssh_tcp_conn_t;

int ssh_tcp_platform_init(ssh_tcp_platform_t *tcp);
void ssh_tcp_platform_deinit(ssh_tcp_platform_t *tcp);
const ssh_net_api_t *ssh_tcp_net_api(ssh_tcp_platform_t *tcp);

int ssh_tcp_listen(
    ssh_tcp_platform_t *tcp,
    const char *host,
    uint16_t port,
    int backlog,
    ssh_tcp_listener_t *listener);

int ssh_tcp_accept(
    ssh_tcp_platform_t *tcp,
    ssh_tcp_listener_t *listener,
    ssh_tcp_conn_t *conn,
    uint32_t timeout_ms);

int ssh_tcp_listener_close(ssh_tcp_platform_t *tcp, ssh_tcp_listener_t *listener);
int ssh_tcp_conn_close(ssh_tcp_platform_t *tcp, ssh_tcp_conn_t *conn);
int ssh_tcp_listener_port(ssh_tcp_platform_t *tcp, const ssh_tcp_listener_t *listener, uint16_t *port);
const char *ssh_tcp_conn_peer_address(const ssh_tcp_conn_t *conn);

#endif
