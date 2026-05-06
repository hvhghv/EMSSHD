#include "emssh/platform_lwip.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "emssh/ssh_error.h"

#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

static int is_peer_closed_error(void)
{
    return errno == ECONNRESET || errno == ENOTCONN || errno == EPIPE;
}

static int wait_for_socket(int socket_fd, int for_write, uint32_t timeout_ms)
{
    fd_set fds;
    struct timeval tv;
    struct timeval *tv_ptr;
    int status;

    FD_ZERO(&fds);
    FD_SET(socket_fd, &fds);

    if (timeout_ms == 0u) {
        tv_ptr = NULL;
    } else {
        tv.tv_sec = (long)(timeout_ms / 1000u);
        tv.tv_usec = (long)((timeout_ms % 1000u) * 1000u);
        tv_ptr = &tv;
    }

    status = lwip_select(
        socket_fd + 1,
        for_write ? NULL : &fds,
        for_write ? &fds : NULL,
        NULL,
        tv_ptr);
    if (status > 0) {
        return 1;
    }
    if (status == 0) {
        return 0;
    }
    return -1;
}

static int lwip_read(void *ctx, void *conn, uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    ssh_lwip_conn_t *lwip_conn = (ssh_lwip_conn_t *)conn;
    int n;

    (void)ctx;

    if (lwip_conn == NULL || !lwip_conn->open || buf == NULL || len == 0u) {
        return -1;
    }

    if (wait_for_socket(lwip_conn->socket_fd, 0, timeout_ms) <= 0) {
        return -1;
    }

    n = (int)lwip_recv(lwip_conn->socket_fd, buf, len, 0);
    if (n < 0 && is_peer_closed_error()) {
        return 0;
    }
    return n;
}

static int lwip_write(void *ctx, void *conn, const uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    ssh_lwip_conn_t *lwip_conn = (ssh_lwip_conn_t *)conn;
    int n;

    (void)ctx;

    if (lwip_conn == NULL || !lwip_conn->open || (buf == NULL && len != 0u)) {
        return -1;
    }
    if (len == 0u) {
        return 0;
    }

    if (wait_for_socket(lwip_conn->socket_fd, 1, timeout_ms) <= 0) {
        return -1;
    }

    n = (int)lwip_send(lwip_conn->socket_fd, buf, len, 0);
    if (n < 0 && is_peer_closed_error()) {
        return 0;
    }
    return n;
}

static int lwip_close_api(void *ctx, void *conn)
{
    return ssh_lwip_conn_close((ssh_lwip_platform_t *)ctx, (ssh_lwip_conn_t *)conn);
}

int ssh_lwip_platform_init(ssh_lwip_platform_t *net)
{
    if (net == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(net, 0, sizeof(*net));
    net->api.read = lwip_read;
    net->api.write = lwip_write;
    net->api.close = lwip_close_api;
    net->api.ctx = net;
    net->initialized = 1;
    return SSH_OK;
}

void ssh_lwip_platform_deinit(ssh_lwip_platform_t *net)
{
    if (net == NULL || !net->initialized) {
        return;
    }
    memset(net, 0, sizeof(*net));
}

const ssh_net_api_t *ssh_lwip_net_api(ssh_lwip_platform_t *net)
{
    if (net == NULL || !net->initialized) {
        return NULL;
    }
    return &net->api;
}

int ssh_lwip_listen(
    ssh_lwip_platform_t *net,
    const char *host,
    uint16_t port,
    int backlog,
    ssh_lwip_listener_t *listener)
{
    struct addrinfo hints;
    struct addrinfo *result;
    struct addrinfo *it;
    char port_text[16];
    int listen_fd;
    int status;
    int yes;

    if (net == NULL || !net->initialized || listener == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(listener, 0, sizeof(*listener));
    listen_fd = -1;
    snprintf(port_text, sizeof(port_text), "%u", (unsigned)port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = (host == NULL || host[0] == '\0') ? AF_INET : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (host == NULL || host[0] == '\0') {
        hints.ai_flags = AI_PASSIVE;
    }

    status = lwip_getaddrinfo((host != NULL && host[0] != '\0') ? host : NULL, port_text, &hints, &result);
    if (status != 0) {
        return SSH_ERR_PLATFORM;
    }

    for (it = result; it != NULL; it = it->ai_next) {
        listen_fd = lwip_socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (listen_fd < 0) {
            continue;
        }

        yes = 1;
        (void)lwip_setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, (socklen_t)sizeof(yes));

        if (lwip_bind(listen_fd, it->ai_addr, (socklen_t)it->ai_addrlen) == 0 &&
            lwip_listen(listen_fd, backlog > 0 ? backlog : 1) == 0) {
            break;
        }

        (void)lwip_close(listen_fd);
        listen_fd = -1;
    }

    lwip_freeaddrinfo(result);
    if (listen_fd < 0) {
        return SSH_ERR_PLATFORM;
    }

    listener->socket_fd = listen_fd;
    listener->open = 1;
    return SSH_OK;
}

int ssh_lwip_accept(
    ssh_lwip_platform_t *net,
    ssh_lwip_listener_t *listener,
    ssh_lwip_conn_t *conn,
    uint32_t timeout_ms)
{
    int accepted_fd;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;

    if (net == NULL || !net->initialized || listener == NULL || !listener->open || conn == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(conn, 0, sizeof(*conn));
    if (wait_for_socket(listener->socket_fd, 0, timeout_ms) <= 0) {
        return SSH_ERR_PLATFORM;
    }

    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr_len = (socklen_t)sizeof(peer_addr);
    accepted_fd = lwip_accept(listener->socket_fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
    if (accepted_fd < 0) {
        return SSH_ERR_PLATFORM;
    }

    conn->socket_fd = accepted_fd;
    if (peer_addr.ss_family == AF_INET) {
        const struct sockaddr_in *addr = (const struct sockaddr_in *)&peer_addr;
        (void)lwip_inet_ntop(AF_INET, &addr->sin_addr, conn->peer_address, (socklen_t)sizeof(conn->peer_address));
    } else if (peer_addr.ss_family == AF_INET6) {
        const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)&peer_addr;
        (void)lwip_inet_ntop(AF_INET6, &addr->sin6_addr, conn->peer_address, (socklen_t)sizeof(conn->peer_address));
    }
    conn->open = 1;
    return SSH_OK;
}

int ssh_lwip_listener_close(ssh_lwip_platform_t *net, ssh_lwip_listener_t *listener)
{
    int fd;

    (void)net;

    if (listener == NULL || !listener->open) {
        return SSH_OK;
    }

    fd = listener->socket_fd;
    listener->open = 0;
    listener->socket_fd = -1;
    return lwip_close(fd) == 0 ? SSH_OK : SSH_ERR_PLATFORM;
}

int ssh_lwip_conn_close(ssh_lwip_platform_t *net, ssh_lwip_conn_t *conn)
{
    int fd;

    (void)net;

    if (conn == NULL || !conn->open) {
        return SSH_OK;
    }

    fd = conn->socket_fd;
    conn->open = 0;
    conn->socket_fd = -1;
    return lwip_close(fd) == 0 ? SSH_OK : SSH_ERR_PLATFORM;
}

int ssh_lwip_listener_port(ssh_lwip_platform_t *net, const ssh_lwip_listener_t *listener, uint16_t *port)
{
    struct sockaddr_storage addr;
    socklen_t addr_len;
    uint16_t value;

    if (net == NULL || !net->initialized || listener == NULL || !listener->open || port == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(&addr, 0, sizeof(addr));
    addr_len = (socklen_t)sizeof(addr);
    if (lwip_getsockname(listener->socket_fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        return SSH_ERR_PLATFORM;
    }

    if (addr.ss_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)&addr;
        value = lwip_ntohs(in->sin_port);
    } else if (addr.ss_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)&addr;
        value = lwip_ntohs(in6->sin6_port);
    } else {
        return SSH_ERR_PLATFORM;
    }

    *port = value;
    return SSH_OK;
}

const char *ssh_lwip_conn_peer_address(const ssh_lwip_conn_t *conn)
{
    if (conn == NULL || !conn->open || conn->peer_address[0] == '\0') {
        return NULL;
    }
    return conn->peer_address;
}
