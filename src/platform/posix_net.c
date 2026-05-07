#include "emssh/platform_posix_net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "emssh/ssh_error.h"

#define EMSSH_NET_IO_TIMEOUT (-2)

static int posix_is_peer_closed_error(void)
{
    return errno == ECONNRESET || errno == EPIPE || errno == ENOTCONN;
}

static int posix_wait_socket(int socket_fd, int for_write, uint32_t timeout_ms)
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

    status = select(socket_fd + 1, for_write ? NULL : &fds, for_write ? &fds : NULL, NULL, tv_ptr);
    if (status > 0) {
        return 1;
    }
    if (status == 0) {
        return 0;
    }
    return -1;
}

static int posix_net_read(void *ctx, void *conn, uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    ssh_posix_conn_t *posix_conn = (ssh_posix_conn_t *)conn;
    int n;

    (void)ctx;

    if (posix_conn == NULL || !posix_conn->open || buf == NULL || len == 0u) {
        return -1;
    }

    switch (posix_wait_socket(posix_conn->socket_fd, 0, timeout_ms)) {
    case 0:
        return EMSSH_NET_IO_TIMEOUT;
    case -1:
        return -1;
    default:
        break;
    }

    n = (int)recv(posix_conn->socket_fd, buf, len, 0);
    if (n < 0 && posix_is_peer_closed_error()) {
        return 0;
    }
    return n;
}

static int posix_net_write(void *ctx, void *conn, const uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    ssh_posix_conn_t *posix_conn = (ssh_posix_conn_t *)conn;
    int n;

    (void)ctx;

    if (posix_conn == NULL || !posix_conn->open || (buf == NULL && len != 0u)) {
        return -1;
    }
    if (len == 0u) {
        return 0;
    }

    switch (posix_wait_socket(posix_conn->socket_fd, 1, timeout_ms)) {
    case 0:
        return EMSSH_NET_IO_TIMEOUT;
    case -1:
        return -1;
    default:
        break;
    }

    n = (int)send(posix_conn->socket_fd, buf, len, 0);
    if (n < 0 && posix_is_peer_closed_error()) {
        return 0;
    }
    return n;
}

static int posix_net_close_api(void *ctx, void *conn)
{
    return ssh_posix_conn_close((ssh_posix_net_platform_t *)ctx, (ssh_posix_conn_t *)conn);
}

int ssh_posix_net_platform_init(ssh_posix_net_platform_t *net)
{
    if (net == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(net, 0, sizeof(*net));
    net->api.read = posix_net_read;
    net->api.write = posix_net_write;
    net->api.close = posix_net_close_api;
    net->api.ctx = net;
    net->initialized = 1;
    return SSH_OK;
}

void ssh_posix_net_platform_deinit(ssh_posix_net_platform_t *net)
{
    if (net == NULL) {
        return;
    }
    memset(net, 0, sizeof(*net));
}

const ssh_net_api_t *ssh_posix_net_api(ssh_posix_net_platform_t *net)
{
    if (net == NULL || !net->initialized) {
        return NULL;
    }
    return &net->api;
}

int ssh_posix_listen(
    ssh_posix_net_platform_t *net,
    const char *host,
    uint16_t port,
    int backlog,
    ssh_posix_listener_t *listener)
{
    struct addrinfo hints;
    struct addrinfo *result;
    struct addrinfo *it;
    char port_text[16];
    int listen_fd;
    int yes;
    int status;

    if (net == NULL || !net->initialized || listener == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(listener, 0, sizeof(*listener));
    listen_fd = -1;
    (void)snprintf(port_text, sizeof(port_text), "%u", (unsigned)port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = (host == NULL || host[0] == '\0') ? AF_INET : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (host == NULL || host[0] == '\0') {
        hints.ai_flags = AI_PASSIVE;
    }

    status = getaddrinfo((host != NULL && host[0] != '\0') ? host : NULL, port_text, &hints, &result);
    if (status != 0) {
        return SSH_ERR_PLATFORM;
    }

    for (it = result; it != NULL; it = it->ai_next) {
        listen_fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (listen_fd < 0) {
            continue;
        }

        yes = 1;
        (void)setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (bind(listen_fd, it->ai_addr, it->ai_addrlen) == 0 &&
            listen(listen_fd, backlog > 0 ? backlog : 1) == 0) {
            break;
        }

        (void)close(listen_fd);
        listen_fd = -1;
    }

    freeaddrinfo(result);
    if (listen_fd < 0) {
        return SSH_ERR_PLATFORM;
    }

    listener->socket_fd = listen_fd;
    listener->open = 1;
    return SSH_OK;
}

int ssh_posix_accept(
    ssh_posix_net_platform_t *net,
    ssh_posix_listener_t *listener,
    ssh_posix_conn_t *conn,
    uint32_t timeout_ms)
{
    int accepted_fd;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;

    if (net == NULL || !net->initialized || listener == NULL || !listener->open || conn == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(conn, 0, sizeof(*conn));
    if (posix_wait_socket(listener->socket_fd, 0, timeout_ms) <= 0) {
        return SSH_ERR_PLATFORM;
    }

    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr_len = (socklen_t)sizeof(peer_addr);
    accepted_fd = accept(listener->socket_fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
    if (accepted_fd < 0) {
        return SSH_ERR_PLATFORM;
    }

    conn->socket_fd = accepted_fd;
    if (peer_addr.ss_family == AF_INET) {
        const struct sockaddr_in *addr = (const struct sockaddr_in *)&peer_addr;
        (void)inet_ntop(AF_INET, &addr->sin_addr, conn->peer_address, sizeof(conn->peer_address));
    } else if (peer_addr.ss_family == AF_INET6) {
        const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)&peer_addr;
        (void)inet_ntop(AF_INET6, &addr->sin6_addr, conn->peer_address, sizeof(conn->peer_address));
    }
    conn->open = 1;
    return SSH_OK;
}

int ssh_posix_listener_close(ssh_posix_net_platform_t *net, ssh_posix_listener_t *listener)
{
    int fd;

    (void)net;

    if (listener == NULL || !listener->open) {
        return SSH_OK;
    }

    fd = listener->socket_fd;
    listener->open = 0;
    listener->socket_fd = -1;
    return close(fd) == 0 ? SSH_OK : SSH_ERR_PLATFORM;
}

int ssh_posix_conn_close(ssh_posix_net_platform_t *net, ssh_posix_conn_t *conn)
{
    int fd;

    (void)net;

    if (conn == NULL || !conn->open) {
        return SSH_OK;
    }

    fd = conn->socket_fd;
    conn->open = 0;
    conn->socket_fd = -1;
    return close(fd) == 0 ? SSH_OK : SSH_ERR_PLATFORM;
}

int ssh_posix_listener_port(ssh_posix_net_platform_t *net, const ssh_posix_listener_t *listener, uint16_t *port)
{
    struct sockaddr_storage addr;
    socklen_t addr_len;
    uint16_t value;

    if (net == NULL || !net->initialized || listener == NULL || !listener->open || port == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(&addr, 0, sizeof(addr));
    addr_len = (socklen_t)sizeof(addr);
    if (getsockname(listener->socket_fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        return SSH_ERR_PLATFORM;
    }

    if (addr.ss_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)&addr;
        value = ntohs(in->sin_port);
    } else if (addr.ss_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)&addr;
        value = ntohs(in6->sin6_port);
    } else {
        return SSH_ERR_PLATFORM;
    }

    *port = value;
    return SSH_OK;
}

const char *ssh_posix_conn_peer_address(const ssh_posix_conn_t *conn)
{
    if (conn == NULL || !conn->open || conn->peer_address[0] == '\0') {
        return NULL;
    }
    return conn->peer_address;
}
