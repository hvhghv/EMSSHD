#include "emssh/platform_tcp.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32) || defined(__CYGWIN__)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef WINVER
#define WINVER _WIN32_WINNT
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET emssh_socket_t;
#define EMSSH_INVALID_SOCKET INVALID_SOCKET
#define emssh_close_socket closesocket
static int emssh_socket_last_error(void)
{
    return WSAGetLastError();
}
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int emssh_socket_t;
#define EMSSH_INVALID_SOCKET (-1)
#define emssh_close_socket close
static int emssh_socket_last_error(void)
{
    return errno;
}
#endif

#include "emssh/ssh_error.h"

#define EMSSH_NET_IO_TIMEOUT (-2)

static emssh_socket_t handle_to_socket(uintptr_t handle)
{
    return (emssh_socket_t)handle;
}

static uintptr_t socket_to_handle(emssh_socket_t socket_handle)
{
    return (uintptr_t)socket_handle;
}

static int is_peer_closed_error(void)
{
#if defined(_WIN32) || defined(__CYGWIN__)
    int err = WSAGetLastError();
    return err == WSAECONNRESET || err == WSAECONNABORTED ||
           err == WSAENOTCONN || err == WSAESHUTDOWN;
#else
    return errno == ECONNRESET || errno == EPIPE || errno == ENOTCONN;
#endif
}

static int wait_for_socket(emssh_socket_t socket_handle, int for_write, uint32_t timeout_ms)
{
    fd_set fds;
#if defined(_WIN32) || defined(__CYGWIN__)
    TIMEVAL tv;
    const TIMEVAL *tv_ptr;
#else
    struct timeval tv;
    struct timeval *tv_ptr;
#endif
    int status;

    FD_ZERO(&fds);
    FD_SET(socket_handle, &fds);

    if (timeout_ms == 0u) {
        tv_ptr = NULL;
    } else {
        tv.tv_sec = (long)(timeout_ms / 1000u);
        tv.tv_usec = (long)((timeout_ms % 1000u) * 1000u);
        tv_ptr = &tv;
    }

    status = select((int)(socket_handle + 1), for_write ? NULL : &fds, for_write ? &fds : NULL, NULL, tv_ptr);
    if (status > 0) {
        return 1;
    }
    if (status == 0) {
        return 0;
    }
    return -1;
}

static int tcp_read(void *ctx, void *conn, uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    ssh_tcp_conn_t *tcp_conn = (ssh_tcp_conn_t *)conn;
    emssh_socket_t socket_handle;
    int n;

    (void)ctx;

    if (tcp_conn == NULL || !tcp_conn->open || buf == NULL || len == 0u) {
        return -1;
    }

    socket_handle = handle_to_socket(tcp_conn->socket_handle);
    switch (wait_for_socket(socket_handle, 0, timeout_ms)) {
    case 0:
        return EMSSH_NET_IO_TIMEOUT;
    case -1:
        return -1;
    default:
        break;
    }

    n = (int)recv(socket_handle, (char *)buf, (int)len, 0);
    if (n < 0 && is_peer_closed_error()) {
        return 0;
    }
    return n;
}

static int tcp_write(void *ctx, void *conn, const uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    ssh_tcp_conn_t *tcp_conn = (ssh_tcp_conn_t *)conn;
    emssh_socket_t socket_handle;
    int n;

    (void)ctx;

    if (tcp_conn == NULL || !tcp_conn->open || (buf == NULL && len != 0u)) {
        return -1;
    }
    if (len == 0u) {
        return 0;
    }

    socket_handle = handle_to_socket(tcp_conn->socket_handle);
    switch (wait_for_socket(socket_handle, 1, timeout_ms)) {
    case 0:
        return EMSSH_NET_IO_TIMEOUT;
    case -1:
        return -1;
    default:
        break;
    }

    n = (int)send(socket_handle, (const char *)buf, (int)len, 0);
    if (n < 0 && is_peer_closed_error()) {
        return 0;
    }
    return n;
}

static int tcp_close_api(void *ctx, void *conn)
{
    return ssh_tcp_conn_close((ssh_tcp_platform_t *)ctx, (ssh_tcp_conn_t *)conn);
}

int ssh_tcp_platform_init(ssh_tcp_platform_t *tcp)
{
#if defined(_WIN32) || defined(__CYGWIN__)
    WSADATA wsa_data;
#endif

    if (tcp == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(tcp, 0, sizeof(*tcp));

#if defined(_WIN32) || defined(__CYGWIN__)
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return SSH_ERR_PLATFORM;
    }
#endif

    tcp->api.read = tcp_read;
    tcp->api.write = tcp_write;
    tcp->api.close = tcp_close_api;
    tcp->api.ctx = tcp;
    tcp->initialized = 1;
    return SSH_OK;
}

void ssh_tcp_platform_deinit(ssh_tcp_platform_t *tcp)
{
    if (tcp == NULL || !tcp->initialized) {
        return;
    }

#if defined(_WIN32) || defined(__CYGWIN__)
    WSACleanup();
#endif

    memset(tcp, 0, sizeof(*tcp));
}

const ssh_net_api_t *ssh_tcp_net_api(ssh_tcp_platform_t *tcp)
{
    if (tcp == NULL || !tcp->initialized) {
        return NULL;
    }

    return &tcp->api;
}

int ssh_tcp_listen(
    ssh_tcp_platform_t *tcp,
    const char *host,
    uint16_t port,
    int backlog,
    ssh_tcp_listener_t *listener)
{
    struct addrinfo hints;
    struct addrinfo *result;
    struct addrinfo *it;
    char port_text[16];
    emssh_socket_t listen_socket;
    int status;
    int yes;
    int last_error;

    if (tcp == NULL || !tcp->initialized || listener == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(listener, 0, sizeof(*listener));
    listen_socket = EMSSH_INVALID_SOCKET;
    snprintf(port_text, sizeof(port_text), "%u", (unsigned)port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = (host == NULL || host[0] == '\0') ? AF_INET : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (host == NULL || host[0] == '\0') {
        hints.ai_flags = AI_PASSIVE;
    }

    status = getaddrinfo((host != NULL && host[0] != '\0') ? host : NULL, port_text, &hints, &result);
    if (status != 0) {
        fprintf(stderr, "[emssh] getaddrinfo(%s:%s) failed: %d\n", host != NULL ? host : "*", port_text, status);
        return SSH_ERR_PLATFORM;
    }

    last_error = 0;
    for (it = result; it != NULL; it = it->ai_next) {
        listen_socket = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (listen_socket == EMSSH_INVALID_SOCKET) {
            last_error = emssh_socket_last_error();
            continue;
        }

        yes = 1;
        (void)setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));

        if (bind(listen_socket, it->ai_addr, (int)it->ai_addrlen) == 0 &&
            listen(listen_socket, backlog > 0 ? backlog : 1) == 0) {
            break;
        }

        last_error = emssh_socket_last_error();

        (void)emssh_close_socket(listen_socket);
        listen_socket = EMSSH_INVALID_SOCKET;
    }

    freeaddrinfo(result);
    if (listen_socket == EMSSH_INVALID_SOCKET) {
        fprintf(stderr, "[emssh] listen(%s:%s) failed: socket error %d\n", host != NULL ? host : "*", port_text, last_error);
        return SSH_ERR_PLATFORM;
    }

    listener->socket_handle = socket_to_handle(listen_socket);
    listener->open = 1;
    return SSH_OK;
}

int ssh_tcp_accept(
    ssh_tcp_platform_t *tcp,
    ssh_tcp_listener_t *listener,
    ssh_tcp_conn_t *conn,
    uint32_t timeout_ms)
{
    emssh_socket_t listen_socket;
    emssh_socket_t accepted;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;

    if (tcp == NULL || !tcp->initialized || listener == NULL || !listener->open || conn == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(conn, 0, sizeof(*conn));
    listen_socket = handle_to_socket(listener->socket_handle);
    if (wait_for_socket(listen_socket, 0, timeout_ms) <= 0) {
        return SSH_ERR_PLATFORM;
    }

    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr_len = (socklen_t)sizeof(peer_addr);
    accepted = accept(listen_socket, (struct sockaddr *)&peer_addr, &peer_addr_len);
    if (accepted == EMSSH_INVALID_SOCKET) {
        return SSH_ERR_PLATFORM;
    }

    conn->socket_handle = socket_to_handle(accepted);
    (void)getnameinfo(
        (const struct sockaddr *)&peer_addr,
        peer_addr_len,
        conn->peer_address,
        (socklen_t)sizeof(conn->peer_address),
        NULL,
        0,
        NI_NUMERICHOST);
    conn->open = 1;
    return SSH_OK;
}

int ssh_tcp_listener_close(ssh_tcp_platform_t *tcp, ssh_tcp_listener_t *listener)
{
    emssh_socket_t socket_handle;

    (void)tcp;

    if (listener == NULL || !listener->open) {
        return SSH_OK;
    }

    socket_handle = handle_to_socket(listener->socket_handle);
    listener->open = 0;
    listener->socket_handle = 0u;
    return emssh_close_socket(socket_handle) == 0 ? SSH_OK : SSH_ERR_PLATFORM;
}

int ssh_tcp_conn_close(ssh_tcp_platform_t *tcp, ssh_tcp_conn_t *conn)
{
    emssh_socket_t socket_handle;

    (void)tcp;

    if (conn == NULL || !conn->open) {
        return SSH_OK;
    }

    socket_handle = handle_to_socket(conn->socket_handle);
    conn->open = 0;
    conn->socket_handle = 0u;
    return emssh_close_socket(socket_handle) == 0 ? SSH_OK : SSH_ERR_PLATFORM;
}

int ssh_tcp_listener_port(ssh_tcp_platform_t *tcp, const ssh_tcp_listener_t *listener, uint16_t *port)
{
    emssh_socket_t socket_handle;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    uint16_t value;

    if (tcp == NULL || !tcp->initialized || listener == NULL || !listener->open || port == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    socket_handle = handle_to_socket(listener->socket_handle);
    memset(&addr, 0, sizeof(addr));
    addr_len = (socklen_t)sizeof(addr);
    if (getsockname(socket_handle, (struct sockaddr *)&addr, &addr_len) != 0) {
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

const char *ssh_tcp_conn_peer_address(const ssh_tcp_conn_t *conn)
{
    if (conn == NULL || !conn->open || conn->peer_address[0] == '\0') {
        return NULL;
    }

    return conn->peer_address;
}
