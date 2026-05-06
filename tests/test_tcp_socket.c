#include <stdio.h>

#include "emssh/platform_tcp.h"
#include "emssh/ssh_error.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

int main(void)
{
    ssh_tcp_platform_t tcp;
    ssh_tcp_listener_t listener;
    ssh_tcp_conn_t conn;
    const ssh_net_api_t *net;
    uint16_t port;

    CHECK(ssh_tcp_platform_init(&tcp) == SSH_OK);
    net = ssh_tcp_net_api(&tcp);
    CHECK(net != NULL);
    CHECK(net->read != NULL);
    CHECK(net->write != NULL);
    CHECK(net->close != NULL);

    CHECK(ssh_tcp_listen(&tcp, "127.0.0.1", 0u, 1, &listener) == SSH_OK);
    CHECK(ssh_tcp_listener_port(&tcp, &listener, &port) == SSH_OK);
    CHECK(port != 0u);
    CHECK(ssh_tcp_accept(&tcp, &listener, &conn, 1u) == SSH_ERR_PLATFORM);
    CHECK(ssh_tcp_listener_close(&tcp, &listener) == SSH_OK);

    ssh_tcp_platform_deinit(&tcp);
    return 0;
}
