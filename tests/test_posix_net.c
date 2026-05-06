#include <stdio.h>
#include <string.h>

#include "emssh/platform_posix_net.h"
#include "emssh/ssh_error.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

int main(void)
{
    ssh_posix_net_platform_t net;
    ssh_posix_listener_t listener;
    ssh_posix_conn_t conn;
    const ssh_net_api_t *api;
    uint16_t port;

    memset(&net, 0, sizeof(net));
    memset(&listener, 0, sizeof(listener));
    memset(&conn, 0, sizeof(conn));

    CHECK(ssh_posix_net_platform_init(NULL) == SSH_ERR_INVALID_ARGUMENT);

#ifdef _WIN32
    CHECK(ssh_posix_net_platform_init(&net) == SSH_ERR_UNSUPPORTED);
    CHECK(ssh_posix_net_api(&net) == NULL);
    CHECK(ssh_posix_listen(&net, "127.0.0.1", 0u, 1, &listener) == SSH_ERR_UNSUPPORTED);
    CHECK(ssh_posix_accept(&net, &listener, &conn, 1u) == SSH_ERR_UNSUPPORTED);
    CHECK(ssh_posix_listener_close(&net, &listener) == SSH_ERR_UNSUPPORTED);
    CHECK(ssh_posix_conn_close(&net, &conn) == SSH_ERR_UNSUPPORTED);
    CHECK(ssh_posix_listener_port(&net, &listener, &port) == SSH_ERR_UNSUPPORTED);
#else
    CHECK(ssh_posix_net_platform_init(&net) == SSH_OK);
    api = ssh_posix_net_api(&net);
    CHECK(api != NULL);
    CHECK(api->read != NULL);
    CHECK(api->write != NULL);
    CHECK(api->close != NULL);

    CHECK(ssh_posix_listen(&net, "127.0.0.1", 0u, 1, &listener) == SSH_OK);
    CHECK(ssh_posix_listener_port(&net, &listener, &port) == SSH_OK);
    CHECK(port != 0u);
    CHECK(ssh_posix_accept(&net, &listener, &conn, 1u) == SSH_ERR_PLATFORM);
    CHECK(ssh_posix_conn_peer_address(&conn) == NULL);
    CHECK(ssh_posix_listener_close(&net, &listener) == SSH_OK);
    CHECK(ssh_posix_conn_close(&net, &conn) == SSH_OK);

    ssh_posix_net_platform_deinit(&net);
    CHECK(ssh_posix_net_api(&net) == NULL);
#endif

    return 0;
}
