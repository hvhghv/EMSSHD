#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "emssh/platform_posix_net.h"
#include "emssh/platform_posix_passwd_auth.h"
#include "emssh/platform_posix_runtime.h"
#include "emssh/platform_posix_term.h"
#include "emssh/platform_stdio_fs.h"
#include "emssh/sshd_config_file.h"
#include "emssh/ssh_crypto.h"
#include "emssh/ssh_error.h"
#include "emssh/ssh_server.h"

#define POSIX_OPENSSL_DEFAULT_PORT 2222u
#define POSIX_OPENSSL_DEFAULT_TIMEOUT_MS 30000u

#if !defined(EMSSH_BUILD_POSIX_PASSWD_AUTH)
#error "embedded_posix_socket_stdio_openssl_server requires EMSSH_BUILD_POSIX_PASSWD_AUTH=ON"
#endif

static uint16_t parse_port(const char *text)
{
    unsigned long value;
    char *end;

    if (text == NULL || text[0] == '\0') {
        return 0u;
    }

    value = strtoul(text, &end, 10);
    if (*end != '\0' || value == 0ul || value > 65535ul) {
        return 0u;
    }
    return (uint16_t)value;
}

static void usage(const char *program)
{
    fprintf(
        stderr,
        "usage: %s <port> <root-dir> [--passwd-file <path>] [--sshd-config <path>] [--mode sftp|term]\n",
        program);
}

int main(int argc, char **argv)
{
    const char *root_dir;
    const char *sshd_config_path;
    uint16_t port;
    ssh_posix_runtime_t runtime;
    ssh_posix_net_platform_t net;
    ssh_posix_listener_t listener;
    ssh_posix_conn_t conn;
    ssh_posix_term_platform_t term;
    ssh_stdio_fs_t fs;
    ssh_crypto_context_t crypto_ctx;
    ssh_platform_t platform;
    ssh_server_t server;
    ssh_server_config_t config;
    ssh_server_session_options_t options;
    ssh_sshd_config_file_t sshd_config;
    ssh_posix_passwd_auth_t passwd_auth;
    const char *passwd_path;
    int status;
    int initialized_runtime;
    int initialized_net;
    int initialized_fs;
    int initialized_crypto;
    int initialized_server;
    int initialized_passwd_auth;
    int initialized_term;
    int run_terminal_mode;
    int argi;

    if (argc < 3) {
        usage(argv[0]);
        return 2;
    }

    port = parse_port(argv[1]);
    if (port == 0u) {
        usage(argv[0]);
        return 2;
    }
    root_dir = argv[2];

    memset(&runtime, 0, sizeof(runtime));
    memset(&net, 0, sizeof(net));
    memset(&listener, 0, sizeof(listener));
    memset(&conn, 0, sizeof(conn));
    memset(&term, 0, sizeof(term));
    memset(&fs, 0, sizeof(fs));
    memset(&crypto_ctx, 0, sizeof(crypto_ctx));
    memset(&platform, 0, sizeof(platform));
    memset(&server, 0, sizeof(server));
    memset(&config, 0, sizeof(config));
    memset(&options, 0, sizeof(options));
    memset(&algorithms, 0, sizeof(algorithms));
    memset(&sshd_config, 0, sizeof(sshd_config));
    memset(&passwd_auth, 0, sizeof(passwd_auth));
    passwd_path = NULL;
    sshd_config_path = NULL;
    initialized_runtime = 0;
    initialized_net = 0;
    initialized_fs = 0;
    initialized_crypto = 0;
    initialized_server = 0;
    initialized_passwd_auth = 0;
    initialized_term = 0;
    run_terminal_mode = 0;
    argi = 3;
    status = SSH_OK;

    while (argi < argc) {
        if (strcmp(argv[argi], "--passwd-file") == 0) {
            if (argi + 1 >= argc) {
                usage(argv[0]);
                return 2;
            }
            passwd_path = argv[argi + 1];
            argi += 2;
            continue;
        }
        if (strcmp(argv[argi], "--sshd-config") == 0) {
            if (argi + 1 >= argc) {
                usage(argv[0]);
                return 2;
            }
            sshd_config_path = argv[argi + 1];
            argi += 2;
            continue;
        }
        if (strcmp(argv[argi], "--mode") == 0) {
            if (argi + 1 >= argc) {
                usage(argv[0]);
                return 2;
            }
            if (strcmp(argv[argi + 1], "sftp") == 0) {
                run_terminal_mode = 0;
            } else if (strcmp(argv[argi + 1], "term") == 0) {
                run_terminal_mode = 1;
            } else {
                usage(argv[0]);
                return 2;
            }
            argi += 2;
            continue;
        }
        usage(argv[0]);
        return 2;
    }

    status = ssh_posix_runtime_init(&runtime, NULL, NULL);
    if (status != SSH_OK) {
        fprintf(stderr, "posix runtime init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_runtime = 1;

    status = ssh_posix_net_platform_init(&net);
    if (status != SSH_OK) {
        fprintf(stderr, "posix net init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_net = 1;

    status = ssh_stdio_fs_init(&fs, root_dir);
    if (status != SSH_OK) {
        fprintf(stderr, "stdio fs init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_fs = 1;

    if (run_terminal_mode) {
#if defined(EMSSH_BUILD_POSIX_TERM)
        status = ssh_posix_term_platform_init(&term);
        if (status != SSH_OK) {
            fprintf(stderr, "posix term init failed: %s\n", ssh_status_string(status));
            goto cleanup;
        }
        initialized_term = 1;
#else
        fprintf(stderr, "--mode term requires EMSSH_BUILD_POSIX_TERM=ON\n");
        status = SSH_ERR_UNSUPPORTED;
        goto cleanup;
#endif
    }

    status = ssh_crypto_open(&crypto_ctx);
    if (status != SSH_OK) {
        fprintf(stderr, "crypto context init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_crypto = 1;

    platform.mem = ssh_posix_mem_api(&runtime);
    platform.time = ssh_posix_time_api(&runtime);
    platform.log = ssh_posix_log_api(&runtime);
    platform.net = ssh_posix_net_api(&net);
    platform.fs = ssh_stdio_fs_api(&fs);
    platform.term = run_terminal_mode ? ssh_posix_term_api(&term) : NULL;
    platform.crypto = ssh_crypto_api(&crypto_ctx);
    platform.rng = ssh_crypto_rng_api(&crypto_ctx);

    ssh_server_config_defaults(&config);
    ssh_server_session_options_defaults(&options);
    options.timeout_ms = POSIX_OPENSSL_DEFAULT_TIMEOUT_MS;

    status = ssh_posix_passwd_auth_init(&passwd_auth, ssh_stdio_fs_api(&fs), passwd_path, NULL);
    if (status != SSH_OK) {
        fprintf(stderr, "posix passwd auth init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_passwd_auth = 1;
    config.password_auth = ssh_posix_passwd_auth_cb;
    config.auth_ctx = &passwd_auth;

    if (sshd_config_path != NULL) {
        ssh_sshd_config_file_defaults(&sshd_config);
        status = ssh_sshd_config_file_load(ssh_stdio_fs_api(&fs), sshd_config_path, &sshd_config);
        if (status != SSH_OK) {
            fprintf(stderr, "sshd_config load failed: %s\n", ssh_status_string(status));
            goto cleanup;
        }
        status = ssh_sshd_config_file_apply(&sshd_config, &config, &options, &algorithms, &port, NULL, NULL);
        if (status != SSH_OK) {
            fprintf(stderr, "sshd_config apply failed: %s\n", ssh_status_string(status));
            goto cleanup;
        }
    }

    status = ssh_server_init(&server, &platform, &config);
    if (status != SSH_OK) {
        fprintf(stderr, "server init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_server = 1;

    status = ssh_posix_listen(&net, config.listen_address, port, 4, &listener);
    if (status != SSH_OK) {
        fprintf(stderr, "listen failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }

    printf(
        "posix+posix-socket+stdio+%s server listening on 0.0.0.0:%u (mode=%s)\n",
        ssh_crypto_name(),
        (unsigned)port,
        run_terminal_mode ? "term" : "sftp");
    fflush(stdout);

    for (;;) {
        memset(&conn, 0, sizeof(conn));
        status = ssh_posix_accept(&net, &listener, &conn, 0u);
        if (status != SSH_OK) {
            fprintf(stderr, "accept failed: %s\n", ssh_status_string(status));
            continue;
        }

        if (run_terminal_mode) {
            status = ssh_server_run_terminal_session(&server, &conn, &options);
        } else {
            status = ssh_server_run_sftp_session(&server, &conn, &options);
        }
        if (status != SSH_OK) {
            fprintf(stderr, "session ended: %s\n", ssh_status_string(status));
        }
        (void)ssh_posix_conn_close(&net, &conn);
    }

cleanup:
    (void)ssh_posix_conn_close(&net, &conn);
    (void)ssh_posix_listener_close(&net, &listener);
    if (initialized_server) {
        ssh_server_deinit(&server);
    }
    if (initialized_crypto) {
        ssh_crypto_close(&crypto_ctx);
    }
    if (initialized_fs) {
        ssh_stdio_fs_deinit(&fs);
    }
    if (initialized_net) {
        ssh_posix_net_platform_deinit(&net);
    }
    if (initialized_runtime) {
        ssh_posix_runtime_deinit(&runtime);
    }
    if (initialized_term) {
        ssh_posix_term_platform_deinit(&term);
    }
    if (initialized_passwd_auth) {
        ssh_posix_passwd_auth_deinit(&passwd_auth);
    }

    return status == SSH_OK ? 0 : 1;
}
