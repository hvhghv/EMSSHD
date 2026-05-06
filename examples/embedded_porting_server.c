#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "emssh/crypto_mbedtls.h"
#include "emssh/platform_fatfs_adapter.h"
#include "emssh/platform_freertos.h"
#include "emssh/platform_littlefs_adapter.h"
#include "emssh/platform_lwip.h"
#include "emssh/platform_openssl.h"
#include "emssh/ssh_error.h"
#include "emssh/ssh_server.h"

#ifndef EMSSH_TEMPLATE_LISTEN_PORT
#define EMSSH_TEMPLATE_LISTEN_PORT 2222u
#endif

#ifndef EMSSH_TEMPLATE_LISTEN_BACKLOG
#define EMSSH_TEMPLATE_LISTEN_BACKLOG 2
#endif

#ifndef EMSSH_TEMPLATE_SESSION_TIMEOUT_MS
#define EMSSH_TEMPLATE_SESSION_TIMEOUT_MS 30000u
#endif

#ifndef EMSSH_TEMPLATE_MAX_SFTP_PACKETS
#define EMSSH_TEMPLATE_MAX_SFTP_PACKETS 0u
#endif

#ifndef EMSSH_TEMPLATE_USERNAME
#define EMSSH_TEMPLATE_USERNAME "admin"
#endif

#ifndef EMSSH_TEMPLATE_PASSWORD
#define EMSSH_TEMPLATE_PASSWORD "admin123"
#endif

#ifndef EMSSH_TEMPLATE_USE_OPENSSL
#define EMSSH_TEMPLATE_USE_OPENSSL 0
#endif

#ifndef EMSSH_TEMPLATE_FS_BACKEND_LITTLEFS
#define EMSSH_TEMPLATE_FS_BACKEND_LITTLEFS 1
#endif

#define EMSSH_TEMPLATE_HOSTKEY_PRIVATE_MAX 128u

typedef struct embedded_auth_ctx {
    const char *username;
    const char *password;
} embedded_auth_ctx_t;

static void board_log_sink(void *ctx, ssh_log_level_t level, const char *message)
{
    (void)ctx;
    (void)level;
    (void)message;
    /* TODO: redirect to UART/RTT/syslog on your board. */
}

static int board_network_ready(void)
{
    /* TODO: block until lwIP link up + IP ready (DHCP/static). */
    return SSH_OK;
}

static int board_load_hostkey_private(uint8_t *buf, size_t capacity, size_t *out_len)
{
    (void)buf;
    (void)capacity;
    (void)out_len;
    /* TODO: load hostkey from Flash/OTP/secure element. */
    return SSH_ERR_NOT_FOUND;
}

static int board_store_hostkey_private(const uint8_t *buf, size_t len)
{
    (void)buf;
    (void)len;
    /* TODO: persist hostkey when first generated. */
    return SSH_OK;
}

#if EMSSH_TEMPLATE_FS_BACKEND_LITTLEFS
static lfs_t *board_littlefs_instance(void)
{
    /* TODO: return mounted littlefs instance pointer. */
    return NULL;
}
#else
static const char *board_fatfs_prefix(void)
{
    /* TODO: return mounted FatFS prefix, e.g. "0:" or "1:". */
    return "0:";
}
#endif

static int string_view_matches(const char *expected, const char *actual, size_t actual_len)
{
    size_t expected_len;

    if (expected == NULL || actual == NULL) {
        return 0;
    }

    expected_len = strlen(expected);
    return expected_len == actual_len && memcmp(expected, actual, actual_len) == 0;
}

static int template_password_auth(void *ctx, const ssh_password_auth_request_t *request)
{
    embedded_auth_ctx_t *auth = (embedded_auth_ctx_t *)ctx;

    if (auth == NULL || request == NULL) {
        return 0;
    }

    return string_view_matches(auth->username, request->username, request->username_len) &&
           string_view_matches(auth->password, request->password, request->password_len);
}

static int configure_mbedtls_hostkey(ssh_mbedtls_crypto_t *crypto)
{
    uint8_t private_key[EMSSH_TEMPLATE_HOSTKEY_PRIVATE_MAX];
    size_t private_key_len;
    int status;

    if (crypto == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(private_key, 0, sizeof(private_key));
    private_key_len = 0u;
    status = board_load_hostkey_private(private_key, sizeof(private_key), &private_key_len);
    if (status == SSH_OK) {
        status = ssh_mbedtls_crypto_import_ecdsa_p256_hostkey(crypto, private_key, private_key_len);
        memset(private_key, 0, sizeof(private_key));
        return status;
    }
    if (status != SSH_ERR_NOT_FOUND) {
        memset(private_key, 0, sizeof(private_key));
        return status;
    }

    status = ssh_mbedtls_crypto_generate_ecdsa_p256_hostkey(crypto);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_mbedtls_crypto_export_hostkey_private(
        crypto,
        private_key,
        sizeof(private_key),
        &private_key_len);
    if (status == SSH_OK) {
        status = board_store_hostkey_private(private_key, private_key_len);
    }
    memset(private_key, 0, sizeof(private_key));
    return status;
}

int main(void)
{
    ssh_freertos_runtime_t runtime;
    ssh_lwip_platform_t net;
    ssh_lwip_listener_t listener;
    ssh_lwip_conn_t conn;
    ssh_server_t server;
    ssh_server_config_t config;
    ssh_server_session_options_t options;
    ssh_kexinit_algorithm_set_t algorithms;
    embedded_auth_ctx_t auth;
    int status;
    int initialized_runtime;
    int initialized_net;
    int initialized_fs;
    int initialized_crypto;
    int initialized_server;
#if EMSSH_TEMPLATE_FS_BACKEND_LITTLEFS
    ssh_littlefs_adapter_t lfs_adapter;
    lfs_t *lfs;
#else
    ssh_fatfs_adapter_t fatfs_adapter;
#endif
#if EMSSH_TEMPLATE_USE_OPENSSL
    ssh_openssl_platform_t openssl_platform;
    const ssh_platform_t *platform_api;
#else
    ssh_mbedtls_crypto_t mbedtls_crypto;
    ssh_platform_t platform;
#endif
    const ssh_fs_api_t *fs_api;

    memset(&runtime, 0, sizeof(runtime));
    memset(&net, 0, sizeof(net));
    memset(&listener, 0, sizeof(listener));
    memset(&conn, 0, sizeof(conn));
    memset(&server, 0, sizeof(server));
    memset(&algorithms, 0, sizeof(algorithms));
    memset(&auth, 0, sizeof(auth));
    fs_api = NULL;
    initialized_runtime = 0;
    initialized_net = 0;
    initialized_fs = 0;
    initialized_crypto = 0;
    initialized_server = 0;

#if EMSSH_TEMPLATE_FS_BACKEND_LITTLEFS
    memset(&lfs_adapter, 0, sizeof(lfs_adapter));
#else
    memset(&fatfs_adapter, 0, sizeof(fatfs_adapter));
#endif
#if EMSSH_TEMPLATE_USE_OPENSSL
    memset(&openssl_platform, 0, sizeof(openssl_platform));
    platform_api = NULL;
#else
    memset(&mbedtls_crypto, 0, sizeof(mbedtls_crypto));
    memset(&platform, 0, sizeof(platform));
#endif

    status = board_network_ready();
    if (status != SSH_OK) {
        printf("network not ready: %s\n", ssh_status_string(status));
        goto cleanup;
    }

    status = ssh_freertos_runtime_init(&runtime, board_log_sink, NULL);
    if (status != SSH_OK) {
        printf("runtime init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_runtime = 1;

    status = ssh_lwip_platform_init(&net);
    if (status != SSH_OK) {
        printf("lwip net init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_net = 1;

#if EMSSH_TEMPLATE_FS_BACKEND_LITTLEFS
    lfs = board_littlefs_instance();
    if (lfs == NULL) {
        status = SSH_ERR_INVALID_ARGUMENT;
        printf("littlefs instance is null\n");
        goto cleanup;
    }
    status = ssh_littlefs_adapter_init(&lfs_adapter, lfs);
    if (status != SSH_OK) {
        printf("littlefs adapter init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    fs_api = ssh_littlefs_adapter_api(&lfs_adapter);
#else
    status = ssh_fatfs_adapter_init(&fatfs_adapter, board_fatfs_prefix());
    if (status != SSH_OK) {
        printf("fatfs adapter init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    fs_api = ssh_fatfs_adapter_api(&fatfs_adapter);
#endif
    if (fs_api == NULL) {
        status = SSH_ERR_PLATFORM;
        goto cleanup;
    }
    initialized_fs = 1;

#if EMSSH_TEMPLATE_USE_OPENSSL
    status = ssh_openssl_platform_init(
        &openssl_platform,
        ssh_lwip_net_api(&net),
        fs_api,
        NULL,
        ssh_freertos_mem_api(&runtime),
        ssh_freertos_time_api(&runtime),
        ssh_freertos_log_api(&runtime));
    if (status != SSH_OK) {
        printf("openssl platform init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    platform_api = ssh_openssl_platform_api(&openssl_platform);
    initialized_crypto = 1;
#else
    status = ssh_mbedtls_crypto_init(&mbedtls_crypto);
    if (status != SSH_OK) {
        printf("mbedtls crypto init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_crypto = 1;

    status = configure_mbedtls_hostkey(&mbedtls_crypto);
    if (status != SSH_OK) {
        printf("hostkey setup failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }

    platform.mem = ssh_freertos_mem_api(&runtime);
    platform.time = ssh_freertos_time_api(&runtime);
    platform.log = ssh_freertos_log_api(&runtime);
    platform.net = ssh_lwip_net_api(&net);
    platform.fs = fs_api;
    platform.crypto = ssh_mbedtls_crypto_api(&mbedtls_crypto);
    platform.rng = ssh_mbedtls_rng_api(&mbedtls_crypto);
#endif

    auth.username = EMSSH_TEMPLATE_USERNAME;
    auth.password = EMSSH_TEMPLATE_PASSWORD;

    ssh_server_config_defaults(&config);
    config.password_auth = template_password_auth;
    config.auth_ctx = &auth;

    status = ssh_server_init(
        &server,
#if EMSSH_TEMPLATE_USE_OPENSSL
        platform_api,
#else
        &platform,
#endif
        &config);
    if (status != SSH_OK) {
        printf("server init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_server = 1;

    status = ssh_lwip_listen(&net, NULL, EMSSH_TEMPLATE_LISTEN_PORT, EMSSH_TEMPLATE_LISTEN_BACKLOG, &listener);
    if (status != SSH_OK) {
        printf("listen failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }

    ssh_server_session_options_defaults(&options);
#if EMSSH_TEMPLATE_USE_OPENSSL
    ssh_openssl_kexinit_algorithm_set_defaults(&algorithms);
#else
    ssh_mbedtls_kexinit_algorithm_set_defaults(&algorithms);
#endif
    options.algorithms = &algorithms;
    options.timeout_ms = EMSSH_TEMPLATE_SESSION_TIMEOUT_MS;
    options.max_sftp_packets = EMSSH_TEMPLATE_MAX_SFTP_PACKETS;

    printf("embedded template server listening on port %u\n", (unsigned)EMSSH_TEMPLATE_LISTEN_PORT);
    fflush(stdout);

    for (;;) {
        memset(&conn, 0, sizeof(conn));
        status = ssh_lwip_accept(&net, &listener, &conn, 0u);
        if (status != SSH_OK) {
            printf("accept failed: %s\n", ssh_status_string(status));
            continue;
        }

        status = ssh_server_run_sftp_session(&server, &conn, &options);
        if (status != SSH_OK) {
            printf("session ended: %s\n", ssh_status_string(status));
        }
        (void)ssh_lwip_conn_close(&net, &conn);
    }

cleanup:
    (void)ssh_lwip_conn_close(&net, &conn);
    (void)ssh_lwip_listener_close(&net, &listener);
    if (initialized_server) {
        ssh_server_deinit(&server);
    }
    if (initialized_crypto) {
#if EMSSH_TEMPLATE_USE_OPENSSL
        ssh_openssl_platform_deinit(&openssl_platform);
#else
        ssh_mbedtls_crypto_free(&mbedtls_crypto);
#endif
    }
    if (initialized_fs) {
#if EMSSH_TEMPLATE_FS_BACKEND_LITTLEFS
        ssh_littlefs_adapter_deinit(&lfs_adapter);
#else
        ssh_fatfs_adapter_deinit(&fatfs_adapter);
#endif
    }
    if (initialized_net) {
        ssh_lwip_platform_deinit(&net);
    }
    if (initialized_runtime) {
        ssh_freertos_runtime_deinit(&runtime);
    }

    return status == SSH_OK ? 0 : 1;
}
