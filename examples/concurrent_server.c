#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <process.h>
#include <windows.h>
#else
#include <pthread.h>
#endif

#include "emssh/platform_stdio_fs.h"
#include "emssh/platform_tcp.h"
#include "emssh/ssh_crypto.h"
#include "emssh/ssh_error.h"
#include "emssh/ssh_server.h"

#define CONCURRENT_SERVER_MAX_TEXT 512u
#define CONCURRENT_SERVER_MAX_HOSTKEY_PRIVATE 128u

typedef struct password_auth_ctx {
    const char *username;
    const char *password;
} password_auth_ctx_t;

typedef struct worker_pool_sync {
    unsigned max_workers;
    unsigned active_workers;
#ifdef _WIN32
    CRITICAL_SECTION lock;
    CONDITION_VARIABLE cv;
#else
    pthread_mutex_t lock;
    pthread_cond_t cv;
#endif
} worker_pool_sync_t;

typedef struct worker_context {
    ssh_tcp_platform_t *tcp;
    ssh_tcp_conn_t conn;
    worker_pool_sync_t *pool;
    char root_dir[CONCURRENT_SERVER_MAX_TEXT];
    char username[CONCURRENT_SERVER_MAX_TEXT];
    char password[CONCURRENT_SERVER_MAX_TEXT];
    uint8_t hostkey_private[CONCURRENT_SERVER_MAX_HOSTKEY_PRIVATE];
    size_t hostkey_private_len;
    uint32_t timeout_ms;
} worker_context_t;

static ssh_string_view_t hostkey_algorithm_view_ecdsa(void)
{
    static const char k_alg[] = "ecdsa-sha2-nistp256";
    ssh_string_view_t view;
    view.data = (const uint8_t *)k_alg;
    view.len = sizeof(k_alg) - 1u;
    return view;
}

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

static unsigned parse_positive_unsigned(const char *text)
{
    unsigned long value;
    char *end;

    if (text == NULL || text[0] == '\0') {
        return 0u;
    }

    value = strtoul(text, &end, 10);
    if (*end != '\0' || value == 0ul || value > 1000000ul) {
        return 0u;
    }

    return (unsigned)value;
}

static void usage(const char *program)
{
    fprintf(
        stderr,
        "usage: %s <port> <root-dir> <username> <password> [hostkey-file] [--max-workers N] [--max-connections N] [--timeout-ms N] [--hostkey-algorithm ecdsa-p256]\n",
        program);
}

static int copy_text(char *dst, size_t dst_capacity, const char *src)
{
    size_t len;

    if (dst == NULL || src == NULL || dst_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    len = strlen(src);
    if (len + 1u > dst_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(dst, src, len + 1u);
    return SSH_OK;
}

static int load_file(const char *path, uint8_t *data, size_t data_capacity, size_t *data_len)
{
    FILE *file;
    size_t len;

    if (path == NULL || data == NULL || data_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        return errno == ENOENT ? SSH_ERR_NOT_FOUND : SSH_ERR_PLATFORM;
    }

    len = fread(data, 1u, data_capacity, file);
    if (ferror(file)) {
        (void)fclose(file);
        return SSH_ERR_PLATFORM;
    }
    if (!feof(file)) {
        (void)fclose(file);
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    if (fclose(file) != 0) {
        return SSH_ERR_PLATFORM;
    }

    *data_len = len;
    return len != 0u ? SSH_OK : SSH_ERR_MALFORMED_PACKET;
}

static int save_file(const char *path, const uint8_t *data, size_t data_len)
{
    FILE *file;

    if (path == NULL || data == NULL || data_len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    file = fopen(path, "wb");
    if (file == NULL) {
        return SSH_ERR_PLATFORM;
    }
    if (fwrite(data, 1u, data_len, file) != data_len) {
        (void)fclose(file);
        return SSH_ERR_PLATFORM;
    }
    return fclose(file) == 0 ? SSH_OK : SSH_ERR_PLATFORM;
}

static int configure_bootstrap_hostkey(ssh_crypto_context_t *crypto_ctx, const char *hostkey_path)
{
    const ssh_crypto_api_t *crypto;
    ssh_string_view_t hostkey_alg;
    uint8_t private_key[CONCURRENT_SERVER_MAX_HOSTKEY_PRIVATE];
    size_t private_key_len;
    int status;

    if (crypto_ctx == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    crypto = ssh_crypto_api(crypto_ctx);
    if (crypto == NULL) {
        return SSH_ERR_PLATFORM;
    }
    hostkey_alg = hostkey_algorithm_view_ecdsa();

    if (hostkey_path != NULL) {
        status = load_file(hostkey_path, private_key, sizeof(private_key), &private_key_len);
        if (status == SSH_OK) {
            if (crypto->hostkey_import_private_auto == NULL) {
                memset(private_key, 0, sizeof(private_key));
                return SSH_ERR_UNSUPPORTED;
            }
            status = crypto->hostkey_import_private_auto(
                crypto->ctx,
                hostkey_alg,
                private_key,
                private_key_len);
            memset(private_key, 0, sizeof(private_key));
            return status;
        }
        if (status != SSH_ERR_NOT_FOUND) {
            return status;
        }
    }

    if (crypto->hostkey_generate == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    status = crypto->hostkey_generate(crypto->ctx, hostkey_alg);
    if (status != SSH_OK || hostkey_path == NULL) {
        return status;
    }

    if (crypto->hostkey_export_private == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    status = crypto->hostkey_export_private(
        crypto->ctx,
        hostkey_alg,
        private_key,
        sizeof(private_key),
        &private_key_len);
    if (status == SSH_OK) {
        status = save_file(hostkey_path, private_key, private_key_len);
    }
    memset(private_key, 0, sizeof(private_key));
    return status;
}

static int password_auth(void *ctx, const ssh_password_auth_request_t *request)
{
    password_auth_ctx_t *auth = (password_auth_ctx_t *)ctx;
    size_t username_len;
    size_t password_len;

    if (auth == NULL || request == NULL || auth->username == NULL || auth->password == NULL) {
        return 0;
    }

    username_len = strlen(auth->username);
    password_len = strlen(auth->password);
    return request->username_len == username_len &&
           request->password_len == password_len &&
           memcmp(request->username, auth->username, username_len) == 0 &&
           memcmp(request->password, auth->password, password_len) == 0;
}

static int worker_pool_init(worker_pool_sync_t *pool, unsigned max_workers)
{
    if (pool == NULL || max_workers == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(pool, 0, sizeof(*pool));
    pool->max_workers = max_workers;
#ifdef _WIN32
    InitializeCriticalSection(&pool->lock);
    InitializeConditionVariable(&pool->cv);
#else
    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        return SSH_ERR_PLATFORM;
    }
    if (pthread_cond_init(&pool->cv, NULL) != 0) {
        pthread_mutex_destroy(&pool->lock);
        return SSH_ERR_PLATFORM;
    }
#endif
    return SSH_OK;
}

static void worker_pool_deinit(worker_pool_sync_t *pool)
{
    if (pool == NULL) {
        return;
    }
#ifdef _WIN32
    DeleteCriticalSection(&pool->lock);
#else
    pthread_cond_destroy(&pool->cv);
    pthread_mutex_destroy(&pool->lock);
#endif
    memset(pool, 0, sizeof(*pool));
}

static void worker_pool_reserve_slot(worker_pool_sync_t *pool)
{
#ifdef _WIN32
    EnterCriticalSection(&pool->lock);
    while (pool->active_workers >= pool->max_workers) {
        SleepConditionVariableCS(&pool->cv, &pool->lock, INFINITE);
    }
    ++pool->active_workers;
    LeaveCriticalSection(&pool->lock);
#else
    pthread_mutex_lock(&pool->lock);
    while (pool->active_workers >= pool->max_workers) {
        pthread_cond_wait(&pool->cv, &pool->lock);
    }
    ++pool->active_workers;
    pthread_mutex_unlock(&pool->lock);
#endif
}

static void worker_pool_release_slot(worker_pool_sync_t *pool)
{
    if (pool == NULL) {
        return;
    }

#ifdef _WIN32
    EnterCriticalSection(&pool->lock);
    if (pool->active_workers > 0u) {
        --pool->active_workers;
    }
    WakeAllConditionVariable(&pool->cv);
    LeaveCriticalSection(&pool->lock);
#else
    pthread_mutex_lock(&pool->lock);
    if (pool->active_workers > 0u) {
        --pool->active_workers;
    }
    pthread_cond_broadcast(&pool->cv);
    pthread_mutex_unlock(&pool->lock);
#endif
}

static void worker_pool_wait_idle(worker_pool_sync_t *pool)
{
#ifdef _WIN32
    EnterCriticalSection(&pool->lock);
    while (pool->active_workers != 0u) {
        SleepConditionVariableCS(&pool->cv, &pool->lock, INFINITE);
    }
    LeaveCriticalSection(&pool->lock);
#else
    pthread_mutex_lock(&pool->lock);
    while (pool->active_workers != 0u) {
        pthread_cond_wait(&pool->cv, &pool->lock);
    }
    pthread_mutex_unlock(&pool->lock);
#endif
}

static int run_worker_session(worker_context_t *ctx)
{
    ssh_crypto_context_t crypto_ctx;
    const ssh_crypto_api_t *crypto;
    ssh_stdio_fs_t fs;
    ssh_platform_t platform;
    ssh_server_config_t config;
    ssh_server_session_options_t options;
    ssh_server_t server;
    password_auth_ctx_t auth;
    int status;
    int initialized_crypto;
    int initialized_fs;
    int initialized_server;

    if (ctx == NULL || ctx->tcp == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(&crypto_ctx, 0, sizeof(crypto_ctx));
    memset(&fs, 0, sizeof(fs));
    memset(&platform, 0, sizeof(platform));
    memset(&server, 0, sizeof(server));
    initialized_crypto = 0;
    initialized_fs = 0;
    initialized_server = 0;

    status = ssh_crypto_open(&crypto_ctx);
    if (status != SSH_OK) {
        return status;
    }
    initialized_crypto = 1;

    crypto = ssh_crypto_api(&crypto_ctx);
    if (crypto == NULL || crypto->hostkey_import_private_auto == NULL) {
        status = SSH_ERR_UNSUPPORTED;
        goto cleanup;
    }
    status = crypto->hostkey_import_private_auto(
        crypto->ctx,
        hostkey_algorithm_view_ecdsa(),
        ctx->hostkey_private,
        ctx->hostkey_private_len);
    if (status != SSH_OK) {
        goto cleanup;
    }

    status = ssh_stdio_fs_init(&fs, ctx->root_dir);
    if (status != SSH_OK) {
        goto cleanup;
    }
    initialized_fs = 1;

    platform.net = ssh_tcp_net_api(ctx->tcp);
    platform.fs = ssh_stdio_fs_api(&fs);
    platform.crypto = ssh_crypto_api(&crypto_ctx);
    platform.rng = ssh_crypto_rng_api(&crypto_ctx);

    auth.username = ctx->username;
    auth.password = ctx->password;

    ssh_server_config_defaults(&config);
    config.password_auth = password_auth;
    config.auth_ctx = &auth;
    status = ssh_server_init(&server, &platform, &config);
    if (status != SSH_OK) {
        goto cleanup;
    }
    initialized_server = 1;

    ssh_server_session_options_defaults(&options);
    options.timeout_ms = ctx->timeout_ms;
    options.max_sftp_packets = 0u;

    status = ssh_server_run_sftp_session(&server, &ctx->conn, &options);

cleanup:
    (void)ssh_tcp_conn_close(ctx->tcp, &ctx->conn);
    if (initialized_server) {
        ssh_server_deinit(&server);
    }
    if (initialized_fs) {
        ssh_stdio_fs_deinit(&fs);
    }
    if (initialized_crypto) {
        ssh_crypto_close(&crypto_ctx);
    }
    return status;
}

#ifdef _WIN32
static unsigned __stdcall worker_thread_entry(void *arg)
#else
static void *worker_thread_entry(void *arg)
#endif
{
    worker_context_t *ctx = (worker_context_t *)arg;
    char peer_address[64];
    const char *peer;
    int status;

    peer_address[0] = '\0';
    if (ctx != NULL) {
        peer = ssh_tcp_conn_peer_address(&ctx->conn);
        if (peer != NULL) {
            (void)copy_text(peer_address, sizeof(peer_address), peer);
        }
        status = run_worker_session(ctx);
        if (status != SSH_OK) {
            fprintf(stderr, "session ended (%s): %s\n", peer_address[0] != '\0' ? peer_address : "unknown", ssh_status_string(status));
        }
        worker_pool_release_slot(ctx->pool);
        free(ctx);
    }

#ifdef _WIN32
    return 0u;
#else
    return NULL;
#endif
}

static int start_worker_thread(worker_context_t *ctx)
{
#ifdef _WIN32
    uintptr_t handle;

    handle = _beginthreadex(NULL, 0u, worker_thread_entry, ctx, 0u, NULL);
    if (handle == 0u) {
        return SSH_ERR_PLATFORM;
    }
    (void)CloseHandle((HANDLE)handle);
    return SSH_OK;
#else
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker_thread_entry, ctx) != 0) {
        return SSH_ERR_PLATFORM;
    }
    if (pthread_detach(thread) != 0) {
        return SSH_ERR_PLATFORM;
    }
    return SSH_OK;
#endif
}

int main(int argc, char **argv)
{
    uint16_t port;
    const char *hostkey_path;
    unsigned max_workers;
    unsigned max_connections;
    uint32_t timeout_ms;
    const char *hostkey_algorithm;
    unsigned accepted_count;
    int positional_argc;
    ssh_crypto_context_t bootstrap_crypto_ctx;
    const ssh_crypto_api_t *bootstrap_crypto_api;
    ssh_tcp_platform_t tcp;
    ssh_tcp_listener_t listener;
    worker_pool_sync_t pool;
    uint8_t hostkey_private[CONCURRENT_SERVER_MAX_HOSTKEY_PRIVATE];
    size_t hostkey_private_len;
    int status;
    int initialized_bootstrap_crypto;
    int initialized_tcp;
    int initialized_pool;

    max_workers = 4u;
    max_connections = 0u;
    timeout_ms = 30000u;
    hostkey_algorithm = "ecdsa-p256";

    positional_argc = argc;
    while (positional_argc >= 3) {
        if (strcmp(argv[positional_argc - 2], "--max-workers") == 0) {
            max_workers = parse_positive_unsigned(argv[positional_argc - 1]);
            if (max_workers == 0u) {
                usage(argv[0]);
                return 2;
            }
            positional_argc -= 2;
            continue;
        }
        if (strcmp(argv[positional_argc - 2], "--max-connections") == 0) {
            max_connections = parse_positive_unsigned(argv[positional_argc - 1]);
            if (max_connections == 0u) {
                usage(argv[0]);
                return 2;
            }
            positional_argc -= 2;
            continue;
        }
        if (strcmp(argv[positional_argc - 2], "--timeout-ms") == 0) {
            unsigned parsed_timeout = parse_positive_unsigned(argv[positional_argc - 1]);
            if (parsed_timeout == 0u) {
                usage(argv[0]);
                return 2;
            }
            timeout_ms = (uint32_t)parsed_timeout;
            positional_argc -= 2;
            continue;
        }
        if (strcmp(argv[positional_argc - 2], "--hostkey-algorithm") == 0) {
            hostkey_algorithm = argv[positional_argc - 1];
            if (strcmp(hostkey_algorithm, "ecdsa-p256") != 0 &&
                strcmp(hostkey_algorithm, "ecdsa-sha2-nistp256") != 0) {
                usage(argv[0]);
                return 2;
            }
            positional_argc -= 2;
            continue;
        }
        break;
    }

    if (positional_argc < 5 || positional_argc > 6) {
        usage(argv[0]);
        return 2;
    }

    port = parse_port(argv[1]);
    if (port == 0u) {
        usage(argv[0]);
        return 2;
    }
    hostkey_path = positional_argc >= 6 ? argv[5] : NULL;

    memset(&bootstrap_crypto_ctx, 0, sizeof(bootstrap_crypto_ctx));
    memset(&tcp, 0, sizeof(tcp));
    memset(&listener, 0, sizeof(listener));
    memset(&pool, 0, sizeof(pool));
    memset(hostkey_private, 0, sizeof(hostkey_private));
    hostkey_private_len = 0u;
    initialized_bootstrap_crypto = 0;
    initialized_tcp = 0;
    initialized_pool = 0;

    status = ssh_crypto_open(&bootstrap_crypto_ctx);
    if (status != SSH_OK) {
        fprintf(stderr, "bootstrap crypto init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_bootstrap_crypto = 1;

    status = configure_bootstrap_hostkey(&bootstrap_crypto_ctx, hostkey_path);
    if (status != SSH_OK) {
        fprintf(stderr, "hostkey setup failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }

    bootstrap_crypto_api = ssh_crypto_api(&bootstrap_crypto_ctx);
    if (bootstrap_crypto_api == NULL || bootstrap_crypto_api->hostkey_export_private == NULL) {
        status = SSH_ERR_UNSUPPORTED;
        fprintf(stderr, "hostkey export failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    status = bootstrap_crypto_api->hostkey_export_private(
        bootstrap_crypto_api->ctx,
        hostkey_algorithm_view_ecdsa(),
        hostkey_private,
        sizeof(hostkey_private),
        &hostkey_private_len);
    if (status != SSH_OK) {
        fprintf(stderr, "hostkey export failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    ssh_crypto_close(&bootstrap_crypto_ctx);
    initialized_bootstrap_crypto = 0;

    status = ssh_tcp_platform_init(&tcp);
    if (status != SSH_OK) {
        fprintf(stderr, "tcp init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_tcp = 1;

    status = ssh_tcp_listen(&tcp, NULL, port, (int)max_workers, &listener);
    if (status != SSH_OK) {
        fprintf(stderr, "listen failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }

    status = worker_pool_init(&pool, max_workers);
    if (status != SSH_OK) {
        fprintf(stderr, "worker pool init failed: %s\n", ssh_status_string(status));
        goto cleanup;
    }
    initialized_pool = 1;

    printf(
        "concurrent server listening on 0.0.0.0:%u, root=%s, user=%s, max_workers=%u, max_connections=%u (0 means unlimited)\n",
        (unsigned)port,
        argv[2],
        argv[3],
        max_workers,
        max_connections);
    fflush(stdout);

    status = SSH_OK;
    accepted_count = 0u;
    while (max_connections == 0u || accepted_count < max_connections) {
        worker_context_t *ctx;

        worker_pool_reserve_slot(&pool);

        ctx = (worker_context_t *)calloc(1u, sizeof(*ctx));
        if (ctx == NULL) {
            worker_pool_release_slot(&pool);
            status = SSH_ERR_PLATFORM;
            break;
        }

        status = ssh_tcp_accept(&tcp, &listener, &ctx->conn, 0u);
        if (status != SSH_OK) {
            free(ctx);
            worker_pool_release_slot(&pool);
            fprintf(stderr, "accept failed: %s\n", ssh_status_string(status));
            break;
        }

        ctx->tcp = &tcp;
        ctx->pool = &pool;
        ctx->hostkey_private_len = hostkey_private_len;
        ctx->timeout_ms = timeout_ms;
        memcpy(ctx->hostkey_private, hostkey_private, hostkey_private_len);
        if (copy_text(ctx->root_dir, sizeof(ctx->root_dir), argv[2]) != SSH_OK ||
            copy_text(ctx->username, sizeof(ctx->username), argv[3]) != SSH_OK ||
            copy_text(ctx->password, sizeof(ctx->password), argv[4]) != SSH_OK) {
            (void)ssh_tcp_conn_close(&tcp, &ctx->conn);
            free(ctx);
            worker_pool_release_slot(&pool);
            status = SSH_ERR_BUFFER_TOO_SMALL;
            break;
        }

        status = start_worker_thread(ctx);
        if (status != SSH_OK) {
            (void)ssh_tcp_conn_close(&tcp, &ctx->conn);
            free(ctx);
            worker_pool_release_slot(&pool);
            fprintf(stderr, "failed to start worker thread\n");
            break;
        }

        ++accepted_count;
    }

cleanup:
    (void)ssh_tcp_listener_close(&tcp, &listener);
    if (initialized_pool) {
        worker_pool_wait_idle(&pool);
        worker_pool_deinit(&pool);
    }
    if (initialized_tcp) {
        ssh_tcp_platform_deinit(&tcp);
    }
    if (initialized_bootstrap_crypto) {
        ssh_crypto_close(&bootstrap_crypto_ctx);
    }
    memset(hostkey_private, 0, sizeof(hostkey_private));

    return status == SSH_OK ? 0 : 1;
}
