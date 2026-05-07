#include <stdio.h>
#include <string.h>

#include "emssh/sshd_config_file.h"
#include "emssh/ssh_error.h"
#include "emssh/ssh_server.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

typedef struct mock_file_ctx {
    const char *text;
    size_t text_len;
    size_t offset;
    int opened;
} mock_file_ctx_t;

static int mock_open(void *ctx, const char *path, uint32_t flags, void **handle)
{
    mock_file_ctx_t *mock = (mock_file_ctx_t *)ctx;
    (void)flags;
    if (mock == NULL || handle == NULL || path == NULL || strcmp(path, "/etc/ssh/sshd_config") != 0) {
        return SSH_ERR_NOT_FOUND;
    }
    mock->offset = 0u;
    mock->opened = 1;
    *handle = mock;
    return SSH_OK;
}

static int mock_close(void *ctx, void *handle)
{
    mock_file_ctx_t *mock = (mock_file_ctx_t *)ctx;
    if (mock == NULL || handle != mock || !mock->opened) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    mock->opened = 0;
    return SSH_OK;
}

static int mock_read(void *ctx, void *handle, uint8_t *buf, size_t len, size_t *read_len)
{
    mock_file_ctx_t *mock = (mock_file_ctx_t *)ctx;
    size_t remain;
    size_t to_copy;

    if (mock == NULL || handle != mock || !mock->opened || buf == NULL || read_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    remain = mock->text_len - mock->offset;
    if (remain == 0u) {
        *read_len = 0u;
        return SSH_OK;
    }

    to_copy = len < remain ? len : remain;
    memcpy(buf, mock->text + mock->offset, to_copy);
    mock->offset += to_copy;
    *read_len = to_copy;
    return SSH_OK;
}

int main(void)
{
    const char *config_text =
        "# sample sshd_config\n"
        "ListenAddress 127.0.0.1\n"
        "Port 2222\n"
        "MaxAuthTries 5\n"
        "PasswordAuthentication yes\n"
        "PubkeyAuthentication no\n"
        "PermitRootLogin prohibit-password\n"
        "AllowUsers alice bob\n"
        "ChrootDirectory /mnt/host\n"
        "Subsystem sftp /usr/lib/openssh/sftp-server\n"
        "AuthorizedKeysFile .ssh/authorized_keys\n"
        "HostKey /etc/emssh/hostkey.p256.raw\n"
        "KexAlgorithms curve25519-sha256\n"
        "HostKeyAlgorithms ecdsa-sha2-nistp256\n"
        "Ciphers aes128-ctr\n"
        "MACs hmac-sha2-256\n"
        "Compression no\n";
    const char *config_text_with_bracket_port =
        "ListenAddress [::1]:2200\n"
        "PermitRootLogin no\n";
    const char *config_text_compression_yes =
        "Compression yes\n";
    const char *config_text_match_blocks =
        "Port 2201\n"
        "Match User root\n"
        "Port 2202\n"
        "MaxAuthTries 9\n"
        "Match all\n"
        "ListenAddress 127.0.0.2\n"
        "MaxAuthTries 6\n";
    const char *config_text_match_full =
        "Port 2200\n"
        "Match User root Address 192.168.* LocalPort 2200\n"
        "MaxAuthTries 10\n"
        "PermitRootLogin no\n"
        "Match User !root\n"
        "MaxAuthTries 3\n";
    mock_file_ctx_t mock;
    ssh_fs_api_t fs;
    ssh_sshd_config_file_t parsed;
    ssh_server_config_t server_config;
    ssh_server_session_options_t session_options;
    ssh_kexinit_algorithm_set_t algorithms;
    const char *chroot_directory;
    const char *hostkey_file;
    uint16_t port;
    ssh_sshd_match_context_t match_ctx;

    memset(&mock, 0, sizeof(mock));
    mock.text = config_text;
    mock.text_len = strlen(config_text);

    memset(&fs, 0, sizeof(fs));
    fs.open = mock_open;
    fs.close = mock_close;
    fs.read = mock_read;
    fs.ctx = &mock;

    ssh_sshd_config_file_defaults(&parsed);
    CHECK(ssh_sshd_config_file_load(&fs, "/etc/ssh/sshd_config", &parsed) == SSH_OK);
    CHECK(parsed.has_port && parsed.port == 2222u);
    CHECK(parsed.has_listen_address);
    CHECK(strcmp(parsed.listen_address, "127.0.0.1") == 0);
    CHECK(parsed.has_max_auth_tries && parsed.max_auth_tries == 5u);
    CHECK(parsed.has_password_authentication && parsed.password_authentication == 1);
    CHECK(parsed.has_pubkey_authentication && parsed.pubkey_authentication == 0);
    CHECK(parsed.has_permit_root_login && parsed.permit_root_login == EMSSH_PERMIT_ROOT_LOGIN_PROHIBIT_PASSWORD);
    CHECK(parsed.has_allow_users);
    CHECK(strcmp(parsed.allow_users, "alice bob") == 0);
    CHECK(parsed.has_chroot_directory);
    CHECK(strcmp(parsed.chroot_directory, "/mnt/host") == 0);
    CHECK(parsed.has_subsystem);
    CHECK(strcmp(parsed.subsystem_name, "sftp") == 0);
    CHECK(parsed.has_authorized_keys_file);
    CHECK(strcmp(parsed.authorized_keys_file, ".ssh/authorized_keys") == 0);
    CHECK(parsed.has_host_key);
    CHECK(strcmp(parsed.host_key_file, "/etc/emssh/hostkey.p256.raw") == 0);
    CHECK(parsed.has_kex_algorithms);
    CHECK(strcmp(parsed.kex_algorithms, "curve25519-sha256") == 0);
    CHECK(parsed.has_hostkey_algorithms);
    CHECK(strcmp(parsed.hostkey_algorithms, "ecdsa-sha2-nistp256") == 0);
    CHECK(parsed.has_ciphers);
    CHECK(strcmp(parsed.ciphers, "aes128-ctr") == 0);
    CHECK(parsed.has_macs);
    CHECK(strcmp(parsed.macs, "hmac-sha2-256") == 0);
    CHECK(parsed.has_compression_algorithms);
    CHECK(strcmp(parsed.compression_algorithms, "none") == 0);

    ssh_server_config_defaults(&server_config);
    ssh_server_session_options_defaults(&session_options);
    ssh_kexinit_algorithm_set_defaults(&algorithms);
    server_config.password_auth = (ssh_password_auth_fn)1;
    server_config.publickey_auth = (ssh_publickey_auth_fn)1;
    chroot_directory = NULL;
    hostkey_file = NULL;
    port = 22u;

    CHECK(ssh_sshd_config_file_apply(
        &parsed,
        &server_config,
        &session_options,
        &algorithms,
        &port,
        &chroot_directory,
        &hostkey_file) == SSH_OK);
    CHECK(port == 2222u);
    CHECK(chroot_directory != NULL);
    CHECK(strcmp(chroot_directory, "/mnt/host") == 0);
    CHECK(hostkey_file != NULL);
    CHECK(strcmp(hostkey_file, "/etc/emssh/hostkey.p256.raw") == 0);
    CHECK(server_config.listen_address != NULL);
    CHECK(strcmp(server_config.listen_address, "127.0.0.1") == 0);
    CHECK(server_config.max_auth_tries == 5u);
    CHECK(server_config.password_auth != NULL);
    CHECK(server_config.publickey_auth == NULL);
    CHECK(server_config.permit_root_login == EMSSH_PERMIT_ROOT_LOGIN_PROHIBIT_PASSWORD);
    CHECK(server_config.allow_users != NULL);
    CHECK(strcmp(server_config.allow_users, "alice bob") == 0);
    CHECK(server_config.authorized_keys_file != NULL);
    CHECK(strcmp(server_config.authorized_keys_file, ".ssh/authorized_keys") == 0);
    CHECK(session_options.sftp_subsystem_name != NULL);
    CHECK(strcmp(session_options.sftp_subsystem_name, "sftp") == 0);
    CHECK(strcmp(algorithms.kex_algorithms, "curve25519-sha256") == 0);
    CHECK(strcmp(algorithms.server_host_key_algorithms, "ecdsa-sha2-nistp256") == 0);
    CHECK(strcmp(algorithms.encryption_algorithms_client_to_server, "aes128-ctr") == 0);
    CHECK(strcmp(algorithms.mac_algorithms_client_to_server, "hmac-sha2-256") == 0);
    CHECK(strcmp(algorithms.compression_algorithms_client_to_server, "none") == 0);

    mock.text = config_text_with_bracket_port;
    mock.text_len = strlen(config_text_with_bracket_port);
    ssh_sshd_config_file_defaults(&parsed);
    CHECK(ssh_sshd_config_file_load(&fs, "/etc/ssh/sshd_config", &parsed) == SSH_OK);
    CHECK(parsed.has_listen_address);
    CHECK(strcmp(parsed.listen_address, "::1") == 0);
    CHECK(parsed.has_port && parsed.port == 2200u);
    CHECK(parsed.has_permit_root_login);
    CHECK(parsed.permit_root_login == EMSSH_PERMIT_ROOT_LOGIN_NO);

    mock.text = config_text_compression_yes;
    mock.text_len = strlen(config_text_compression_yes);
    ssh_sshd_config_file_defaults(&parsed);
    CHECK(ssh_sshd_config_file_load(&fs, "/etc/ssh/sshd_config", &parsed) == SSH_ERR_UNSUPPORTED);

    mock.text = config_text_match_blocks;
    mock.text_len = strlen(config_text_match_blocks);
    ssh_sshd_config_file_defaults(&parsed);
    CHECK(ssh_sshd_config_file_load(&fs, "/etc/ssh/sshd_config", &parsed) == SSH_OK);
    CHECK(parsed.has_port && parsed.port == 2201u);
    CHECK(parsed.has_listen_address);
    CHECK(strcmp(parsed.listen_address, "127.0.0.2") == 0);
    CHECK(parsed.has_max_auth_tries && parsed.max_auth_tries == 6u);

    mock.text = config_text_match_full;
    mock.text_len = strlen(config_text_match_full);
    memset(&match_ctx, 0, sizeof(match_ctx));
    match_ctx.user = "root";
    match_ctx.address = "192.168.1.88";
    match_ctx.local_port = 2200u;
    ssh_sshd_config_file_defaults(&parsed);
    CHECK(ssh_sshd_config_file_load_with_match_context(&fs, "/etc/ssh/sshd_config", &match_ctx, &parsed) == SSH_OK);
    CHECK(parsed.has_port && parsed.port == 2200u);
    CHECK(parsed.has_max_auth_tries && parsed.max_auth_tries == 10u);
    CHECK(parsed.has_permit_root_login && parsed.permit_root_login == EMSSH_PERMIT_ROOT_LOGIN_NO);

    memset(&match_ctx, 0, sizeof(match_ctx));
    match_ctx.user = "alice";
    match_ctx.address = "192.168.1.88";
    match_ctx.local_port = 2200u;
    ssh_sshd_config_file_defaults(&parsed);
    CHECK(ssh_sshd_config_file_load_with_match_context(&fs, "/etc/ssh/sshd_config", &match_ctx, &parsed) == SSH_OK);
    CHECK(parsed.has_port && parsed.port == 2200u);
    CHECK(parsed.has_max_auth_tries && parsed.max_auth_tries == 3u);

    return 0;
}
