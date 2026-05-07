#ifndef EMSSH_SSHD_CONFIG_FILE_H
#define EMSSH_SSHD_CONFIG_FILE_H

#include <stdint.h>

#include "emssh/ssh_kex.h"
#include "emssh/ssh_platform.h"
#include "emssh/ssh_server.h"

#define EMSSH_SSHD_CONFIG_VALUE_MAX 512u

typedef struct ssh_sshd_config_file {
    int has_port;
    uint16_t port;

    int has_listen_address;
    char listen_address[EMSSH_SSHD_CONFIG_VALUE_MAX];

    int has_max_auth_tries;
    unsigned max_auth_tries;

    int has_password_authentication;
    int password_authentication;

    int has_pubkey_authentication;
    int pubkey_authentication;

    int has_permit_root_login;
    int permit_root_login;

    int has_allow_users;
    char allow_users[EMSSH_SSHD_CONFIG_VALUE_MAX];

    int has_subsystem;
    char subsystem_name[EMSSH_SSHD_CONFIG_VALUE_MAX];

    int has_authorized_keys_file;
    char authorized_keys_file[EMSSH_SSHD_CONFIG_VALUE_MAX];

    int has_chroot_directory;
    char chroot_directory[EMSSH_SSHD_CONFIG_VALUE_MAX];

    int has_host_key;
    char host_key_file[EMSSH_SSHD_CONFIG_VALUE_MAX];

    int has_kex_algorithms;
    char kex_algorithms[EMSSH_SSHD_CONFIG_VALUE_MAX];

    int has_hostkey_algorithms;
    char hostkey_algorithms[EMSSH_SSHD_CONFIG_VALUE_MAX];

    int has_ciphers;
    char ciphers[EMSSH_SSHD_CONFIG_VALUE_MAX];

    int has_macs;
    char macs[EMSSH_SSHD_CONFIG_VALUE_MAX];

    int has_compression_algorithms;
    char compression_algorithms[EMSSH_SSHD_CONFIG_VALUE_MAX];
} ssh_sshd_config_file_t;

typedef struct ssh_sshd_match_context {
    const char *user;
    const char *group;
    const char *host;
    const char *address;
    const char *local_address;
    uint16_t local_port;
    const char *rdomain;
} ssh_sshd_match_context_t;

void ssh_sshd_config_file_defaults(ssh_sshd_config_file_t *config);

int ssh_sshd_config_file_load(
    const ssh_fs_api_t *fs,
    const char *path,
    ssh_sshd_config_file_t *config);

int ssh_sshd_config_file_load_with_match_context(
    const ssh_fs_api_t *fs,
    const char *path,
    const ssh_sshd_match_context_t *match_context,
    ssh_sshd_config_file_t *config);

int ssh_sshd_config_file_apply(
    const ssh_sshd_config_file_t *config,
    ssh_server_config_t *server_config,
    ssh_server_session_options_t *session_options,
    ssh_kexinit_algorithm_set_t *algorithms,
    uint16_t *port,
    const char **chroot_directory,
    const char **host_key_file);

#endif
