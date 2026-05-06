#ifndef EMSSH_SSH_KEX_H
#define EMSSH_SSH_KEX_H

#include <stddef.h>
#include <stdint.h>

#include "emssh/ssh_buffer.h"
#include "emssh/ssh_crypto.h"

#define SSH_KEX_COOKIE_LEN 16u
#define SSH_KEXINIT_NAMELIST_COUNT 10u

#define SSH_MSG_KEXINIT 20u
#define SSH_MSG_NEWKEYS 21u
#define SSH_MSG_KEX_ECDH_INIT 30u
#define SSH_MSG_KEX_ECDH_REPLY 31u

typedef enum ssh_kexinit_name_list_index {
    SSH_KEX_ALGORITHMS = 0,
    SSH_SERVER_HOST_KEY_ALGORITHMS = 1,
    SSH_ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER = 2,
    SSH_ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT = 3,
    SSH_MAC_ALGORITHMS_CLIENT_TO_SERVER = 4,
    SSH_MAC_ALGORITHMS_SERVER_TO_CLIENT = 5,
    SSH_COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER = 6,
    SSH_COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT = 7,
    SSH_LANGUAGES_CLIENT_TO_SERVER = 8,
    SSH_LANGUAGES_SERVER_TO_CLIENT = 9
} ssh_kexinit_name_list_index_t;

typedef struct ssh_kexinit {
    uint8_t cookie[SSH_KEX_COOKIE_LEN];
    ssh_string_view_t name_lists[SSH_KEXINIT_NAMELIST_COUNT];
    int first_kex_packet_follows;
    uint32_t reserved;
} ssh_kexinit_t;

typedef struct ssh_kex_ecdh_init {
    ssh_string_view_t client_public_key;
} ssh_kex_ecdh_init_t;

typedef struct ssh_kex_ecdh_reply {
    ssh_string_view_t server_host_key;
    ssh_string_view_t server_public_key;
    ssh_string_view_t signature;
} ssh_kex_ecdh_reply_t;

typedef struct ssh_kexinit_algorithm_set {
    const char *kex_algorithms;
    const char *server_host_key_algorithms;
    const char *encryption_algorithms_client_to_server;
    const char *encryption_algorithms_server_to_client;
    const char *mac_algorithms_client_to_server;
    const char *mac_algorithms_server_to_client;
    const char *compression_algorithms_client_to_server;
    const char *compression_algorithms_server_to_client;
    const char *languages_client_to_server;
    const char *languages_server_to_client;
} ssh_kexinit_algorithm_set_t;

typedef struct ssh_kex_negotiation {
    ssh_string_view_t kex_algorithm;
    ssh_string_view_t server_host_key_algorithm;
    ssh_string_view_t encryption_algorithm_client_to_server;
    ssh_string_view_t encryption_algorithm_server_to_client;
    ssh_string_view_t mac_algorithm_client_to_server;
    ssh_string_view_t mac_algorithm_server_to_client;
    ssh_string_view_t compression_algorithm_client_to_server;
    ssh_string_view_t compression_algorithm_server_to_client;
    ssh_string_view_t language_client_to_server;
    ssh_string_view_t language_server_to_client;
} ssh_kex_negotiation_t;

void ssh_kexinit_algorithm_set_defaults(ssh_kexinit_algorithm_set_t *algorithms);

int ssh_kexinit_encode(
    ssh_buffer_t *buf,
    const uint8_t cookie[SSH_KEX_COOKIE_LEN],
    const ssh_kexinit_algorithm_set_t *algorithms,
    int first_kex_packet_follows);

int ssh_kexinit_decode(ssh_buffer_t *payload, ssh_kexinit_t *kexinit);

int ssh_kex_negotiate(
    const ssh_kexinit_t *client,
    const ssh_kexinit_algorithm_set_t *server_algorithms,
    ssh_kex_negotiation_t *negotiation);

int ssh_kex_ecdh_init_encode(
    ssh_buffer_t *buf,
    const uint8_t *client_public_key,
    size_t client_public_key_len);

int ssh_kex_ecdh_init_decode(ssh_buffer_t *payload, ssh_kex_ecdh_init_t *init);

int ssh_kex_ecdh_reply_encode(
    ssh_buffer_t *buf,
    const uint8_t *server_host_key,
    size_t server_host_key_len,
    const uint8_t *server_public_key,
    size_t server_public_key_len,
    const uint8_t *signature,
    size_t signature_len);

int ssh_kex_ecdh_reply_decode(ssh_buffer_t *payload, ssh_kex_ecdh_reply_t *reply);

int ssh_kex_newkeys_encode(ssh_buffer_t *buf);
int ssh_kex_newkeys_decode(ssh_buffer_t *payload);

#endif
