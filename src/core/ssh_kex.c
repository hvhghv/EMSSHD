#include "emssh/ssh_kex.h"

#include <string.h>

#include "emssh/ssh_error.h"

static const char *const default_name_lists[SSH_KEXINIT_NAMELIST_COUNT] = {
    "curve25519-sha256,ecdh-sha2-nistp256",
    "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-256",
    "aes128-ctr",
    "aes128-ctr",
    "hmac-sha2-256",
    "hmac-sha2-256",
    "none",
    "none",
    "",
    ""
};

static void algorithm_set_to_array(
    const ssh_kexinit_algorithm_set_t *algorithms,
    const char *out[SSH_KEXINIT_NAMELIST_COUNT])
{
    if (algorithms == NULL) {
        memcpy(out, default_name_lists, sizeof(default_name_lists));
        return;
    }

    out[SSH_KEX_ALGORITHMS] = algorithms->kex_algorithms;
    out[SSH_SERVER_HOST_KEY_ALGORITHMS] = algorithms->server_host_key_algorithms;
    out[SSH_ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER] = algorithms->encryption_algorithms_client_to_server;
    out[SSH_ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT] = algorithms->encryption_algorithms_server_to_client;
    out[SSH_MAC_ALGORITHMS_CLIENT_TO_SERVER] = algorithms->mac_algorithms_client_to_server;
    out[SSH_MAC_ALGORITHMS_SERVER_TO_CLIENT] = algorithms->mac_algorithms_server_to_client;
    out[SSH_COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER] = algorithms->compression_algorithms_client_to_server;
    out[SSH_COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT] = algorithms->compression_algorithms_server_to_client;
    out[SSH_LANGUAGES_CLIENT_TO_SERVER] = algorithms->languages_client_to_server;
    out[SSH_LANGUAGES_SERVER_TO_CLIENT] = algorithms->languages_server_to_client;
}

static int cstring_to_name_list_view(const char *value, ssh_string_view_t *view)
{
    if (view == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (value == NULL) {
        value = "";
    }

    view->data = (const uint8_t *)value;
    view->len = strlen(value);

    return ssh_name_list_is_valid(*view) ? SSH_OK : SSH_ERR_INVALID_ARGUMENT;
}

static int select_first_match(
    ssh_string_view_t client,
    const char *server_list,
    int allow_empty,
    ssh_string_view_t *selected)
{
    ssh_string_view_t server;
    size_t start;
    size_t i;
    int status;

    if (selected == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    selected->data = NULL;
    selected->len = 0u;

    status = cstring_to_name_list_view(server_list, &server);
    if (status != SSH_OK) {
        return status;
    }

    if (!ssh_name_list_is_valid(client)) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    if (server.len == 0u || client.len == 0u) {
        return allow_empty ? SSH_OK : SSH_ERR_UNSUPPORTED;
    }

    start = 0u;
    for (i = 0u; i <= server.len; ++i) {
        if (i == server.len || server.data[i] == ',') {
            size_t item_len = i - start;
            size_t c_start = 0u;
            size_t c_i;

            for (c_i = 0u; c_i <= client.len; ++c_i) {
                if (c_i == client.len || client.data[c_i] == ',') {
                    size_t client_item_len = c_i - c_start;
                    if (item_len == client_item_len &&
                        memcmp(server.data + start, client.data + c_start, item_len) == 0) {
                        selected->data = server.data + start;
                        selected->len = item_len;
                        return SSH_OK;
                    }
                    c_start = c_i + 1u;
                }
            }

            start = i + 1u;
        }
    }

    return SSH_ERR_UNSUPPORTED;
}

static int negotiate_one(
    const ssh_kexinit_t *client,
    ssh_kexinit_name_list_index_t index,
    const char *server_list,
    int allow_empty,
    ssh_string_view_t *selected)
{
    return select_first_match(client->name_lists[index], server_list, allow_empty, selected);
}

void ssh_kexinit_algorithm_set_defaults(ssh_kexinit_algorithm_set_t *algorithms)
{
    if (algorithms == NULL) {
        return;
    }

    algorithms->kex_algorithms = default_name_lists[SSH_KEX_ALGORITHMS];
    algorithms->server_host_key_algorithms = default_name_lists[SSH_SERVER_HOST_KEY_ALGORITHMS];
    algorithms->encryption_algorithms_client_to_server = default_name_lists[SSH_ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER];
    algorithms->encryption_algorithms_server_to_client = default_name_lists[SSH_ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT];
    algorithms->mac_algorithms_client_to_server = default_name_lists[SSH_MAC_ALGORITHMS_CLIENT_TO_SERVER];
    algorithms->mac_algorithms_server_to_client = default_name_lists[SSH_MAC_ALGORITHMS_SERVER_TO_CLIENT];
    algorithms->compression_algorithms_client_to_server = default_name_lists[SSH_COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER];
    algorithms->compression_algorithms_server_to_client = default_name_lists[SSH_COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT];
    algorithms->languages_client_to_server = default_name_lists[SSH_LANGUAGES_CLIENT_TO_SERVER];
    algorithms->languages_server_to_client = default_name_lists[SSH_LANGUAGES_SERVER_TO_CLIENT];
}

int ssh_kexinit_encode(
    ssh_buffer_t *buf,
    const uint8_t cookie[SSH_KEX_COOKIE_LEN],
    const ssh_kexinit_algorithm_set_t *algorithms,
    int first_kex_packet_follows)
{
    const char *name_lists[SSH_KEXINIT_NAMELIST_COUNT];
    size_t i;
    int status;

    if (buf == NULL || cookie == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    algorithm_set_to_array(algorithms, name_lists);

    status = ssh_buffer_put_u8(buf, SSH_MSG_KEXINIT);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_bytes(buf, cookie, SSH_KEX_COOKIE_LEN);
    if (status != SSH_OK) {
        return status;
    }

    for (i = 0u; i < SSH_KEXINIT_NAMELIST_COUNT; ++i) {
        const char *list = name_lists[i] != NULL ? name_lists[i] : "";
        ssh_string_view_t view;

        view.data = (const uint8_t *)list;
        view.len = strlen(list);
        if (!ssh_name_list_is_valid(view)) {
            return SSH_ERR_INVALID_ARGUMENT;
        }

        status = ssh_buffer_put_cstring(buf, list);
        if (status != SSH_OK) {
            return status;
        }
    }

    status = ssh_buffer_put_bool(buf, first_kex_packet_follows);
    if (status != SSH_OK) {
        return status;
    }

    return ssh_buffer_put_u32(buf, 0u);
}

int ssh_kexinit_decode(ssh_buffer_t *payload, ssh_kexinit_t *kexinit)
{
    uint8_t message_id;
    size_t i;
    int status;

    if (payload == NULL || kexinit == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(kexinit, 0, sizeof(*kexinit));

    status = ssh_buffer_get_u8(payload, &message_id);
    if (status != SSH_OK) {
        return status;
    }

    if (message_id != SSH_MSG_KEXINIT) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    status = ssh_buffer_get_bytes(payload, kexinit->cookie, SSH_KEX_COOKIE_LEN);
    if (status != SSH_OK) {
        return status;
    }

    for (i = 0u; i < SSH_KEXINIT_NAMELIST_COUNT; ++i) {
        status = ssh_buffer_get_string_view(payload, &kexinit->name_lists[i]);
        if (status != SSH_OK) {
            return status;
        }

        if (!ssh_name_list_is_valid(kexinit->name_lists[i])) {
            return SSH_ERR_MALFORMED_PACKET;
        }
    }

    status = ssh_buffer_get_bool(payload, &kexinit->first_kex_packet_follows);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_get_u32(payload, &kexinit->reserved);
    if (status != SSH_OK) {
        return status;
    }

    if (kexinit->reserved != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    if (ssh_buffer_remaining_read(payload) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return SSH_OK;
}

int ssh_kex_negotiate(
    const ssh_kexinit_t *client,
    const ssh_kexinit_algorithm_set_t *server_algorithms,
    ssh_kex_negotiation_t *negotiation)
{
    ssh_kexinit_algorithm_set_t defaults;
    const ssh_kexinit_algorithm_set_t *server;
    int status;

    if (client == NULL || negotiation == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(negotiation, 0, sizeof(*negotiation));

    if (server_algorithms == NULL) {
        ssh_kexinit_algorithm_set_defaults(&defaults);
        server = &defaults;
    } else {
        server = server_algorithms;
    }

    status = negotiate_one(client, SSH_KEX_ALGORITHMS, server->kex_algorithms, 0, &negotiation->kex_algorithm);
    if (status != SSH_OK) {
        return status;
    }

    status = negotiate_one(client, SSH_SERVER_HOST_KEY_ALGORITHMS, server->server_host_key_algorithms, 0, &negotiation->server_host_key_algorithm);
    if (status != SSH_OK) {
        return status;
    }

    status = negotiate_one(client, SSH_ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER, server->encryption_algorithms_client_to_server, 0, &negotiation->encryption_algorithm_client_to_server);
    if (status != SSH_OK) {
        return status;
    }

    status = negotiate_one(client, SSH_ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT, server->encryption_algorithms_server_to_client, 0, &negotiation->encryption_algorithm_server_to_client);
    if (status != SSH_OK) {
        return status;
    }

    status = negotiate_one(client, SSH_MAC_ALGORITHMS_CLIENT_TO_SERVER, server->mac_algorithms_client_to_server, 0, &negotiation->mac_algorithm_client_to_server);
    if (status != SSH_OK) {
        return status;
    }

    status = negotiate_one(client, SSH_MAC_ALGORITHMS_SERVER_TO_CLIENT, server->mac_algorithms_server_to_client, 0, &negotiation->mac_algorithm_server_to_client);
    if (status != SSH_OK) {
        return status;
    }

    status = negotiate_one(client, SSH_COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER, server->compression_algorithms_client_to_server, 0, &negotiation->compression_algorithm_client_to_server);
    if (status != SSH_OK) {
        return status;
    }

    status = negotiate_one(client, SSH_COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT, server->compression_algorithms_server_to_client, 0, &negotiation->compression_algorithm_server_to_client);
    if (status != SSH_OK) {
        return status;
    }

    status = negotiate_one(client, SSH_LANGUAGES_CLIENT_TO_SERVER, server->languages_client_to_server, 1, &negotiation->language_client_to_server);
    if (status != SSH_OK) {
        return status;
    }

    return negotiate_one(client, SSH_LANGUAGES_SERVER_TO_CLIENT, server->languages_server_to_client, 1, &negotiation->language_server_to_client);
}

int ssh_kex_ecdh_init_encode(
    ssh_buffer_t *buf,
    const uint8_t *client_public_key,
    size_t client_public_key_len)
{
    int status;

    if (buf == NULL || (client_public_key == NULL && client_public_key_len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (client_public_key_len == 0u || client_public_key_len > EMSSH_MAX_KEX_PUBLIC_KEY) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_KEX_ECDH_INIT);
    if (status != SSH_OK) {
        return status;
    }

    return ssh_buffer_put_string(buf, client_public_key, client_public_key_len);
}

int ssh_kex_ecdh_init_decode(ssh_buffer_t *payload, ssh_kex_ecdh_init_t *init)
{
    uint8_t message_id;
    int status;

    if (payload == NULL || init == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(init, 0, sizeof(*init));

    status = ssh_buffer_get_u8(payload, &message_id);
    if (status != SSH_OK) {
        return status;
    }

    if (message_id != SSH_MSG_KEX_ECDH_INIT) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    status = ssh_buffer_get_string_view(payload, &init->client_public_key);
    if (status != SSH_OK) {
        return status;
    }

    if (init->client_public_key.len == 0u || init->client_public_key.len > EMSSH_MAX_KEX_PUBLIC_KEY) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    if (ssh_buffer_remaining_read(payload) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return SSH_OK;
}

int ssh_kex_ecdh_reply_encode(
    ssh_buffer_t *buf,
    const uint8_t *server_host_key,
    size_t server_host_key_len,
    const uint8_t *server_public_key,
    size_t server_public_key_len,
    const uint8_t *signature,
    size_t signature_len)
{
    int status;

    if (buf == NULL ||
        (server_host_key == NULL && server_host_key_len != 0u) ||
        (server_public_key == NULL && server_public_key_len != 0u) ||
        (signature == NULL && signature_len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (server_host_key_len == 0u || server_host_key_len > EMSSH_MAX_HOST_KEY_BLOB ||
        server_public_key_len == 0u || server_public_key_len > EMSSH_MAX_KEX_PUBLIC_KEY ||
        signature_len == 0u || signature_len > EMSSH_MAX_SIGNATURE) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_put_u8(buf, SSH_MSG_KEX_ECDH_REPLY);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_string(buf, server_host_key, server_host_key_len);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_string(buf, server_public_key, server_public_key_len);
    if (status != SSH_OK) {
        return status;
    }

    return ssh_buffer_put_string(buf, signature, signature_len);
}

int ssh_kex_ecdh_reply_decode(ssh_buffer_t *payload, ssh_kex_ecdh_reply_t *reply)
{
    uint8_t message_id;
    int status;

    if (payload == NULL || reply == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(reply, 0, sizeof(*reply));

    status = ssh_buffer_get_u8(payload, &message_id);
    if (status != SSH_OK) {
        return status;
    }

    if (message_id != SSH_MSG_KEX_ECDH_REPLY) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    status = ssh_buffer_get_string_view(payload, &reply->server_host_key);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_get_string_view(payload, &reply->server_public_key);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_get_string_view(payload, &reply->signature);
    if (status != SSH_OK) {
        return status;
    }

    if (reply->server_host_key.len == 0u || reply->server_host_key.len > EMSSH_MAX_HOST_KEY_BLOB ||
        reply->server_public_key.len == 0u || reply->server_public_key.len > EMSSH_MAX_KEX_PUBLIC_KEY ||
        reply->signature.len == 0u || reply->signature.len > EMSSH_MAX_SIGNATURE) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    if (ssh_buffer_remaining_read(payload) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return SSH_OK;
}

int ssh_kex_newkeys_encode(ssh_buffer_t *buf)
{
    if (buf == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    return ssh_buffer_put_u8(buf, SSH_MSG_NEWKEYS);
}

int ssh_kex_newkeys_decode(ssh_buffer_t *payload)
{
    uint8_t message_id;
    int status;

    if (payload == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_get_u8(payload, &message_id);
    if (status != SSH_OK) {
        return status;
    }

    if (message_id != SSH_MSG_NEWKEYS) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    if (ssh_buffer_remaining_read(payload) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return SSH_OK;
}
