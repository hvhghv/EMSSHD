#include "fuzz_decode_common.h"

#include <string.h>

#include "emssh/sftp.h"
#include "emssh/ssh_error.h"
#include "emssh/ssh_packet.h"
#include "emssh/ssh_service.h"
#include "emssh/ssh_userauth.h"

static ssh_string_view_t sv(const char *value)
{
    ssh_string_view_t view;
    view.data = (const uint8_t *)value;
    view.len = strlen(value);
    return view;
}

static int fuzz_cipher_crypt(
    void *ctx,
    ssh_string_view_t cipher_algorithm,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *iv,
    size_t iv_len,
    uint32_t sequence,
    ssh_cipher_direction_t direction,
    uint8_t *data,
    size_t data_len)
{
    size_t i;

    (void)ctx;
    (void)cipher_algorithm;
    (void)iv;
    (void)iv_len;
    (void)direction;

    if (key == NULL || key_len == 0u || (data == NULL && data_len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    for (i = 0u; i < data_len; ++i) {
        data[i] ^= (uint8_t)(key[i % key_len] ^ (uint8_t)sequence);
    }

    return SSH_OK;
}

static int fuzz_mac_compute(
    void *ctx,
    ssh_string_view_t mac_algorithm,
    const uint8_t *key,
    size_t key_len,
    uint32_t sequence,
    const uint8_t *data,
    size_t data_len,
    uint8_t *mac,
    size_t mac_capacity,
    size_t *mac_len)
{
    size_t i;
    uint8_t acc;

    (void)ctx;
    (void)mac_algorithm;

    if (key == NULL || key_len == 0u || data == NULL || mac == NULL ||
        mac_len == NULL || mac_capacity < 32u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    acc = (uint8_t)sequence;
    for (i = 0u; i < data_len; ++i) {
        acc = (uint8_t)(acc + data[i] + (uint8_t)i);
    }
    for (i = 0u; i < 32u; ++i) {
        mac[i] = (uint8_t)(acc ^ key[i % key_len] ^ (uint8_t)i);
    }
    *mac_len = 32u;
    return SSH_OK;
}

static void put_u32_be(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void init_crypto(ssh_crypto_api_t *crypto)
{
    memset(crypto, 0, sizeof(*crypto));
    crypto->name = "fuzz-decode-crypto";
    crypto->cipher_crypt = fuzz_cipher_crypt;
    crypto->mac_compute = fuzz_mac_compute;
}

void emssh_fuzz_exercise_decoders(const uint8_t *data, size_t data_len)
{
    uint8_t work[256];
    uint8_t key[32];
    uint8_t iv[16];
    ssh_crypto_api_t crypto;
    ssh_packet_view_t packet_view;
    ssh_packet_protection_t protection;
    ssh_buffer_t payload;
    ssh_service_request_t service;
    ssh_userauth_request_t userauth;
    sftp_packet_t sftp_packet;
    sftp_request_t sftp_request;
    sftp_init_t sftp_init;
    sftp_path_request_t path_request;
    sftp_open_request_t open_request;
    sftp_handle_request_t handle_request;
    sftp_read_request_t read_request;
    sftp_write_request_t write_request;
    sftp_rename_request_t rename_request;
    sftp_mkdir_request_t mkdir_request;
    sftp_setstat_request_t setstat_request;
    sftp_fsetstat_request_t fsetstat_request;
    sftp_extended_request_t extended_request;
    ssh_fs_attrs_t attrs;
    ssh_string_view_t attrs_view;
    size_t i;

    if (data == NULL && data_len != 0u) {
        return;
    }
    if (data_len > sizeof(work)) {
        return;
    }

    init_crypto(&crypto);

    memcpy(work, data, data_len);
    (void)ssh_packet_decode_plain(work, data_len, &packet_view);

    for (i = 0u; i < sizeof(key); ++i) {
        key[i] = (uint8_t)(0x11u + i);
    }
    for (i = 0u; i < sizeof(iv); ++i) {
        iv[i] = (uint8_t)(0x41u + i);
    }
    ssh_packet_protection_init(&protection);
    if (ssh_packet_protection_set(
            &protection,
            &crypto,
            sv("aes128-ctr"),
            sv("hmac-sha2-256"),
            key,
            16u,
            iv,
            sizeof(iv),
            key,
            sizeof(key),
            16u,
            32u) == SSH_OK) {
        memcpy(work, data, data_len);
        (void)ssh_packet_decode_protected(&protection, work, data_len, &packet_view);
    }

    ssh_buffer_wrap(&payload, (uint8_t *)data, data_len);
    (void)ssh_service_request_decode(&payload, &service);
    ssh_buffer_wrap(&payload, (uint8_t *)data, data_len);
    (void)ssh_service_accept_decode(&payload, &service);
    ssh_buffer_wrap(&payload, (uint8_t *)data, data_len);
    (void)ssh_userauth_request_decode(&payload, &userauth);

    (void)sftp_packet_wrap(data, data_len, &sftp_packet);
    (void)sftp_request_decode(data, data_len, &sftp_request);
    (void)sftp_init_decode(data, data_len, &sftp_init);
    (void)sftp_realpath_request_decode(data, data_len, &path_request);
    (void)sftp_lstat_request_decode(data, data_len, &path_request);
    (void)sftp_stat_request_decode(data, data_len, &path_request);
    (void)sftp_opendir_request_decode(data, data_len, &path_request);
    (void)sftp_open_request_decode(data, data_len, &open_request);
    (void)sftp_close_request_decode(data, data_len, &handle_request);
    (void)sftp_fstat_request_decode(data, data_len, &handle_request);
    (void)sftp_readdir_request_decode(data, data_len, &handle_request);
    (void)sftp_read_request_decode(data, data_len, &read_request);
    (void)sftp_write_request_decode(data, data_len, &write_request);
    (void)sftp_remove_request_decode(data, data_len, &path_request);
    (void)sftp_mkdir_request_decode(data, data_len, &mkdir_request);
    (void)sftp_rmdir_request_decode(data, data_len, &path_request);
    (void)sftp_rename_request_decode(data, data_len, &rename_request);
    (void)sftp_setstat_request_decode(data, data_len, &setstat_request);
    (void)sftp_fsetstat_request_decode(data, data_len, &fsetstat_request);
    (void)sftp_extended_request_decode(data, data_len, &extended_request);

    attrs_view.data = data;
    attrs_view.len = data_len;
    (void)sftp_attrs_decode(attrs_view, &attrs);
}

void emssh_fuzz_mutate_seed(const uint8_t *seed, size_t seed_len)
{
    uint8_t mutated[256];
    size_t len;
    size_t i;
    uint8_t bit;

    if (seed == NULL && seed_len != 0u) {
        return;
    }
    if (seed_len > sizeof(mutated)) {
        return;
    }

    for (len = 0u; len <= seed_len; ++len) {
        emssh_fuzz_exercise_decoders(seed, len);
    }

    memcpy(mutated, seed, seed_len);
    for (i = 0u; i < seed_len; ++i) {
        for (bit = 0u; bit < 8u; ++bit) {
            mutated[i] ^= (uint8_t)(1u << bit);
            emssh_fuzz_exercise_decoders(mutated, seed_len);
            mutated[i] ^= (uint8_t)(1u << bit);
        }
    }

    if (seed_len >= 4u) {
        memcpy(mutated, seed, seed_len);
        put_u32_be(mutated, 0xffffffffu);
        emssh_fuzz_exercise_decoders(mutated, seed_len);
        put_u32_be(mutated, 0u);
        emssh_fuzz_exercise_decoders(mutated, seed_len);
    }
}
