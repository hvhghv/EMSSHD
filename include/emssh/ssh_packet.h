#ifndef EMSSH_SSH_PACKET_H
#define EMSSH_SSH_PACKET_H

#include <stddef.h>
#include <stdint.h>

#include "emssh/ssh_crypto.h"
#include "emssh/ssh_platform.h"

#define SSH_PACKET_MIN_PADDING 4u
#define SSH_PACKET_MIN_BLOCK_SIZE 8u

typedef struct ssh_packet_view {
    const uint8_t *payload;
    size_t payload_len;
} ssh_packet_view_t;

typedef struct ssh_packet_protection {
    const ssh_crypto_api_t *crypto;
    ssh_string_view_t cipher_algorithm;
    ssh_string_view_t mac_algorithm;
    uint8_t cipher_key[EMSSH_MAX_CIPHER_KEY];
    size_t cipher_key_len;
    uint8_t cipher_iv[EMSSH_MAX_CIPHER_IV];
    size_t cipher_iv_len;
    uint8_t mac_key[EMSSH_MAX_MAC_KEY];
    size_t mac_key_len;
    size_t block_size;
    size_t mac_len;
    uint32_t sequence;
    int active;
} ssh_packet_protection_t;

size_t ssh_packet_padding_len(size_t payload_len, size_t block_size);
size_t ssh_packet_encoded_len(size_t payload_len, size_t block_size);

int ssh_packet_encode_plain(
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    const uint8_t *payload,
    size_t payload_len,
    size_t block_size,
    const ssh_rng_api_t *rng);

int ssh_packet_decode_plain(
    uint8_t *packet,
    size_t packet_len,
    ssh_packet_view_t *view);

void ssh_packet_protection_init(ssh_packet_protection_t *protection);

int ssh_packet_protection_set(
    ssh_packet_protection_t *protection,
    const ssh_crypto_api_t *crypto,
    ssh_string_view_t cipher_algorithm,
    ssh_string_view_t mac_algorithm,
    const uint8_t *cipher_key,
    size_t cipher_key_len,
    const uint8_t *cipher_iv,
    size_t cipher_iv_len,
    const uint8_t *mac_key,
    size_t mac_key_len,
    size_t block_size,
    size_t mac_len);

int ssh_packet_encode_protected(
    ssh_packet_protection_t *protection,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    const uint8_t *payload,
    size_t payload_len,
    const ssh_rng_api_t *rng);

int ssh_packet_decode_protected(
    ssh_packet_protection_t *protection,
    uint8_t *packet,
    size_t packet_len,
    ssh_packet_view_t *view);

#endif
