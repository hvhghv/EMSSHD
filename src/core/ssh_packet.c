#include "emssh/ssh_packet.h"

#include <string.h>

#include "emssh/ssh_buffer.h"
#include "emssh/ssh_config.h"
#include "emssh/ssh_error.h"

static size_t normalized_block_size(size_t block_size)
{
    return block_size < SSH_PACKET_MIN_BLOCK_SIZE ? SSH_PACKET_MIN_BLOCK_SIZE : block_size;
}

size_t ssh_packet_padding_len(size_t payload_len, size_t block_size)
{
    size_t padding_len;
    size_t total_without_padding;

    block_size = normalized_block_size(block_size);
    total_without_padding = 4u + 1u + payload_len;
    padding_len = block_size - (total_without_padding % block_size);
    if (padding_len == block_size) {
        padding_len = 0u;
    }

    while (padding_len < SSH_PACKET_MIN_PADDING) {
        padding_len += block_size;
    }

    return padding_len;
}

size_t ssh_packet_encoded_len(size_t payload_len, size_t block_size)
{
    return 4u + 1u + payload_len + ssh_packet_padding_len(payload_len, block_size);
}

int ssh_packet_encode_plain(
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    const uint8_t *payload,
    size_t payload_len,
    size_t block_size,
    const ssh_rng_api_t *rng)
{
    ssh_buffer_t writer;
    size_t padding_len;
    size_t encoded_len;
    uint32_t packet_length;
    int status;

    if (out == NULL || out_len == NULL || (payload == NULL && payload_len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (payload_len > EMSSH_MAX_PAYLOAD_SIZE) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    padding_len = ssh_packet_padding_len(payload_len, block_size);
    encoded_len = 4u + 1u + payload_len + padding_len;
    if (encoded_len > out_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    packet_length = (uint32_t)(1u + payload_len + padding_len);
    ssh_buffer_init(&writer, out, out_capacity);

    status = ssh_buffer_put_u32(&writer, packet_length);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_u8(&writer, (uint8_t)padding_len);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_buffer_put_bytes(&writer, payload, payload_len);
    if (status != SSH_OK) {
        return status;
    }

    if (padding_len != 0u) {
        uint8_t *padding = out + writer.len;
        if (rng != NULL && rng->fill != NULL) {
            status = rng->fill(rng->ctx, padding, padding_len);
            if (status != SSH_OK) {
                return SSH_ERR_PLATFORM;
            }
        } else {
            memset(padding, 0, padding_len);
        }
        writer.len += padding_len;
    }

    *out_len = writer.len;
    return SSH_OK;
}

int ssh_packet_decode_plain(
    uint8_t *packet,
    size_t packet_len,
    ssh_packet_view_t *view)
{
    ssh_buffer_t reader;
    uint32_t packet_length;
    uint8_t padding_len;
    int status;

    if (packet == NULL || view == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (packet_len < 4u + 1u + SSH_PACKET_MIN_PADDING) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    if (packet_len > EMSSH_MAX_PACKET_SIZE + 4u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    ssh_buffer_wrap(&reader, packet, packet_len);
    status = ssh_buffer_get_u32(&reader, &packet_length);
    if (status != SSH_OK) {
        return status;
    }

    if ((size_t)packet_length + 4u != packet_len) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    status = ssh_buffer_get_u8(&reader, &padding_len);
    if (status != SSH_OK) {
        return status;
    }

    if (padding_len < SSH_PACKET_MIN_PADDING) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    if ((size_t)padding_len + 1u > (size_t)packet_length) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    view->payload = packet + 5u;
    view->payload_len = (size_t)packet_length - 1u - (size_t)padding_len;
    return SSH_OK;
}

static int mac_matches(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff;
    size_t i;

    diff = 0u;
    for (i = 0u; i < len; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }

    return diff == 0u;
}

static void advance_counter_be(uint8_t *counter, size_t counter_len, size_t blocks)
{
    size_t i;

    if (counter == NULL || counter_len == 0u) {
        return;
    }

    while (blocks-- != 0u) {
        for (i = counter_len; i > 0u; --i) {
            ++counter[i - 1u];
            if (counter[i - 1u] != 0u) {
                break;
            }
        }
    }
}

static void advance_stream_position(ssh_packet_protection_t *protection, size_t data_len)
{
    size_t block_len;
    size_t blocks;

    if (protection == NULL || protection->cipher_iv_len == 0u || data_len == 0u) {
        return;
    }

    block_len = protection->cipher_iv_len;
    blocks = (data_len + block_len - 1u) / block_len;
    advance_counter_be(protection->cipher_iv, protection->cipher_iv_len, blocks);
}

void ssh_packet_protection_init(ssh_packet_protection_t *protection)
{
    if (protection == NULL) {
        return;
    }

    memset(protection, 0, sizeof(*protection));
    protection->block_size = SSH_PACKET_MIN_BLOCK_SIZE;
}

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
    size_t mac_len)
{
    if (protection == NULL || crypto == NULL ||
        crypto->cipher_crypt == NULL || crypto->mac_compute == NULL ||
        (cipher_key == NULL && cipher_key_len != 0u) ||
        (cipher_iv == NULL && cipher_iv_len != 0u) ||
        (mac_key == NULL && mac_key_len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (cipher_key_len == 0u || cipher_key_len > sizeof(protection->cipher_key) ||
        cipher_iv_len > sizeof(protection->cipher_iv) ||
        mac_key_len == 0u || mac_key_len > sizeof(protection->mac_key) ||
        mac_len == 0u || mac_len > EMSSH_MAX_MAC) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(protection, 0, sizeof(*protection));
    protection->crypto = crypto;
    protection->cipher_algorithm = cipher_algorithm;
    protection->mac_algorithm = mac_algorithm;
    memcpy(protection->cipher_key, cipher_key, cipher_key_len);
    protection->cipher_key_len = cipher_key_len;
    if (cipher_iv_len != 0u) {
        memcpy(protection->cipher_iv, cipher_iv, cipher_iv_len);
    }
    protection->cipher_iv_len = cipher_iv_len;
    memcpy(protection->mac_key, mac_key, mac_key_len);
    protection->mac_key_len = mac_key_len;
    protection->block_size = normalized_block_size(block_size);
    protection->mac_len = mac_len;
    protection->sequence = 0u;
    protection->active = 1;
    return SSH_OK;
}

int ssh_packet_encode_protected(
    ssh_packet_protection_t *protection,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    const uint8_t *payload,
    size_t payload_len,
    const ssh_rng_api_t *rng)
{
    uint8_t mac[EMSSH_MAX_MAC];
    size_t packet_len;
    size_t mac_len;
    int status;

    if (protection == NULL || !protection->active || out == NULL || out_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_packet_encode_plain(
        out,
        out_capacity,
        &packet_len,
        payload,
        payload_len,
        protection->block_size,
        rng);
    if (status != SSH_OK) {
        return status;
    }

    if (packet_len + protection->mac_len > out_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    status = protection->crypto->mac_compute(
        protection->crypto->ctx,
        protection->mac_algorithm,
        protection->mac_key,
        protection->mac_key_len,
        protection->sequence,
        out,
        packet_len,
        mac,
        sizeof(mac),
        &mac_len);
    if (status != SSH_OK || mac_len != protection->mac_len) {
        return SSH_ERR_PLATFORM;
    }

    status = protection->crypto->cipher_crypt(
        protection->crypto->ctx,
        protection->cipher_algorithm,
        protection->cipher_key,
        protection->cipher_key_len,
        protection->cipher_iv,
        protection->cipher_iv_len,
        protection->sequence,
        SSH_CIPHER_ENCRYPT,
        out,
        packet_len);
    if (status != SSH_OK) {
        return SSH_ERR_PLATFORM;
    }

    advance_stream_position(protection, packet_len);
    memcpy(out + packet_len, mac, mac_len);
    *out_len = packet_len + mac_len;
    ++protection->sequence;
    return SSH_OK;
}

int ssh_packet_decode_protected(
    ssh_packet_protection_t *protection,
    uint8_t *packet,
    size_t packet_len,
    ssh_packet_view_t *view)
{
    uint8_t expected_mac[EMSSH_MAX_MAC];
    uint8_t received_mac[EMSSH_MAX_MAC];
    uint8_t original_iv[EMSSH_MAX_CIPHER_IV];
    uint8_t next_iv[EMSSH_MAX_CIPHER_IV];
    size_t encrypted_len;
    size_t expected_mac_len;
    int status;

    if (protection == NULL || !protection->active || packet == NULL || view == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (packet_len <= protection->mac_len || protection->mac_len > sizeof(received_mac)) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    encrypted_len = packet_len - protection->mac_len;
    if (encrypted_len < protection->block_size || (encrypted_len % protection->block_size) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }
    if (encrypted_len > EMSSH_MAX_PACKET_SIZE + 4u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    memcpy(original_iv, protection->cipher_iv, protection->cipher_iv_len);
    memcpy(next_iv, protection->cipher_iv, protection->cipher_iv_len);
    memcpy(received_mac, packet + encrypted_len, protection->mac_len);

    status = protection->crypto->cipher_crypt(
        protection->crypto->ctx,
        protection->cipher_algorithm,
        protection->cipher_key,
        protection->cipher_key_len,
        next_iv,
        protection->cipher_iv_len,
        protection->sequence,
        SSH_CIPHER_DECRYPT,
        packet,
        encrypted_len);
    if (status != SSH_OK) {
        return SSH_ERR_PLATFORM;
    }

    if (protection->cipher_iv_len != 0u) {
        size_t blocks = (encrypted_len + protection->cipher_iv_len - 1u) / protection->cipher_iv_len;
        advance_counter_be(next_iv, protection->cipher_iv_len, blocks);
    }
    status = protection->crypto->mac_compute(
        protection->crypto->ctx,
        protection->mac_algorithm,
        protection->mac_key,
        protection->mac_key_len,
        protection->sequence,
        packet,
        encrypted_len,
        expected_mac,
        sizeof(expected_mac),
        &expected_mac_len);
    if (status != SSH_OK || expected_mac_len != protection->mac_len) {
        (void)protection->crypto->cipher_crypt(
            protection->crypto->ctx,
            protection->cipher_algorithm,
            protection->cipher_key,
            protection->cipher_key_len,
            original_iv,
            protection->cipher_iv_len,
            protection->sequence,
            SSH_CIPHER_ENCRYPT,
            packet,
            encrypted_len);
        return SSH_ERR_PLATFORM;
    }

    if (!mac_matches(expected_mac, received_mac, protection->mac_len)) {
        (void)protection->crypto->cipher_crypt(
            protection->crypto->ctx,
            protection->cipher_algorithm,
            protection->cipher_key,
            protection->cipher_key_len,
            original_iv,
            protection->cipher_iv_len,
            protection->sequence,
            SSH_CIPHER_ENCRYPT,
            packet,
            encrypted_len);
        return SSH_ERR_SECURITY;
    }

    {
        uint32_t packet_length;

        packet_length = ((uint32_t)packet[0] << 24) |
                        ((uint32_t)packet[1] << 16) |
                        ((uint32_t)packet[2] << 8) |
                        (uint32_t)packet[3];
        if ((size_t)packet_length + 4u != encrypted_len) {
            (void)protection->crypto->cipher_crypt(
                protection->crypto->ctx,
                protection->cipher_algorithm,
                protection->cipher_key,
                protection->cipher_key_len,
                original_iv,
                protection->cipher_iv_len,
                protection->sequence,
                SSH_CIPHER_ENCRYPT,
                packet,
                encrypted_len);
            return SSH_ERR_MALFORMED_PACKET;
        }
    }

    status = ssh_packet_decode_plain(packet, encrypted_len, view);
    if (status != SSH_OK) {
        (void)protection->crypto->cipher_crypt(
            protection->crypto->ctx,
            protection->cipher_algorithm,
            protection->cipher_key,
            protection->cipher_key_len,
            original_iv,
            protection->cipher_iv_len,
            protection->sequence,
            SSH_CIPHER_ENCRYPT,
            packet,
            encrypted_len);
        return status;
    }

    memcpy(protection->cipher_iv, next_iv, protection->cipher_iv_len);
    ++protection->sequence;
    return SSH_OK;
}
