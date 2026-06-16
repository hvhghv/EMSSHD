#ifndef EMSSH_MBEDTLS_OPENSSH_KEY_H
#define EMSSH_MBEDTLS_OPENSSH_KEY_H

#include <stddef.h>
#include <stdint.h>

#include "emssh/ssh_buffer.h"

int emssh_mbedtls_openssh_rsa_private_to_pkcs1_der(
    const uint8_t *private_key_data,
    size_t private_key_data_len,
    uint8_t *der,
    size_t der_capacity,
    size_t *der_len);

int emssh_mbedtls_openssh_rsa_private_to_pkcs1_pem(
    const uint8_t *private_key_data,
    size_t private_key_data_len,
    uint8_t *pem,
    size_t pem_capacity,
    size_t *pem_len);

int emssh_mbedtls_decode_pem_block(
    const uint8_t *data,
    size_t data_len,
    const char *begin_marker,
    const char *end_marker,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len);

#endif
