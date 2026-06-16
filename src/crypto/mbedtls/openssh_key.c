#include "openssh_key.h"

#include <string.h>

#include "emssh/ssh_buffer.h"
#include "emssh/ssh_error.h"

#include <mbedtls/bignum.h>

static int ascii_is_space(uint8_t ch)
{
    return ch == (uint8_t)' ' ||
           ch == (uint8_t)'\t' ||
           ch == (uint8_t)'\r' ||
           ch == (uint8_t)'\n';
}

static int base64_value(uint8_t ch)
{
    if (ch >= (uint8_t)'A' && ch <= (uint8_t)'Z') {
        return (int)(ch - (uint8_t)'A');
    }
    if (ch >= (uint8_t)'a' && ch <= (uint8_t)'z') {
        return (int)(ch - (uint8_t)'a' + 26u);
    }
    if (ch >= (uint8_t)'0' && ch <= (uint8_t)'9') {
        return (int)(ch - (uint8_t)'0' + 52u);
    }
    if (ch == (uint8_t)'+') {
        return 62;
    }
    if (ch == (uint8_t)'/') {
        return 63;
    }
    if (ch == (uint8_t)'=') {
        return -2;
    }
    if (ascii_is_space(ch)) {
        return -3;
    }
    return -1;
}

static int decode_base64_data(
    const uint8_t *text,
    size_t text_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    uint32_t acc;
    unsigned bits;
    size_t i;
    size_t written;
    int saw_padding;

    if (text == NULL || out == NULL || out_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    acc = 0u;
    bits = 0u;
    written = 0u;
    saw_padding = 0;
    for (i = 0u; i < text_len; ++i) {
        int value = base64_value(text[i]);
        if (value == -3) {
            continue;
        }
        if (value == -2) {
            saw_padding = 1;
            continue;
        }
        if (value < 0) {
            return SSH_ERR_MALFORMED_PACKET;
        }
        if (saw_padding) {
            return SSH_ERR_MALFORMED_PACKET;
        }
        acc = (acc << 6) | (uint32_t)value;
        bits += 6u;
        if (bits >= 8u) {
            bits -= 8u;
            if (written >= out_capacity) {
                return SSH_ERR_BUFFER_TOO_SMALL;
            }
            out[written++] = (uint8_t)((acc >> bits) & 0xffu);
        }
    }

    if (bits >= 6u) {
        return SSH_ERR_MALFORMED_PACKET;
    }
    *out_len = written;
    return written != 0u ? SSH_OK : SSH_ERR_MALFORMED_PACKET;
}

int emssh_mbedtls_decode_pem_block(
    const uint8_t *data,
    size_t data_len,
    const char *begin_marker,
    const char *end_marker,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    const uint8_t *begin;
    const uint8_t *end;
    const uint8_t *base64_start;
    size_t marker_len;
    size_t tail_len;

    if (data == NULL || begin_marker == NULL || end_marker == NULL ||
        out == NULL || out_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    marker_len = strlen(begin_marker);
    begin = NULL;
    if (data_len >= marker_len) {
        size_t i;
        for (i = 0u; i + marker_len <= data_len; ++i) {
            if (memcmp(data + i, begin_marker, marker_len) == 0) {
                begin = data + i;
                break;
            }
        }
    }
    if (begin == NULL) {
        return SSH_ERR_NOT_FOUND;
    }
    base64_start = begin + marker_len;
    while ((size_t)(base64_start - data) < data_len && *base64_start != (uint8_t)'\n') {
        ++base64_start;
    }
    if ((size_t)(base64_start - data) < data_len && *base64_start == (uint8_t)'\n') {
        ++base64_start;
    }

    marker_len = strlen(end_marker);
    end = NULL;
    tail_len = data_len - (size_t)(base64_start - data);
    if (tail_len >= marker_len) {
        size_t i;
        for (i = 0u; i + marker_len <= tail_len; ++i) {
            if (memcmp(base64_start + i, end_marker, marker_len) == 0) {
                end = base64_start + i;
                break;
            }
        }
    }
    if (end == NULL || end <= base64_start) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return decode_base64_data(
        base64_start,
        (size_t)(end - base64_start),
        out,
        out_capacity,
        out_len);
}

static void secure_zero_bytes(void *ptr, size_t len)
{
    volatile uint8_t *p;

    if (ptr == NULL) {
        return;
    }

    p = (volatile uint8_t *)ptr;
    while (len-- != 0u) {
        *p++ = 0u;
    }
}

static int view_eq(ssh_string_view_t view, const char *value)
{
    size_t len;

    if (value == NULL || view.data == NULL) {
        return 0;
    }
    len = strlen(value);
    return view.len == len && memcmp(view.data, value, len) == 0;
}

static int der_length_size(size_t len, size_t *encoded_len)
{
    size_t bytes;
    size_t tmp;

    if (encoded_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (len < 128u) {
        *encoded_len = 1u;
        return SSH_OK;
    }

    bytes = 0u;
    tmp = len;
    while (tmp != 0u) {
        ++bytes;
        tmp >>= 8;
    }
    *encoded_len = 1u + bytes;
    return SSH_OK;
}

static int der_put_length(uint8_t *out, size_t out_capacity, size_t *offset, size_t len)
{
    size_t len_len;
    size_t i;

    if (out == NULL || offset == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (der_length_size(len, &len_len) != SSH_OK || *offset > out_capacity || len_len > out_capacity - *offset) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    if (len < 128u) {
        out[(*offset)++] = (uint8_t)len;
        return SSH_OK;
    }

    out[(*offset)++] = (uint8_t)(0x80u | (len_len - 1u));
    for (i = len_len - 1u; i > 0u; --i) {
        out[(*offset)++] = (uint8_t)(len >> ((i - 1u) * 8u));
    }

    return SSH_OK;
}

static int mpint_payload(ssh_string_view_t value, size_t *start, size_t *payload_len, int *needs_zero)
{
    size_t i;

    if (value.data == NULL || start == NULL || payload_len == NULL || needs_zero == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    i = 0u;
    while (i < value.len && value.data[i] == 0u) {
        ++i;
    }
    if (i == value.len) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    *start = i;
    *payload_len = value.len - i;
    *needs_zero = (value.data[i] & 0x80u) != 0u;
    return SSH_OK;
}

static int der_integer_total_len(ssh_string_view_t value, size_t *total_len)
{
    size_t start;
    size_t payload_len;
    size_t len_len;
    int needs_zero;
    int rc;

    if (total_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    rc = mpint_payload(value, &start, &payload_len, &needs_zero);
    (void)start;
    if (rc != SSH_OK) {
        return rc;
    }
    rc = der_length_size(payload_len + (needs_zero ? 1u : 0u), &len_len);
    if (rc != SSH_OK) {
        return rc;
    }

    *total_len = 1u + len_len + payload_len + (needs_zero ? 1u : 0u);
    return SSH_OK;
}

static int der_put_integer(uint8_t *out, size_t out_capacity, size_t *offset, ssh_string_view_t value)
{
    size_t start;
    size_t payload_len;
    int needs_zero;
    int rc;

    if (out == NULL || offset == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    rc = mpint_payload(value, &start, &payload_len, &needs_zero);
    if (rc != SSH_OK) {
        return rc;
    }

    if (*offset >= out_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    out[(*offset)++] = 0x02u;
    rc = der_put_length(out, out_capacity, offset, payload_len + (needs_zero ? 1u : 0u));
    if (rc != SSH_OK) {
        return rc;
    }
    if (needs_zero) {
        if (*offset >= out_capacity) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        out[(*offset)++] = 0u;
    }
    if (*offset > out_capacity || payload_len > out_capacity - *offset) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(out + *offset, value.data + start, payload_len);
    *offset += payload_len;
    return SSH_OK;
}

static int mpi_to_der_integer_view(
    const mbedtls_mpi *value,
    uint8_t *storage,
    size_t storage_capacity,
    ssh_string_view_t *view)
{
    size_t len;

    if (value == NULL || storage == NULL || view == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    len = mbedtls_mpi_size(value);
    if (len == 0u || len > storage_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    if (mbedtls_mpi_write_binary(value, storage, len) != 0) {
        return SSH_ERR_PLATFORM;
    }

    view->data = storage;
    view->len = len;
    return SSH_OK;
}

static int compute_rsa_crt_exponent(
    ssh_string_view_t d,
    ssh_string_view_t prime,
    uint8_t *storage,
    size_t storage_capacity,
    ssh_string_view_t *out)
{
    mbedtls_mpi mpi_d;
    mbedtls_mpi mpi_prime;
    mbedtls_mpi phi;
    mbedtls_mpi result;
    int rc;
    int status;

    if (d.data == NULL || prime.data == NULL || storage == NULL || out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    mbedtls_mpi_init(&mpi_d);
    mbedtls_mpi_init(&mpi_prime);
    mbedtls_mpi_init(&phi);
    mbedtls_mpi_init(&result);

    rc = mbedtls_mpi_read_binary(&mpi_d, d.data, d.len);
    if (rc == 0) {
        rc = mbedtls_mpi_read_binary(&mpi_prime, prime.data, prime.len);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_sub_int(&phi, &mpi_prime, 1);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_mod_mpi(&result, &mpi_d, &phi);
    }
    status = rc == 0 ? mpi_to_der_integer_view(&result, storage, storage_capacity, out) : SSH_ERR_PLATFORM;

    mbedtls_mpi_free(&result);
    mbedtls_mpi_free(&phi);
    mbedtls_mpi_free(&mpi_prime);
    mbedtls_mpi_free(&mpi_d);
    return status;
}

static int pkcs1_private_der_encode(
    ssh_string_view_t n,
    ssh_string_view_t e,
    ssh_string_view_t d,
    ssh_string_view_t p,
    ssh_string_view_t q,
    ssh_string_view_t dmp1,
    ssh_string_view_t dmq1,
    ssh_string_view_t iqmp,
    uint8_t *der,
    size_t der_capacity,
    size_t *der_len)
{
    ssh_string_view_t values[8];
    size_t item_lens[8];
    size_t sequence_len;
    size_t offset;
    size_t i;
    int rc;

    if (der == NULL || der_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    values[0] = n;
    values[1] = e;
    values[2] = d;
    values[3] = p;
    values[4] = q;
    values[5] = dmp1;
    values[6] = dmq1;
    values[7] = iqmp;

    sequence_len = 3u; /* INTEGER version = 0 */
    for (i = 0u; i < 8u; ++i) {
        rc = der_integer_total_len(values[i], &item_lens[i]);
        if (rc != SSH_OK) {
            return rc;
        }
        if (sequence_len > (size_t)-1 - item_lens[i]) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        sequence_len += item_lens[i];
    }

    offset = 0u;
    if (der_capacity < 1u) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    der[offset++] = 0x30u;
    rc = der_put_length(der, der_capacity, &offset, sequence_len);
    if (rc == SSH_OK) {
        if (offset + 3u > der_capacity) {
            rc = SSH_ERR_BUFFER_TOO_SMALL;
        } else {
            der[offset++] = 0x02u;
            der[offset++] = 0x01u;
            der[offset++] = 0x00u;
        }
    }
    for (i = 0u; rc == SSH_OK && i < 8u; ++i) {
        rc = der_put_integer(der, der_capacity, &offset, values[i]);
    }
    if (rc != SSH_OK) {
        return rc;
    }

    *der_len = offset;
    return SSH_OK;
}

static int openssh_skip_string(ssh_buffer_t *buf)
{
    ssh_string_view_t ignored;
    return ssh_buffer_get_string_view(buf, &ignored);
}

static int openssh_check_private_padding(ssh_buffer_t *buf)
{
    uint8_t expected;

    if (buf == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    expected = 1u;
    while (ssh_buffer_remaining_read(buf) != 0u) {
        uint8_t value;
        int status = ssh_buffer_get_u8(buf, &value);
        if (status != SSH_OK) {
            return status;
        }
        if (value != expected) {
            return SSH_ERR_MALFORMED_PACKET;
        }
        expected = expected == 255u ? 1u : (uint8_t)(expected + 1u);
    }

    return SSH_OK;
}

static int openssh_check_public_blob(
    ssh_string_view_t blob,
    ssh_string_view_t n,
    ssh_string_view_t e)
{
    ssh_buffer_t buf;
    ssh_string_view_t alg;
    ssh_string_view_t pub_e;
    ssh_string_view_t pub_n;
    int status;

    ssh_buffer_wrap(&buf, (uint8_t *)blob.data, blob.len);
    status = ssh_buffer_get_string_view(&buf, &alg);
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&buf, &pub_e);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&buf, &pub_n);
    }
    if (status != SSH_OK || ssh_buffer_remaining_read(&buf) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }
    if (!view_eq(alg, "ssh-rsa") ||
        pub_e.len != e.len || memcmp(pub_e.data, e.data, e.len) != 0 ||
        pub_n.len != n.len || memcmp(pub_n.data, n.data, n.len) != 0) {
        return SSH_ERR_MALFORMED_PACKET;
    }
    return SSH_OK;
}

int emssh_mbedtls_openssh_rsa_private_to_pkcs1_der(
    const uint8_t *private_key_data,
    size_t private_key_data_len,
    uint8_t *der,
    size_t der_capacity,
    size_t *der_len)
{
    static const char k_begin_openssh[] = "-----BEGIN OPENSSH PRIVATE KEY-----";
    static const char k_end_openssh[] = "-----END OPENSSH PRIVATE KEY-----";
    static const uint8_t k_magic[] = "openssh-key-v1";
    uint8_t openssh_blob[8192];
    size_t openssh_blob_len;
    ssh_buffer_t outer;
    ssh_buffer_t private_buf;
    ssh_string_view_t ciphername;
    ssh_string_view_t kdfname;
    ssh_string_view_t kdfoptions;
    ssh_string_view_t public_blob;
    ssh_string_view_t private_blob;
    ssh_string_view_t alg;
    ssh_string_view_t n;
    ssh_string_view_t e;
    ssh_string_view_t d;
    ssh_string_view_t iqmp;
    ssh_string_view_t p;
    ssh_string_view_t q;
    ssh_string_view_t dmp1;
    ssh_string_view_t dmq1;
    uint32_t key_count;
    uint32_t check1;
    uint32_t check2;
    uint8_t dmp1_storage[1024];
    uint8_t dmq1_storage[1024];
    int status;

    if (private_key_data == NULL || der == NULL || der_len == NULL || private_key_data_len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = emssh_mbedtls_decode_pem_block(
        private_key_data,
        private_key_data_len,
        k_begin_openssh,
        k_end_openssh,
        openssh_blob,
        sizeof(openssh_blob),
        &openssh_blob_len);
    if (status != SSH_OK) {
        secure_zero_bytes(openssh_blob, sizeof(openssh_blob));
        return status;
    }

    if (openssh_blob_len < sizeof(k_magic) ||
        memcmp(openssh_blob, k_magic, sizeof(k_magic)) != 0) {
        secure_zero_bytes(openssh_blob, sizeof(openssh_blob));
        return SSH_ERR_MALFORMED_PACKET;
    }
    ssh_buffer_wrap(&outer, openssh_blob + sizeof(k_magic), openssh_blob_len - sizeof(k_magic));

    status = ssh_buffer_get_string_view(&outer, &ciphername);
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&outer, &kdfname);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&outer, &kdfoptions);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_u32(&outer, &key_count);
    }
    if (status == SSH_OK && key_count != 1u) {
        status = SSH_ERR_UNSUPPORTED;
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&outer, &public_blob);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&outer, &private_blob);
    }
    if (status != SSH_OK || ssh_buffer_remaining_read(&outer) != 0u) {
        secure_zero_bytes(openssh_blob, sizeof(openssh_blob));
        return status != SSH_OK ? status : SSH_ERR_MALFORMED_PACKET;
    }
    if (!view_eq(ciphername, "none") || !view_eq(kdfname, "none") || kdfoptions.len != 0u) {
        secure_zero_bytes(openssh_blob, sizeof(openssh_blob));
        return SSH_ERR_UNSUPPORTED;
    }

    ssh_buffer_wrap(&private_buf, (uint8_t *)private_blob.data, private_blob.len);
    status = ssh_buffer_get_u32(&private_buf, &check1);
    if (status == SSH_OK) {
        status = ssh_buffer_get_u32(&private_buf, &check2);
    }
    if (status == SSH_OK && check1 != check2) {
        status = SSH_ERR_MALFORMED_PACKET;
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&private_buf, &alg);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&private_buf, &n);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&private_buf, &e);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&private_buf, &d);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&private_buf, &iqmp);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&private_buf, &p);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&private_buf, &q);
    }
    if (status == SSH_OK) {
        status = openssh_skip_string(&private_buf);
    }
    if (status == SSH_OK) {
        status = openssh_check_private_padding(&private_buf);
    }
    if (status == SSH_OK && !view_eq(alg, "ssh-rsa")) {
        status = SSH_ERR_UNSUPPORTED;
    }
    if (status == SSH_OK) {
        status = openssh_check_public_blob(public_blob, n, e);
    }
    if (status == SSH_OK) {
        status = compute_rsa_crt_exponent(d, p, dmp1_storage, sizeof(dmp1_storage), &dmp1);
    }
    if (status == SSH_OK) {
        status = compute_rsa_crt_exponent(d, q, dmq1_storage, sizeof(dmq1_storage), &dmq1);
    }
    if (status == SSH_OK) {
        status = pkcs1_private_der_encode(n, e, d, p, q, dmp1, dmq1, iqmp, der, der_capacity, der_len);
    }

    secure_zero_bytes(dmp1_storage, sizeof(dmp1_storage));
    secure_zero_bytes(dmq1_storage, sizeof(dmq1_storage));
    secure_zero_bytes(openssh_blob, sizeof(openssh_blob));
    return status;
}

int emssh_mbedtls_openssh_rsa_private_to_pkcs1_pem(
    const uint8_t *private_key_data,
    size_t private_key_data_len,
    uint8_t *pem,
    size_t pem_capacity,
    size_t *pem_len)
{
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const char begin[] = "-----BEGIN RSA PRIVATE KEY-----\n";
    static const char end[] = "-----END RSA PRIVATE KEY-----\n";
    uint8_t der[4096];
    size_t der_len;
    size_t i;
    size_t used;
    size_t line;
    int status;

    if (pem == NULL || pem_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = emssh_mbedtls_openssh_rsa_private_to_pkcs1_der(
        private_key_data,
        private_key_data_len,
        der,
        sizeof(der),
        &der_len);
    if (status != SSH_OK) {
        secure_zero_bytes(der, sizeof(der));
        return status;
    }

    used = 0u;
    if (sizeof(begin) - 1u + sizeof(end) - 1u + 1u > pem_capacity) {
        secure_zero_bytes(der, sizeof(der));
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(pem + used, begin, sizeof(begin) - 1u);
    used += sizeof(begin) - 1u;
    line = 0u;

    for (i = 0u; i < der_len; i += 3u) {
        uint32_t triple = 0u;
        size_t rem = der_len - i;
        if (rem > 3u) {
            rem = 3u;
        }
        triple |= ((uint32_t)der[i]) << 16;
        if (rem > 1u) {
            triple |= ((uint32_t)der[i + 1u]) << 8;
        }
        if (rem > 2u) {
            triple |= (uint32_t)der[i + 2u];
        }

        if (used + 4u + 2u + (sizeof(end) - 1u) + 1u > pem_capacity) {
            secure_zero_bytes(der, sizeof(der));
            return SSH_ERR_BUFFER_TOO_SMALL;
        }

        pem[used++] = b64[(triple >> 18) & 0x3fu];
        pem[used++] = b64[(triple >> 12) & 0x3fu];
        pem[used++] = rem > 1u ? b64[(triple >> 6) & 0x3fu] : '=';
        pem[used++] = rem > 2u ? b64[triple & 0x3fu] : '=';
        line += 4u;

        if (line >= 64u) {
            pem[used++] = '\n';
            line = 0u;
        }
    }
    if (line != 0u) {
        pem[used++] = '\n';
    }
    memcpy(pem + used, end, sizeof(end) - 1u);
    used += sizeof(end) - 1u;
    pem[used] = '\0';
    *pem_len = used;

    secure_zero_bytes(der, sizeof(der));
    return SSH_OK;
}
