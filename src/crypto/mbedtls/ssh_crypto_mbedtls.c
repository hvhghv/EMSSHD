#include "emssh/crypto_mbedtls.h"

#include <string.h>

#include "emssh/ssh_crypto.h"
#include "emssh/ssh_buffer.h"
#include "emssh/ssh_config.h"
#include "emssh/ssh_error.h"

#include <psa/crypto.h>

static int view_eq(ssh_string_view_t view, const char *value)
{
    size_t len;

    if (value == NULL || view.data == NULL) {
        return 0;
    }

    len = strlen(value);
    return view.len == len && memcmp(view.data, value, len) == 0;
}

static int psa_ok(psa_status_t status)
{
    return status == PSA_SUCCESS ? SSH_OK : SSH_ERR_PLATFORM;
}

static int psa_ok_or_unsupported(psa_status_t status)
{
    if (status == PSA_SUCCESS) {
        return SSH_OK;
    }
    if (status == PSA_ERROR_NOT_SUPPORTED) {
        return SSH_ERR_UNSUPPORTED;
    }
    return SSH_ERR_PLATFORM;
}

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

static int import_rsa_hostkey_auto(
    ssh_mbedtls_crypto_t *ctx,
    const uint8_t *private_key_data,
    size_t private_key_data_len);

static int rsa_public_der_to_ssh_blob(
    const uint8_t *der,
    size_t der_len,
    ssh_buffer_t *out);

static void destroy_owned_hostkey(ssh_mbedtls_crypto_t *ctx)
{
    if (ctx != NULL && ctx->owns_hostkey && ctx->hostkey_id != 0u) {
        (void)psa_destroy_key((mbedtls_svc_key_id_t)ctx->hostkey_id);
        ctx->hostkey_id = 0u;
        ctx->owns_hostkey = 0;
    }
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

static int mbedtls_rng_fill(void *ctx, uint8_t *buf, size_t len)
{
    (void)ctx;

    if (buf == NULL && len != 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    return psa_ok(psa_generate_random(buf, len));
}

static int mbedtls_kex_generate_keypair(
    void *ctx,
    ssh_string_view_t kex_algorithm,
    uint8_t *public_key,
    size_t public_key_capacity,
    size_t *public_key_len,
    uint8_t *private_key,
    size_t private_key_capacity,
    size_t *private_key_len)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = 0;
    psa_status_t status;

    (void)ctx;

    if (!view_eq(kex_algorithm, "curve25519-sha256") ||
        public_key == NULL || public_key_len == NULL ||
        private_key == NULL || private_key_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attributes, 255u);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);

    status = psa_generate_key(&attributes, &key);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        return psa_ok_or_unsupported(status);
    }

    status = psa_export_public_key(key, public_key, public_key_capacity, public_key_len);
    if (status == PSA_SUCCESS) {
        status = psa_export_key(key, private_key, private_key_capacity, private_key_len);
    }

    (void)psa_destroy_key(key);
    return psa_ok(status);
}

static int import_x25519_private_key(
    const uint8_t *private_key,
    size_t private_key_len,
    mbedtls_svc_key_id_t *key)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;

    if (private_key == NULL || private_key_len == 0u || key == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attributes, 255u);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);

    status = psa_import_key(&attributes, private_key, private_key_len, key);
    psa_reset_key_attributes(&attributes);
    return psa_ok(status);
}

static int mbedtls_kex_compute_shared_secret(
    void *ctx,
    ssh_string_view_t kex_algorithm,
    const uint8_t *private_key,
    size_t private_key_len,
    const uint8_t *peer_public_key,
    size_t peer_public_key_len,
    uint8_t *shared_secret,
    size_t shared_secret_capacity,
    size_t *shared_secret_len)
{
    mbedtls_svc_key_id_t key = 0;
    psa_status_t status;
    size_t i;
    int all_zero;
    int rc;

    (void)ctx;

    if (!view_eq(kex_algorithm, "curve25519-sha256") ||
        peer_public_key == NULL || peer_public_key_len == 0u ||
        shared_secret == NULL || shared_secret_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    rc = import_x25519_private_key(private_key, private_key_len, &key);
    if (rc != SSH_OK) {
        return rc;
    }

    status = psa_raw_key_agreement(
        PSA_ALG_ECDH,
        key,
        peer_public_key,
        peer_public_key_len,
        shared_secret,
        shared_secret_capacity,
        shared_secret_len);

    (void)psa_destroy_key(key);
    if (status != PSA_SUCCESS) {
        return psa_ok_or_unsupported(status);
    }

    all_zero = 1;
    for (i = 0u; i < *shared_secret_len; ++i) {
        if (shared_secret[i] != 0u) {
            all_zero = 0;
            break;
        }
    }

    return all_zero ? SSH_ERR_PLATFORM : SSH_OK;
}

static int mbedtls_hostkey_public(
    void *ctx,
    ssh_string_view_t hostkey_algorithm,
    uint8_t *hostkey_blob,
    size_t hostkey_blob_capacity,
    size_t *hostkey_blob_len)
{
    ssh_mbedtls_crypto_t *mbed = (ssh_mbedtls_crypto_t *)ctx;
    uint8_t raw_public[EMSSH_MAX_HOST_KEY_BLOB];
    size_t raw_public_len;
    ssh_buffer_t buf;
    psa_status_t status;
    int rc;

    if (mbed == NULL ||
        hostkey_blob == NULL || hostkey_blob_len == NULL ||
        mbed->hostkey_id == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = psa_export_public_key((mbedtls_svc_key_id_t)mbed->hostkey_id, raw_public, sizeof(raw_public), &raw_public_len);
    if (status != PSA_SUCCESS) {
        return psa_ok_or_unsupported(status);
    }

    ssh_buffer_init(&buf, hostkey_blob, hostkey_blob_capacity);
    if (view_eq(hostkey_algorithm, "ssh-ed25519")) {
        rc = ssh_buffer_put_cstring(&buf, "ssh-ed25519");
        if (rc == SSH_OK) {
            rc = ssh_buffer_put_string(&buf, raw_public, raw_public_len);
        }
    } else if (view_eq(hostkey_algorithm, "ecdsa-sha2-nistp256")) {
        rc = ssh_buffer_put_cstring(&buf, "ecdsa-sha2-nistp256");
        if (rc == SSH_OK) {
            rc = ssh_buffer_put_cstring(&buf, "nistp256");
        }
        if (rc == SSH_OK) {
            rc = ssh_buffer_put_string(&buf, raw_public, raw_public_len);
        }
    } else if (view_eq(hostkey_algorithm, "rsa-sha2-256") ||
               view_eq(hostkey_algorithm, "rsa-sha2-512") ||
               view_eq(hostkey_algorithm, "ssh-rsa")) {
        rc = rsa_public_der_to_ssh_blob(raw_public, raw_public_len, &buf);
    } else {
        rc = SSH_ERR_INVALID_ARGUMENT;
    }

    secure_zero_bytes(raw_public, sizeof(raw_public));
    if (rc != SSH_OK) {
        return rc;
    }

    *hostkey_blob_len = ssh_buffer_len(&buf);
    return SSH_OK;
}

static int mbedtls_hash_exchange(
    void *ctx,
    ssh_string_view_t kex_algorithm,
    const uint8_t *data,
    size_t data_len,
    uint8_t *hash,
    size_t hash_capacity,
    size_t *hash_len)
{
    (void)ctx;

    if (!view_eq(kex_algorithm, "curve25519-sha256") ||
        data == NULL || hash == NULL || hash_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    return psa_ok_or_unsupported(psa_hash_compute(PSA_ALG_SHA_256, data, data_len, hash, hash_capacity, hash_len));
}

static int put_ssh_ecdsa_signature_blob(ssh_buffer_t *outer, const uint8_t *raw_signature, size_t raw_signature_len)
{
    uint8_t inner_storage[160];
    ssh_buffer_t inner;
    int rc;

    if (outer == NULL || raw_signature == NULL || raw_signature_len != 64u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&inner, inner_storage, sizeof(inner_storage));
    rc = ssh_buffer_put_mpint_positive(&inner, raw_signature, 32u);
    if (rc == SSH_OK) {
        rc = ssh_buffer_put_mpint_positive(&inner, raw_signature + 32u, 32u);
    }
    if (rc == SSH_OK) {
        rc = ssh_buffer_put_string(outer, inner_storage, ssh_buffer_len(&inner));
    }

    secure_zero_bytes(inner_storage, sizeof(inner_storage));
    return rc;
}

static int mpint_view_to_fixed(ssh_string_view_t value, uint8_t *out, size_t out_len)
{
    size_t start;
    size_t copy_len;

    if (value.data == NULL || out == NULL || out_len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    start = 0u;
    while (start < value.len && value.data[start] == 0u) {
        ++start;
    }

    copy_len = value.len - start;
    if (copy_len > out_len) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    memset(out, 0, out_len);
    if (copy_len != 0u) {
        memcpy(out + out_len - copy_len, value.data + start, copy_len);
    }
    return SSH_OK;
}

static int decode_ecdsa_p256_public_key_blob(
    const uint8_t *publickey_blob,
    size_t publickey_blob_len,
    ssh_string_view_t *q)
{
    ssh_buffer_t buf;
    ssh_string_view_t algorithm;
    ssh_string_view_t curve;
    int status;

    if (publickey_blob == NULL || q == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(&algorithm, 0, sizeof(algorithm));
    memset(&curve, 0, sizeof(curve));
    memset(q, 0, sizeof(*q));

    ssh_buffer_wrap(&buf, (uint8_t *)publickey_blob, publickey_blob_len);
    status = ssh_buffer_get_string_view(&buf, &algorithm);
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&buf, &curve);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&buf, q);
    }
    if (status != SSH_OK) {
        return status;
    }

    if (!view_eq(algorithm, "ecdsa-sha2-nistp256") ||
        !view_eq(curve, "nistp256") ||
        q->len == 0u ||
        ssh_buffer_remaining_read(&buf) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return SSH_OK;
}

static int decode_ed25519_public_key_blob(
    const uint8_t *publickey_blob,
    size_t publickey_blob_len,
    ssh_string_view_t *raw_public)
{
    ssh_buffer_t buf;
    ssh_string_view_t algorithm;
    int status;

    if (publickey_blob == NULL || raw_public == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(&algorithm, 0, sizeof(algorithm));
    memset(raw_public, 0, sizeof(*raw_public));

    ssh_buffer_wrap(&buf, (uint8_t *)publickey_blob, publickey_blob_len);
    status = ssh_buffer_get_string_view(&buf, &algorithm);
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&buf, raw_public);
    }
    if (status != SSH_OK) {
        return status;
    }

    if (!view_eq(algorithm, "ssh-ed25519") ||
        raw_public->len != 32u ||
        ssh_buffer_remaining_read(&buf) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return SSH_OK;
}

static int decode_ecdsa_p256_signature_blob(
    const uint8_t *signature,
    size_t signature_len,
    uint8_t raw_signature[64])
{
    ssh_buffer_t outer;
    ssh_buffer_t inner;
    ssh_string_view_t algorithm;
    ssh_string_view_t inner_blob;
    ssh_string_view_t r;
    ssh_string_view_t s;
    int status;

    if (signature == NULL || raw_signature == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(&algorithm, 0, sizeof(algorithm));
    memset(&inner_blob, 0, sizeof(inner_blob));
    memset(&r, 0, sizeof(r));
    memset(&s, 0, sizeof(s));

    ssh_buffer_wrap(&outer, (uint8_t *)signature, signature_len);
    status = ssh_buffer_get_string_view(&outer, &algorithm);
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&outer, &inner_blob);
    }
    if (status != SSH_OK) {
        return status;
    }
    if (!view_eq(algorithm, "ecdsa-sha2-nistp256") || ssh_buffer_remaining_read(&outer) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    ssh_buffer_wrap(&inner, (uint8_t *)inner_blob.data, inner_blob.len);
    status = ssh_buffer_get_string_view(&inner, &r);
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&inner, &s);
    }
    if (status != SSH_OK) {
        return status;
    }
    if (ssh_buffer_remaining_read(&inner) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    status = mpint_view_to_fixed(r, raw_signature, 32u);
    if (status == SSH_OK) {
        status = mpint_view_to_fixed(s, raw_signature + 32u, 32u);
    }
    return status;
}

static int decode_ed25519_signature_blob(
    const uint8_t *signature,
    size_t signature_len,
    ssh_string_view_t *raw_signature)
{
    ssh_buffer_t buf;
    ssh_string_view_t algorithm;
    int status;

    if (signature == NULL || raw_signature == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(&algorithm, 0, sizeof(algorithm));
    memset(raw_signature, 0, sizeof(*raw_signature));

    ssh_buffer_wrap(&buf, (uint8_t *)signature, signature_len);
    status = ssh_buffer_get_string_view(&buf, &algorithm);
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&buf, raw_signature);
    }
    if (status != SSH_OK) {
        return status;
    }

    if (!view_eq(algorithm, "ssh-ed25519") ||
        raw_signature->len != 64u ||
        ssh_buffer_remaining_read(&buf) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return SSH_OK;
}

static int view_is_rsa_algorithm(ssh_string_view_t algorithm)
{
    return view_eq(algorithm, "ssh-rsa") ||
           view_eq(algorithm, "rsa-sha2-256") ||
           view_eq(algorithm, "rsa-sha2-512");
}

static psa_algorithm_t rsa_signature_psa_algorithm(ssh_string_view_t algorithm)
{
    if (view_eq(algorithm, "rsa-sha2-256")) {
        return PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
    }
    if (view_eq(algorithm, "rsa-sha2-512")) {
        return PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_512);
    }
    return 0;
}

static int decode_rsa_public_key_blob(
    const uint8_t *publickey_blob,
    size_t publickey_blob_len,
    ssh_string_view_t *e,
    ssh_string_view_t *n)
{
    ssh_buffer_t buf;
    ssh_string_view_t algorithm;
    int status;

    if (publickey_blob == NULL || e == NULL || n == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(&algorithm, 0, sizeof(algorithm));
    memset(e, 0, sizeof(*e));
    memset(n, 0, sizeof(*n));

    ssh_buffer_wrap(&buf, (uint8_t *)publickey_blob, publickey_blob_len);
    status = ssh_buffer_get_string_view(&buf, &algorithm);
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&buf, e);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&buf, n);
    }
    if (status != SSH_OK) {
        return status;
    }

    if (!view_is_rsa_algorithm(algorithm) ||
        e->len == 0u ||
        n->len == 0u ||
        ssh_buffer_remaining_read(&buf) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return SSH_OK;
}

static int decode_rsa_signature_blob(
    const uint8_t *signature,
    size_t signature_len,
    ssh_string_view_t *algorithm,
    ssh_string_view_t *raw_signature)
{
    ssh_buffer_t buf;
    int status;

    if (signature == NULL || algorithm == NULL || raw_signature == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(algorithm, 0, sizeof(*algorithm));
    memset(raw_signature, 0, sizeof(*raw_signature));

    ssh_buffer_wrap(&buf, (uint8_t *)signature, signature_len);
    status = ssh_buffer_get_string_view(&buf, algorithm);
    if (status == SSH_OK) {
        status = ssh_buffer_get_string_view(&buf, raw_signature);
    }
    if (status != SSH_OK) {
        return status;
    }

    if (!view_is_rsa_algorithm(*algorithm) ||
        raw_signature->len == 0u ||
        ssh_buffer_remaining_read(&buf) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return SSH_OK;
}

static int der_get_length(
    const uint8_t *der,
    size_t der_len,
    size_t *offset,
    size_t *len)
{
    uint8_t first;
    size_t count;
    size_t value;
    size_t i;

    if (der == NULL || offset == NULL || len == NULL || *offset >= der_len) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    first = der[(*offset)++];
    if ((first & 0x80u) == 0u) {
        *len = first;
        return *offset + *len <= der_len ? SSH_OK : SSH_ERR_MALFORMED_PACKET;
    }

    count = first & 0x7fu;
    if (count == 0u || count > sizeof(size_t) || count > der_len - *offset) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    value = 0u;
    for (i = 0u; i < count; ++i) {
        value = (value << 8) | der[(*offset)++];
    }

    *len = value;
    return *offset + *len <= der_len ? SSH_OK : SSH_ERR_MALFORMED_PACKET;
}

static int der_get_integer_view(
    const uint8_t *der,
    size_t der_len,
    size_t *offset,
    ssh_string_view_t *integer)
{
    size_t len;

    if (der == NULL || offset == NULL || integer == NULL || *offset >= der_len || der[(*offset)++] != 0x02u) {
        return SSH_ERR_MALFORMED_PACKET;
    }
    if (der_get_length(der, der_len, offset, &len) != SSH_OK || len == 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    integer->data = der + *offset;
    integer->len = len;
    *offset += len;
    return SSH_OK;
}

static int rsa_public_der_to_ssh_blob(
    const uint8_t *der,
    size_t der_len,
    ssh_buffer_t *out)
{
    ssh_string_view_t n;
    ssh_string_view_t e;
    size_t offset;
    size_t sequence_len;
    size_t sequence_end;
    int status;

    if (der == NULL || out == NULL || der_len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    offset = 0u;
    if (der[offset++] != 0x30u) {
        return SSH_ERR_MALFORMED_PACKET;
    }
    status = der_get_length(der, der_len, &offset, &sequence_len);
    if (status != SSH_OK) {
        return status;
    }
    sequence_end = offset + sequence_len;
    if (sequence_end > der_len) {
        return SSH_ERR_MALFORMED_PACKET;
    }
    status = der_get_integer_view(der, sequence_end, &offset, &n);
    if (status == SSH_OK) {
        status = der_get_integer_view(der, sequence_end, &offset, &e);
    }
    if (status != SSH_OK || offset != sequence_end) {
        return status != SSH_OK ? status : SSH_ERR_MALFORMED_PACKET;
    }

    status = ssh_buffer_put_cstring(out, "ssh-rsa");
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(out, e.data, e.len);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(out, n.data, n.len);
    }
    return status;
}

static int decode_pem_block(
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

static int der_integer_payload(ssh_string_view_t value, size_t *start, size_t *payload_len, int *needs_zero)
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

    rc = der_integer_payload(value, &start, &payload_len, &needs_zero);
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

    rc = der_integer_payload(value, &start, &payload_len, &needs_zero);
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

static int rsa_public_key_blob_to_der(
    ssh_string_view_t e,
    ssh_string_view_t n,
    uint8_t *der,
    size_t der_capacity,
    size_t *der_len)
{
    size_t n_len = 0u;
    size_t e_len = 0u;
    size_t sequence_len;
    size_t offset;
    int rc;

    if (der == NULL || der_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    rc = der_integer_total_len(n, &n_len);
    if (rc == SSH_OK) {
        rc = der_integer_total_len(e, &e_len);
    }
    if (rc != SSH_OK) {
        return rc;
    }

    sequence_len = n_len + e_len;
    if (der_capacity < 1u) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    offset = 0u;
    der[offset++] = 0x30u;
    rc = der_put_length(der, der_capacity, &offset, sequence_len);
    if (rc == SSH_OK) {
        rc = der_put_integer(der, der_capacity, &offset, n);
    }
    if (rc == SSH_OK) {
        rc = der_put_integer(der, der_capacity, &offset, e);
    }
    if (rc != SSH_OK) {
        return rc;
    }

    *der_len = offset;
    return SSH_OK;
}

static int mbedtls_hostkey_sign(
    void *ctx,
    ssh_string_view_t hostkey_algorithm,
    const uint8_t *exchange_hash,
    size_t exchange_hash_len,
    uint8_t *signature,
    size_t signature_capacity,
    size_t *signature_len)
{
    ssh_mbedtls_crypto_t *mbed = (ssh_mbedtls_crypto_t *)ctx;
    uint8_t raw_signature[EMSSH_MAX_SIGNATURE];
    size_t raw_signature_len;
    ssh_buffer_t buf;
    psa_status_t status;
    int rc;

    if (mbed == NULL ||
        exchange_hash == NULL || exchange_hash_len == 0u ||
        signature == NULL || signature_len == NULL ||
        mbed->hostkey_id == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&buf, signature, signature_capacity);

    if (view_eq(hostkey_algorithm, "ssh-ed25519")) {
        status = psa_sign_message(
            (mbedtls_svc_key_id_t)mbed->hostkey_id,
            PSA_ALG_PURE_EDDSA,
            exchange_hash,
            exchange_hash_len,
            raw_signature,
            sizeof(raw_signature),
            &raw_signature_len);
        if (status != PSA_SUCCESS) {
            return psa_ok_or_unsupported(status);
        }

        rc = ssh_buffer_put_cstring(&buf, "ssh-ed25519");
        if (rc == SSH_OK) {
            rc = ssh_buffer_put_string(&buf, raw_signature, raw_signature_len);
        }
    } else if (view_eq(hostkey_algorithm, "ecdsa-sha2-nistp256")) {
        status = psa_sign_message(
            (mbedtls_svc_key_id_t)mbed->hostkey_id,
            PSA_ALG_ECDSA(PSA_ALG_SHA_256),
            exchange_hash,
            exchange_hash_len,
            raw_signature,
            sizeof(raw_signature),
            &raw_signature_len);
        if (status != PSA_SUCCESS) {
            return psa_ok_or_unsupported(status);
        }

        rc = ssh_buffer_put_cstring(&buf, "ecdsa-sha2-nistp256");
        if (rc == SSH_OK) {
            rc = put_ssh_ecdsa_signature_blob(&buf, raw_signature, raw_signature_len);
        }
    } else if (view_eq(hostkey_algorithm, "rsa-sha2-256") ||
               view_eq(hostkey_algorithm, "rsa-sha2-512")) {
        psa_algorithm_t rsa_alg = rsa_signature_psa_algorithm(hostkey_algorithm);
        if (rsa_alg == 0) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        status = psa_sign_message(
            (mbedtls_svc_key_id_t)mbed->hostkey_id,
            rsa_alg,
            exchange_hash,
            exchange_hash_len,
            raw_signature,
            sizeof(raw_signature),
            &raw_signature_len);
        if (status != PSA_SUCCESS) {
            return psa_ok_or_unsupported(status);
        }

        rc = ssh_buffer_put_string(&buf, hostkey_algorithm.data, hostkey_algorithm.len);
        if (rc == SSH_OK) {
            rc = ssh_buffer_put_string(&buf, raw_signature, raw_signature_len);
        }
    } else {
        rc = SSH_ERR_INVALID_ARGUMENT;
    }

    secure_zero_bytes(raw_signature, sizeof(raw_signature));
    if (rc != SSH_OK) {
        return rc;
    }

    *signature_len = ssh_buffer_len(&buf);
    return SSH_OK;
}

static int verify_ed25519_publickey(
    const uint8_t *publickey_blob,
    size_t publickey_blob_len,
    const uint8_t *signed_data,
    size_t signed_data_len,
    const uint8_t *signature,
    size_t signature_len)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = 0;
    ssh_string_view_t raw_public;
    ssh_string_view_t raw_signature;
    psa_status_t status;
    int rc;

    rc = decode_ed25519_public_key_blob(publickey_blob, publickey_blob_len, &raw_public);
    if (rc != SSH_OK) {
        return rc;
    }

    rc = decode_ed25519_signature_blob(signature, signature_len, &raw_signature);
    if (rc != SSH_OK) {
        return rc;
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attributes, 255u);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_PURE_EDDSA);

    status = psa_import_key(&attributes, raw_public.data, raw_public.len, &key);
    psa_reset_key_attributes(&attributes);
    if (status == PSA_SUCCESS) {
        status = psa_verify_message(
            key,
            PSA_ALG_PURE_EDDSA,
            signed_data,
            signed_data_len,
            raw_signature.data,
            raw_signature.len);
    }

    if (key != 0) {
        (void)psa_destroy_key(key);
    }
    if (status == PSA_SUCCESS) {
        return SSH_OK;
    }
    if (status == PSA_ERROR_NOT_SUPPORTED) {
        return SSH_ERR_UNSUPPORTED;
    }
    return SSH_ERR_SECURITY;
}

static int verify_rsa_publickey(
    ssh_string_view_t publickey_algorithm,
    const uint8_t *publickey_blob,
    size_t publickey_blob_len,
    const uint8_t *signed_data,
    size_t signed_data_len,
    const uint8_t *signature,
    size_t signature_len)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = 0;
    ssh_string_view_t e;
    ssh_string_view_t n;
    ssh_string_view_t signature_algorithm;
    ssh_string_view_t raw_signature;
    uint8_t public_der[EMSSH_MAX_HOST_KEY_BLOB];
    size_t public_der_len;
    psa_algorithm_t psa_alg;
    psa_status_t status;
    int rc;

    if (!view_is_rsa_algorithm(publickey_algorithm)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    rc = decode_rsa_public_key_blob(publickey_blob, publickey_blob_len, &e, &n);
    if (rc != SSH_OK) {
        return rc;
    }
    rc = decode_rsa_signature_blob(signature, signature_len, &signature_algorithm, &raw_signature);
    if (rc != SSH_OK) {
        return rc;
    }
    if (view_eq(signature_algorithm, "ssh-rsa")) {
        return SSH_ERR_UNSUPPORTED;
    }
    psa_alg = rsa_signature_psa_algorithm(signature_algorithm);
    if (psa_alg == 0) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    rc = rsa_public_key_blob_to_der(e, n, public_der, sizeof(public_der), &public_der_len);
    if (rc != SSH_OK) {
        secure_zero_bytes(public_der, sizeof(public_der));
        return rc;
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, psa_alg);

    status = psa_import_key(&attributes, public_der, public_der_len, &key);
    psa_reset_key_attributes(&attributes);
    if (status == PSA_SUCCESS) {
        status = psa_verify_message(
            key,
            psa_alg,
            signed_data,
            signed_data_len,
            raw_signature.data,
            raw_signature.len);
    }

    if (key != 0) {
        (void)psa_destroy_key(key);
    }
    secure_zero_bytes(public_der, sizeof(public_der));
    if (status == PSA_SUCCESS) {
        return SSH_OK;
    }
    if (status == PSA_ERROR_NOT_SUPPORTED) {
        return SSH_ERR_UNSUPPORTED;
    }
    return SSH_ERR_SECURITY;
}

static int verify_ecdsa_p256_publickey(
    const uint8_t *publickey_blob,
    size_t publickey_blob_len,
    const uint8_t *signed_data,
    size_t signed_data_len,
    const uint8_t *signature,
    size_t signature_len)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = 0;
    ssh_string_view_t q;
    uint8_t raw_signature[64];
    psa_status_t status;
    int rc;

    rc = decode_ecdsa_p256_public_key_blob(publickey_blob, publickey_blob_len, &q);
    if (rc != SSH_OK) {
        return rc;
    }

    rc = decode_ecdsa_p256_signature_blob(signature, signature_len, raw_signature);
    if (rc != SSH_OK) {
        secure_zero_bytes(raw_signature, sizeof(raw_signature));
        return rc;
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256u);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    status = psa_import_key(&attributes, q.data, q.len, &key);
    psa_reset_key_attributes(&attributes);
    if (status == PSA_SUCCESS) {
        status = psa_verify_message(
            key,
            PSA_ALG_ECDSA(PSA_ALG_SHA_256),
            signed_data,
            signed_data_len,
            raw_signature,
            sizeof(raw_signature));
    }

    if (key != 0) {
        (void)psa_destroy_key(key);
    }
    secure_zero_bytes(raw_signature, sizeof(raw_signature));
    if (status == PSA_SUCCESS) {
        return SSH_OK;
    }
    if (status == PSA_ERROR_NOT_SUPPORTED) {
        return SSH_ERR_UNSUPPORTED;
    }
    return SSH_ERR_SECURITY;
}

static int mbedtls_publickey_verify(
    void *ctx,
    ssh_string_view_t publickey_algorithm,
    const uint8_t *publickey_blob,
    size_t publickey_blob_len,
    const uint8_t *signed_data,
    size_t signed_data_len,
    const uint8_t *signature,
    size_t signature_len)
{
    (void)ctx;

    if (publickey_blob == NULL || publickey_blob_len == 0u ||
        signed_data == NULL || signed_data_len == 0u ||
        signature == NULL || signature_len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (view_eq(publickey_algorithm, "ecdsa-sha2-nistp256")) {
        return verify_ecdsa_p256_publickey(
            publickey_blob,
            publickey_blob_len,
            signed_data,
            signed_data_len,
            signature,
            signature_len);
    }

    if (view_eq(publickey_algorithm, "ssh-ed25519")) {
        return verify_ed25519_publickey(
            publickey_blob,
            publickey_blob_len,
            signed_data,
            signed_data_len,
            signature,
            signature_len);
    }

    if (view_is_rsa_algorithm(publickey_algorithm)) {
        return verify_rsa_publickey(
            publickey_algorithm,
            publickey_blob,
            publickey_blob_len,
            signed_data,
            signed_data_len,
            signature,
            signature_len);
    }

    return SSH_ERR_INVALID_ARGUMENT;
}

static int ssh_kdf_hash_round(
    const uint8_t *shared_secret,
    size_t shared_secret_len,
    const uint8_t *exchange_hash,
    size_t exchange_hash_len,
    const uint8_t *session_id,
    size_t session_id_len,
    char key_id,
    const uint8_t *previous,
    size_t previous_len,
    uint8_t out[32])
{
    uint8_t input[EMSSH_MAX_KEX_SHARED_SECRET + (EMSSH_MAX_EXCHANGE_HASH * 2u) + 1u + 256u];
    ssh_buffer_t buf;
    size_t hash_len;
    int rc;
    psa_status_t status;

    ssh_buffer_init(&buf, input, sizeof(input));
    rc = ssh_buffer_put_mpint_positive(&buf, shared_secret, shared_secret_len);
    if (rc == SSH_OK) {
        rc = ssh_buffer_put_bytes(&buf, exchange_hash, exchange_hash_len);
    }
    if (rc == SSH_OK && previous == NULL) {
        rc = ssh_buffer_put_u8(&buf, (uint8_t)key_id);
    }
    if (rc == SSH_OK && previous == NULL) {
        rc = ssh_buffer_put_bytes(&buf, session_id, session_id_len);
    }
    if (rc == SSH_OK && previous != NULL) {
        rc = ssh_buffer_put_bytes(&buf, previous, previous_len);
    }
    if (rc != SSH_OK) {
        secure_zero_bytes(input, sizeof(input));
        return rc;
    }

    status = psa_hash_compute(PSA_ALG_SHA_256, input, ssh_buffer_len(&buf), out, 32u, &hash_len);
    secure_zero_bytes(input, sizeof(input));
    return status == PSA_SUCCESS && hash_len == 32u ? SSH_OK : SSH_ERR_PLATFORM;
}

static int mbedtls_derive_key(
    void *ctx,
    ssh_string_view_t hash_algorithm,
    const uint8_t *shared_secret,
    size_t shared_secret_len,
    const uint8_t *exchange_hash,
    size_t exchange_hash_len,
    const uint8_t *session_id,
    size_t session_id_len,
    char key_id,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    uint8_t round[32];
    size_t written;
    int rc;

    (void)ctx;

    if (!view_eq(hash_algorithm, "curve25519-sha256") ||
        shared_secret == NULL || exchange_hash == NULL || session_id == NULL ||
        out == NULL || out_len == NULL || out_capacity == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    written = 0u;
    rc = ssh_kdf_hash_round(
        shared_secret,
        shared_secret_len,
        exchange_hash,
        exchange_hash_len,
        session_id,
        session_id_len,
        key_id,
        NULL,
        0u,
        round);
    if (rc != SSH_OK) {
        return rc;
    }

    while (written < out_capacity) {
        size_t take = out_capacity - written;
        if (take > sizeof(round)) {
            take = sizeof(round);
        }
        memcpy(out + written, round, take);
        written += take;

        if (written < out_capacity) {
            rc = ssh_kdf_hash_round(
                shared_secret,
                shared_secret_len,
                exchange_hash,
                exchange_hash_len,
                session_id,
                session_id_len,
                key_id,
                out,
                written,
                round);
            if (rc != SSH_OK) {
                secure_zero_bytes(round, sizeof(round));
                return rc;
            }
        }
    }

    secure_zero_bytes(round, sizeof(round));
    *out_len = out_capacity;
    return SSH_OK;
}

static int import_transient_key(
    psa_key_type_t type,
    psa_key_usage_t usage,
    psa_algorithm_t alg,
    const uint8_t *key_data,
    size_t key_len,
    mbedtls_svc_key_id_t *key)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;

    psa_set_key_type(&attributes, type);
    psa_set_key_bits(&attributes, key_len * 8u);
    psa_set_key_usage_flags(&attributes, usage);
    psa_set_key_algorithm(&attributes, alg);
    status = psa_import_key(&attributes, key_data, key_len, key);
    psa_reset_key_attributes(&attributes);
    return psa_ok(status);
}

static int mbedtls_cipher_crypt(
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
    mbedtls_svc_key_id_t key_id = 0;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    uint8_t output[EMSSH_MAX_PACKET_SIZE + 4u];
    size_t output_len = 0u;
    size_t finish_len = 0u;
    psa_status_t status;
    int rc;

    (void)ctx;
    (void)sequence;

    if (!view_eq(cipher_algorithm, "aes128-ctr") ||
        key == NULL || key_len != 16u || iv == NULL || iv_len != 16u ||
        (data == NULL && data_len != 0u) || data_len > sizeof(output)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    rc = import_transient_key(
        PSA_KEY_TYPE_AES,
        direction == SSH_CIPHER_ENCRYPT ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT,
        PSA_ALG_CTR,
        key,
        key_len,
        &key_id);
    if (rc != SSH_OK) {
        return rc;
    }

    if (direction == SSH_CIPHER_ENCRYPT) {
        status = psa_cipher_encrypt_setup(&operation, key_id, PSA_ALG_CTR);
    } else {
        status = psa_cipher_decrypt_setup(&operation, key_id, PSA_ALG_CTR);
    }
    if (status == PSA_SUCCESS) {
        status = psa_cipher_set_iv(&operation, iv, iv_len);
    }
    if (status == PSA_SUCCESS) {
        status = psa_cipher_update(&operation, data, data_len, output, sizeof(output), &output_len);
    }
    if (status == PSA_SUCCESS) {
        status = psa_cipher_finish(&operation, output + output_len, sizeof(output) - output_len, &finish_len);
    }

    (void)psa_cipher_abort(&operation);
    (void)psa_destroy_key(key_id);

    if (status != PSA_SUCCESS || output_len + finish_len != data_len) {
        secure_zero_bytes(output, sizeof(output));
        return SSH_ERR_PLATFORM;
    }

    memcpy(data, output, data_len);
    secure_zero_bytes(output, sizeof(output));
    return SSH_OK;
}

static int mbedtls_mac_compute(
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
    mbedtls_svc_key_id_t key_id = 0;
    uint8_t input[4u + EMSSH_MAX_PACKET_SIZE + 4u];
    int rc;
    psa_status_t status;

    (void)ctx;

    if (!view_eq(mac_algorithm, "hmac-sha2-256") ||
        key == NULL || key_len == 0u ||
        data == NULL || data_len > EMSSH_MAX_PACKET_SIZE + 4u ||
        mac == NULL || mac_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    input[0] = (uint8_t)((sequence >> 24) & 0xffu);
    input[1] = (uint8_t)((sequence >> 16) & 0xffu);
    input[2] = (uint8_t)((sequence >> 8) & 0xffu);
    input[3] = (uint8_t)(sequence & 0xffu);
    memcpy(input + 4u, data, data_len);

    rc = import_transient_key(
        PSA_KEY_TYPE_HMAC,
        PSA_KEY_USAGE_SIGN_MESSAGE,
        PSA_ALG_HMAC(PSA_ALG_SHA_256),
        key,
        key_len,
        &key_id);
    if (rc != SSH_OK) {
        secure_zero_bytes(input, sizeof(input));
        return rc;
    }

    status = psa_mac_compute(
        key_id,
        PSA_ALG_HMAC(PSA_ALG_SHA_256),
        input,
        data_len + 4u,
        mac,
        mac_capacity,
        mac_len);

    (void)psa_destroy_key(key_id);
    secure_zero_bytes(input, sizeof(input));
    return psa_ok(status);
}

static void mbedtls_secure_zero(void *ctx, void *ptr, size_t len)
{
    (void)ctx;
    secure_zero_bytes(ptr, len);
}

static int mbedtls_hostkey_import_private_auto(
    void *ctx,
    ssh_string_view_t hostkey_algorithm,
    const uint8_t *private_key_data,
    size_t private_key_data_len)
{
    ssh_mbedtls_crypto_t *crypto = (ssh_mbedtls_crypto_t *)ctx;

    if (crypto == NULL || private_key_data == NULL || private_key_data_len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (view_eq(hostkey_algorithm, "ecdsa-sha2-nistp256")) {
        return ssh_mbedtls_crypto_import_ecdsa_p256_hostkey(crypto, private_key_data, private_key_data_len);
    }
    if (view_eq(hostkey_algorithm, "ssh-ed25519")) {
        return ssh_mbedtls_crypto_import_ed25519_hostkey(crypto, private_key_data, private_key_data_len);
    }
    if (view_eq(hostkey_algorithm, "rsa-sha2-256") ||
        view_eq(hostkey_algorithm, "rsa-sha2-512") ||
        view_eq(hostkey_algorithm, "ssh-rsa")) {
        return import_rsa_hostkey_auto(crypto, private_key_data, private_key_data_len);
    }
    return SSH_ERR_UNSUPPORTED;
}

static int mbedtls_hostkey_export_private(
    void *ctx,
    ssh_string_view_t hostkey_algorithm,
    uint8_t *private_key,
    size_t private_key_capacity,
    size_t *private_key_len)
{
    ssh_mbedtls_crypto_t *crypto = (ssh_mbedtls_crypto_t *)ctx;

    if (crypto == NULL || private_key == NULL || private_key_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (view_eq(hostkey_algorithm, "ecdsa-sha2-nistp256") ||
        view_eq(hostkey_algorithm, "ssh-ed25519") ||
        view_eq(hostkey_algorithm, "rsa-sha2-256") ||
        view_eq(hostkey_algorithm, "rsa-sha2-512") ||
        view_eq(hostkey_algorithm, "ssh-rsa")) {
        return ssh_mbedtls_crypto_export_hostkey_private(
            crypto,
            private_key,
            private_key_capacity,
            private_key_len);
    }
    return SSH_ERR_UNSUPPORTED;
}

static int mbedtls_hostkey_generate(void *ctx, ssh_string_view_t hostkey_algorithm)
{
    ssh_mbedtls_crypto_t *crypto = (ssh_mbedtls_crypto_t *)ctx;

    if (crypto == NULL || hostkey_algorithm.data == NULL || hostkey_algorithm.len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (view_eq(hostkey_algorithm, "ecdsa-sha2-nistp256")) {
        return ssh_mbedtls_crypto_generate_ecdsa_p256_hostkey(crypto);
    }
    if (view_eq(hostkey_algorithm, "ssh-ed25519")) {
        return ssh_mbedtls_crypto_generate_ed25519_hostkey(crypto);
    }
    return SSH_ERR_UNSUPPORTED;
}

static void mbedtls_kexinit_defaults(void *ctx, ssh_kexinit_algorithm_set_t *algorithms)
{
    (void)ctx;
    if (algorithms == NULL) {
        return;
    }
    ssh_mbedtls_kexinit_algorithm_set_defaults(algorithms);
}

int ssh_mbedtls_crypto_init(ssh_mbedtls_crypto_t *ctx)
{
    psa_status_t status;

    if (ctx == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(ctx, 0, sizeof(*ctx));

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return psa_ok_or_unsupported(status);
    }

    ctx->api.name = "mbedtls-psa";
    ctx->api.kex_generate_keypair = mbedtls_kex_generate_keypair;
    ctx->api.kex_compute_shared_secret = mbedtls_kex_compute_shared_secret;
    ctx->api.hostkey_public = mbedtls_hostkey_public;
    ctx->api.hash_exchange = mbedtls_hash_exchange;
    ctx->api.hostkey_sign = mbedtls_hostkey_sign;
    ctx->api.publickey_verify = mbedtls_publickey_verify;
    ctx->api.derive_key = mbedtls_derive_key;
    ctx->api.cipher_crypt = mbedtls_cipher_crypt;
    ctx->api.mac_compute = mbedtls_mac_compute;
    ctx->api.hostkey_import_private_auto = mbedtls_hostkey_import_private_auto;
    ctx->api.hostkey_export_private = mbedtls_hostkey_export_private;
    ctx->api.hostkey_generate = mbedtls_hostkey_generate;
    ctx->api.kexinit_defaults = mbedtls_kexinit_defaults;
    ctx->api.secure_zero = mbedtls_secure_zero;
    ctx->api.ctx = ctx;

    ctx->rng.fill = mbedtls_rng_fill;
    ctx->rng.ctx = ctx;

    ctx->initialized = 1;
    return SSH_OK;
}

void ssh_mbedtls_crypto_free(ssh_mbedtls_crypto_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    destroy_owned_hostkey(ctx);

    secure_zero_bytes(ctx, sizeof(*ctx));
}

int ssh_mbedtls_crypto_generate_ed25519_hostkey(ssh_mbedtls_crypto_t *ctx)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = 0;
    psa_status_t status;

    if (ctx == NULL || !ctx->initialized) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    destroy_owned_hostkey(ctx);

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attributes, 255u);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_PURE_EDDSA);

    status = psa_generate_key(&attributes, &key);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        return psa_ok_or_unsupported(status);
    }

    ctx->hostkey_id = (uint32_t)key;
    ctx->owns_hostkey = 1;
    return SSH_OK;
}

int ssh_mbedtls_crypto_generate_ecdsa_p256_hostkey(ssh_mbedtls_crypto_t *ctx)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = 0;
    psa_status_t status;

    if (ctx == NULL || !ctx->initialized) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    destroy_owned_hostkey(ctx);

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256u);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    status = psa_generate_key(&attributes, &key);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        return SSH_ERR_PLATFORM;
    }

    ctx->hostkey_id = (uint32_t)key;
    ctx->owns_hostkey = 1;
    return SSH_OK;
}

static int import_hostkey(
    ssh_mbedtls_crypto_t *ctx,
    psa_ecc_family_t family,
    size_t bits,
    psa_key_usage_t usage,
    psa_algorithm_t alg,
    const uint8_t *private_key,
    size_t private_key_len)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = 0;
    psa_status_t status;

    if (ctx == NULL || !ctx->initialized ||
        private_key == NULL || private_key_len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    destroy_owned_hostkey(ctx);

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(family));
    psa_set_key_bits(&attributes, bits);
    psa_set_key_usage_flags(&attributes, usage | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, alg);

    status = psa_import_key(&attributes, private_key, private_key_len, &key);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        return psa_ok_or_unsupported(status);
    }

    ctx->hostkey_id = (uint32_t)key;
    ctx->owns_hostkey = 1;
    return SSH_OK;
}

int ssh_mbedtls_crypto_import_ed25519_hostkey(
    ssh_mbedtls_crypto_t *ctx,
    const uint8_t *private_key,
    size_t private_key_len)
{
    return import_hostkey(
        ctx,
        PSA_ECC_FAMILY_TWISTED_EDWARDS,
        255u,
        PSA_KEY_USAGE_SIGN_MESSAGE,
        PSA_ALG_PURE_EDDSA,
        private_key,
        private_key_len);
}

int ssh_mbedtls_crypto_import_ecdsa_p256_hostkey(
    ssh_mbedtls_crypto_t *ctx,
    const uint8_t *private_key,
    size_t private_key_len)
{
    return import_hostkey(
        ctx,
        PSA_ECC_FAMILY_SECP_R1,
        256u,
        PSA_KEY_USAGE_SIGN_MESSAGE,
        PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        private_key,
        private_key_len);
}

static int import_rsa_hostkey_der(
    ssh_mbedtls_crypto_t *ctx,
    const uint8_t *private_key_der,
    size_t private_key_der_len)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = 0;
    psa_status_t status;

    if (ctx == NULL || !ctx->initialized ||
        private_key_der == NULL || private_key_der_len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    destroy_owned_hostkey(ctx);

    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH));

    status = psa_import_key(&attributes, private_key_der, private_key_der_len, &key);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        return psa_ok_or_unsupported(status);
    }

    ctx->hostkey_id = (uint32_t)key;
    ctx->owns_hostkey = 1;
    return SSH_OK;
}

static int import_rsa_hostkey_auto(
    ssh_mbedtls_crypto_t *ctx,
    const uint8_t *private_key_data,
    size_t private_key_data_len)
{
    static const char k_begin_rsa[] = "-----BEGIN RSA PRIVATE KEY-----";
    static const char k_end_rsa[] = "-----END RSA PRIVATE KEY-----";
    static const char k_begin_pkcs8[] = "-----BEGIN PRIVATE KEY-----";
    static const char k_end_pkcs8[] = "-----END PRIVATE KEY-----";
    uint8_t der[4096];
    size_t der_len;
    int status;

    if (ctx == NULL || private_key_data == NULL || private_key_data_len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = decode_pem_block(
        private_key_data,
        private_key_data_len,
        k_begin_rsa,
        k_end_rsa,
        der,
        sizeof(der),
        &der_len);
    if (status == SSH_ERR_NOT_FOUND) {
        status = decode_pem_block(
            private_key_data,
            private_key_data_len,
            k_begin_pkcs8,
            k_end_pkcs8,
            der,
            sizeof(der),
            &der_len);
    }
    if (status == SSH_OK) {
        int import_status = import_rsa_hostkey_der(ctx, der, der_len);
        secure_zero_bytes(der, sizeof(der));
        return import_status;
    }
    if (status != SSH_ERR_NOT_FOUND) {
        secure_zero_bytes(der, sizeof(der));
        return status;
    }
    secure_zero_bytes(der, sizeof(der));
    return import_rsa_hostkey_der(ctx, private_key_data, private_key_data_len);
}

int ssh_mbedtls_crypto_export_hostkey_private(
    ssh_mbedtls_crypto_t *ctx,
    uint8_t *private_key,
    size_t private_key_capacity,
    size_t *private_key_len)
{
    psa_status_t status;

    if (ctx == NULL || !ctx->initialized ||
        ctx->hostkey_id == 0u ||
        private_key == NULL || private_key_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = psa_export_key(
        (mbedtls_svc_key_id_t)ctx->hostkey_id,
        private_key,
        private_key_capacity,
        private_key_len);
    return psa_ok_or_unsupported(status);
}

static int probe_ed25519_support(int verify_publickey)
{
    ssh_mbedtls_crypto_t probe;
    const ssh_crypto_api_t *crypto;
    ssh_string_view_t algorithm;
    uint8_t hostkey_blob[EMSSH_MAX_HOST_KEY_BLOB];
    uint8_t exchange_hash[32];
    uint8_t signature[EMSSH_MAX_SIGNATURE];
    size_t hostkey_blob_len;
    size_t signature_len;
    int status;

    memset(&probe, 0, sizeof(probe));
    memset(exchange_hash, verify_publickey ? 0x3cu : 0x5au, sizeof(exchange_hash));
    memset(&algorithm, 0, sizeof(algorithm));
    algorithm.data = (const uint8_t *)"ssh-ed25519";
    algorithm.len = strlen("ssh-ed25519");
    hostkey_blob_len = 0u;
    signature_len = 0u;

    status = ssh_mbedtls_crypto_init(&probe);
    if (status != SSH_OK) {
        return status;
    }

    status = ssh_mbedtls_crypto_generate_ed25519_hostkey(&probe);
    if (status != SSH_OK) {
        ssh_mbedtls_crypto_free(&probe);
        return status;
    }

    crypto = ssh_mbedtls_crypto_api(&probe);
    if (crypto == NULL || crypto->hostkey_public == NULL || crypto->hostkey_sign == NULL ||
        (verify_publickey && crypto->publickey_verify == NULL)) {
        ssh_mbedtls_crypto_free(&probe);
        return SSH_ERR_PLATFORM;
    }

    status = crypto->hostkey_public(
        crypto->ctx,
        algorithm,
        hostkey_blob,
        sizeof(hostkey_blob),
        &hostkey_blob_len);
    if (status == SSH_OK) {
        status = crypto->hostkey_sign(
            crypto->ctx,
            algorithm,
            exchange_hash,
            sizeof(exchange_hash),
            signature,
            sizeof(signature),
            &signature_len);
    }
    if (status == SSH_OK && verify_publickey) {
        status = crypto->publickey_verify(
            crypto->ctx,
            algorithm,
            hostkey_blob,
            hostkey_blob_len,
            exchange_hash,
            sizeof(exchange_hash),
            signature,
            signature_len);
    }

    ssh_mbedtls_crypto_free(&probe);
    return status;
}

int ssh_mbedtls_probe_ed25519_hostkey_support(void)
{
    return probe_ed25519_support(0);
}

int ssh_mbedtls_probe_ed25519_publickey_verify_support(void)
{
    return probe_ed25519_support(1);
}

const ssh_crypto_api_t *ssh_mbedtls_crypto_api(ssh_mbedtls_crypto_t *ctx)
{
    return ctx != NULL && ctx->initialized ? &ctx->api : NULL;
}

const ssh_rng_api_t *ssh_mbedtls_rng_api(ssh_mbedtls_crypto_t *ctx)
{
    return ctx != NULL && ctx->initialized ? &ctx->rng : NULL;
}

void ssh_mbedtls_kexinit_algorithm_set_defaults(ssh_kexinit_algorithm_set_t *algorithms)
{
    if (algorithms == NULL) {
        return;
    }

    ssh_kexinit_algorithm_set_defaults(algorithms);
    algorithms->kex_algorithms = "curve25519-sha256,ext-info-s";
    algorithms->server_host_key_algorithms = "ecdsa-sha2-nistp256";
    algorithms->encryption_algorithms_client_to_server = "aes128-ctr";
    algorithms->encryption_algorithms_server_to_client = "aes128-ctr";
    algorithms->mac_algorithms_client_to_server = "hmac-sha2-256";
    algorithms->mac_algorithms_server_to_client = "hmac-sha2-256";
    algorithms->compression_algorithms_client_to_server = "none";
    algorithms->compression_algorithms_server_to_client = "none";
}

static ssh_crypto_context_mbedtls_t *crypto_context_mbedtls_mut(ssh_crypto_context_t *crypto_ctx)
{
    if (crypto_ctx == NULL) {
        return NULL;
    }
    return (ssh_crypto_context_mbedtls_t *)crypto_ctx;
}

static const ssh_crypto_context_mbedtls_t *crypto_context_mbedtls(const ssh_crypto_context_t *crypto_ctx)
{
    if (crypto_ctx == NULL) {
        return NULL;
    }
    return (const ssh_crypto_context_mbedtls_t *)crypto_ctx;
}

const char *ssh_crypto_name(void)
{
    return "mbedtls";
}

const char *ssh_crypto_publickey_signature_algorithms(void)
{
    if (ssh_mbedtls_probe_ed25519_publickey_verify_support() == SSH_OK) {
        return "rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256,ssh-ed25519";
    }
    return "rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256";
}

int ssh_crypto_open(ssh_crypto_context_t *crypto_ctx)
{
    ssh_crypto_context_mbedtls_t *impl;
    int status;

    if (crypto_ctx == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    impl = crypto_context_mbedtls_mut(crypto_ctx);
    memset(impl, 0, sizeof(*impl));

    status = ssh_mbedtls_crypto_init(&impl->mbedtls);
    if (status != SSH_OK) {
        memset(impl, 0, sizeof(*impl));
        return status;
    }
    impl->crypto = ssh_mbedtls_crypto_api(&impl->mbedtls);
    impl->rng = ssh_mbedtls_rng_api(&impl->mbedtls);
    if (impl->crypto == NULL || impl->rng == NULL) {
        ssh_mbedtls_crypto_free(&impl->mbedtls);
        memset(impl, 0, sizeof(*impl));
        return SSH_ERR_PLATFORM;
    }
    return SSH_OK;
}

void ssh_crypto_close(ssh_crypto_context_t *crypto_ctx)
{
    ssh_crypto_context_mbedtls_t *impl = crypto_context_mbedtls_mut(crypto_ctx);

    if (impl == NULL) {
        return;
    }
    ssh_mbedtls_crypto_free(&impl->mbedtls);
    memset(impl, 0, sizeof(*impl));
}

const ssh_crypto_api_t *ssh_crypto_api(const ssh_crypto_context_t *crypto_ctx)
{
    const ssh_crypto_context_mbedtls_t *impl = crypto_context_mbedtls(crypto_ctx);
    return impl != NULL ? impl->crypto : NULL;
}

const ssh_rng_api_t *ssh_crypto_rng_api(const ssh_crypto_context_t *crypto_ctx)
{
    const ssh_crypto_context_mbedtls_t *impl = crypto_context_mbedtls(crypto_ctx);
    return impl != NULL ? impl->rng : NULL;
}
