#include <stdio.h>
#include <string.h>

#include "emssh/crypto_mbedtls.h"
#include "emssh/ssh_buffer.h"
#include "emssh/ssh_error.h"

#include <psa/crypto.h>

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static ssh_string_view_t sv(const char *value)
{
    ssh_string_view_t view;
    view.data = (const uint8_t *)value;
    view.len = strlen(value);
    return view;
}

static int der_get_length(const uint8_t *der, size_t der_len, size_t *offset, size_t *len)
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

static int rsa_der_public_to_ssh_blob(
    const uint8_t *der,
    size_t der_len,
    uint8_t *blob,
    size_t blob_capacity,
    size_t *blob_len)
{
    ssh_buffer_t out;
    ssh_string_view_t n;
    ssh_string_view_t e;
    size_t offset;
    size_t sequence_len;
    size_t sequence_end;
    int status;

    if (der == NULL || blob == NULL || blob_len == NULL || der_len == 0u) {
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

    ssh_buffer_init(&out, blob, blob_capacity);
    status = ssh_buffer_put_cstring(&out, "ssh-rsa");
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(&out, e.data, e.len);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(&out, n.data, n.len);
    }
    if (status != SSH_OK) {
        return status;
    }

    *blob_len = ssh_buffer_len(&out);
    return SSH_OK;
}

static int rsa_signature_blob_encode(
    const char *algorithm,
    const uint8_t *signature,
    size_t signature_len,
    uint8_t *blob,
    size_t blob_capacity,
    size_t *blob_len)
{
    ssh_buffer_t out;
    int status;

    if (algorithm == NULL || signature == NULL || blob == NULL || blob_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    ssh_buffer_init(&out, blob, blob_capacity);
    status = ssh_buffer_put_cstring(&out, algorithm);
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(&out, signature, signature_len);
    }
    if (status != SSH_OK) {
        return status;
    }

    *blob_len = ssh_buffer_len(&out);
    return SSH_OK;
}

typedef struct rsa_private_der_views {
    ssh_string_view_t n;
    ssh_string_view_t e;
    ssh_string_view_t d;
    ssh_string_view_t p;
    ssh_string_view_t q;
    ssh_string_view_t iqmp;
} rsa_private_der_views_t;

static int rsa_private_der_parse(
    const uint8_t *der,
    size_t der_len,
    rsa_private_der_views_t *key)
{
    ssh_string_view_t version;
    ssh_string_view_t ignored;
    size_t offset;
    size_t sequence_len;
    size_t sequence_end;
    int status;

    if (der == NULL || key == NULL || der_len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(key, 0, sizeof(*key));
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

    status = der_get_integer_view(der, sequence_end, &offset, &version);
    if (status == SSH_OK) {
        status = der_get_integer_view(der, sequence_end, &offset, &key->n);
    }
    if (status == SSH_OK) {
        status = der_get_integer_view(der, sequence_end, &offset, &key->e);
    }
    if (status == SSH_OK) {
        status = der_get_integer_view(der, sequence_end, &offset, &key->d);
    }
    if (status == SSH_OK) {
        status = der_get_integer_view(der, sequence_end, &offset, &key->p);
    }
    if (status == SSH_OK) {
        status = der_get_integer_view(der, sequence_end, &offset, &key->q);
    }
    if (status == SSH_OK) {
        status = der_get_integer_view(der, sequence_end, &offset, &ignored);
    }
    if (status == SSH_OK) {
        status = der_get_integer_view(der, sequence_end, &offset, &ignored);
    }
    if (status == SSH_OK) {
        status = der_get_integer_view(der, sequence_end, &offset, &key->iqmp);
    }
    if (status != SSH_OK) {
        return status;
    }
    if (version.len != 1u || version.data[0] != 0u || offset != sequence_end) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return SSH_OK;
}

static int pem_wrap_base64(
    const uint8_t *data,
    size_t data_len,
    const char *begin,
    const char *end,
    char *pem,
    size_t pem_capacity,
    size_t *pem_len)
{
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i;
    size_t used;
    size_t line;
    size_t begin_len;
    size_t end_len;

    if (data == NULL || begin == NULL || end == NULL || pem == NULL || pem_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    begin_len = strlen(begin);
    end_len = strlen(end);
    used = 0u;
    if (begin_len + end_len + 1u > pem_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(pem + used, begin, begin_len);
    used += begin_len;
    line = 0u;

    for (i = 0u; i < data_len; i += 3u) {
        uint32_t triple = 0u;
        size_t rem = data_len - i;
        if (rem > 3u) {
            rem = 3u;
        }
        triple |= ((uint32_t)data[i]) << 16;
        if (rem > 1u) {
            triple |= ((uint32_t)data[i + 1u]) << 8;
        }
        if (rem > 2u) {
            triple |= (uint32_t)data[i + 2u];
        }

        if (used + 4u + 2u + end_len + 1u > pem_capacity) {
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
    memcpy(pem + used, end, end_len);
    used += end_len;
    pem[used] = '\0';
    *pem_len = used;
    return SSH_OK;
}

static int der_to_rsa_private_pem(
    const uint8_t *der,
    size_t der_len,
    char *pem,
    size_t pem_capacity,
    size_t *pem_len)
{
    return pem_wrap_base64(
        der,
        der_len,
        "-----BEGIN RSA PRIVATE KEY-----\n",
        "-----END RSA PRIVATE KEY-----\n",
        pem,
        pem_capacity,
        pem_len);
}

static int rsa_private_der_to_openssh_pem(
    const uint8_t *der,
    size_t der_len,
    char *pem,
    size_t pem_capacity,
    size_t *pem_len)
{
    static const uint8_t magic[] = "openssh-key-v1";
    static const uint8_t empty[] = "";
    rsa_private_der_views_t key;
    uint8_t public_blob[512];
    uint8_t private_blob[2048];
    uint8_t openssh_blob[3072];
    ssh_buffer_t public_buf;
    ssh_buffer_t private_buf;
    ssh_buffer_t outer;
    size_t pad_len;
    size_t i;
    int status;

    if (der == NULL || pem == NULL || pem_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = rsa_private_der_parse(der, der_len, &key);
    if (status != SSH_OK) {
        return status;
    }

    ssh_buffer_init(&public_buf, public_blob, sizeof(public_blob));
    status = ssh_buffer_put_cstring(&public_buf, "ssh-rsa");
    if (status == SSH_OK) {
        status = ssh_buffer_put_mpint_positive(&public_buf, key.e.data, key.e.len);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_mpint_positive(&public_buf, key.n.data, key.n.len);
    }
    if (status != SSH_OK) {
        return status;
    }

    ssh_buffer_init(&private_buf, private_blob, sizeof(private_blob));
    status = ssh_buffer_put_u32(&private_buf, 0x12345678u);
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(&private_buf, 0x12345678u);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(&private_buf, "ssh-rsa");
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_mpint_positive(&private_buf, key.n.data, key.n.len);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_mpint_positive(&private_buf, key.e.data, key.e.len);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_mpint_positive(&private_buf, key.d.data, key.d.len);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_mpint_positive(&private_buf, key.iqmp.data, key.iqmp.len);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_mpint_positive(&private_buf, key.p.data, key.p.len);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_mpint_positive(&private_buf, key.q.data, key.q.len);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(&private_buf, "emssh-test");
    }
    if (status != SSH_OK) {
        return status;
    }

    pad_len = 8u - (ssh_buffer_len(&private_buf) % 8u);
    if (pad_len == 0u) {
        pad_len = 8u;
    }
    for (i = 1u; status == SSH_OK && i <= pad_len; ++i) {
        status = ssh_buffer_put_u8(&private_buf, (uint8_t)i);
    }
    if (status != SSH_OK) {
        return status;
    }

    ssh_buffer_init(&outer, openssh_blob, sizeof(openssh_blob));
    status = ssh_buffer_put_bytes(&outer, magic, sizeof(magic));
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(&outer, "none");
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_cstring(&outer, "none");
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(&outer, empty, 0u);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_u32(&outer, 1u);
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(&outer, public_blob, ssh_buffer_len(&public_buf));
    }
    if (status == SSH_OK) {
        status = ssh_buffer_put_string(&outer, private_blob, ssh_buffer_len(&private_buf));
    }
    if (status != SSH_OK) {
        return status;
    }

    return pem_wrap_base64(
        openssh_blob,
        ssh_buffer_len(&outer),
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "-----END OPENSSH PRIVATE KEY-----\n",
        pem,
        pem_capacity,
        pem_len);
}

int main(void)
{
    ssh_mbedtls_crypto_t crypto_ctx;
    ssh_mbedtls_crypto_t imported_ctx;
    psa_key_attributes_t rsa_attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t rsa_key = 0;
    const ssh_crypto_api_t *crypto;
    const ssh_crypto_api_t *imported_crypto;
    const ssh_rng_api_t *rng;
    uint8_t random_buf[16];
    uint8_t public_key_a[EMSSH_MAX_KEX_PUBLIC_KEY];
    uint8_t private_key_a[EMSSH_MAX_KEX_PRIVATE_KEY];
    uint8_t public_key_b[EMSSH_MAX_KEX_PUBLIC_KEY];
    uint8_t private_key_b[EMSSH_MAX_KEX_PRIVATE_KEY];
    uint8_t secret_a[EMSSH_MAX_KEX_SHARED_SECRET];
    uint8_t secret_b[EMSSH_MAX_KEX_SHARED_SECRET];
    uint8_t hostkey[EMSSH_MAX_HOST_KEY_BLOB];
    uint8_t imported_hostkey[EMSSH_MAX_HOST_KEY_BLOB];
    uint8_t rsa_public_der[192];
    uint8_t rsa_public_blob[EMSSH_MAX_HOST_KEY_BLOB];
    uint8_t rsa_raw_signature[192];
    uint8_t rsa_signature_blob[256];
    uint8_t rsa_legacy_signature_blob[256];
    uint8_t rsa_private_der[2048];
    char rsa_private_pem[3072];
    char rsa_private_openssh_pem[4096];
    uint8_t rsa_hostkey_blob[EMSSH_MAX_HOST_KEY_BLOB];
    uint8_t rsa_openssh_hostkey_blob[EMSSH_MAX_HOST_KEY_BLOB];
    uint8_t rsa_hostkey_signature[EMSSH_MAX_SIGNATURE];
    uint8_t rsa_openssh_hostkey_signature[EMSSH_MAX_SIGNATURE];
    uint8_t hostkey_private[128];
    uint8_t hash[EMSSH_MAX_EXCHANGE_HASH];
    uint8_t signature[EMSSH_MAX_SIGNATURE];
    uint8_t derived[32];
    uint8_t mac[EMSSH_MAX_MAC];
    uint8_t packet[16] = {0, 0, 0, 12, 8, 1, 2, 3, 4, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11, 0x22};
    uint8_t original_packet[16];
    uint8_t key[16];
    uint8_t iv[16];
    size_t public_key_a_len;
    size_t private_key_a_len;
    size_t public_key_b_len;
    size_t private_key_b_len;
    size_t secret_a_len;
    size_t secret_b_len;
    size_t hostkey_len;
    size_t imported_hostkey_len;
    size_t rsa_public_der_len;
    size_t rsa_public_blob_len;
    size_t rsa_raw_signature_len;
    size_t rsa_signature_blob_len;
    size_t rsa_legacy_signature_blob_len;
    size_t rsa_private_der_len;
    size_t rsa_private_pem_len;
    size_t rsa_private_openssh_pem_len;
    size_t rsa_hostkey_blob_len;
    size_t rsa_openssh_hostkey_blob_len;
    size_t rsa_hostkey_signature_len;
    size_t rsa_openssh_hostkey_signature_len;
    size_t hostkey_private_len;
    size_t hash_len;
    size_t signature_len;
    size_t derived_len;
    size_t mac_len;
    int status;
    size_t i;

    memset(&imported_ctx, 0, sizeof(imported_ctx));
    CHECK(ssh_mbedtls_crypto_init(&crypto_ctx) == SSH_OK);
    crypto = ssh_mbedtls_crypto_api(&crypto_ctx);
    rng = ssh_mbedtls_rng_api(&crypto_ctx);
    CHECK(crypto != NULL);
    CHECK(rng != NULL);
    CHECK(rng->fill(rng->ctx, random_buf, sizeof(random_buf)) == SSH_OK);

    CHECK(ssh_mbedtls_crypto_generate_ecdsa_p256_hostkey(&crypto_ctx) == SSH_OK);
    CHECK(crypto->hostkey_public(crypto->ctx, sv("ecdsa-sha2-nistp256"), hostkey, sizeof(hostkey), &hostkey_len) == SSH_OK);
    CHECK(hostkey_len > strlen("ecdsa-sha2-nistp256"));
    CHECK(ssh_mbedtls_crypto_export_hostkey_private(
        &crypto_ctx,
        hostkey_private,
        sizeof(hostkey_private),
        &hostkey_private_len) == SSH_OK);
    CHECK(hostkey_private_len > 0u);

    CHECK(ssh_mbedtls_crypto_init(&imported_ctx) == SSH_OK);
    CHECK(ssh_mbedtls_crypto_import_ecdsa_p256_hostkey(&imported_ctx, hostkey_private, hostkey_private_len) == SSH_OK);
    imported_crypto = ssh_mbedtls_crypto_api(&imported_ctx);
    CHECK(imported_crypto != NULL);
    CHECK(imported_crypto->hostkey_public(
        imported_crypto->ctx,
        sv("ecdsa-sha2-nistp256"),
        imported_hostkey,
        sizeof(imported_hostkey),
        &imported_hostkey_len) == SSH_OK);
    CHECK(imported_hostkey_len == hostkey_len);
    CHECK(memcmp(imported_hostkey, hostkey, hostkey_len) == 0);

    CHECK(crypto->kex_generate_keypair(
        crypto->ctx,
        sv("curve25519-sha256"),
        public_key_a,
        sizeof(public_key_a),
        &public_key_a_len,
        private_key_a,
        sizeof(private_key_a),
        &private_key_a_len) == SSH_OK);
    CHECK(crypto->kex_generate_keypair(
        crypto->ctx,
        sv("curve25519-sha256"),
        public_key_b,
        sizeof(public_key_b),
        &public_key_b_len,
        private_key_b,
        sizeof(private_key_b),
        &private_key_b_len) == SSH_OK);

    CHECK(crypto->kex_compute_shared_secret(
        crypto->ctx,
        sv("curve25519-sha256"),
        private_key_a,
        private_key_a_len,
        public_key_b,
        public_key_b_len,
        secret_a,
        sizeof(secret_a),
        &secret_a_len) == SSH_OK);
    CHECK(crypto->kex_compute_shared_secret(
        crypto->ctx,
        sv("curve25519-sha256"),
        private_key_b,
        private_key_b_len,
        public_key_a,
        public_key_a_len,
        secret_b,
        sizeof(secret_b),
        &secret_b_len) == SSH_OK);
    CHECK(secret_a_len == secret_b_len);
    CHECK(memcmp(secret_a, secret_b, secret_a_len) == 0);

    CHECK(crypto->hash_exchange(
        crypto->ctx,
        sv("curve25519-sha256"),
        (const uint8_t *)"exchange-data",
        strlen("exchange-data"),
        hash,
        sizeof(hash),
        &hash_len) == SSH_OK);
    CHECK(hash_len == 32u);

    CHECK(imported_crypto->hostkey_sign(
        imported_crypto->ctx,
        sv("ecdsa-sha2-nistp256"),
        hash,
        hash_len,
        signature,
        sizeof(signature),
        &signature_len) == SSH_OK);
    CHECK(signature_len > strlen("ecdsa-sha2-nistp256"));
    CHECK(imported_crypto->publickey_verify(
        imported_crypto->ctx,
        sv("ecdsa-sha2-nistp256"),
        imported_hostkey,
        imported_hostkey_len,
        hash,
        hash_len,
        signature,
        signature_len) == SSH_OK);

    {
        ssh_mbedtls_crypto_t ed25519_ctx;
        ssh_mbedtls_crypto_t ed25519_imported_ctx;
        const ssh_crypto_api_t *ed25519_crypto;
        const ssh_crypto_api_t *ed25519_imported_crypto;
        uint8_t ed25519_hostkey[EMSSH_MAX_HOST_KEY_BLOB];
        uint8_t ed25519_imported_hostkey[EMSSH_MAX_HOST_KEY_BLOB];
        uint8_t ed25519_private[128];
        uint8_t ed25519_signature[EMSSH_MAX_SIGNATURE];
        size_t ed25519_hostkey_len;
        size_t ed25519_imported_hostkey_len;
        size_t ed25519_private_len;
        size_t ed25519_signature_len;
        int ed25519_status;

        memset(&ed25519_ctx, 0, sizeof(ed25519_ctx));
        memset(&ed25519_imported_ctx, 0, sizeof(ed25519_imported_ctx));
        CHECK(ssh_mbedtls_crypto_init(&ed25519_ctx) == SSH_OK);
        CHECK(ssh_mbedtls_crypto_init(&ed25519_imported_ctx) == SSH_OK);
        ed25519_crypto = ssh_mbedtls_crypto_api(&ed25519_ctx);
        ed25519_imported_crypto = ssh_mbedtls_crypto_api(&ed25519_imported_ctx);
        CHECK(ed25519_crypto != NULL);
        CHECK(ed25519_imported_crypto != NULL);

        ed25519_status = ssh_mbedtls_crypto_generate_ed25519_hostkey(&ed25519_ctx);
        CHECK(ed25519_status == SSH_OK || ed25519_status == SSH_ERR_UNSUPPORTED);
        if (ed25519_status == SSH_OK) {
            CHECK(ssh_mbedtls_crypto_export_hostkey_private(
                &ed25519_ctx,
                ed25519_private,
                sizeof(ed25519_private),
                &ed25519_private_len) == SSH_OK);
            CHECK(ed25519_private_len > 0u);
            CHECK(ssh_mbedtls_crypto_import_ed25519_hostkey(
                &ed25519_imported_ctx,
                ed25519_private,
                ed25519_private_len) == SSH_OK);
            CHECK(ed25519_crypto->hostkey_public(
                ed25519_crypto->ctx,
                sv("ssh-ed25519"),
                ed25519_hostkey,
                sizeof(ed25519_hostkey),
                &ed25519_hostkey_len) == SSH_OK);
            CHECK(ed25519_imported_crypto->hostkey_public(
                ed25519_imported_crypto->ctx,
                sv("ssh-ed25519"),
                ed25519_imported_hostkey,
                sizeof(ed25519_imported_hostkey),
                &ed25519_imported_hostkey_len) == SSH_OK);
            CHECK(ed25519_imported_hostkey_len == ed25519_hostkey_len);
            CHECK(memcmp(ed25519_imported_hostkey, ed25519_hostkey, ed25519_hostkey_len) == 0);
            CHECK(ed25519_imported_crypto->hostkey_sign(
                ed25519_imported_crypto->ctx,
                sv("ssh-ed25519"),
                hash,
                hash_len,
                ed25519_signature,
                sizeof(ed25519_signature),
                &ed25519_signature_len) == SSH_OK);
            CHECK(ed25519_imported_crypto->publickey_verify(
                ed25519_imported_crypto->ctx,
                sv("ssh-ed25519"),
                ed25519_imported_hostkey,
                ed25519_imported_hostkey_len,
                hash,
                hash_len,
                ed25519_signature,
                ed25519_signature_len) == SSH_OK);
        }

        ssh_mbedtls_crypto_free(&ed25519_imported_ctx);
        ssh_mbedtls_crypto_free(&ed25519_ctx);
    }

    {
        int hostkey_probe_status;
        int publickey_probe_status;

        hostkey_probe_status = ssh_mbedtls_probe_ed25519_hostkey_support();
        CHECK(hostkey_probe_status == SSH_OK ||
              hostkey_probe_status == SSH_ERR_UNSUPPORTED ||
              hostkey_probe_status == SSH_ERR_PLATFORM);

        publickey_probe_status = ssh_mbedtls_probe_ed25519_publickey_verify_support();
        CHECK(publickey_probe_status == SSH_OK ||
              publickey_probe_status == SSH_ERR_UNSUPPORTED ||
              publickey_probe_status == SSH_ERR_PLATFORM);
    }

    psa_set_key_type(&rsa_attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&rsa_attributes, 1024u);
    psa_set_key_usage_flags(&rsa_attributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&rsa_attributes, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
    {
        psa_status_t rsa_status = psa_generate_key(&rsa_attributes, &rsa_key);
        psa_reset_key_attributes(&rsa_attributes);
        if (rsa_status == PSA_SUCCESS) {
            CHECK(psa_export_key(rsa_key, rsa_private_der, sizeof(rsa_private_der), &rsa_private_der_len) == PSA_SUCCESS);
            CHECK(der_to_rsa_private_pem(
                rsa_private_der,
                rsa_private_der_len,
                rsa_private_pem,
                sizeof(rsa_private_pem),
                &rsa_private_pem_len) == SSH_OK);
            CHECK(rsa_private_der_to_openssh_pem(
                rsa_private_der,
                rsa_private_der_len,
                rsa_private_openssh_pem,
                sizeof(rsa_private_openssh_pem),
                &rsa_private_openssh_pem_len) == SSH_OK);
            CHECK(psa_export_public_key(rsa_key, rsa_public_der, sizeof(rsa_public_der), &rsa_public_der_len) == PSA_SUCCESS);
            CHECK(psa_sign_message(
                rsa_key,
                PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
                (const uint8_t *)"rsa-auth-data",
                strlen("rsa-auth-data"),
                rsa_raw_signature,
                sizeof(rsa_raw_signature),
                &rsa_raw_signature_len) == PSA_SUCCESS);
            CHECK(rsa_der_public_to_ssh_blob(
                rsa_public_der,
                rsa_public_der_len,
                rsa_public_blob,
                sizeof(rsa_public_blob),
                &rsa_public_blob_len) == SSH_OK);
            CHECK(rsa_signature_blob_encode(
                "rsa-sha2-256",
                rsa_raw_signature,
                rsa_raw_signature_len,
                rsa_signature_blob,
                sizeof(rsa_signature_blob),
                &rsa_signature_blob_len) == SSH_OK);
            CHECK(crypto->publickey_verify(
                crypto->ctx,
                sv("rsa-sha2-256"),
                rsa_public_blob,
                rsa_public_blob_len,
                (const uint8_t *)"rsa-auth-data",
                strlen("rsa-auth-data"),
                rsa_signature_blob,
                rsa_signature_blob_len) == SSH_OK);
            CHECK(rsa_signature_blob_encode(
                "ssh-rsa",
                rsa_raw_signature,
                rsa_raw_signature_len,
                rsa_legacy_signature_blob,
                sizeof(rsa_legacy_signature_blob),
                &rsa_legacy_signature_blob_len) == SSH_OK);
            status = crypto->publickey_verify(
                crypto->ctx,
                sv("ssh-rsa"),
                rsa_public_blob,
                rsa_public_blob_len,
                (const uint8_t *)"rsa-auth-data",
                strlen("rsa-auth-data"),
                rsa_legacy_signature_blob,
                rsa_legacy_signature_blob_len);
            CHECK(status == SSH_ERR_UNSUPPORTED);

            CHECK(imported_crypto->hostkey_import_private_auto(
                imported_crypto->ctx,
                sv("rsa-sha2-256"),
                (const uint8_t *)rsa_private_pem,
                rsa_private_pem_len) == SSH_OK);
            CHECK(imported_crypto->hostkey_public(
                imported_crypto->ctx,
                sv("rsa-sha2-256"),
                rsa_hostkey_blob,
                sizeof(rsa_hostkey_blob),
                &rsa_hostkey_blob_len) == SSH_OK);
            CHECK(rsa_hostkey_blob_len > strlen("ssh-rsa"));
            CHECK(imported_crypto->hostkey_sign(
                imported_crypto->ctx,
                sv("rsa-sha2-256"),
                hash,
                hash_len,
                rsa_hostkey_signature,
                sizeof(rsa_hostkey_signature),
                &rsa_hostkey_signature_len) == SSH_OK);
            CHECK(imported_crypto->publickey_verify(
                imported_crypto->ctx,
                sv("rsa-sha2-256"),
                rsa_hostkey_blob,
                rsa_hostkey_blob_len,
                hash,
                hash_len,
                rsa_hostkey_signature,
                rsa_hostkey_signature_len) == SSH_OK);

            CHECK(imported_crypto->hostkey_import_private_auto(
                imported_crypto->ctx,
                sv("rsa-sha2-256"),
                (const uint8_t *)rsa_private_openssh_pem,
                rsa_private_openssh_pem_len) == SSH_OK);
            CHECK(imported_crypto->hostkey_public(
                imported_crypto->ctx,
                sv("rsa-sha2-256"),
                rsa_openssh_hostkey_blob,
                sizeof(rsa_openssh_hostkey_blob),
                &rsa_openssh_hostkey_blob_len) == SSH_OK);
            CHECK(rsa_openssh_hostkey_blob_len == rsa_hostkey_blob_len);
            CHECK(memcmp(rsa_openssh_hostkey_blob, rsa_hostkey_blob, rsa_hostkey_blob_len) == 0);
            CHECK(imported_crypto->hostkey_sign(
                imported_crypto->ctx,
                sv("rsa-sha2-256"),
                hash,
                hash_len,
                rsa_openssh_hostkey_signature,
                sizeof(rsa_openssh_hostkey_signature),
                &rsa_openssh_hostkey_signature_len) == SSH_OK);
            CHECK(imported_crypto->publickey_verify(
                imported_crypto->ctx,
                sv("rsa-sha2-256"),
                rsa_openssh_hostkey_blob,
                rsa_openssh_hostkey_blob_len,
                hash,
                hash_len,
                rsa_openssh_hostkey_signature,
                rsa_openssh_hostkey_signature_len) == SSH_OK);

            CHECK(psa_destroy_key(rsa_key) == PSA_SUCCESS);
            rsa_key = 0;
        } else {
            (void)rsa_status;
        }
    }

    CHECK(crypto->derive_key(
        crypto->ctx,
        sv("curve25519-sha256"),
        secret_a,
        secret_a_len,
        hash,
        hash_len,
        hash,
        hash_len,
        'A',
        derived,
        sizeof(derived),
        &derived_len) == SSH_OK);
    CHECK(derived_len == sizeof(derived));

    for (i = 0u; i < sizeof(key); ++i) {
        key[i] = (uint8_t)i;
        iv[i] = (uint8_t)(0x40u + i);
    }
    memcpy(original_packet, packet, sizeof(packet));
    CHECK(crypto->cipher_crypt(
        crypto->ctx,
        sv("aes128-ctr"),
        key,
        sizeof(key),
        iv,
        sizeof(iv),
        0u,
        SSH_CIPHER_ENCRYPT,
        packet,
        sizeof(packet)) == SSH_OK);
    CHECK(memcmp(packet, original_packet, sizeof(packet)) != 0);
    CHECK(crypto->cipher_crypt(
        crypto->ctx,
        sv("aes128-ctr"),
        key,
        sizeof(key),
        iv,
        sizeof(iv),
        0u,
        SSH_CIPHER_DECRYPT,
        packet,
        sizeof(packet)) == SSH_OK);
    CHECK(memcmp(packet, original_packet, sizeof(packet)) == 0);

    CHECK(crypto->mac_compute(
        crypto->ctx,
        sv("hmac-sha2-256"),
        derived,
        sizeof(derived),
        7u,
        packet,
        sizeof(packet),
        mac,
        sizeof(mac),
        &mac_len) == SSH_OK);
    CHECK(mac_len == 32u);

    ssh_mbedtls_crypto_free(&crypto_ctx);
    ssh_mbedtls_crypto_free(&imported_ctx);
    if (rsa_key != 0) {
        (void)psa_destroy_key(rsa_key);
    }
    return 0;
}
