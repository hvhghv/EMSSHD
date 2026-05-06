#include "emssh/crypto_mbedtls.h"

#include <stdlib.h>
#include <string.h>

#include "emssh/ssh_buffer.h"
#include "emssh/ssh_config.h"
#include "emssh/ssh_error.h"

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <mbedtls/private/aes.h>
#include <mbedtls/private/ctr_drbg.h>
#include <mbedtls/private/ecdsa.h>
#include <mbedtls/private/ecp.h>
#include <mbedtls/private/entropy.h>
#include <mbedtls/private/rsa.h>
#include <mbedtls/md.h>

typedef struct ssh_mbedtls_legacy_state {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    int drbg_ready;
    int hostkey_type;
    uint8_t hostkey_private[64];
    size_t hostkey_private_len;
} ssh_mbedtls_legacy_state_t;

#define SSH_MBEDTLS_LEGACY_HOSTKEY_NONE 0
#define SSH_MBEDTLS_LEGACY_HOSTKEY_ECDSA_P256 1

static int view_eq(ssh_string_view_t view, const char *value)
{
    size_t len;

    if (value == NULL || view.data == NULL) {
        return 0;
    }
    len = strlen(value);
    return view.len == len && memcmp(view.data, value, len) == 0;
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

static int mbedtls_ok(int rc)
{
    return rc == 0 ? SSH_OK : SSH_ERR_PLATFORM;
}

static ssh_mbedtls_legacy_state_t *legacy_state(void *ctx)
{
    ssh_mbedtls_crypto_t *crypto = (ssh_mbedtls_crypto_t *)ctx;
    if (crypto == NULL || crypto->backend_state == NULL) {
        return NULL;
    }
    return (ssh_mbedtls_legacy_state_t *)crypto->backend_state;
}

static int compute_hash(mbedtls_md_type_t md_type, const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len)
{
    const mbedtls_md_info_t *info;
    size_t expected;
    int rc;

    if (data == NULL || out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    info = mbedtls_md_info_from_type(md_type);
    if (info == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    expected = mbedtls_md_get_size(info);
    if (out_len < expected) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    rc = mbedtls_md(info, data, data_len, out);
    return mbedtls_ok(rc);
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

    memset(raw_signature, 0, 64u);
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
    if (status != SSH_OK || ssh_buffer_remaining_read(&inner) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    status = mpint_view_to_fixed(r, raw_signature, 32u);
    if (status == SSH_OK) {
        status = mpint_view_to_fixed(s, raw_signature + 32u, 32u);
    }
    return status;
}

static int view_is_rsa_algorithm(ssh_string_view_t algorithm)
{
    return view_eq(algorithm, "ssh-rsa") ||
           view_eq(algorithm, "rsa-sha2-256") ||
           view_eq(algorithm, "rsa-sha2-512");
}

static int kex_algorithm_to_group(ssh_string_view_t algorithm, mbedtls_ecp_group_id *group_id)
{
    if (group_id == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (view_eq(algorithm, "ecdh-sha2-nistp256")) {
        *group_id = MBEDTLS_ECP_DP_SECP256R1;
        return SSH_OK;
    }
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
    if (view_eq(algorithm, "curve25519-sha256")) {
        *group_id = MBEDTLS_ECP_DP_CURVE25519;
        return SSH_OK;
    }
#endif
    return SSH_ERR_UNSUPPORTED;
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

    if (!view_eq(algorithm, "ssh-rsa") ||
        e->len == 0u || n->len == 0u ||
        ssh_buffer_remaining_read(&buf) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return SSH_OK;
}

static int decode_rsa_signature_blob(
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

    if (!view_is_rsa_algorithm(algorithm) ||
        raw_signature->len == 0u ||
        ssh_buffer_remaining_read(&buf) != 0u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    return SSH_OK;
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
    int rc;

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

    rc = compute_hash(MBEDTLS_MD_SHA256, input, ssh_buffer_len(&buf), out, 32u);
    secure_zero_bytes(input, sizeof(input));
    return rc;
}

static int ecdsa_p256_make_public_from_private(
    ssh_mbedtls_legacy_state_t *state,
    const uint8_t *private_key,
    size_t private_key_len,
    uint8_t *public_key,
    size_t public_key_capacity,
    size_t *public_key_len)
{
    mbedtls_ecp_keypair key;
    int rc;

    if (state == NULL || private_key == NULL || private_key_len == 0u ||
        public_key == NULL || public_key_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    mbedtls_ecp_keypair_init(&key);

    rc = mbedtls_ecp_group_load(&key.grp, MBEDTLS_ECP_DP_SECP256R1);
    if (rc == 0) {
        rc = mbedtls_mpi_read_binary(&key.d, private_key, private_key_len);
    }
    if (rc == 0) {
        rc = mbedtls_ecp_mul(
            &key.grp,
            &key.Q,
            &key.d,
            &key.grp.G,
            mbedtls_ctr_drbg_random,
            &state->drbg);
    }
    if (rc == 0) {
        rc = mbedtls_ecp_point_write_binary(
            &key.grp,
            &key.Q,
            MBEDTLS_ECP_PF_UNCOMPRESSED,
            public_key_len,
            public_key,
            public_key_capacity);
    }

    mbedtls_ecp_keypair_free(&key);
    return mbedtls_ok(rc);
}

static int mbedtls_rng_fill(void *ctx, uint8_t *buf, size_t len)
{
    ssh_mbedtls_legacy_state_t *state = legacy_state(ctx);
    if (state == NULL || !state->drbg_ready || (buf == NULL && len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    return mbedtls_ok(mbedtls_ctr_drbg_random(&state->drbg, buf, len));
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
    ssh_mbedtls_legacy_state_t *state = legacy_state(ctx);
    mbedtls_ecp_group_id group_id;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi d;
    int rc;

    if (state == NULL || public_key == NULL || public_key_len == NULL ||
        private_key == NULL || private_key_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    rc = kex_algorithm_to_group(kex_algorithm, &group_id);
    if (rc != SSH_OK) {
        return rc;
    }
    if (private_key_capacity < 32u) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&d);

    rc = mbedtls_ecp_group_load(&grp, group_id);
    if (rc == 0) {
        rc = mbedtls_ecp_gen_keypair(
            &grp,
            &d,
            &q,
            mbedtls_ctr_drbg_random,
            &state->drbg);
    }
    if (rc == 0) {
        rc = mbedtls_ecp_point_write_binary(
            &grp,
            &q,
            MBEDTLS_ECP_PF_UNCOMPRESSED,
            public_key_len,
            public_key,
            public_key_capacity);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_write_binary(&d, private_key, 32u);
    }
    if (rc == 0) {
        *private_key_len = 32u;
    }

    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    return mbedtls_ok(rc);
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
    ssh_mbedtls_legacy_state_t *state = legacy_state(ctx);
    mbedtls_ecp_group_id group_id;
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q_peer;
    mbedtls_ecp_point q_shared;
    uint8_t shared_point[MBEDTLS_ECP_MAX_PT_LEN];
    size_t shared_point_len = 0u;
    int rc;
    size_t coordinate_len = 32u;

    if (state == NULL || private_key == NULL || private_key_len == 0u ||
        peer_public_key == NULL || peer_public_key_len == 0u ||
        shared_secret == NULL || shared_secret_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    rc = kex_algorithm_to_group(kex_algorithm, &group_id);
    if (rc != SSH_OK) {
        return rc;
    }
    if (private_key_len > 32u || shared_secret_capacity < coordinate_len) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q_peer);
    mbedtls_ecp_point_init(&q_shared);

    rc = mbedtls_ecp_group_load(&grp, group_id);
    if (rc == 0) {
        rc = mbedtls_mpi_read_binary(&d, private_key, private_key_len);
    }
    if (rc == 0) {
        rc = mbedtls_ecp_check_privkey(&grp, &d);
    }
    if (rc == 0) {
        rc = mbedtls_ecp_point_read_binary(&grp, &q_peer, peer_public_key, peer_public_key_len);
    }
    if (rc == 0) {
        rc = mbedtls_ecp_check_pubkey(&grp, &q_peer);
    }
    if (rc == 0) {
        rc = mbedtls_ecp_mul(&grp, &q_shared, &d, &q_peer, mbedtls_ctr_drbg_random, &state->drbg);
    }
    if (rc == 0) {
        rc = mbedtls_ecp_point_write_binary(
            &grp,
            &q_shared,
            MBEDTLS_ECP_PF_UNCOMPRESSED,
            &shared_point_len,
            shared_point,
            sizeof(shared_point));
    }
    if (rc == 0) {
        if (
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
            group_id == MBEDTLS_ECP_DP_CURVE25519
#else
            0
#endif
        ) {
            if (shared_point_len != coordinate_len) {
                rc = -1;
            } else {
                memcpy(shared_secret, shared_point, coordinate_len);
            }
        } else {
            if (shared_point_len < (coordinate_len + 1u) || shared_point[0] != 0x04u) {
                rc = -1;
            } else {
                memcpy(shared_secret, shared_point + 1u, coordinate_len);
            }
        }
    }
    if (rc == 0) {
        *shared_secret_len = coordinate_len;
    }

    secure_zero_bytes(shared_point, sizeof(shared_point));
    mbedtls_ecp_point_free(&q_shared);
    mbedtls_ecp_point_free(&q_peer);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return mbedtls_ok(rc);
}

static int mbedtls_hostkey_public(
    void *ctx,
    ssh_string_view_t hostkey_algorithm,
    uint8_t *hostkey_blob,
    size_t hostkey_blob_capacity,
    size_t *hostkey_blob_len)
{
    ssh_mbedtls_legacy_state_t *state = legacy_state(ctx);
    uint8_t raw_public[128];
    size_t raw_public_len;
    ssh_buffer_t buf;
    int rc;

    if (state == NULL || hostkey_blob == NULL || hostkey_blob_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (state->hostkey_type != SSH_MBEDTLS_LEGACY_HOSTKEY_ECDSA_P256 ||
        state->hostkey_private_len != 32u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (!view_eq(hostkey_algorithm, "ecdsa-sha2-nistp256")) {
        return SSH_ERR_UNSUPPORTED;
    }

    raw_public_len = 0u;
    rc = ecdsa_p256_make_public_from_private(
        state,
        state->hostkey_private,
        state->hostkey_private_len,
        raw_public,
        sizeof(raw_public),
        &raw_public_len);
    if (rc != SSH_OK) {
        return rc;
    }

    ssh_buffer_init(&buf, hostkey_blob, hostkey_blob_capacity);
    rc = ssh_buffer_put_cstring(&buf, "ecdsa-sha2-nistp256");
    if (rc == SSH_OK) {
        rc = ssh_buffer_put_cstring(&buf, "nistp256");
    }
    if (rc == SSH_OK) {
        rc = ssh_buffer_put_string(&buf, raw_public, raw_public_len);
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

    if ((data == NULL && data_len != 0u) || hash == NULL || hash_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (!view_eq(kex_algorithm, "curve25519-sha256") &&
        !view_eq(kex_algorithm, "ecdh-sha2-nistp256")) {
        return SSH_ERR_UNSUPPORTED;
    }
    if (hash_capacity < 32u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (compute_hash(MBEDTLS_MD_SHA256, data, data_len, hash, hash_capacity) != SSH_OK) {
        return SSH_ERR_PLATFORM;
    }
    *hash_len = 32u;
    return SSH_OK;
}

static int put_ssh_ecdsa_signature_blob_from_rs(
    ssh_buffer_t *outer,
    const mbedtls_mpi *r,
    const mbedtls_mpi *s)
{
    uint8_t inner_storage[160];
    uint8_t r_buf[40];
    uint8_t s_buf[40];
    size_t r_len;
    size_t s_len;
    ssh_buffer_t inner;
    int rc;

    if (outer == NULL || r == NULL || s == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    r_len = mbedtls_mpi_size(r);
    s_len = mbedtls_mpi_size(s);
    if (r_len == 0u || s_len == 0u || r_len > sizeof(r_buf) || s_len > sizeof(s_buf)) {
        return SSH_ERR_PLATFORM;
    }

    if (mbedtls_mpi_write_binary(r, r_buf, r_len) != 0 ||
        mbedtls_mpi_write_binary(s, s_buf, s_len) != 0) {
        secure_zero_bytes(r_buf, sizeof(r_buf));
        secure_zero_bytes(s_buf, sizeof(s_buf));
        return SSH_ERR_PLATFORM;
    }

    ssh_buffer_init(&inner, inner_storage, sizeof(inner_storage));
    rc = ssh_buffer_put_mpint_positive(&inner, r_buf, r_len);
    if (rc == SSH_OK) {
        rc = ssh_buffer_put_mpint_positive(&inner, s_buf, s_len);
    }
    if (rc == SSH_OK) {
        rc = ssh_buffer_put_string(outer, inner_storage, ssh_buffer_len(&inner));
    }

    secure_zero_bytes(inner_storage, sizeof(inner_storage));
    secure_zero_bytes(r_buf, sizeof(r_buf));
    secure_zero_bytes(s_buf, sizeof(s_buf));
    return rc;
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
    ssh_mbedtls_legacy_state_t *state = legacy_state(ctx);
    ssh_buffer_t buf;
    mbedtls_ecp_keypair key;
    mbedtls_mpi r;
    mbedtls_mpi s;
    uint8_t digest[32];
    int rc;

    if (state == NULL || exchange_hash == NULL || exchange_hash_len == 0u ||
        signature == NULL || signature_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (!view_eq(hostkey_algorithm, "ecdsa-sha2-nistp256")) {
        return SSH_ERR_UNSUPPORTED;
    }
    if (state->hostkey_type != SSH_MBEDTLS_LEGACY_HOSTKEY_ECDSA_P256 ||
        state->hostkey_private_len != 32u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    mbedtls_ecp_keypair_init(&key);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    memset(digest, 0, sizeof(digest));

    rc = compute_hash(MBEDTLS_MD_SHA256, exchange_hash, exchange_hash_len, digest, sizeof(digest));
    if (rc != SSH_OK) {
        mbedtls_mpi_free(&s);
        mbedtls_mpi_free(&r);
        mbedtls_ecp_keypair_free(&key);
        return rc;
    }

    rc = mbedtls_ecp_group_load(&key.grp, MBEDTLS_ECP_DP_SECP256R1);
    if (rc == 0) {
        rc = mbedtls_mpi_read_binary(&key.d, state->hostkey_private, state->hostkey_private_len);
    }
    if (rc == 0) {
        rc = mbedtls_ecp_mul(
            &key.grp,
            &key.Q,
            &key.d,
            &key.grp.G,
            mbedtls_ctr_drbg_random,
            &state->drbg);
    }
    if (rc == 0) {
        rc = mbedtls_ecdsa_sign(
            &key.grp,
            &r,
            &s,
            &key.d,
            digest,
            sizeof(digest),
            mbedtls_ctr_drbg_random,
            &state->drbg);
    }
    if (rc != 0) {
        secure_zero_bytes(digest, sizeof(digest));
        mbedtls_mpi_free(&s);
        mbedtls_mpi_free(&r);
        mbedtls_ecp_keypair_free(&key);
        return SSH_ERR_PLATFORM;
    }

    ssh_buffer_init(&buf, signature, signature_capacity);
    rc = ssh_buffer_put_cstring(&buf, "ecdsa-sha2-nistp256");
    if (rc == SSH_OK) {
        rc = put_ssh_ecdsa_signature_blob_from_rs(&buf, &r, &s);
    }

    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_keypair_free(&key);
    secure_zero_bytes(digest, sizeof(digest));

    if (rc != SSH_OK) {
        return rc;
    }
    *signature_len = ssh_buffer_len(&buf);
    return SSH_OK;
}

static int verify_ecdsa_p256_publickey(
    const uint8_t *publickey_blob,
    size_t publickey_blob_len,
    const uint8_t *signed_data,
    size_t signed_data_len,
    const uint8_t *signature,
    size_t signature_len)
{
    mbedtls_ecp_keypair key;
    mbedtls_mpi r;
    mbedtls_mpi s;
    ssh_string_view_t q;
    uint8_t raw_signature[64];
    uint8_t hash[32];
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
    rc = compute_hash(MBEDTLS_MD_SHA256, signed_data, signed_data_len, hash, sizeof(hash));
    if (rc != SSH_OK) {
        secure_zero_bytes(raw_signature, sizeof(raw_signature));
        return rc;
    }

    mbedtls_ecp_keypair_init(&key);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    rc = mbedtls_ecp_group_load(&key.grp, MBEDTLS_ECP_DP_SECP256R1);
    if (rc == 0) {
        rc = mbedtls_ecp_point_read_binary(&key.grp, &key.Q, q.data, q.len);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_read_binary(&r, raw_signature, 32u);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_read_binary(&s, raw_signature + 32u, 32u);
    }
    if (rc == 0) {
        rc = mbedtls_ecdsa_verify(&key.grp, hash, sizeof(hash), &key.Q, &r, &s);
    }

    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_keypair_free(&key);
    secure_zero_bytes(hash, sizeof(hash));
    secure_zero_bytes(raw_signature, sizeof(raw_signature));

    if (rc == 0) {
        return SSH_OK;
    }
    return SSH_ERR_SECURITY;
}

static int verify_rsa_publickey(
    ssh_string_view_t algorithm,
    const uint8_t *publickey_blob,
    size_t publickey_blob_len,
    const uint8_t *signed_data,
    size_t signed_data_len,
    const uint8_t *signature,
    size_t signature_len)
{
    mbedtls_rsa_context rsa;
    ssh_string_view_t e;
    ssh_string_view_t n;
    ssh_string_view_t raw_signature;
    uint8_t hash[64];
    mbedtls_md_type_t md_alg;
    size_t hash_len;
    int rc;

    rc = decode_rsa_public_key_blob(publickey_blob, publickey_blob_len, &e, &n);
    if (rc != SSH_OK) {
        return rc;
    }
    rc = decode_rsa_signature_blob(signature, signature_len, &raw_signature);
    if (rc != SSH_OK) {
        return rc;
    }

    if (view_eq(algorithm, "rsa-sha2-256")) {
        md_alg = MBEDTLS_MD_SHA256;
        hash_len = 32u;
    } else if (view_eq(algorithm, "rsa-sha2-512")) {
        md_alg = MBEDTLS_MD_SHA512;
        hash_len = 64u;
    } else {
        return SSH_ERR_UNSUPPORTED;
    }

    rc = compute_hash(md_alg, signed_data, signed_data_len, hash, sizeof(hash));
    if (rc != SSH_OK) {
        return rc;
    }
    if (raw_signature.len == 0u) {
        secure_zero_bytes(hash, sizeof(hash));
        return SSH_ERR_MALFORMED_PACKET;
    }

    mbedtls_rsa_init(&rsa);
    rc = mbedtls_mpi_read_binary(&rsa.N, n.data, n.len);
    if (rc == 0) {
        rc = mbedtls_mpi_read_binary(&rsa.E, e.data, e.len);
    }
    if (rc == 0) {
        rsa.len = mbedtls_mpi_size(&rsa.N);
    }
    if (rc == 0) {
        rc = mbedtls_rsa_check_pubkey(&rsa);
    }
    if (rc == 0) {
        if (raw_signature.len != rsa.len) {
            rc = -1;
        }
    }
    if (rc == 0) {
        rc = mbedtls_rsa_rsassa_pkcs1_v15_verify(
            &rsa,
            md_alg,
            (unsigned int)hash_len,
            hash,
            raw_signature.data);
    }

    mbedtls_rsa_free(&rsa);
    secure_zero_bytes(hash, sizeof(hash));
    return rc == 0 ? SSH_OK : SSH_ERR_SECURITY;
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
        return SSH_ERR_UNSUPPORTED;
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

    if (!view_eq(hash_algorithm, "curve25519-sha256") &&
        !view_eq(hash_algorithm, "ecdh-sha2-nistp256")) {
        return SSH_ERR_UNSUPPORTED;
    }
    if (shared_secret == NULL || shared_secret_len == 0u ||
        exchange_hash == NULL || exchange_hash_len == 0u ||
        session_id == NULL || session_id_len == 0u ||
        out == NULL || out_len == NULL) {
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
        secure_zero_bytes(round, sizeof(round));
        return rc;
    }

    while (written < out_capacity) {
        size_t take = out_capacity - written;
        if (take > sizeof(round)) {
            take = sizeof(round);
        }
        memcpy(out + written, round, take);
        written += take;
        if (written >= out_capacity) {
            break;
        }
        rc = ssh_kdf_hash_round(
            shared_secret,
            shared_secret_len,
            exchange_hash,
            exchange_hash_len,
            session_id,
            session_id_len,
            key_id,
            round,
            sizeof(round),
            round);
        if (rc != SSH_OK) {
            secure_zero_bytes(round, sizeof(round));
            return rc;
        }
    }

    *out_len = written;
    secure_zero_bytes(round, sizeof(round));
    return SSH_OK;
}

static int legacy_cipher_crypt(
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
    mbedtls_aes_context aes;
    uint8_t nonce_counter[16];
    uint8_t stream_block[16];
    size_t nc_off;
    int rc;

    (void)ctx;
    (void)sequence;
    (void)direction;

    if (!view_eq(cipher_algorithm, "aes128-ctr") ||
        key == NULL || key_len != 16u ||
        iv == NULL || iv_len != 16u ||
        (data == NULL && data_len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    mbedtls_aes_init(&aes);
    rc = mbedtls_aes_setkey_enc(&aes, key, 128u);
    if (rc != 0) {
        mbedtls_aes_free(&aes);
        return SSH_ERR_PLATFORM;
    }

    memcpy(nonce_counter, iv, sizeof(nonce_counter));
    memset(stream_block, 0, sizeof(stream_block));
    nc_off = 0u;
    rc = mbedtls_aes_crypt_ctr(
        &aes,
        data_len,
        &nc_off,
        nonce_counter,
        stream_block,
        data,
        data);

    mbedtls_aes_free(&aes);
    secure_zero_bytes(stream_block, sizeof(stream_block));
    secure_zero_bytes(nonce_counter, sizeof(nonce_counter));
    return mbedtls_ok(rc);
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
    const mbedtls_md_info_t *md_info;
    uint8_t input[4u + EMSSH_MAX_PACKET_SIZE + 4u];
    size_t input_len;
    int rc;

    (void)ctx;

    if (!view_eq(mac_algorithm, "hmac-sha2-256") ||
        key == NULL || key_len == 0u ||
        data == NULL || data_len > EMSSH_MAX_PACKET_SIZE + 4u ||
        mac == NULL || mac_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        return SSH_ERR_UNSUPPORTED;
    }
    if (mac_capacity < 32u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    input[0] = (uint8_t)((sequence >> 24) & 0xffu);
    input[1] = (uint8_t)((sequence >> 16) & 0xffu);
    input[2] = (uint8_t)((sequence >> 8) & 0xffu);
    input[3] = (uint8_t)(sequence & 0xffu);
    memcpy(input + 4u, data, data_len);
    input_len = data_len + 4u;

    rc = mbedtls_md_hmac(md_info, key, key_len, input, input_len, mac);
    secure_zero_bytes(input, sizeof(input));
    if (rc != 0) {
        return SSH_ERR_PLATFORM;
    }
    *mac_len = 32u;
    return SSH_OK;
}

static void mbedtls_secure_zero(void *ctx, void *ptr, size_t len)
{
    (void)ctx;
    secure_zero_bytes(ptr, len);
}

int ssh_mbedtls_crypto_init(ssh_mbedtls_crypto_t *ctx)
{
    static const uint8_t pers[] = "emssh-mbedtls-legacy";
    ssh_mbedtls_legacy_state_t *state;
    int rc;

    if (ctx == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(ctx, 0, sizeof(*ctx));
    state = (ssh_mbedtls_legacy_state_t *)calloc(1u, sizeof(*state));
    if (state == NULL) {
        return SSH_ERR_PLATFORM;
    }

    mbedtls_entropy_init(&state->entropy);
    mbedtls_ctr_drbg_init(&state->drbg);
    rc = mbedtls_ctr_drbg_seed(
        &state->drbg,
        mbedtls_entropy_func,
        &state->entropy,
        pers,
        sizeof(pers) - 1u);
    if (rc != 0) {
        mbedtls_ctr_drbg_free(&state->drbg);
        mbedtls_entropy_free(&state->entropy);
        free(state);
        return SSH_ERR_PLATFORM;
    }
    state->drbg_ready = 1;

    ctx->api.name = "mbedtls-legacy";
    ctx->api.kex_generate_keypair = mbedtls_kex_generate_keypair;
    ctx->api.kex_compute_shared_secret = mbedtls_kex_compute_shared_secret;
    ctx->api.hostkey_public = mbedtls_hostkey_public;
    ctx->api.hash_exchange = mbedtls_hash_exchange;
    ctx->api.hostkey_sign = mbedtls_hostkey_sign;
    ctx->api.publickey_verify = mbedtls_publickey_verify;
    ctx->api.derive_key = mbedtls_derive_key;
    ctx->api.cipher_crypt = legacy_cipher_crypt;
    ctx->api.mac_compute = mbedtls_mac_compute;
    ctx->api.secure_zero = mbedtls_secure_zero;
    ctx->api.ctx = ctx;

    ctx->rng.fill = mbedtls_rng_fill;
    ctx->rng.ctx = ctx;

    ctx->backend_state = state;
    ctx->initialized = 1;
    return SSH_OK;
}

void ssh_mbedtls_crypto_free(ssh_mbedtls_crypto_t *ctx)
{
    ssh_mbedtls_legacy_state_t *state;

    if (ctx == NULL) {
        return;
    }

    state = legacy_state(ctx);
    if (state != NULL) {
        secure_zero_bytes(state->hostkey_private, sizeof(state->hostkey_private));
        mbedtls_ctr_drbg_free(&state->drbg);
        mbedtls_entropy_free(&state->entropy);
        secure_zero_bytes(state, sizeof(*state));
        free(state);
    }

    secure_zero_bytes(ctx, sizeof(*ctx));
}

int ssh_mbedtls_crypto_generate_ed25519_hostkey(ssh_mbedtls_crypto_t *ctx)
{
    (void)ctx;
    return SSH_ERR_UNSUPPORTED;
}

int ssh_mbedtls_crypto_generate_ecdsa_p256_hostkey(ssh_mbedtls_crypto_t *ctx)
{
    ssh_mbedtls_legacy_state_t *state = legacy_state(ctx);
    mbedtls_ecp_keypair key;
    int rc;

    if (state == NULL || !ctx->initialized) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    mbedtls_ecp_keypair_init(&key);
    rc = mbedtls_ecp_group_load(&key.grp, MBEDTLS_ECP_DP_SECP256R1);
    if (rc == 0) {
        rc = mbedtls_ecp_gen_keypair(
            &key.grp,
            &key.d,
            &key.Q,
            mbedtls_ctr_drbg_random,
            &state->drbg);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_write_binary(&key.d, state->hostkey_private, 32u);
    }
    mbedtls_ecp_keypair_free(&key);
    if (rc != 0) {
        return SSH_ERR_PLATFORM;
    }

    state->hostkey_type = SSH_MBEDTLS_LEGACY_HOSTKEY_ECDSA_P256;
    state->hostkey_private_len = 32u;
    return SSH_OK;
}

int ssh_mbedtls_crypto_import_ed25519_hostkey(
    ssh_mbedtls_crypto_t *ctx,
    const uint8_t *private_key,
    size_t private_key_len)
{
    (void)ctx;
    (void)private_key;
    (void)private_key_len;
    return SSH_ERR_UNSUPPORTED;
}

int ssh_mbedtls_crypto_import_ecdsa_p256_hostkey(
    ssh_mbedtls_crypto_t *ctx,
    const uint8_t *private_key,
    size_t private_key_len)
{
    ssh_mbedtls_legacy_state_t *state = legacy_state(ctx);

    if (state == NULL || !ctx->initialized || private_key == NULL || private_key_len == 0u || private_key_len > 32u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(state->hostkey_private, 0, 32u);
    memcpy(state->hostkey_private + (32u - private_key_len), private_key, private_key_len);
    state->hostkey_type = SSH_MBEDTLS_LEGACY_HOSTKEY_ECDSA_P256;
    state->hostkey_private_len = 32u;
    return SSH_OK;
}

int ssh_mbedtls_crypto_export_hostkey_private(
    ssh_mbedtls_crypto_t *ctx,
    uint8_t *private_key,
    size_t private_key_capacity,
    size_t *private_key_len)
{
    ssh_mbedtls_legacy_state_t *state = legacy_state(ctx);

    if (state == NULL || !ctx->initialized ||
        private_key == NULL || private_key_len == NULL ||
        state->hostkey_type != SSH_MBEDTLS_LEGACY_HOSTKEY_ECDSA_P256 ||
        state->hostkey_private_len != 32u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (private_key_capacity < 32u) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(private_key, state->hostkey_private, 32u);
    *private_key_len = 32u;
    return SSH_OK;
}

int ssh_mbedtls_probe_ed25519_hostkey_support(void)
{
    return SSH_ERR_UNSUPPORTED;
}

int ssh_mbedtls_probe_ed25519_publickey_verify_support(void)
{
    return SSH_ERR_UNSUPPORTED;
}

const ssh_crypto_api_t *ssh_mbedtls_crypto_api(ssh_mbedtls_crypto_t *ctx)
{
    if (ctx == NULL || !ctx->initialized) {
        return NULL;
    }
    return &ctx->api;
}

const ssh_rng_api_t *ssh_mbedtls_rng_api(ssh_mbedtls_crypto_t *ctx)
{
    if (ctx == NULL || !ctx->initialized) {
        return NULL;
    }
    return &ctx->rng;
}

void ssh_mbedtls_kexinit_algorithm_set_defaults(ssh_kexinit_algorithm_set_t *algorithms)
{
    if (algorithms == NULL) {
        return;
    }

    /*
     * Keep legacy backend on the conservative ECDH-P256 path.
     * This avoids curve25519-specific interop/runtime instability on some
     * musl/embedded targets while keeping standards-compliant SSH KEX.
     */
    algorithms->kex_algorithms = "ecdh-sha2-nistp256,ext-info-s";
    algorithms->server_host_key_algorithms = "ecdsa-sha2-nistp256";
    algorithms->encryption_algorithms_client_to_server = "aes128-ctr";
    algorithms->encryption_algorithms_server_to_client = "aes128-ctr";
    algorithms->mac_algorithms_client_to_server = "hmac-sha2-256";
    algorithms->mac_algorithms_server_to_client = "hmac-sha2-256";
    algorithms->compression_algorithms_client_to_server = "none";
    algorithms->compression_algorithms_server_to_client = "none";
    algorithms->languages_client_to_server = "";
    algorithms->languages_server_to_client = "";
}
