#include <stdio.h>
#include <string.h>

#include "emssh/crypto_mbedtls.h"
#include "emssh/ssh_error.h"

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

static const char k_openssh_rsa_key[] =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n"
    "NhAAAAAwEAAQAAAQEAuj2arFdJIbV7tIPdjHkqvhutdBAO1qAhsF8Ace9eVGApmZXZlVpr\n"
    "+dn4kfPCPFYcjb+CDiM1GYBG/O72H4m2LSM8vG1DiTetZ/ue7wv3DbjYOt+hhAS9ROWpZQ\n"
    "fAJsSvWfs67PNHubwpxV5ste0rKlzECiaWiPWQimzlHUT+huD22ad8ReeKiLK4mmTumDKJ\n"
    "axIkFhjkrU+b5TwnS+osXg+CIPMyZ4gh4Wdq1LN2SZobkVa5HU0iDqmad9mXwH19PuyXsx\n"
    "nD/YWGf7vvkVsEAkI60+/qHc4kyjRn9R9zMuUchIaAqRYrKHCRUyvdPbRbZ3HyOPn/bD8N\n"
    "Zl7qN9v5GwAAA9AiW1AFIltQBQAAAAdzc2gtcnNhAAABAQC6PZqsV0khtXu0g92MeSq+G6\n"
    "10EA7WoCGwXwBx715UYCmZldmVWmv52fiR88I8VhyNv4IOIzUZgEb87vYfibYtIzy8bUOJ\n"
    "N61n+57vC/cNuNg636GEBL1E5allB8AmxK9Z+zrs80e5vCnFXmy17SsqXMQKJpaI9ZCKbO\n"
    "UdRP6G4PbZp3xF54qIsriaZO6YMolrEiQWGOStT5vlPCdL6ixeD4Ig8zJniCHhZ2rUs3ZJ\n"
    "mhuRVrkdTSIOqZp32ZfAfX0+7JezGcP9hYZ/u++RWwQCQjrT7+odziTKNGf1H3My5RyEho\n"
    "CpFisocJFTK909tFtncfI4+f9sPw1mXuo32/kbAAAAAwEAAQAAAQACtsEZP9BeAGIEGGPT\n"
    "FzTrPkYByfYdZIn5IvlDr8RFIH2asldQWNf39RgtMEslS+/wlNjVUegFLhxatTS68uvHrp\n"
    "rE+Caiyj/pov4G57q65XWpLfcRkGwdo+cbBMjlB7qyafnK2CS0bSyCpsSYxhL59A4bQ8Kv\n"
    "zjxD+CBCk+3Nk1VDOKBw5ICk83gqzmfXhS1GXeWKr0751FzOXXpB74JpAriCNg3q0xZO5S\n"
    "FODGUmV3He/PWdndV7fkH8i0HLdzmm5r+3Lyzk1y96sAEqEZz3U/YxhGbnRUQiUg+Qghvi\n"
    "BxSyYT3wfKZHI2oLsXPoz9Os5XlBCyK7xsMl9aOQcYI5AAAAgQDDmHytEdscIsj3sh2akF\n"
    "AtwQZhizbPLx+7wfmkXBkxdmSOCV5dr66kYTbWnq4fD7FJLbvPsYfTJB71e3v51iwMwmEe\n"
    "uyX7AUpIKBNk4CSGg7GSeukZ2zkyr1of8sw6ROIYGVIqZn+u9IQAH+oYgatzbCwfZ2EOMg\n"
    "6tC6YiX3vIKwAAAIEAyZX9K+V4jbSF6ejKnNk/maMcQqE4whjiZInM10kzTgZ9C+KQIbXC\n"
    "Jfsg1w90xNLI/5XZHAtexHF6RTKMOb4a8dzQlmMfmHsz9yG9+9wqoT3n7YuYoxUSWFOOKP\n"
    "uYBeD6FCFfoXf6XWlFGiQGYlaHvCVx0Ef4Kqw29b89e+QMtX0AAACBAOyDOdFxms5VFS+o\n"
    "mmnkNGYef7CDZBzp2RM93zIlFr4I/p69TD7VbK74YvA0TabP7CBsY/xYlEUh8hYPn9b637\n"
    "LBKgwNhuHJmh6L+BglB+YiMa9D5G8QMaNK5yXkcIluEwxI5epBTXVXx7JlspZxTB93Thk5\n"
    "jDYUm0dxTpfa5Mx3AAAAFmVtc3NoLXRlc3Qtb3BlbnNzaC1yc2EBAgME\n"
    "-----END OPENSSH PRIVATE KEY-----\n";

int main(void)
{
    ssh_mbedtls_crypto_t ctx;
    const ssh_crypto_api_t *crypto;
    uint8_t hostkey[EMSSH_MAX_HOST_KEY_BLOB];
    uint8_t hash[32];
    uint8_t signature[EMSSH_MAX_SIGNATURE];
    size_t hostkey_len;
    size_t signature_len;
    size_t i;

    memset(&ctx, 0, sizeof(ctx));
    CHECK(ssh_mbedtls_crypto_init(&ctx) == SSH_OK);
    crypto = ssh_mbedtls_crypto_api(&ctx);
    CHECK(crypto != NULL);
    CHECK(crypto->hostkey_import_private_auto(
        crypto->ctx,
        sv("rsa-sha2-256"),
        (const uint8_t *)k_openssh_rsa_key,
        strlen(k_openssh_rsa_key)) == SSH_OK);
    CHECK(crypto->hostkey_public(
        crypto->ctx,
        sv("rsa-sha2-256"),
        hostkey,
        sizeof(hostkey),
        &hostkey_len) == SSH_OK);
    CHECK(hostkey_len > strlen("ssh-rsa"));

    for (i = 0u; i < sizeof(hash); ++i) {
        hash[i] = (uint8_t)(0xa0u + i);
    }

    CHECK(crypto->hostkey_sign(
        crypto->ctx,
        sv("rsa-sha2-256"),
        hash,
        sizeof(hash),
        signature,
        sizeof(signature),
        &signature_len) == SSH_OK);
    CHECK(crypto->publickey_verify(
        crypto->ctx,
        sv("rsa-sha2-256"),
        hostkey,
        hostkey_len,
        hash,
        sizeof(hash),
        signature,
        signature_len) == SSH_OK);

    ssh_mbedtls_crypto_free(&ctx);
    return 0;
}
