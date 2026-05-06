#include <stdio.h>
#include <string.h>

#include "emssh/ssh_error.h"
#include "emssh/ssh_kex.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static int view_eq(ssh_string_view_t view, const char *text)
{
    size_t len = strlen(text);
    return view.len == len && memcmp(view.data, text, len) == 0;
}

int main(void)
{
    uint8_t storage[512];
    uint8_t cookie[SSH_KEX_COOKIE_LEN];
    ssh_buffer_t buf;
    ssh_kexinit_algorithm_set_t algorithms;
    ssh_kexinit_t parsed;
    ssh_kex_negotiation_t negotiated;
    ssh_kex_ecdh_init_t parsed_init;
    ssh_kex_ecdh_reply_t parsed_reply;
    size_t i;

    for (i = 0u; i < sizeof(cookie); ++i) {
        cookie[i] = (uint8_t)i;
    }

    ssh_kexinit_algorithm_set_defaults(&algorithms);
    algorithms.kex_algorithms = "curve25519-sha256";
    algorithms.server_host_key_algorithms = "ssh-ed25519";

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_kexinit_encode(&buf, cookie, &algorithms, 0) == SSH_OK);

    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_kexinit_decode(&buf, &parsed) == SSH_OK);
    CHECK(memcmp(parsed.cookie, cookie, sizeof(cookie)) == 0);
    CHECK(view_eq(parsed.name_lists[SSH_KEX_ALGORITHMS], "curve25519-sha256"));
    CHECK(view_eq(parsed.name_lists[SSH_SERVER_HOST_KEY_ALGORITHMS], "ssh-ed25519"));
    CHECK(ssh_name_list_contains_token(parsed.name_lists[SSH_KEX_ALGORITHMS], "curve25519-sha256"));
    CHECK(!ssh_name_list_contains_token(parsed.name_lists[SSH_KEX_ALGORITHMS], "ecdh-sha2-nistp256"));
    CHECK(parsed.first_kex_packet_follows == 0);
    CHECK(parsed.reserved == 0u);
    CHECK(ssh_kex_negotiate(&parsed, NULL, &negotiated) == SSH_OK);
    CHECK(view_eq(negotiated.kex_algorithm, "curve25519-sha256"));
    CHECK(view_eq(negotiated.server_host_key_algorithm, "ssh-ed25519"));

    {
        ssh_string_view_t bad;
        bad.data = (const uint8_t *)"aes128-ctr,,aes256-ctr";
        bad.len = strlen((const char *)bad.data);
        CHECK(!ssh_name_list_is_valid(bad));
    }

    algorithms.kex_algorithms = "diffie-hellman-group1-sha1";
    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_kexinit_encode(&buf, cookie, &algorithms, 0) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_kexinit_decode(&buf, &parsed) == SSH_OK);
    CHECK(ssh_kex_negotiate(&parsed, NULL, &negotiated) == SSH_ERR_UNSUPPORTED);

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_kex_ecdh_init_encode(&buf, (const uint8_t *)"client-key", strlen("client-key")) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_kex_ecdh_init_decode(&buf, &parsed_init) == SSH_OK);
    CHECK(view_eq(parsed_init.client_public_key, "client-key"));

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_kex_ecdh_reply_encode(
        &buf,
        (const uint8_t *)"host-key",
        strlen("host-key"),
        (const uint8_t *)"server-key",
        strlen("server-key"),
        (const uint8_t *)"signature",
        strlen("signature")) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_kex_ecdh_reply_decode(&buf, &parsed_reply) == SSH_OK);
    CHECK(view_eq(parsed_reply.server_host_key, "host-key"));
    CHECK(view_eq(parsed_reply.server_public_key, "server-key"));
    CHECK(view_eq(parsed_reply.signature, "signature"));

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_kex_newkeys_encode(&buf) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_kex_newkeys_decode(&buf) == SSH_OK);

    return 0;
}
