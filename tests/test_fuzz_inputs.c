#include <stdio.h>
#include <string.h>

#include "emssh/sftp.h"
#include "emssh/ssh_error.h"
#include "emssh/ssh_packet.h"
#include "emssh/ssh_service.h"
#include "emssh/ssh_userauth.h"
#include "fuzz_decode_common.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static int deterministic_rng(void *ctx, uint8_t *buf, size_t len)
{
    size_t i;

    (void)ctx;

    if (buf == NULL && len != 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    for (i = 0u; i < len; ++i) {
        buf[i] = (uint8_t)(0x53u + (uint8_t)i);
    }
    return SSH_OK;
}

static void put_u32_be(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

int main(void)
{
    static const uint8_t sftp_init_seed[] = {
        0u, 0u, 0u, 5u,
        SSH_FXP_INIT,
        0u, 0u, 0u, SFTP_VERSION_3
    };
    static const uint8_t random_seed[] = {
        0xffu, 0x00u, 0x7fu, 0x80u, 0x01u, 0x02u, 0x03u, 0x04u,
        0x10u, 0x20u, 0x30u, 0x40u, 0x50u, 0x60u, 0x70u, 0x90u
    };
    uint8_t packet_seed[128];
    uint8_t userauth_seed[128];
    uint8_t sftp_open_seed[128];
    size_t packet_seed_len;
    size_t userauth_seed_len;
    size_t sftp_open_len;
    ssh_buffer_t buf;
    ssh_rng_api_t rng;

    rng.fill = deterministic_rng;
    rng.ctx = NULL;

    CHECK(ssh_packet_encode_plain(
        packet_seed,
        sizeof(packet_seed),
        &packet_seed_len,
        random_seed,
        sizeof(random_seed),
        8u,
        &rng) == SSH_OK);

    ssh_buffer_init(&buf, userauth_seed, sizeof(userauth_seed));
    CHECK(ssh_userauth_request_password_encode(&buf, "alice", SSH_SERVICE_CONNECTION, "secret") == SSH_OK);
    userauth_seed_len = ssh_buffer_len(&buf);

    ssh_buffer_init(&buf, sftp_open_seed + 4u, sizeof(sftp_open_seed) - 4u);
    CHECK(ssh_buffer_put_u8(&buf, SSH_FXP_OPEN) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 7u) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "file.txt") == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, SSH_FXF_READ) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 0u) == SSH_OK);
    sftp_open_len = ssh_buffer_len(&buf) + 4u;
    put_u32_be(sftp_open_seed, (uint32_t)ssh_buffer_len(&buf));

    emssh_fuzz_mutate_seed(packet_seed, packet_seed_len);
    emssh_fuzz_mutate_seed(userauth_seed, userauth_seed_len);
    emssh_fuzz_mutate_seed(sftp_init_seed, sizeof(sftp_init_seed));
    emssh_fuzz_mutate_seed(sftp_open_seed, sftp_open_len);
    emssh_fuzz_mutate_seed(random_seed, sizeof(random_seed));

    return 0;
}
