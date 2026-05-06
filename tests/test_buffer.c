#include <stdio.h>
#include <string.h>

#include "emssh/ssh_buffer.h"
#include "emssh/ssh_error.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

int main(void)
{
    uint8_t storage[64];
    ssh_buffer_t buf;
    ssh_string_view_t view;
    uint8_t u8;
    uint32_t u32;
    uint64_t u64;
    const uint8_t mpint_zero[] = {0x00u, 0x00u};
    const uint8_t mpint_trim[] = {0x00u, 0x00u, 0x7fu};
    const uint8_t mpint_prefix[] = {0x80u, 0x01u};
    const uint8_t expected_mpints[] = {
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x01u, 0x7fu,
        0x00u, 0x00u, 0x00u, 0x03u, 0x00u, 0x80u, 0x01u
    };

    ssh_buffer_init(&buf, storage, sizeof(storage));

    CHECK(ssh_buffer_put_u8(&buf, 0x5au) == SSH_OK);
    CHECK(ssh_buffer_put_u32(&buf, 0x01020304u) == SSH_OK);
    CHECK(ssh_buffer_put_u64(&buf, 0x0102030405060708ull) == SSH_OK);
    CHECK(ssh_buffer_put_cstring(&buf, "hello") == SSH_OK);
    CHECK(ssh_buffer_len(&buf) == 22u);

    CHECK(ssh_buffer_get_u8(&buf, &u8) == SSH_OK);
    CHECK(u8 == 0x5au);

    CHECK(ssh_buffer_get_u32(&buf, &u32) == SSH_OK);
    CHECK(u32 == 0x01020304u);

    CHECK(ssh_buffer_get_u64(&buf, &u64) == SSH_OK);
    CHECK(u64 == 0x0102030405060708ull);

    CHECK(ssh_buffer_get_string_view(&buf, &view) == SSH_OK);
    CHECK(view.len == 5u);
    CHECK(memcmp(view.data, "hello", 5u) == 0);
    CHECK(ssh_buffer_remaining_read(&buf) == 0u);

    ssh_buffer_reset(&buf);
    CHECK(ssh_buffer_put_mpint_positive(&buf, mpint_zero, sizeof(mpint_zero)) == SSH_OK);
    CHECK(ssh_buffer_put_mpint_positive(&buf, mpint_trim, sizeof(mpint_trim)) == SSH_OK);
    CHECK(ssh_buffer_put_mpint_positive(&buf, mpint_prefix, sizeof(mpint_prefix)) == SSH_OK);
    CHECK(ssh_buffer_len(&buf) == sizeof(expected_mpints));
    CHECK(memcmp(storage, expected_mpints, sizeof(expected_mpints)) == 0);

    return 0;
}
