#ifndef EMSSH_SSH_BUFFER_H
#define EMSSH_SSH_BUFFER_H

#include <stddef.h>
#include <stdint.h>

typedef struct ssh_buffer {
    uint8_t *data;
    size_t capacity;
    size_t len;
    size_t pos;
} ssh_buffer_t;

typedef struct ssh_string_view {
    const uint8_t *data;
    size_t len;
} ssh_string_view_t;

void ssh_buffer_init(ssh_buffer_t *buf, uint8_t *storage, size_t capacity);
void ssh_buffer_wrap(ssh_buffer_t *buf, uint8_t *storage, size_t len);
void ssh_buffer_reset(ssh_buffer_t *buf);

size_t ssh_buffer_len(const ssh_buffer_t *buf);
size_t ssh_buffer_capacity(const ssh_buffer_t *buf);
size_t ssh_buffer_remaining_read(const ssh_buffer_t *buf);
size_t ssh_buffer_remaining_write(const ssh_buffer_t *buf);
uint8_t *ssh_buffer_data(ssh_buffer_t *buf);
const uint8_t *ssh_buffer_const_data(const ssh_buffer_t *buf);

int ssh_buffer_put_u8(ssh_buffer_t *buf, uint8_t value);
int ssh_buffer_put_bool(ssh_buffer_t *buf, int value);
int ssh_buffer_put_u32(ssh_buffer_t *buf, uint32_t value);
int ssh_buffer_put_u64(ssh_buffer_t *buf, uint64_t value);
int ssh_buffer_put_bytes(ssh_buffer_t *buf, const uint8_t *data, size_t len);
int ssh_buffer_put_string(ssh_buffer_t *buf, const uint8_t *data, size_t len);
int ssh_buffer_put_cstring(ssh_buffer_t *buf, const char *value);
int ssh_buffer_put_mpint_positive(ssh_buffer_t *buf, const uint8_t *data, size_t len);

int ssh_buffer_get_u8(ssh_buffer_t *buf, uint8_t *value);
int ssh_buffer_get_bool(ssh_buffer_t *buf, int *value);
int ssh_buffer_get_u32(ssh_buffer_t *buf, uint32_t *value);
int ssh_buffer_get_u64(ssh_buffer_t *buf, uint64_t *value);
int ssh_buffer_get_bytes(ssh_buffer_t *buf, uint8_t *out, size_t len);
int ssh_buffer_get_string_view(ssh_buffer_t *buf, ssh_string_view_t *view);

int ssh_name_list_is_valid(ssh_string_view_t list);
int ssh_name_list_contains_token(ssh_string_view_t list, const char *token);

#endif
