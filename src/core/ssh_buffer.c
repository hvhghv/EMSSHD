#include "emssh/ssh_buffer.h"

#include <string.h>

#include "emssh/ssh_error.h"

void ssh_buffer_init(ssh_buffer_t *buf, uint8_t *storage, size_t capacity)
{
    if (buf == NULL) {
        return;
    }

    buf->data = storage;
    buf->capacity = capacity;
    buf->len = 0;
    buf->pos = 0;
}

void ssh_buffer_wrap(ssh_buffer_t *buf, uint8_t *storage, size_t len)
{
    if (buf == NULL) {
        return;
    }

    buf->data = storage;
    buf->capacity = len;
    buf->len = len;
    buf->pos = 0;
}

void ssh_buffer_reset(ssh_buffer_t *buf)
{
    if (buf == NULL) {
        return;
    }

    buf->len = 0;
    buf->pos = 0;
}

size_t ssh_buffer_len(const ssh_buffer_t *buf)
{
    return buf != NULL ? buf->len : 0u;
}

size_t ssh_buffer_capacity(const ssh_buffer_t *buf)
{
    return buf != NULL ? buf->capacity : 0u;
}

size_t ssh_buffer_remaining_read(const ssh_buffer_t *buf)
{
    if (buf == NULL || buf->pos > buf->len) {
        return 0u;
    }

    return buf->len - buf->pos;
}

size_t ssh_buffer_remaining_write(const ssh_buffer_t *buf)
{
    if (buf == NULL || buf->len > buf->capacity) {
        return 0u;
    }

    return buf->capacity - buf->len;
}

uint8_t *ssh_buffer_data(ssh_buffer_t *buf)
{
    return buf != NULL ? buf->data : NULL;
}

const uint8_t *ssh_buffer_const_data(const ssh_buffer_t *buf)
{
    return buf != NULL ? buf->data : NULL;
}

int ssh_buffer_put_u8(ssh_buffer_t *buf, uint8_t value)
{
    if (buf == NULL || buf->data == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (ssh_buffer_remaining_write(buf) < 1u) {
        return SSH_ERR_BUFFER_OVERFLOW;
    }

    buf->data[buf->len++] = value;
    return SSH_OK;
}

int ssh_buffer_put_bool(ssh_buffer_t *buf, int value)
{
    return ssh_buffer_put_u8(buf, value ? 1u : 0u);
}

int ssh_buffer_put_u32(ssh_buffer_t *buf, uint32_t value)
{
    if (buf == NULL || buf->data == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (ssh_buffer_remaining_write(buf) < 4u) {
        return SSH_ERR_BUFFER_OVERFLOW;
    }

    buf->data[buf->len++] = (uint8_t)((value >> 24) & 0xffu);
    buf->data[buf->len++] = (uint8_t)((value >> 16) & 0xffu);
    buf->data[buf->len++] = (uint8_t)((value >> 8) & 0xffu);
    buf->data[buf->len++] = (uint8_t)(value & 0xffu);
    return SSH_OK;
}

int ssh_buffer_put_u64(ssh_buffer_t *buf, uint64_t value)
{
    if (buf == NULL || buf->data == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (ssh_buffer_remaining_write(buf) < 8u) {
        return SSH_ERR_BUFFER_OVERFLOW;
    }

    buf->data[buf->len++] = (uint8_t)((value >> 56) & 0xffu);
    buf->data[buf->len++] = (uint8_t)((value >> 48) & 0xffu);
    buf->data[buf->len++] = (uint8_t)((value >> 40) & 0xffu);
    buf->data[buf->len++] = (uint8_t)((value >> 32) & 0xffu);
    buf->data[buf->len++] = (uint8_t)((value >> 24) & 0xffu);
    buf->data[buf->len++] = (uint8_t)((value >> 16) & 0xffu);
    buf->data[buf->len++] = (uint8_t)((value >> 8) & 0xffu);
    buf->data[buf->len++] = (uint8_t)(value & 0xffu);
    return SSH_OK;
}

int ssh_buffer_put_bytes(ssh_buffer_t *buf, const uint8_t *data, size_t len)
{
    if (buf == NULL || buf->data == NULL || (data == NULL && len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (ssh_buffer_remaining_write(buf) < len) {
        return SSH_ERR_BUFFER_OVERFLOW;
    }

    if (len != 0u) {
        memcpy(buf->data + buf->len, data, len);
        buf->len += len;
    }

    return SSH_OK;
}

int ssh_buffer_put_string(ssh_buffer_t *buf, const uint8_t *data, size_t len)
{
    if (len > UINT32_MAX) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    {
        int status = ssh_buffer_put_u32(buf, (uint32_t)len);
        if (status != SSH_OK) {
            return status;
        }
    }

    return ssh_buffer_put_bytes(buf, data, len);
}

int ssh_buffer_put_cstring(ssh_buffer_t *buf, const char *value)
{
    if (value == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    return ssh_buffer_put_string(buf, (const uint8_t *)value, strlen(value));
}

int ssh_buffer_put_mpint_positive(ssh_buffer_t *buf, const uint8_t *data, size_t len)
{
    size_t start;
    size_t encoded_len;
    int status;

    if (buf == NULL || buf->data == NULL || (data == NULL && len != 0u) || len > UINT32_MAX) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    start = 0u;
    while (start < len && data[start] == 0u) {
        ++start;
    }

    if (start == len) {
        return ssh_buffer_put_u32(buf, 0u);
    }

    encoded_len = len - start;
    if ((data[start] & 0x80u) != 0u) {
        if (encoded_len >= UINT32_MAX) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        status = ssh_buffer_put_u32(buf, (uint32_t)(encoded_len + 1u));
        if (status == SSH_OK) {
            status = ssh_buffer_put_u8(buf, 0u);
        }
        if (status == SSH_OK) {
            status = ssh_buffer_put_bytes(buf, data + start, encoded_len);
        }
        return status;
    }

    return ssh_buffer_put_string(buf, data + start, encoded_len);
}

int ssh_buffer_get_u8(ssh_buffer_t *buf, uint8_t *value)
{
    if (buf == NULL || value == NULL || buf->data == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (ssh_buffer_remaining_read(buf) < 1u) {
        return SSH_ERR_BUFFER_UNDERFLOW;
    }

    *value = buf->data[buf->pos++];
    return SSH_OK;
}

int ssh_buffer_get_bool(ssh_buffer_t *buf, int *value)
{
    uint8_t raw;
    int status;

    if (value == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_get_u8(buf, &raw);
    if (status != SSH_OK) {
        return status;
    }

    if (raw != 0u && raw != 1u) {
        return SSH_ERR_MALFORMED_PACKET;
    }

    *value = raw != 0u;
    return SSH_OK;
}

int ssh_buffer_get_u32(ssh_buffer_t *buf, uint32_t *value)
{
    const uint8_t *p;

    if (buf == NULL || value == NULL || buf->data == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (ssh_buffer_remaining_read(buf) < 4u) {
        return SSH_ERR_BUFFER_UNDERFLOW;
    }

    p = buf->data + buf->pos;
    *value = ((uint32_t)p[0] << 24) |
             ((uint32_t)p[1] << 16) |
             ((uint32_t)p[2] << 8) |
             (uint32_t)p[3];
    buf->pos += 4u;
    return SSH_OK;
}

int ssh_buffer_get_u64(ssh_buffer_t *buf, uint64_t *value)
{
    const uint8_t *p;

    if (buf == NULL || value == NULL || buf->data == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (ssh_buffer_remaining_read(buf) < 8u) {
        return SSH_ERR_BUFFER_UNDERFLOW;
    }

    p = buf->data + buf->pos;
    *value = ((uint64_t)p[0] << 56) |
             ((uint64_t)p[1] << 48) |
             ((uint64_t)p[2] << 40) |
             ((uint64_t)p[3] << 32) |
             ((uint64_t)p[4] << 24) |
             ((uint64_t)p[5] << 16) |
             ((uint64_t)p[6] << 8) |
             (uint64_t)p[7];
    buf->pos += 8u;
    return SSH_OK;
}

int ssh_buffer_get_bytes(ssh_buffer_t *buf, uint8_t *out, size_t len)
{
    if (buf == NULL || buf->data == NULL || (out == NULL && len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (ssh_buffer_remaining_read(buf) < len) {
        return SSH_ERR_BUFFER_UNDERFLOW;
    }

    if (len != 0u) {
        memcpy(out, buf->data + buf->pos, len);
        buf->pos += len;
    }

    return SSH_OK;
}

int ssh_buffer_get_string_view(ssh_buffer_t *buf, ssh_string_view_t *view)
{
    uint32_t len;
    int status;

    if (buf == NULL || view == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    status = ssh_buffer_get_u32(buf, &len);
    if (status != SSH_OK) {
        return status;
    }

    if (ssh_buffer_remaining_read(buf) < (size_t)len) {
        return SSH_ERR_BUFFER_UNDERFLOW;
    }

    view->data = buf->data + buf->pos;
    view->len = (size_t)len;
    buf->pos += (size_t)len;
    return SSH_OK;
}

static int ssh_name_char_is_valid(uint8_t c)
{
    return c >= 0x21u && c <= 0x7eu && c != ',';
}

int ssh_name_list_is_valid(ssh_string_view_t list)
{
    size_t i;
    int previous_was_comma = 0;

    if (list.len == 0u) {
        return 1;
    }

    if (list.data == NULL || list.data[0] == ',' || list.data[list.len - 1u] == ',') {
        return 0;
    }

    for (i = 0; i < list.len; ++i) {
        if (list.data[i] == ',') {
            if (previous_was_comma) {
                return 0;
            }
            previous_was_comma = 1;
            continue;
        }

        if (!ssh_name_char_is_valid(list.data[i])) {
            return 0;
        }

        previous_was_comma = 0;
    }

    return 1;
}

int ssh_name_list_contains_token(ssh_string_view_t list, const char *token)
{
    size_t token_len;
    size_t start;
    size_t i;

    if (token == NULL || list.data == NULL) {
        return 0;
    }

    token_len = strlen(token);
    if (token_len == 0u || list.len == 0u) {
        return 0;
    }

    start = 0u;
    for (i = 0u; i <= list.len; ++i) {
        if (i == list.len || list.data[i] == ',') {
            size_t item_len = i - start;
            if (item_len == token_len && memcmp(list.data + start, token, token_len) == 0) {
                return 1;
            }
            start = i + 1u;
        }
    }

    return 0;
}
