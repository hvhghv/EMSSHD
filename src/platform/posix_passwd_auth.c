#include "emssh/platform_posix_passwd_auth.h"

#include <string.h>

#include "emssh/sftp.h"
#include "emssh/ssh_error.h"

#include <crypt.h>

#define EMSSH_POSIX_PASSWD_PATH "/etc/passwd"
#define EMSSH_POSIX_SHADOW_PATH "/etc/shadow"
#define EMSSH_POSIX_PASSWD_AUTH_LINE_MAX 2048u
#define EMSSH_POSIX_PASSWD_AUTH_HASH_MAX 512u
#define EMSSH_POSIX_PASSWD_AUTH_USERNAME_MAX 256u
#define EMSSH_POSIX_PASSWD_AUTH_PASSWORD_MAX 256u

static void secure_zero_bytes(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    size_t i;

    if (p == NULL) {
        return;
    }
    for (i = 0u; i < len; ++i) {
        p[i] = 0u;
    }
}

static int copy_request_field(
    const char *data,
    size_t len,
    char *out,
    size_t out_capacity,
    size_t *out_len)
{
    if (out == NULL || out_len == NULL || out_capacity == 0u || (data == NULL && len != 0u)) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (len + 1u > out_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    if (len != 0u) {
        memcpy(out, data, len);
    }
    out[len] = '\0';
    *out_len = len;
    return SSH_OK;
}

static int line_extract_hash_for_user(
    const char *line,
    const char *username,
    const char **hash,
    size_t *hash_len)
{
    const char *user_end;
    const char *hash_begin;
    const char *hash_end;
    size_t user_len;
    size_t expected_user_len;

    if (line == NULL || username == NULL || hash == NULL || hash_len == NULL) {
        return 0;
    }

    user_end = strchr(line, ':');
    if (user_end == NULL) {
        return 0;
    }
    user_len = (size_t)(user_end - line);
    expected_user_len = strlen(username);
    if (user_len != expected_user_len || memcmp(line, username, user_len) != 0) {
        return 0;
    }

    hash_begin = user_end + 1;
    hash_end = strchr(hash_begin, ':');
    if (hash_end == NULL || hash_end <= hash_begin) {
        return 0;
    }

    *hash = hash_begin;
    *hash_len = (size_t)(hash_end - hash_begin);
    return 1;
}

static int hash_field_requires_shadow(const char *hash, size_t hash_len)
{
    if (hash == NULL || hash_len == 0u) {
        return 0;
    }
    if (hash_len == 1u && (hash[0] == 'x' || hash[0] == '*' || hash[0] == '!')) {
        return 1;
    }
    if (hash_len == 2u && hash[0] == '!' && hash[1] == '!') {
        return 1;
    }
    return 0;
}

static int hash_field_is_usable(const char *hash, size_t hash_len)
{
    if (hash == NULL || hash_len == 0u) {
        return 0;
    }
    if (hash_len == 1u && (hash[0] == 'x' || hash[0] == '*' || hash[0] == '!')) {
        return 0;
    }
    if (hash_len == 2u && hash[0] == '!' && hash[1] == '!') {
        return 0;
    }
    return 1;
}

static int verify_password_against_hash(const char *password, const char *hash, size_t hash_len)
{
    char hash_copy[EMSSH_POSIX_PASSWD_AUTH_HASH_MAX];
    char *result;
    size_t result_len;

    if (password == NULL || hash == NULL || hash_len == 0u || hash_len >= sizeof(hash_copy)) {
        return 0;
    }

    memcpy(hash_copy, hash, hash_len);
    hash_copy[hash_len] = '\0';

    result = crypt(password, hash_copy);
    if (result == NULL) {
        return 0;
    }
    result_len = strlen(result);
    return result_len == hash_len && memcmp(result, hash_copy, hash_len) == 0;
}

static int parse_line_copy_hash_if_match(
    char *line,
    const char *username,
    char *hash,
    size_t hash_capacity,
    size_t *hash_len,
    int *matched)
{
    const char *hash_view;
    size_t view_len;

    if (line == NULL || username == NULL || hash == NULL || hash_len == NULL || matched == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    *matched = 0;
    if (!line_extract_hash_for_user(line, username, &hash_view, &view_len)) {
        return SSH_OK;
    }
    if (view_len + 1u > hash_capacity) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(hash, hash_view, view_len);
    hash[view_len] = '\0';
    *hash_len = view_len;
    *matched = 1;
    return SSH_OK;
}

static int read_hash_from_file(
    const ssh_fs_api_t *fs,
    const char *path,
    const char *username,
    char *hash,
    size_t hash_capacity,
    size_t *hash_len)
{
    void *handle;
    char chunk[512];
    char line[EMSSH_POSIX_PASSWD_AUTH_LINE_MAX];
    size_t line_len;
    size_t i;
    size_t read_len;
    int status;

    if (fs == NULL || fs->open == NULL || fs->read == NULL || fs->close == NULL ||
        path == NULL || username == NULL || hash == NULL || hash_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    handle = NULL;
    line_len = 0u;
    status = fs->open(fs->ctx, path, SSH_FXF_READ, &handle);
    if (status != SSH_OK) {
        return status;
    }

    for (;;) {
        read_len = 0u;
        status = fs->read(fs->ctx, handle, (uint8_t *)chunk, sizeof(chunk), &read_len);
        if (status != SSH_OK) {
            (void)fs->close(fs->ctx, handle);
            return status;
        }
        if (read_len == 0u) {
            break;
        }

        for (i = 0u; i < read_len; ++i) {
            if (chunk[i] == '\n') {
                int matched;

                if (line_len != 0u && line[line_len - 1u] == '\r') {
                    --line_len;
                }
                line[line_len] = '\0';
                status = parse_line_copy_hash_if_match(
                    line,
                    username,
                    hash,
                    hash_capacity,
                    hash_len,
                    &matched);
                if (status != SSH_OK) {
                    (void)fs->close(fs->ctx, handle);
                    return status;
                }
                if (matched) {
                    (void)fs->close(fs->ctx, handle);
                    return SSH_OK;
                }
                line_len = 0u;
                continue;
            }

            if (line_len + 1u >= sizeof(line)) {
                (void)fs->close(fs->ctx, handle);
                return SSH_ERR_BUFFER_TOO_SMALL;
            }
            line[line_len++] = chunk[i];
        }
    }

    if (line_len != 0u) {
        int matched;

        if (line[line_len - 1u] == '\r') {
            --line_len;
        }
        line[line_len] = '\0';
        status = parse_line_copy_hash_if_match(
            line,
            username,
            hash,
            hash_capacity,
            hash_len,
            &matched);
        if (status != SSH_OK) {
            (void)fs->close(fs->ctx, handle);
            return status;
        }
        if (matched) {
            (void)fs->close(fs->ctx, handle);
            return SSH_OK;
        }
    }

    (void)fs->close(fs->ctx, handle);
    return SSH_ERR_NOT_FOUND;
}

static int passwd_auth_verify(
    const ssh_fs_api_t *fs,
    const char *passwd_path,
    const char *shadow_path,
    const char *username,
    const char *password)
{
    char hash[EMSSH_POSIX_PASSWD_AUTH_HASH_MAX];
    size_t hash_len;
    int status;

    if (fs == NULL || passwd_path == NULL || username == NULL || password == NULL) {
        return 0;
    }

    hash_len = 0u;
    status = read_hash_from_file(fs, passwd_path, username, hash, sizeof(hash), &hash_len);
    if (status != SSH_OK) {
        return 0;
    }

    if (hash_field_requires_shadow(hash, hash_len) && shadow_path != NULL && shadow_path[0] != '\0') {
        hash_len = 0u;
        status = read_hash_from_file(fs, shadow_path, username, hash, sizeof(hash), &hash_len);
        if (status != SSH_OK) {
            secure_zero_bytes(hash, sizeof(hash));
            return 0;
        }
    }

    if (!hash_field_is_usable(hash, hash_len)) {
        secure_zero_bytes(hash, sizeof(hash));
        return 0;
    }

    status = verify_password_against_hash(password, hash, hash_len);
    secure_zero_bytes(hash, sizeof(hash));
    return status;
}

int ssh_posix_passwd_auth_init(
    ssh_posix_passwd_auth_t *auth,
    const ssh_fs_api_t *fs,
    const char *passwd_path,
    const char *shadow_path)
{
    if (auth == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (fs == NULL || fs->open == NULL || fs->read == NULL || fs->close == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(auth, 0, sizeof(*auth));
    auth->fs = fs;
    auth->passwd_path = (passwd_path != NULL && passwd_path[0] != '\0') ? passwd_path : EMSSH_POSIX_PASSWD_PATH;
    auth->shadow_path = (shadow_path != NULL && shadow_path[0] != '\0') ? shadow_path : EMSSH_POSIX_SHADOW_PATH;
    auth->initialized = 1;
    return SSH_OK;
}

void ssh_posix_passwd_auth_deinit(ssh_posix_passwd_auth_t *auth)
{
    if (auth == NULL) {
        return;
    }
    memset(auth, 0, sizeof(*auth));
}

int ssh_posix_passwd_auth_cb(void *ctx, const ssh_password_auth_request_t *request)
{
    ssh_posix_passwd_auth_t *auth = (ssh_posix_passwd_auth_t *)ctx;

    if (auth == NULL || !auth->initialized || request == NULL) {
        return 0;
    }

    char username[EMSSH_POSIX_PASSWD_AUTH_USERNAME_MAX];
    char password[EMSSH_POSIX_PASSWD_AUTH_PASSWORD_MAX];
    size_t username_len;
    size_t password_len;
    int rc;
    int allowed;

    username_len = 0u;
    password_len = 0u;
    rc = copy_request_field(
        request->username,
        request->username_len,
        username,
        sizeof(username),
        &username_len);
    if (rc != SSH_OK) {
        return 0;
    }

    rc = copy_request_field(
        request->password,
        request->password_len,
        password,
        sizeof(password),
        &password_len);
    if (rc != SSH_OK) {
        secure_zero_bytes(username, username_len);
        return 0;
    }

    allowed = passwd_auth_verify(auth->fs, auth->passwd_path, auth->shadow_path, username, password);
    secure_zero_bytes(password, password_len);
    secure_zero_bytes(username, username_len);
    return allowed;
}
