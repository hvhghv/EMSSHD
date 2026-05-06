#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "emssh/platform_posix_passwd_auth.h"
#include "emssh/platform_stdio_fs.h"
#include "emssh/ssh_error.h"

#if !defined(_WIN32)
#include <unistd.h>
#if defined(__has_include)
#if __has_include(<crypt.h>)
#include <crypt.h>
#endif
#endif
#endif

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static int build_request(ssh_password_auth_request_t *request, const char *username, const char *password)
{
    if (request == NULL || username == NULL || password == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(request, 0, sizeof(*request));
    request->username = username;
    request->username_len = strlen(username);
    request->password = password;
    request->password_len = strlen(password);
    return SSH_OK;
}

int main(void)
{
    ssh_posix_passwd_auth_t auth;
    ssh_stdio_fs_t fs;
    ssh_password_auth_request_t request;

    memset(&auth, 0, sizeof(auth));
    memset(&fs, 0, sizeof(fs));
    memset(&request, 0, sizeof(request));

#if defined(_WIN32)
    CHECK(ssh_posix_passwd_auth_init(&auth, NULL, NULL, NULL) == SSH_ERR_UNSUPPORTED);
    return 0;
#else
    char passwd_template[] = "/tmp/emssh-passwd-test-XXXXXX";
    char shadow_template[] = "/tmp/emssh-shadow-test-XXXXXX";
    int passwd_fd;
    int shadow_fd;
    FILE *passwd_fp;
    FILE *shadow_fp;
    const char *hash;

    passwd_fd = mkstemp(passwd_template);
    CHECK(passwd_fd >= 0);
    shadow_fd = mkstemp(shadow_template);
    CHECK(shadow_fd >= 0);

    passwd_fp = fdopen(passwd_fd, "w");
    CHECK(passwd_fp != NULL);
    shadow_fp = fdopen(shadow_fd, "w");
    CHECK(shadow_fp != NULL);

    hash = crypt("secret123", "ab");
    CHECK(hash != NULL);
    CHECK(fprintf(passwd_fp, "demo:x:1000:1000::/home/demo:/bin/sh\n") > 0);
    CHECK(fprintf(passwd_fp, "direct:%s:1001:1001::/home/direct:/bin/sh\n", hash) > 0);
    CHECK(fflush(passwd_fp) == 0);
    CHECK(fclose(passwd_fp) == 0);

    CHECK(fprintf(shadow_fp, "demo:%s:20000:0:99999:7:::\n", hash) > 0);
    CHECK(fflush(shadow_fp) == 0);
    CHECK(fclose(shadow_fp) == 0);

    CHECK(ssh_stdio_fs_init(&fs, "/") == SSH_OK);

    CHECK(ssh_posix_passwd_auth_init(&auth, ssh_stdio_fs_api(&fs), passwd_template, shadow_template) == SSH_OK);

    CHECK(build_request(&request, "demo", "secret123") == SSH_OK);
    CHECK(ssh_posix_passwd_auth_cb(&auth, &request) == 1);

    CHECK(build_request(&request, "direct", "secret123") == SSH_OK);
    CHECK(ssh_posix_passwd_auth_cb(&auth, &request) == 1);

    CHECK(build_request(&request, "demo", "bad-password") == SSH_OK);
    CHECK(ssh_posix_passwd_auth_cb(&auth, &request) == 0);

    CHECK(build_request(&request, "nobody", "secret123") == SSH_OK);
    CHECK(ssh_posix_passwd_auth_cb(&auth, &request) == 0);

    ssh_posix_passwd_auth_deinit(&auth);
    ssh_stdio_fs_deinit(&fs);
    CHECK(unlink(passwd_template) == 0);
    CHECK(unlink(shadow_template) == 0);
    return 0;
#endif
}
