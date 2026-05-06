#include <stdio.h>
#include <string.h>

#include "emssh/ssh_error.h"
#include "emssh/ssh_service.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static int view_eq(ssh_string_view_t view, const char *value)
{
    size_t len = strlen(value);
    return view.len == len && memcmp(view.data, value, len) == 0;
}

int main(void)
{
    uint8_t storage[64];
    ssh_buffer_t buf;
    ssh_service_request_t request;

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_service_request_encode(&buf, SSH_SERVICE_USERAUTH) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_service_request_decode(&buf, &request) == SSH_OK);
    CHECK(view_eq(request.service_name, SSH_SERVICE_USERAUTH));
    CHECK(ssh_service_name_is_supported(request.service_name));

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_service_accept_encode(&buf, SSH_SERVICE_USERAUTH) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_service_accept_decode(&buf, &request) == SSH_OK);
    CHECK(view_eq(request.service_name, SSH_SERVICE_USERAUTH));

    ssh_buffer_init(&buf, storage, sizeof(storage));
    CHECK(ssh_service_request_encode(&buf, SSH_SERVICE_CONNECTION) == SSH_OK);
    ssh_buffer_wrap(&buf, storage, ssh_buffer_len(&buf));
    CHECK(ssh_service_request_decode(&buf, &request) == SSH_OK);
    CHECK(!ssh_service_name_is_supported(request.service_name));

    return 0;
}

