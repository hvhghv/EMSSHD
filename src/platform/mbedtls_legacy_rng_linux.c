#include <stddef.h>

#if defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>
#endif

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    (void)data;

    if (output == NULL || olen == NULL) {
        return -1;
    }

    *olen = 0u;
    if (len == 0u) {
        return 0;
    }

#if !defined(__linux__)
    return -1;
#else
    size_t total = 0u;
    int fd;

    /* Prefer getrandom() when available. */
    while (total < len) {
        ssize_t n = getrandom(output + total, len - total, 0u);
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == ENOSYS || errno == EAGAIN)) {
            break;
        }
        if (n <= 0) {
            break;
        }
    }
    if (total == len) {
        *olen = total;
        return 0;
    }

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        fd = open("/dev/random", O_RDONLY);
        if (fd < 0) {
            *olen = total;
            return -1;
        }
    }

    while (total < len) {
        ssize_t n = read(fd, output + total, len - total);
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        if (n == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        (void)close(fd);
        *olen = total;
        return -1;
    }

    (void)close(fd);
    *olen = total;
    return total == len ? 0 : -1;
#endif
}
