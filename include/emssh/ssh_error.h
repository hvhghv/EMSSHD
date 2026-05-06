#ifndef EMSSH_SSH_ERROR_H
#define EMSSH_SSH_ERROR_H

typedef enum ssh_status {
    SSH_OK = 0,
    SSH_ERR_INVALID_ARGUMENT = -1,
    SSH_ERR_BUFFER_TOO_SMALL = -2,
    SSH_ERR_BUFFER_OVERFLOW = -3,
    SSH_ERR_BUFFER_UNDERFLOW = -4,
    SSH_ERR_MALFORMED_PACKET = -5,
    SSH_ERR_UNSUPPORTED = -6,
    SSH_ERR_PLATFORM = -7,
    SSH_ERR_SECURITY = -8,
    SSH_ERR_CLOSED = -9,
    SSH_ERR_NOT_FOUND = -10,
    SSH_ERR_ALREADY_EXISTS = -11,
    SSH_ERR_DIR_NOT_EMPTY = -12,
    SSH_ERR_READ_ONLY = -13
} ssh_status_t;

const char *ssh_status_string(int status);

#endif
