#include "emssh/platform_posix_term.h"

#include <stdlib.h>
#include <string.h>

#include "emssh/ssh_error.h"

#ifdef _WIN32
int ssh_posix_term_platform_init(ssh_posix_term_platform_t *term)
{
    if (term == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    return SSH_ERR_UNSUPPORTED;
}

void ssh_posix_term_platform_deinit(ssh_posix_term_platform_t *term)
{
    (void)term;
}

const ssh_term_api_t *ssh_posix_term_api(ssh_posix_term_platform_t *term)
{
    (void)term;
    return NULL;
}

#else
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <util.h>
#else
#include <pty.h>
#endif

typedef struct ssh_posix_term_handle {
    int master_fd;
    pid_t child_pid;
    int is_pty;
    int exited;
    uint32_t exit_status;
} ssh_posix_term_handle_t;

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return SSH_ERR_PLATFORM;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        return SSH_ERR_PLATFORM;
    }
    return SSH_OK;
}

static void apply_term_env(const char *term_type)
{
    if (term_type != NULL && term_type[0] != '\0') {
        (void)setenv("TERM", term_type, 1);
    }
}

static int apply_user_env_from_passwd(const struct passwd *pw)
{
    if (pw == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (pw->pw_dir != NULL && pw->pw_dir[0] != '\0') {
        if (setenv("HOME", pw->pw_dir, 1) != 0) {
            return SSH_ERR_PLATFORM;
        }
    }
    if (pw->pw_name != NULL && pw->pw_name[0] != '\0') {
        if (setenv("USER", pw->pw_name, 1) != 0) {
            return SSH_ERR_PLATFORM;
        }
        if (setenv("LOGNAME", pw->pw_name, 1) != 0) {
            return SSH_ERR_PLATFORM;
        }
    }
    if (pw->pw_shell != NULL && pw->pw_shell[0] != '\0') {
        if (setenv("SHELL", pw->pw_shell, 1) != 0) {
            return SSH_ERR_PLATFORM;
        }
    }
    return SSH_OK;
}

static int apply_authenticated_user_context(const char *username)
{
    const struct passwd *pw;
    uid_t euid;
    int status;

    if (username == NULL || username[0] == '\0') {
        return SSH_OK;
    }

    errno = 0;
    pw = getpwnam(username);
    if (pw == NULL) {
        return SSH_ERR_SECURITY;
    }

    euid = geteuid();
    if (euid == 0u) {
        if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
            return SSH_ERR_PLATFORM;
        }
        if (setgid(pw->pw_gid) != 0) {
            return SSH_ERR_PLATFORM;
        }
        if (setuid(pw->pw_uid) != 0) {
            return SSH_ERR_PLATFORM;
        }
    } else if (euid != pw->pw_uid) {
        return SSH_ERR_SECURITY;
    }

    status = apply_user_env_from_passwd(pw);
    if (status != SSH_OK) {
        return status;
    }

    if (pw->pw_dir != NULL && pw->pw_dir[0] != '\0') {
        (void)chdir(pw->pw_dir);
    }

    return SSH_OK;
}

static int read_startup_status(int fd, int *status_out)
{
    uint8_t *dst = (uint8_t *)status_out;
    size_t remaining = sizeof(*status_out);

    if (fd < 0 || status_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    while (remaining > 0u) {
        ssize_t n = read(fd, dst, remaining);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return SSH_ERR_PLATFORM;
        }
        if (n == 0) {
            return SSH_ERR_PLATFORM;
        }
        dst += (size_t)n;
        remaining -= (size_t)n;
    }
    return SSH_OK;
}

static int spawn_with_pty(
    const char *username,
    const char *term_type,
    uint32_t cols,
    uint32_t rows,
    uint32_t width_px,
    uint32_t height_px,
    void (*child_main)(const char *arg),
    const char *child_arg,
    void **handle_out)
{
    struct winsize ws;
    int startup_pipe[2];
    int startup_status;
    int master_fd;
    pid_t pid;
    ssh_posix_term_handle_t *handle;
    int status;

    if (child_main == NULL || handle_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(&ws, 0, sizeof(ws));
    ws.ws_col = (unsigned short)(cols != 0u ? cols : 80u);
    ws.ws_row = (unsigned short)(rows != 0u ? rows : 24u);
    ws.ws_xpixel = (unsigned short)width_px;
    ws.ws_ypixel = (unsigned short)height_px;

    startup_pipe[0] = -1;
    startup_pipe[1] = -1;
    if (pipe(startup_pipe) != 0) {
        return SSH_ERR_PLATFORM;
    }

    master_fd = -1;
    pid = forkpty(&master_fd, NULL, NULL, &ws);
    if (pid < 0) {
        (void)close(startup_pipe[0]);
        (void)close(startup_pipe[1]);
        return SSH_ERR_PLATFORM;
    }
    if (pid == 0) {
        (void)close(startup_pipe[0]);
        apply_term_env(term_type);
        startup_status = apply_authenticated_user_context(username);
        (void)write(startup_pipe[1], &startup_status, sizeof(startup_status));
        (void)close(startup_pipe[1]);
        if (startup_status != SSH_OK) {
            _exit(127);
        }
        child_main(child_arg);
        _exit(127);
    }
    (void)close(startup_pipe[1]);
    startup_status = SSH_ERR_PLATFORM;
    status = read_startup_status(startup_pipe[0], &startup_status);
    (void)close(startup_pipe[0]);
    if (status != SSH_OK || startup_status != SSH_OK) {
        (void)close(master_fd);
        (void)waitpid(pid, NULL, 0);
        return (status == SSH_OK) ? startup_status : status;
    }

    if (set_nonblocking(master_fd) != SSH_OK) {
        (void)close(master_fd);
        (void)kill(pid, SIGTERM);
        (void)waitpid(pid, NULL, 0);
        return SSH_ERR_PLATFORM;
    }

    handle = (ssh_posix_term_handle_t *)calloc(1u, sizeof(*handle));
    if (handle == NULL) {
        (void)close(master_fd);
        (void)kill(pid, SIGTERM);
        (void)waitpid(pid, NULL, 0);
        return SSH_ERR_PLATFORM;
    }

    handle->master_fd = master_fd;
    handle->child_pid = pid;
    handle->is_pty = 1;
    handle->exited = 0;
    handle->exit_status = 0u;
    *handle_out = handle;
    return SSH_OK;
}

static int spawn_with_stream(
    const char *username,
    void (*child_main)(const char *arg),
    const char *child_arg,
    void **handle_out)
{
    int startup_pipe[2];
    int stream_fds[2];
    int startup_status;
    pid_t pid;
    ssh_posix_term_handle_t *handle;
    int status;

    if (child_main == NULL || handle_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    startup_pipe[0] = -1;
    startup_pipe[1] = -1;
    stream_fds[0] = -1;
    stream_fds[1] = -1;
    if (pipe(startup_pipe) != 0) {
        return SSH_ERR_PLATFORM;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, stream_fds) != 0) {
        (void)close(startup_pipe[0]);
        (void)close(startup_pipe[1]);
        return SSH_ERR_PLATFORM;
    }
#ifdef SO_NOSIGPIPE
    {
        int enabled = 1;
        (void)setsockopt(stream_fds[0], SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
        (void)setsockopt(stream_fds[1], SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
    }
#endif

    pid = fork();
    if (pid < 0) {
        (void)close(startup_pipe[0]);
        (void)close(startup_pipe[1]);
        (void)close(stream_fds[0]);
        (void)close(stream_fds[1]);
        return SSH_ERR_PLATFORM;
    }
    if (pid == 0) {
        (void)close(startup_pipe[0]);
        (void)close(stream_fds[0]);
        startup_status = SSH_OK;
        if (dup2(stream_fds[1], STDIN_FILENO) < 0 ||
            dup2(stream_fds[1], STDOUT_FILENO) < 0 ||
            dup2(stream_fds[1], STDERR_FILENO) < 0) {
            startup_status = SSH_ERR_PLATFORM;
        }
        if (stream_fds[1] > STDERR_FILENO) {
            (void)close(stream_fds[1]);
        }
        if (startup_status == SSH_OK) {
            startup_status = apply_authenticated_user_context(username);
        }
        (void)write(startup_pipe[1], &startup_status, sizeof(startup_status));
        (void)close(startup_pipe[1]);
        if (startup_status != SSH_OK) {
            _exit(127);
        }
        child_main(child_arg);
        _exit(127);
    }

    (void)close(startup_pipe[1]);
    (void)close(stream_fds[1]);
    startup_status = SSH_ERR_PLATFORM;
    status = read_startup_status(startup_pipe[0], &startup_status);
    (void)close(startup_pipe[0]);
    if (status != SSH_OK || startup_status != SSH_OK) {
        (void)close(stream_fds[0]);
        (void)waitpid(pid, NULL, 0);
        return status == SSH_OK ? startup_status : status;
    }

    if (set_nonblocking(stream_fds[0]) != SSH_OK) {
        (void)close(stream_fds[0]);
        (void)kill(pid, SIGTERM);
        (void)waitpid(pid, NULL, 0);
        return SSH_ERR_PLATFORM;
    }

    handle = (ssh_posix_term_handle_t *)calloc(1u, sizeof(*handle));
    if (handle == NULL) {
        (void)close(stream_fds[0]);
        (void)kill(pid, SIGTERM);
        (void)waitpid(pid, NULL, 0);
        return SSH_ERR_PLATFORM;
    }

    handle->master_fd = stream_fds[0];
    handle->child_pid = pid;
    handle->is_pty = 0;
    handle->exited = 0;
    handle->exit_status = 0u;
    *handle_out = handle;
    return SSH_OK;
}

static void child_main_shell(const char *unused)
{
    const char *shell = getenv("SHELL");
    (void)unused;
    if (shell == NULL || shell[0] == '\0') {
        shell = "/bin/sh";
    }
    execl(shell, shell, (char *)NULL);
}

static void child_main_exec(const char *command)
{
    if (command == NULL || command[0] == '\0') {
        command = "true";
    }
    execl("/bin/sh", "sh", "-c", command, (char *)NULL);
}

static int posix_term_spawn_shell(
    void *ctx,
    const char *username,
    const char *term_type,
    uint32_t cols,
    uint32_t rows,
    uint32_t width_px,
    uint32_t height_px,
    void **handle)
{
    (void)ctx;
    if (term_type == NULL) {
        return spawn_with_stream(username, child_main_shell, NULL, handle);
    }
    return spawn_with_pty(username, term_type, cols, rows, width_px, height_px, child_main_shell, NULL, handle);
}

static int posix_term_spawn_exec(
    void *ctx,
    const char *username,
    const char *command,
    const char *term_type,
    uint32_t cols,
    uint32_t rows,
    uint32_t width_px,
    uint32_t height_px,
    void **handle)
{
    (void)ctx;
    if (term_type == NULL) {
        return spawn_with_stream(username, child_main_exec, command, handle);
    }
    return spawn_with_pty(username, term_type, cols, rows, width_px, height_px, child_main_exec, command, handle);
}

static int posix_term_write(
    void *ctx,
    void *handle_ptr,
    const uint8_t *buf,
    size_t len,
    size_t *written_len)
{
    ssh_posix_term_handle_t *handle = (ssh_posix_term_handle_t *)handle_ptr;
    ssize_t n;
    (void)ctx;

    if (handle == NULL || (buf == NULL && len != 0u) || written_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    *written_len = 0u;
    if (len == 0u) {
        return SSH_OK;
    }

    if (handle->is_pty) {
        n = write(handle->master_fd, buf, len);
    } else {
#ifdef MSG_NOSIGNAL
        n = send(handle->master_fd, buf, len, MSG_NOSIGNAL);
#else
        n = write(handle->master_fd, buf, len);
#endif
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return SSH_OK;
        }
        if (!handle->is_pty && (errno == EPIPE || errno == ECONNRESET)) {
            return SSH_ERR_CLOSED;
        }
        return SSH_ERR_PLATFORM;
    }
    *written_len = (size_t)n;
    return SSH_OK;
}

static int posix_term_read(
    void *ctx,
    void *handle_ptr,
    uint8_t *buf,
    size_t len,
    size_t *read_len)
{
    ssh_posix_term_handle_t *handle = (ssh_posix_term_handle_t *)handle_ptr;
    ssize_t n;
    (void)ctx;

    if (handle == NULL || (buf == NULL && len != 0u) || read_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    *read_len = 0u;
    if (len == 0u) {
        return SSH_OK;
    }

    n = read(handle->master_fd, buf, len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return SSH_OK;
        }
        if (handle->is_pty && errno == EIO) {
            return SSH_OK;
        }
        return SSH_ERR_PLATFORM;
    }
    if (n == 0) {
        return SSH_OK;
    }
    *read_len = (size_t)n;
    return SSH_OK;
}

static int posix_term_resize(
    void *ctx,
    void *handle_ptr,
    uint32_t cols,
    uint32_t rows,
    uint32_t width_px,
    uint32_t height_px)
{
    ssh_posix_term_handle_t *handle = (ssh_posix_term_handle_t *)handle_ptr;
    struct winsize ws;
    (void)ctx;

    if (handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (!handle->is_pty) {
        return SSH_ERR_UNSUPPORTED;
    }

    memset(&ws, 0, sizeof(ws));
    ws.ws_col = (unsigned short)(cols != 0u ? cols : 80u);
    ws.ws_row = (unsigned short)(rows != 0u ? rows : 24u);
    ws.ws_xpixel = (unsigned short)width_px;
    ws.ws_ypixel = (unsigned short)height_px;
    if (ioctl(handle->master_fd, TIOCSWINSZ, &ws) != 0) {
        return SSH_ERR_PLATFORM;
    }
    return SSH_OK;
}

static int signal_name_to_code(const char *signal_name)
{
    if (signal_name == NULL || signal_name[0] == '\0') {
        return SIGTERM;
    }
    if (strcmp(signal_name, "HUP") == 0) return SIGHUP;
    if (strcmp(signal_name, "INT") == 0) return SIGINT;
    if (strcmp(signal_name, "QUIT") == 0) return SIGQUIT;
    if (strcmp(signal_name, "KILL") == 0) return SIGKILL;
    if (strcmp(signal_name, "TERM") == 0) return SIGTERM;
    if (strcmp(signal_name, "USR1") == 0) return SIGUSR1;
    if (strcmp(signal_name, "USR2") == 0) return SIGUSR2;
    return SIGTERM;
}

static int posix_term_signal(void *ctx, void *handle_ptr, const char *signal_name)
{
    ssh_posix_term_handle_t *handle = (ssh_posix_term_handle_t *)handle_ptr;
    int signo;
    (void)ctx;

    if (handle == NULL || handle->child_pid <= 0) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    signo = signal_name_to_code(signal_name);
    if (kill(handle->child_pid, signo) != 0) {
        if (errno == ESRCH) {
            return SSH_OK;
        }
        return SSH_ERR_PLATFORM;
    }
    return SSH_OK;
}

static int posix_term_wait_exit(
    void *ctx,
    void *handle_ptr,
    int *exited,
    uint32_t *exit_status)
{
    ssh_posix_term_handle_t *handle = (ssh_posix_term_handle_t *)handle_ptr;
    int wstatus;
    pid_t r;
    (void)ctx;

    if (handle == NULL || exited == NULL || exit_status == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (handle->exited) {
        *exited = 1;
        *exit_status = handle->exit_status;
        return SSH_OK;
    }

    wstatus = 0;
    r = waitpid(handle->child_pid, &wstatus, WNOHANG);
    if (r < 0) {
        if (errno == EINTR) {
            *exited = 0;
            *exit_status = 0u;
            return SSH_OK;
        }
        return SSH_ERR_PLATFORM;
    }
    if (r == 0) {
        *exited = 0;
        *exit_status = 0u;
        return SSH_OK;
    }

    handle->exited = 1;
    if (WIFEXITED(wstatus)) {
        handle->exit_status = (uint32_t)WEXITSTATUS(wstatus);
    } else if (WIFSIGNALED(wstatus)) {
        handle->exit_status = 128u + (uint32_t)WTERMSIG(wstatus);
    } else {
        handle->exit_status = 255u;
    }

    *exited = 1;
    *exit_status = handle->exit_status;
    return SSH_OK;
}

static int posix_term_close(void *ctx, void *handle_ptr)
{
    ssh_posix_term_handle_t *handle = (ssh_posix_term_handle_t *)handle_ptr;
    int wstatus;
    (void)ctx;

    if (handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (handle->master_fd >= 0) {
        (void)close(handle->master_fd);
        handle->master_fd = -1;
    }

    if (!handle->exited && handle->child_pid > 0) {
        (void)kill(handle->child_pid, SIGTERM);
        while (waitpid(handle->child_pid, &wstatus, 0) < 0) {
            if (errno != EINTR) {
                break;
            }
        }
    }

    free(handle);
    return SSH_OK;
}

int ssh_posix_term_platform_init(ssh_posix_term_platform_t *term)
{
    if (term == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    memset(term, 0, sizeof(*term));
    term->api.spawn_shell = posix_term_spawn_shell;
    term->api.spawn_exec = posix_term_spawn_exec;
    term->api.write = posix_term_write;
    term->api.read = posix_term_read;
    term->api.resize = posix_term_resize;
    term->api.signal = posix_term_signal;
    term->api.wait_exit = posix_term_wait_exit;
    term->api.close = posix_term_close;
    term->api.ctx = term;
    term->initialized = 1;
    return SSH_OK;
}

void ssh_posix_term_platform_deinit(ssh_posix_term_platform_t *term)
{
    if (term == NULL) {
        return;
    }
    memset(term, 0, sizeof(*term));
}

const ssh_term_api_t *ssh_posix_term_api(ssh_posix_term_platform_t *term)
{
    if (term == NULL || !term->initialized) {
        return NULL;
    }
    return &term->api;
}
#endif
