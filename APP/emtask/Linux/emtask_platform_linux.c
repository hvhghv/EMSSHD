#include <arpa/inet.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <util.h>
#else
#include <pty.h>
#endif

#include "emtask_internal.h"

typedef struct emtask_mutex_impl {
    pthread_mutex_t mutex;
} emtask_mutex_impl_t;

typedef struct emtask_cond_impl {
    pthread_cond_t cond;
} emtask_cond_impl_t;

struct emtask_term_platform {
    pthread_t monitor_thread;
    int master_fd;
    pid_t child_pid;
};

int emtask_platform_key_equals(const char *lhs, const char *rhs)
{
    return strcasecmp(lhs, rhs) == 0;
}

int emtask_platform_path_is_absolute(const char *path)
{
    return path != NULL && path[0] == '/';
}

int emtask_platform_join_path(const char *base_dir, const char *value, char out[EMTASK_MAX_PATH])
{
    int written;

    if (base_dir == NULL || value == NULL || out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    written = snprintf(out, EMTASK_MAX_PATH, "%s/%s", base_dir, value);
    if (written < 0 || (size_t)written >= EMTASK_MAX_PATH) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    return SSH_OK;
}

int emtask_platform_default_use_conpty(void)
{
    return 1;
}

int emtask_platform_net_is_peer_closed_error(void)
{
    return errno == ECONNRESET || errno == EPIPE || errno == ENOTCONN;
}

int emtask_platform_net_wait(uintptr_t socket_handle, int for_write, uint32_t timeout_ms)
{
    int sock = (int)socket_handle;
    fd_set fds;
    struct timeval tv;
    struct timeval *tv_ptr;
    int status;

    FD_ZERO(&fds);
    FD_SET(sock, &fds);

    if (timeout_ms == 0u) {
        tv_ptr = NULL;
    } else {
        tv.tv_sec = (long)(timeout_ms / 1000u);
        tv.tv_usec = (long)((timeout_ms % 1000u) * 1000u);
        tv_ptr = &tv;
    }

    status = select(sock + 1, for_write ? NULL : &fds, for_write ? &fds : NULL, NULL, tv_ptr);
    if (status > 0) {
        return 1;
    }
    if (status == 0) {
        return 0;
    }
    return -1;
}

int emtask_platform_net_shutdown(uintptr_t socket_handle)
{
    return shutdown((int)socket_handle, SHUT_RDWR);
}

int emtask_platform_net_close(uintptr_t socket_handle)
{
    return close((int)socket_handle);
}

int emtask_platform_net_recv(uintptr_t socket_handle, uint8_t *buf, size_t len)
{
    return (int)recv((int)socket_handle, buf, len, 0);
}

int emtask_platform_net_send(uintptr_t socket_handle, const uint8_t *buf, size_t len)
{
    return (int)send((int)socket_handle, buf, len, 0);
}

uint64_t emtask_platform_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0u;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000u);
}

void emtask_platform_sleep_ms(uint32_t timeout_ms)
{
    struct timespec req;

    req.tv_sec = (time_t)(timeout_ms / 1000u);
    req.tv_nsec = (long)((timeout_ms % 1000u) * 1000000u);
    while (nanosleep(&req, &req) != 0 && errno == EINTR) {
    }
}

int emtask_platform_library_open(const char *path, void **handle_out)
{
    void *handle;

    if (path == NULL || path[0] == '\0' || handle_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        *handle_out = NULL;
        return SSH_ERR_NOT_FOUND;
    }
    *handle_out = handle;
    return SSH_OK;
}

void emtask_platform_library_close(void *handle)
{
    if (handle != NULL) {
        (void)dlclose(handle);
    }
}

void *emtask_platform_library_symbol(void *handle, const char *name)
{
    if (handle == NULL || name == NULL) {
        return NULL;
    }
    return dlsym(handle, name);
}

int emtask_platform_sqlite_library_open(void **handle_out, int *using_system_out)
{
    int status;

    if (handle_out == NULL || using_system_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    *handle_out = NULL;
    *using_system_out = 0;
    status = emtask_platform_library_open("./libsqlite3.so.0", handle_out);
    if (status == SSH_OK) {
        return SSH_OK;
    }
    status = emtask_platform_library_open("./libsqlite3.so", handle_out);
    if (status == SSH_OK) {
        return SSH_OK;
    }
    status = emtask_platform_library_open("libsqlite3.so.0", handle_out);
    if (status == SSH_OK) {
        *using_system_out = 1;
        return SSH_OK;
    }
    status = emtask_platform_library_open("libsqlite3.so", handle_out);
    if (status == SSH_OK) {
        *using_system_out = 1;
    }
    return status;
}

int emtask_mutex_init(emtask_mutex_t *lock)
{
    emtask_mutex_impl_t *impl;

    if (lock == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    impl = (emtask_mutex_impl_t *)calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        return SSH_ERR_PLATFORM;
    }
    if (pthread_mutex_init(&impl->mutex, NULL) != 0) {
        free(impl);
        return SSH_ERR_PLATFORM;
    }
    lock->impl = impl;
    return SSH_OK;
}

void emtask_mutex_deinit(emtask_mutex_t *lock)
{
    emtask_mutex_impl_t *impl;

    if (lock == NULL || lock->impl == NULL) {
        return;
    }
    impl = (emtask_mutex_impl_t *)lock->impl;
    pthread_mutex_destroy(&impl->mutex);
    free(impl);
    lock->impl = NULL;
}

void emtask_mutex_lock(emtask_mutex_t *lock)
{
    if (lock != NULL && lock->impl != NULL) {
        pthread_mutex_lock(&((emtask_mutex_impl_t *)lock->impl)->mutex);
    }
}

void emtask_mutex_unlock(emtask_mutex_t *lock)
{
    if (lock != NULL && lock->impl != NULL) {
        pthread_mutex_unlock(&((emtask_mutex_impl_t *)lock->impl)->mutex);
    }
}

int emtask_cond_init(emtask_cond_t *cv)
{
    emtask_cond_impl_t *impl;

    if (cv == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    impl = (emtask_cond_impl_t *)calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        return SSH_ERR_PLATFORM;
    }
    if (pthread_cond_init(&impl->cond, NULL) != 0) {
        free(impl);
        return SSH_ERR_PLATFORM;
    }
    cv->impl = impl;
    return SSH_OK;
}

void emtask_cond_deinit(emtask_cond_t *cv)
{
    emtask_cond_impl_t *impl;

    if (cv == NULL || cv->impl == NULL) {
        return;
    }
    impl = (emtask_cond_impl_t *)cv->impl;
    pthread_cond_destroy(&impl->cond);
    free(impl);
    cv->impl = NULL;
}

void emtask_cond_wait(emtask_cond_t *cv, emtask_mutex_t *lock)
{
    if (cv != NULL && cv->impl != NULL && lock != NULL && lock->impl != NULL) {
        pthread_cond_wait(
            &((emtask_cond_impl_t *)cv->impl)->cond,
            &((emtask_mutex_impl_t *)lock->impl)->mutex);
    }
}

void emtask_cond_broadcast(emtask_cond_t *cv)
{
    if (cv != NULL && cv->impl != NULL) {
        pthread_cond_broadcast(&((emtask_cond_impl_t *)cv->impl)->cond);
    }
}

static int emtask_set_nonblocking_fd(int fd)
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

static void emtask_linux_child_main(emtask_term_t *term)
{
    const char *command = term != NULL ? term->command : NULL;

    if (term != NULL && term->working_dir[0] != '\0') {
        if (chdir(term->working_dir) != 0) {
            _exit(126);
        }
    }
    if (term != NULL && term->term_type[0] != '\0') {
        (void)setenv("TERM", term->term_type, 1);
    }
    if (command == NULL || command[0] == '\0') {
        command = "true";
    }
    execl("/bin/sh", "sh", "-lc", command, (char *)NULL);
    _exit(127);
}

static void *emtask_term_monitor_thread_entry(void *arg)
{
    emtask_term_t *term = (emtask_term_t *)arg;

    while (!emtask_term_monitor_step(term)) {
        usleep(200000u);
    }
    return NULL;
}

static void *emtask_worker_thread_entry(void *arg)
{
    emtask_worker_thread_main((emtask_worker_t *)arg);
    return NULL;
}

int emtask_platform_term_init(emtask_term_t *term, const emtask_task_config_t *task_config)
{
    emtask_term_platform_t *platform;

    (void)task_config;

    if (term == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    platform = (emtask_term_platform_t *)calloc(1u, sizeof(*platform));
    if (platform == NULL) {
        return SSH_ERR_PLATFORM;
    }
    platform->master_fd = -1;
    term->platform = platform;
    if (pthread_create(&platform->monitor_thread, NULL, emtask_term_monitor_thread_entry, term) != 0) {
        free(platform);
        term->platform = NULL;
        return SSH_ERR_PLATFORM;
    }
    return SSH_OK;
}

void emtask_platform_term_deinit(emtask_term_t *term)
{
    emtask_term_platform_t *platform = term != NULL ? term->platform : NULL;

    if (platform != NULL) {
        (void)pthread_join(platform->monitor_thread, NULL);
    }
}

void emtask_platform_term_close_handles_locked(emtask_term_t *term, int terminate_child)
{
    emtask_term_platform_t *platform = term != NULL ? term->platform : NULL;

    if (term == NULL) {
        return;
    }

    if (platform != NULL && platform->master_fd >= 0) {
        (void)close(platform->master_fd);
        platform->master_fd = -1;
    }
    if (platform != NULL && platform->child_pid > 0) {
        int wstatus;
        if (terminate_child) {
            (void)kill(platform->child_pid, SIGTERM);
            if (waitpid(platform->child_pid, &wstatus, 0) < 0 && errno == EINTR) {
                while (waitpid(platform->child_pid, &wstatus, 0) < 0 && errno == EINTR) {
                }
            }
        }
        platform->child_pid = 0;
    }
    term->running = 0;
}

int emtask_platform_term_spawn_locked(emtask_term_t *term)
{
    emtask_term_platform_t *platform;
    struct winsize ws;
    int master_fd;
    pid_t pid;

    if (term == NULL || term->platform == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    platform = term->platform;

    emtask_term_default_size(term);
    memset(&ws, 0, sizeof(ws));
    ws.ws_col = (unsigned short)term->cols;
    ws.ws_row = (unsigned short)term->rows;
    ws.ws_xpixel = (unsigned short)term->width_px;
    ws.ws_ypixel = (unsigned short)term->height_px;

    master_fd = -1;
    pid = forkpty(&master_fd, NULL, NULL, &ws);
    if (pid < 0) {
        return SSH_ERR_PLATFORM;
    }
    if (pid == 0) {
        emtask_linux_child_main(term);
    }

    if (emtask_set_nonblocking_fd(master_fd) != SSH_OK) {
        (void)close(master_fd);
        (void)kill(pid, SIGTERM);
        (void)waitpid(pid, NULL, 0);
        return SSH_ERR_PLATFORM;
    }

    platform->master_fd = master_fd;
    platform->child_pid = pid;
    term->running = 1;
    term->faulted = 0;
    term->started_once = 1;
    return SSH_OK;
}

int emtask_platform_term_poll_exit_locked(emtask_term_t *term, int *exited, uint32_t *exit_status)
{
    emtask_term_platform_t *platform = term != NULL ? term->platform : NULL;

    if (platform != NULL && platform->child_pid > 0) {
        int wstatus = 0;
        pid_t r = waitpid(platform->child_pid, &wstatus, WNOHANG);
        if (r == platform->child_pid) {
            if (WIFEXITED(wstatus)) {
                term->last_exit_status = (uint32_t)WEXITSTATUS(wstatus);
            } else if (WIFSIGNALED(wstatus)) {
                term->last_exit_status = 128u + (uint32_t)WTERMSIG(wstatus);
            } else {
                term->last_exit_status = 255u;
            }
            if (exited != NULL) {
                *exited = 1;
            }
            if (exit_status != NULL) {
                *exit_status = term->last_exit_status;
            }
            emtask_platform_term_close_handles_locked(term, 0);
        }
    }
    return SSH_OK;
}

int emtask_platform_term_write_locked(emtask_term_t *term, const uint8_t *buf, size_t len, size_t *written_len)
{
    emtask_term_platform_t *platform = term != NULL ? term->platform : NULL;

    if (platform != NULL && platform->master_fd >= 0) {
        ssize_t n = write(platform->master_fd, buf, len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                return SSH_OK;
            }
            return SSH_ERR_PLATFORM;
        }
        *written_len = (size_t)n;
    }
    return SSH_OK;
}

int emtask_platform_term_read_locked(emtask_term_t *term, uint8_t *buf, size_t len, size_t *read_len)
{
    emtask_term_platform_t *platform = term != NULL ? term->platform : NULL;

    if (platform != NULL && platform->master_fd >= 0) {
        ssize_t n = read(platform->master_fd, buf, len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                return SSH_OK;
            }
            return SSH_ERR_PLATFORM;
        }
        if (n > 0) {
            *read_len = (size_t)n;
        }
    }
    return SSH_OK;
}

int emtask_platform_term_resize_locked(emtask_term_t *term)
{
    emtask_term_platform_t *platform = term != NULL ? term->platform : NULL;

    if (platform != NULL && platform->master_fd >= 0) {
        struct winsize ws;
        memset(&ws, 0, sizeof(ws));
        ws.ws_col = (unsigned short)(term->cols != 0u ? term->cols : EMTASK_DEFAULT_TERM_COLS);
        ws.ws_row = (unsigned short)(term->rows != 0u ? term->rows : EMTASK_DEFAULT_TERM_ROWS);
        ws.ws_xpixel = (unsigned short)term->width_px;
        ws.ws_ypixel = (unsigned short)term->height_px;
        if (ioctl(platform->master_fd, TIOCSWINSZ, &ws) != 0) {
            return SSH_ERR_PLATFORM;
        }
    }
    return SSH_OK;
}

int emtask_platform_term_signal_locked(emtask_term_t *term, const char *signal_name)
{
    emtask_term_platform_t *platform = term != NULL ? term->platform : NULL;

    if (platform != NULL && platform->child_pid > 0) {
        int signo = SIGTERM;
        if (signal_name != NULL) {
            if (strcmp(signal_name, "INT") == 0) {
                signo = SIGINT;
            } else if (strcmp(signal_name, "KILL") == 0) {
                signo = SIGKILL;
            } else if (strcmp(signal_name, "HUP") == 0) {
                signo = SIGHUP;
            }
        }
        if (kill(platform->child_pid, signo) != 0 && errno != ESRCH) {
            return SSH_ERR_PLATFORM;
        }
    }
    return SSH_OK;
}

int emtask_platform_start_worker_thread(emtask_worker_t *worker)
{
    pthread_t thread;

    if (pthread_create(&thread, NULL, emtask_worker_thread_entry, worker) != 0) {
        return SSH_ERR_PLATFORM;
    }
    if (pthread_detach(thread) != 0) {
        return SSH_ERR_PLATFORM;
    }
    return SSH_OK;
}

static void *emtask_listener_thread_entry(void *arg)
{
    emtask_listener_thread_main((emtask_task_t *)arg);
    return NULL;
}

int emtask_platform_start_listener_thread(emtask_task_t *task)
{
    pthread_t thread;

    if (pthread_create(&thread, NULL, emtask_listener_thread_entry, task) != 0) {
        return SSH_ERR_PLATFORM;
    }
    if (pthread_detach(thread) != 0) {
        return SSH_ERR_PLATFORM;
    }
    return SSH_OK;
}

static void *emtask_panel_thread_entry(void *arg)
{
    emtask_panel_thread_main((emtask_app_t *)arg);
    return NULL;
}

int emtask_platform_start_panel_thread(emtask_app_t *app)
{
    pthread_t thread;

    if (pthread_create(&thread, NULL, emtask_panel_thread_entry, app) != 0) {
        return SSH_ERR_PLATFORM;
    }
    if (pthread_detach(thread) != 0) {
        return SSH_ERR_PLATFORM;
    }
    return SSH_OK;
}
