#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef WINVER
#define WINVER _WIN32_WINNT
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <pthread.h>
#include <strings.h>

#include "emtask_internal.h"
#include "emssh/platform_window_term.h"

#define EMTASK_WIN_CYGWIN_VARIANT 1

typedef struct emtask_mutex_impl {
    CRITICAL_SECTION cs;
} emtask_mutex_impl_t;

typedef struct emtask_cond_impl {
    CONDITION_VARIABLE cv;
} emtask_cond_impl_t;

BOOLEAN NTAPI SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);

int emtask_platform_key_equals(const char *lhs, const char *rhs)
{
    return strcasecmp(lhs, rhs) == 0;
}

int emtask_window_start_joinable_thread(
    emtask_thread_handle_t *handle_out,
    void *(*entry)(void *),
    void *arg)
{
    if (handle_out == NULL || entry == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (pthread_create(&handle_out->thread, NULL, entry, arg) != 0) {
        handle_out->valid = 0;
        return SSH_ERR_PLATFORM;
    }
    handle_out->valid = 1;
    return SSH_OK;
}

void emtask_window_join_joinable_thread(emtask_thread_handle_t *handle)
{
    if (handle != NULL && handle->valid) {
        (void)pthread_join(handle->thread, NULL);
        handle->valid = 0;
    }
}

static int emtask_start_detached_thread(void *(*entry)(void *), void *arg)
{
    pthread_t thread;

    if (entry == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    if (pthread_create(&thread, NULL, entry, arg) != 0) {
        return SSH_ERR_PLATFORM;
    }
    if (pthread_detach(thread) != 0) {
        return SSH_ERR_PLATFORM;
    }
    return SSH_OK;
}

int emtask_platform_path_is_absolute(const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    if (path[0] == '/') {
        return 1;
    }
    if (((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
        path[1] == ':') {
        return 1;
    }
    return (path[0] == '\\' && path[1] == '\\') || (path[0] == '/' && path[1] == '/');
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
    int err = WSAGetLastError();
    return err == WSAECONNRESET || err == WSAECONNABORTED ||
           err == WSAENOTCONN || err == WSAESHUTDOWN;
}

int emtask_platform_net_wait(uintptr_t socket_handle, int for_write, uint32_t timeout_ms)
{
    SOCKET sock = (SOCKET)socket_handle;
    fd_set fds;
    TIMEVAL tv;
    const TIMEVAL *tv_ptr;
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

    status = select((int)(sock + 1), for_write ? NULL : &fds, for_write ? &fds : NULL, NULL, tv_ptr);
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
    return shutdown((SOCKET)socket_handle, SD_BOTH);
}

int emtask_platform_net_close(uintptr_t socket_handle)
{
    return closesocket((SOCKET)socket_handle);
}

int emtask_platform_net_recv(uintptr_t socket_handle, uint8_t *buf, size_t len)
{
    return (int)recv((SOCKET)socket_handle, (char *)buf, (int)len, 0);
}

int emtask_platform_net_send(uintptr_t socket_handle, const uint8_t *buf, size_t len)
{
    return (int)send((SOCKET)socket_handle, (const char *)buf, (int)len, 0);
}

uint64_t emtask_platform_monotonic_ms(void)
{
    return (uint64_t)GetTickCount64();
}

void emtask_platform_sleep_ms(uint32_t timeout_ms)
{
    Sleep((DWORD)timeout_ms);
}

int emtask_platform_library_open(const char *path, void **handle_out)
{
    HMODULE handle;

    if (path == NULL || path[0] == '\0' || handle_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    handle = LoadLibraryA(path);
    if (handle == NULL) {
        *handle_out = NULL;
        return SSH_ERR_NOT_FOUND;
    }
    *handle_out = (void *)handle;
    return SSH_OK;
}

void emtask_platform_library_close(void *handle)
{
    if (handle != NULL) {
        FreeLibrary((HMODULE)handle);
    }
}

void *emtask_platform_library_symbol(void *handle, const char *name)
{
    if (handle == NULL || name == NULL) {
        return NULL;
    }
    return (void *)GetProcAddress((HMODULE)handle, name);
}

int emtask_platform_sqlite_library_open(void **handle_out, int *using_system_out)
{
    int status;

    if (handle_out == NULL || using_system_out == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    *handle_out = NULL;
    *using_system_out = 0;
    status = emtask_platform_library_open(".\\sqlite3.dll", handle_out);
    if (status == SSH_OK) {
        return SSH_OK;
    }
    status = emtask_platform_library_open("sqlite3.dll", handle_out);
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
    InitializeCriticalSection(&impl->cs);
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
    DeleteCriticalSection(&impl->cs);
    free(impl);
    lock->impl = NULL;
}

void emtask_mutex_lock(emtask_mutex_t *lock)
{
    if (lock != NULL && lock->impl != NULL) {
        EnterCriticalSection(&((emtask_mutex_impl_t *)lock->impl)->cs);
    }
}

void emtask_mutex_unlock(emtask_mutex_t *lock)
{
    if (lock != NULL && lock->impl != NULL) {
        LeaveCriticalSection(&((emtask_mutex_impl_t *)lock->impl)->cs);
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
    InitializeConditionVariable(&impl->cv);
    cv->impl = impl;
    return SSH_OK;
}

void emtask_cond_deinit(emtask_cond_t *cv)
{
    if (cv != NULL && cv->impl != NULL) {
        free(cv->impl);
        cv->impl = NULL;
    }
}

void emtask_cond_wait(emtask_cond_t *cv, emtask_mutex_t *lock)
{
    if (cv != NULL && cv->impl != NULL && lock != NULL && lock->impl != NULL) {
        SleepConditionVariableCS(
            &((emtask_cond_impl_t *)cv->impl)->cv,
            &((emtask_mutex_impl_t *)lock->impl)->cs,
            INFINITE);
    }
}

void emtask_cond_broadcast(emtask_cond_t *cv)
{
    if (cv != NULL && cv->impl != NULL) {
        WakeAllConditionVariable(&((emtask_cond_impl_t *)cv->impl)->cv);
    }
}

static void *emtask_worker_thread_entry(void *arg)
{
    emtask_worker_thread_main((emtask_worker_t *)arg);
    return NULL;
}

int emtask_platform_start_worker_thread(emtask_worker_t *worker)
{
    return emtask_start_detached_thread(emtask_worker_thread_entry, worker);
}

static void *emtask_listener_thread_entry(void *arg)
{
    emtask_listener_thread_main((emtask_task_t *)arg);
    return NULL;
}

int emtask_platform_start_listener_thread(emtask_task_t *task)
{
    return emtask_start_detached_thread(emtask_listener_thread_entry, task);
}

static void *emtask_panel_thread_entry(void *arg)
{
    emtask_panel_thread_main((emtask_app_t *)arg);
    return NULL;
}

int emtask_platform_start_panel_thread(emtask_app_t *app)
{
    return emtask_start_detached_thread(emtask_panel_thread_entry, app);
}
