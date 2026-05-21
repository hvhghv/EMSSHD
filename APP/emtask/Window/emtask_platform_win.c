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
#ifdef __CYGWIN__
#include <pthread.h>
#include <strings.h>
#else
#include <process.h>
#endif

#include "emtask_internal.h"

#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif

typedef
#ifdef __CYGWIN__
struct emtask_thread_handle {
    pthread_t thread;
    int valid;
}
#else
HANDLE
#endif
emtask_thread_handle_t;

typedef struct emtask_mutex_impl {
    CRITICAL_SECTION cs;
} emtask_mutex_impl_t;

typedef struct emtask_cond_impl {
    CONDITION_VARIABLE cv;
} emtask_cond_impl_t;

struct emtask_term_platform {
    emtask_thread_handle_t monitor_thread;
    HANDLE process_handle;
    HANDLE input_write;
    HANDLE output_read;
    HANDLE pseudo_console;
    int using_conpty;
    int allow_conpty;
    int conpty_win32_input_mode;
    char conpty_vt_tail[16];
    size_t conpty_vt_tail_len;
};

BOOLEAN NTAPI SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);

int emtask_platform_key_equals(const char *lhs, const char *rhs)
{
#ifdef __CYGWIN__
    return strcasecmp(lhs, rhs) == 0;
#else
    return _stricmp(lhs, rhs) == 0;
#endif
}

#ifdef __CYGWIN__
static int emtask_start_joinable_thread(
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

static void emtask_join_joinable_thread(emtask_thread_handle_t *handle)
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
#else
static int emtask_start_joinable_thread(
    emtask_thread_handle_t *handle_out,
    unsigned(__stdcall *entry)(void *),
    void *arg)
{
    uintptr_t handle;

    if (handle_out == NULL || entry == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    handle = _beginthreadex(NULL, 0u, entry, arg, 0u, NULL);
    if (handle == 0u) {
        *handle_out = NULL;
        return SSH_ERR_PLATFORM;
    }
    *handle_out = (HANDLE)handle;
    return SSH_OK;
}

static void emtask_join_joinable_thread(emtask_thread_handle_t *handle)
{
    if (handle != NULL && *handle != NULL) {
        (void)WaitForSingleObject(*handle, 2000u);
        (void)CloseHandle(*handle);
        *handle = NULL;
    }
}

static int emtask_start_detached_thread(unsigned(__stdcall *entry)(void *), void *arg)
{
    uintptr_t handle;

    if (entry == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    handle = _beginthreadex(NULL, 0u, entry, arg, 0u, NULL);
    if (handle == 0u) {
        return SSH_ERR_PLATFORM;
    }
    (void)CloseHandle((HANDLE)handle);
    return SSH_OK;
}
#endif

int emtask_platform_path_is_absolute(const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return 0;
    }
#ifdef EMTASK_WIN_MSYS2_VARIANT
    if (path[0] == '/') {
        return 1;
    }
#endif
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
#ifdef EMTASK_WIN_MSYS2_VARIANT
    written = snprintf(out, EMTASK_MAX_PATH, "%s/%s", base_dir, value);
#else
    written = snprintf(out, EMTASK_MAX_PATH, "%s\\%s", base_dir, value);
#endif
    if (written < 0 || (size_t)written >= EMTASK_MAX_PATH) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    return SSH_OK;
}

int emtask_platform_default_use_conpty(void)
{
#ifdef EMTASK_WIN_MSYS2_VARIANT
    return 1;
#else
    return 1;
#endif
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
#ifdef __CYGWIN__
    const TIMEVAL *tv_ptr;
#else
    TIMEVAL *tv_ptr;
#endif
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
    if (len > 0xffffffffu) {
        return -1;
    }
    if (!SystemFunction036(output, (ULONG)len)) {
        return -1;
    }
    *olen = len;
    return 0;
}

static void emtask_close_pseudo_console(HANDLE pseudo_console)
{
    if (pseudo_console != NULL) {
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32 != NULL) {
            typedef void (WINAPI *close_pseudo_console_fn)(HANDLE);
            close_pseudo_console_fn fn = (close_pseudo_console_fn)GetProcAddress(kernel32, "ClosePseudoConsole");
            if (fn != NULL) {
                fn(pseudo_console);
            }
        }
    }
}

static WCHAR *emtask_utf8_to_wide_alloc(const char *text)
{
    WCHAR *wide;
    int len;

    if (text == NULL) {
        return NULL;
    }

    len = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    if (len <= 0) {
        len = MultiByteToWideChar(CP_ACP, 0, text, -1, NULL, 0);
        if (len <= 0) {
            return NULL;
        }
        wide = (WCHAR *)calloc((size_t)len, sizeof(WCHAR));
        if (wide == NULL) {
            return NULL;
        }
        if (MultiByteToWideChar(CP_ACP, 0, text, -1, wide, len) <= 0) {
            free(wide);
            return NULL;
        }
        return wide;
    }

    wide = (WCHAR *)calloc((size_t)len, sizeof(WCHAR));
    if (wide == NULL) {
        return NULL;
    }
    if (MultiByteToWideChar(CP_UTF8, 0, text, -1, wide, len) <= 0) {
        free(wide);
        return NULL;
    }
    return wide;
}

static WCHAR *emtask_build_windows_command_line(const char *command)
{
    char buffer[EMTASK_MAX_TEXT + 64u];
    int written = snprintf(buffer, sizeof(buffer), "cmd.exe /S /C %s", command != NULL ? command : "");
    if (written < 0 || (size_t)written >= sizeof(buffer)) {
        return NULL;
    }
    return emtask_utf8_to_wide_alloc(buffer);
}

#ifdef EMTASK_WIN_MSYS2_VARIANT
static int emtask_append_command_line_quoted_arg(
    char *buffer,
    size_t buffer_len,
    size_t *offset_io,
    const char *arg)
{
    size_t offset;
    size_t backslash_run = 0u;

    if (buffer == NULL || offset_io == NULL || arg == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    offset = *offset_io;
    if (offset >= buffer_len) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }

    if (offset + 1u >= buffer_len) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    buffer[offset++] = '"';

    while (*arg != '\0') {
        char ch = *arg++;

        if (ch == '\\') {
            ++backslash_run;
            continue;
        }

        while (backslash_run != 0u) {
            if (offset + 1u >= buffer_len) {
                return SSH_ERR_BUFFER_TOO_SMALL;
            }
            buffer[offset++] = '\\';
            --backslash_run;
        }

        if (ch == '"') {
            if (offset + 2u >= buffer_len) {
                return SSH_ERR_BUFFER_TOO_SMALL;
            }
            buffer[offset++] = '\\';
            buffer[offset++] = '"';
            continue;
        }

        if (offset + 1u >= buffer_len) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        buffer[offset++] = ch;
    }

    while (backslash_run != 0u) {
        if (offset + 2u >= buffer_len) {
            return SSH_ERR_BUFFER_TOO_SMALL;
        }
        buffer[offset++] = '\\';
        buffer[offset++] = '\\';
        --backslash_run;
    }

    if (offset + 2u > buffer_len) {
        return SSH_ERR_BUFFER_TOO_SMALL;
    }
    buffer[offset++] = '"';
    buffer[offset] = '\0';
    *offset_io = offset;
    return SSH_OK;
}

static WCHAR *emtask_build_msys2_command_line(const char *command)
{
    char buffer[(EMTASK_MAX_TEXT * 2u) + 64u];
    const char *effective_command = command;
    size_t offset = 0u;
    int status;

    if (effective_command == NULL || effective_command[0] == '\0') {
        effective_command = "true";
    }

    status = snprintf(buffer, sizeof(buffer), "sh.exe -lc ");
    if (status < 0 || (size_t)status >= sizeof(buffer)) {
        return NULL;
    }
    offset = (size_t)status;
    status = emtask_append_command_line_quoted_arg(buffer, sizeof(buffer), &offset, effective_command);
    if (status != SSH_OK) {
        return NULL;
    }
    return emtask_utf8_to_wide_alloc(buffer);
}
#endif

static int emtask_write_handle_all(HANDLE handle, const uint8_t *buf, size_t len)
{
    size_t offset = 0u;

    while (offset < len) {
        DWORD chunk_written = 0u;
        DWORD chunk_len;

        if (handle == NULL || buf == NULL) {
            return SSH_ERR_INVALID_ARGUMENT;
        }
        chunk_len = (DWORD)((len - offset) > 0xffffffffu ? 0xffffffffu : (len - offset));
        if (!WriteFile(handle, buf + offset, chunk_len, &chunk_written, NULL)) {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA) {
                return SSH_OK;
            }
            return SSH_ERR_PLATFORM;
        }
        if (chunk_written == 0u) {
            return SSH_ERR_PLATFORM;
        }
        offset += (size_t)chunk_written;
    }

    return SSH_OK;
}

static void emtask_conpty_track_output_mode(emtask_term_t *term, const uint8_t *buf, size_t len)
{
    static const char enable_seq[] = "\x1b[?9001h";
    static const char disable_seq[] = "\x1b[?9001l";
    emtask_term_platform_t *platform = term != NULL ? term->platform : NULL;
    char window[sizeof(platform->conpty_vt_tail) + 2048u];
    size_t prefix_len = 0u;
    size_t window_len;
    size_t i;

    if (platform == NULL || buf == NULL || len == 0u) {
        return;
    }

    if (platform->conpty_vt_tail_len > sizeof(platform->conpty_vt_tail)) {
        platform->conpty_vt_tail_len = 0u;
    }
    prefix_len = platform->conpty_vt_tail_len;
    if (prefix_len > sizeof(window)) {
        prefix_len = sizeof(window);
    }
    memcpy(window, platform->conpty_vt_tail, prefix_len);
    if (len > sizeof(window) - prefix_len) {
        len = sizeof(window) - prefix_len;
    }
    memcpy(window + prefix_len, buf, len);
    window_len = prefix_len + len;

    for (i = 0u; i + sizeof(enable_seq) - 1u <= window_len; ++i) {
        if (memcmp(window + i, enable_seq, sizeof(enable_seq) - 1u) == 0) {
            platform->conpty_win32_input_mode = 1;
        }
    }
    for (i = 0u; i + sizeof(disable_seq) - 1u <= window_len; ++i) {
        if (memcmp(window + i, disable_seq, sizeof(disable_seq) - 1u) == 0) {
            platform->conpty_win32_input_mode = 0;
        }
    }

    if (window_len >= sizeof(platform->conpty_vt_tail)) {
        memcpy(
            platform->conpty_vt_tail,
            window + (window_len - sizeof(platform->conpty_vt_tail)),
            sizeof(platform->conpty_vt_tail));
        platform->conpty_vt_tail_len = sizeof(platform->conpty_vt_tail);
    } else {
        memcpy(platform->conpty_vt_tail, window, window_len);
        platform->conpty_vt_tail_len = window_len;
    }
}

static DWORD emtask_vk_state_to_control_state(SHORT vk_state)
{
    DWORD control_state = 0u;
    unsigned state_bits = ((unsigned short)vk_state) >> 8;

    if ((state_bits & 0x01u) != 0u) {
        control_state |= SHIFT_PRESSED;
    }
    if ((state_bits & 0x02u) != 0u) {
        control_state |= LEFT_CTRL_PRESSED;
    }
    if ((state_bits & 0x04u) != 0u) {
        control_state |= LEFT_ALT_PRESSED;
    }
    return control_state;
}

static int emtask_write_conpty_key_event(
    HANDLE handle,
    WORD virtual_key,
    WORD scan_code,
    WORD char_code,
    int key_down,
    DWORD control_state)
{
    char seq[96];
    int seq_len = snprintf(
        seq,
        sizeof(seq),
        "\x1b[%u;%u;%u;%u;%lu;1_",
        (unsigned)virtual_key,
        (unsigned)scan_code,
        (unsigned)char_code,
        key_down ? 1u : 0u,
        (unsigned long)control_state);
    if (seq_len < 0 || (size_t)seq_len >= sizeof(seq)) {
        return SSH_ERR_PLATFORM;
    }
    return emtask_write_handle_all(handle, (const uint8_t *)seq, (size_t)seq_len);
}

static int emtask_write_conpty_codepoint(HANDLE handle, WCHAR ch)
{
    SHORT vk_state;
    WORD virtual_key = 0u;
    WORD scan_code = 0u;
    DWORD control_state = 0u;
    int status;

    if (handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    switch (ch) {
    case L'\r':
    case L'\n':
        virtual_key = VK_RETURN;
        scan_code = (WORD)MapVirtualKeyW((UINT)virtual_key, MAPVK_VK_TO_VSC);
        ch = L'\r';
        break;
    case L'\t':
        virtual_key = VK_TAB;
        scan_code = (WORD)MapVirtualKeyW((UINT)virtual_key, MAPVK_VK_TO_VSC);
        break;
    case L'\b':
        virtual_key = VK_BACK;
        scan_code = (WORD)MapVirtualKeyW((UINT)virtual_key, MAPVK_VK_TO_VSC);
        break;
    default:
        vk_state = VkKeyScanW(ch);
        if (vk_state != (SHORT)-1) {
            virtual_key = (WORD)(vk_state & 0xff);
            scan_code = (WORD)MapVirtualKeyW((UINT)virtual_key, MAPVK_VK_TO_VSC);
            control_state = emtask_vk_state_to_control_state(vk_state);
        }
        break;
    }

    status = emtask_write_conpty_key_event(handle, virtual_key, scan_code, (WORD)ch, 1, control_state);
    if (status != SSH_OK) {
        return status;
    }
    return emtask_write_conpty_key_event(handle, virtual_key, scan_code, 0u, 0, control_state);
}

#ifdef __CYGWIN__
static void *emtask_term_monitor_thread_entry(void *arg)
#else
static unsigned __stdcall emtask_term_monitor_thread_entry(void *arg)
#endif
{
    emtask_term_t *term = (emtask_term_t *)arg;

    while (!emtask_term_monitor_step(term)) {
        Sleep(200u);
    }
#ifdef __CYGWIN__
    return NULL;
#else
    return 0u;
#endif
}

#ifdef __CYGWIN__
static void *emtask_worker_thread_entry(void *arg)
#else
static unsigned __stdcall emtask_worker_thread_entry(void *arg)
#endif
{
    emtask_worker_thread_main((emtask_worker_t *)arg);
#ifdef __CYGWIN__
    return NULL;
#else
    return 0u;
#endif
}

int emtask_platform_term_init(emtask_term_t *term, const emtask_task_config_t *task_config)
{
    emtask_term_platform_t *platform;
    int status;

    if (term == NULL || task_config == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    platform = (emtask_term_platform_t *)calloc(1u, sizeof(*platform));
    if (platform == NULL) {
        return SSH_ERR_PLATFORM;
    }
    platform->allow_conpty = task_config->use_conpty;
    term->platform = platform;
    status = emtask_start_joinable_thread(&platform->monitor_thread, emtask_term_monitor_thread_entry, term);
    if (status != SSH_OK) {
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
        emtask_join_joinable_thread(&platform->monitor_thread);
    }
}

void emtask_platform_term_close_handles_locked(emtask_term_t *term, int terminate_child)
{
    emtask_term_platform_t *platform = term != NULL ? term->platform : NULL;

    if (term == NULL) {
        return;
    }

    if (terminate_child && platform != NULL && platform->process_handle != NULL) {
        (void)TerminateProcess(platform->process_handle, 1u);
        (void)WaitForSingleObject(platform->process_handle, 2000u);
    }
    if (platform != NULL && platform->process_handle != NULL) {
        (void)CloseHandle(platform->process_handle);
        platform->process_handle = NULL;
    }
    if (platform != NULL && platform->input_write != NULL) {
        (void)CloseHandle(platform->input_write);
        platform->input_write = NULL;
    }
    if (platform != NULL && platform->output_read != NULL) {
        (void)CloseHandle(platform->output_read);
        platform->output_read = NULL;
    }
    if (platform != NULL && platform->using_conpty && platform->pseudo_console != NULL) {
        emtask_close_pseudo_console(platform->pseudo_console);
        platform->pseudo_console = NULL;
    }
    if (platform != NULL) {
        platform->using_conpty = 0;
    }
    term->running = 0;
}

int emtask_platform_term_spawn_locked(emtask_term_t *term)
{
    emtask_term_platform_t *platform;
    SECURITY_ATTRIBUTES sa;
    HANDLE input_read = NULL;
    HANDLE input_write = NULL;
    HANDLE output_read = NULL;
    HANDLE output_write = NULL;
    HANDLE process_handle = NULL;
    HANDLE pseudo_console = NULL;
    WCHAR *command_line = NULL;
    COORD size;
    int status;

    typedef HRESULT (WINAPI *create_pseudo_console_fn)(COORD, HANDLE, HANDLE, DWORD, HANDLE *);
    typedef HRESULT (WINAPI *resize_pseudo_console_fn)(HANDLE, COORD);
    create_pseudo_console_fn create_pseudo_console = NULL;
    resize_pseudo_console_fn resize_pseudo_console = NULL;

    if (term == NULL || term->platform == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    platform = term->platform;

    emtask_term_default_size(term);
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&input_read, &input_write, &sa, 0u) ||
        !CreatePipe(&output_read, &output_write, &sa, 0u)) {
        status = SSH_ERR_PLATFORM;
        goto cleanup;
    }
    (void)SetHandleInformation(input_write, HANDLE_FLAG_INHERIT, 0u);
    (void)SetHandleInformation(output_read, HANDLE_FLAG_INHERIT, 0u);

    size.X = (SHORT)(term->cols != 0u ? term->cols : EMTASK_DEFAULT_TERM_COLS);
    size.Y = (SHORT)(term->rows != 0u ? term->rows : EMTASK_DEFAULT_TERM_ROWS);

    if (platform->allow_conpty) {
#ifndef EMTASK_WIN_MSYS2_VARIANT
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32 != NULL) {
            create_pseudo_console = (create_pseudo_console_fn)GetProcAddress(kernel32, "CreatePseudoConsole");
            resize_pseudo_console = (resize_pseudo_console_fn)GetProcAddress(kernel32, "ResizePseudoConsole");
        }
#endif
    }

#ifdef EMTASK_WIN_MSYS2_VARIANT
    command_line = emtask_build_msys2_command_line(term->command);
#else
    command_line = emtask_build_windows_command_line(term->command);
#endif
    if (command_line == NULL) {
        status = SSH_ERR_PLATFORM;
        goto cleanup;
    }

    if (create_pseudo_console != NULL) {
        STARTUPINFOEXW si;
        PROCESS_INFORMATION pi;
        SIZE_T attr_list_size = 0u;

        memset(&si, 0, sizeof(si));
        memset(&pi, 0, sizeof(pi));

        if (create_pseudo_console(size, input_read, output_write, 0u, &pseudo_console) < 0) {
            pseudo_console = NULL;
        } else {
            (void)InitializeProcThreadAttributeList(NULL, 1u, 0u, &attr_list_size);
            si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)calloc(1u, attr_list_size);
            if (si.lpAttributeList != NULL &&
                InitializeProcThreadAttributeList(si.lpAttributeList, 1u, 0u, &attr_list_size) &&
                UpdateProcThreadAttribute(
                    si.lpAttributeList,
                    0u,
                    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                    pseudo_console,
                    sizeof(pseudo_console),
                    NULL,
                    NULL)) {
                si.StartupInfo.cb = sizeof(si);
                if (CreateProcessW(
                        NULL,
                        command_line,
                        NULL,
                        NULL,
                        FALSE,
                        EXTENDED_STARTUPINFO_PRESENT,
                        NULL,
                        NULL,
                        &si.StartupInfo,
                        &pi)) {
                    process_handle = pi.hProcess;
                    (void)CloseHandle(pi.hThread);
                    platform->using_conpty = 1;
                }
            }

            if (si.lpAttributeList != NULL) {
                DeleteProcThreadAttributeList(si.lpAttributeList);
                free(si.lpAttributeList);
            }
        }

        if (process_handle == NULL && pseudo_console != NULL) {
            emtask_close_pseudo_console(pseudo_console);
            pseudo_console = NULL;
        }
        (void)resize_pseudo_console;
    }

    if (process_handle == NULL) {
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;

        memset(&si, 0, sizeof(si));
        memset(&pi, 0, sizeof(pi));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = input_read;
        si.hStdOutput = output_write;
        si.hStdError = output_write;

        if (!CreateProcessW(
                NULL,
                command_line,
                NULL,
                NULL,
                TRUE,
                CREATE_NO_WINDOW,
                NULL,
                NULL,
                &si,
                &pi)) {
            status = SSH_ERR_PLATFORM;
            goto cleanup;
        }
        process_handle = pi.hProcess;
        (void)CloseHandle(pi.hThread);
    }

    if (input_read != NULL) {
        (void)CloseHandle(input_read);
        input_read = NULL;
    }
    if (output_write != NULL) {
        (void)CloseHandle(output_write);
        output_write = NULL;
    }

    platform->process_handle = process_handle;
    platform->input_write = input_write;
    platform->output_read = output_read;
    platform->pseudo_console = pseudo_console;
    term->running = 1;
    term->faulted = 0;
    term->started_once = 1;
    free(command_line);
    return SSH_OK;

cleanup:
    if (process_handle != NULL) {
        (void)CloseHandle(process_handle);
    }
    if (pseudo_console != NULL) {
        emtask_close_pseudo_console(pseudo_console);
    }
    if (input_read != NULL) {
        (void)CloseHandle(input_read);
    }
    if (input_write != NULL) {
        (void)CloseHandle(input_write);
    }
    if (output_read != NULL) {
        (void)CloseHandle(output_read);
    }
    if (output_write != NULL) {
        (void)CloseHandle(output_write);
    }
    free(command_line);
    return status;
}

int emtask_platform_term_poll_exit_locked(emtask_term_t *term, int *exited, uint32_t *exit_status)
{
    emtask_term_platform_t *platform = term != NULL ? term->platform : NULL;

    if (platform != NULL && platform->process_handle != NULL) {
        DWORD wait_status = WaitForSingleObject(platform->process_handle, 0u);
        if (wait_status == WAIT_OBJECT_0) {
            DWORD code = 0u;
            (void)GetExitCodeProcess(platform->process_handle, &code);
            term->last_exit_status = (uint32_t)code;
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

    if (platform != NULL && platform->input_write != NULL) {
        if (platform->using_conpty && platform->conpty_win32_input_mode) {
            size_t i;

            for (i = 0u; i < len; ++i) {
                int status;
                if (buf[i] == '\n' && i != 0u && buf[i - 1u] == '\r') {
                    continue;
                }
                status = emtask_write_conpty_codepoint(platform->input_write, (WCHAR)buf[i]);
                if (status != SSH_OK) {
                    return status;
                }
            }
            *written_len = len;
            return SSH_OK;
        }

        DWORD written = 0u;
        if (!WriteFile(platform->input_write, buf, (DWORD)len, &written, NULL)) {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA) {
                return SSH_OK;
            }
            return SSH_ERR_PLATFORM;
        }
        *written_len = (size_t)written;
    }
    return SSH_OK;
}

int emtask_platform_term_read_locked(emtask_term_t *term, uint8_t *buf, size_t len, size_t *read_len)
{
    emtask_term_platform_t *platform = term != NULL ? term->platform : NULL;

    if (platform != NULL && platform->output_read != NULL) {
        DWORD available = 0u;
        if (!PeekNamedPipe(platform->output_read, NULL, 0u, NULL, &available, NULL)) {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE) {
                return SSH_OK;
            }
            return SSH_ERR_PLATFORM;
        }
        if (available != 0u) {
            DWORD want = (DWORD)(len < (size_t)available ? len : (size_t)available);
            DWORD actual = 0u;
            if (!ReadFile(platform->output_read, buf, want, &actual, NULL)) {
                DWORD err = GetLastError();
                if (err == ERROR_BROKEN_PIPE) {
                    return SSH_OK;
                }
                return SSH_ERR_PLATFORM;
            }
            *read_len = (size_t)actual;
            if (platform->using_conpty && actual != 0u) {
                emtask_conpty_track_output_mode(term, buf, (size_t)actual);
            }
        }
    }
    return SSH_OK;
}

int emtask_platform_term_resize_locked(emtask_term_t *term)
{
    emtask_term_platform_t *platform = term != NULL ? term->platform : NULL;

    if (platform != NULL && platform->using_conpty && platform->pseudo_console != NULL) {
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        if (kernel32 != NULL) {
            typedef HRESULT (WINAPI *resize_pseudo_console_fn)(HANDLE, COORD);
            resize_pseudo_console_fn fn =
                (resize_pseudo_console_fn)GetProcAddress(kernel32, "ResizePseudoConsole");
            if (fn != NULL) {
                COORD size;
                size.X = (SHORT)(term->cols != 0u ? term->cols : EMTASK_DEFAULT_TERM_COLS);
                size.Y = (SHORT)(term->rows != 0u ? term->rows : EMTASK_DEFAULT_TERM_ROWS);
                if (fn(platform->pseudo_console, size) < 0) {
                    return SSH_ERR_PLATFORM;
                }
            }
        }
    }
    return SSH_OK;
}

int emtask_platform_term_signal_locked(emtask_term_t *term, const char *signal_name)
{
    emtask_term_platform_t *platform = term != NULL ? term->platform : NULL;

    (void)signal_name;

    if (platform != NULL && platform->process_handle != NULL) {
        if (!TerminateProcess(platform->process_handle, 1u)) {
            return SSH_ERR_PLATFORM;
        }
    }
    return SSH_OK;
}

int emtask_platform_start_worker_thread(emtask_worker_t *worker)
{
    return emtask_start_detached_thread(emtask_worker_thread_entry, worker);
}

#ifdef __CYGWIN__
static void *emtask_listener_thread_entry(void *arg)
#else
static unsigned __stdcall emtask_listener_thread_entry(void *arg)
#endif
{
    emtask_listener_thread_main((emtask_task_t *)arg);
#ifdef __CYGWIN__
    return NULL;
#else
    return 0u;
#endif
}

int emtask_platform_start_listener_thread(emtask_task_t *task)
{
    return emtask_start_detached_thread(emtask_listener_thread_entry, task);
}
