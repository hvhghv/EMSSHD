#include "emssh/platform_window_term.h"

#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif

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

static WCHAR *emtask_build_windows_command_line(const char *command, int wrap_with_cmd)
{
    char buffer[EMTASK_MAX_TEXT + 64u];
    int written;

    if (!wrap_with_cmd) {
        return emtask_utf8_to_wide_alloc(command != NULL ? command : "");
    }

    written = snprintf(buffer, sizeof(buffer), "cmd.exe /S /C %s", command != NULL ? command : "");
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

static int emtask_try_decode_utf8_wide_char(
    const uint8_t *buf,
    size_t len,
    WCHAR wide[2],
    size_t *wide_len,
    size_t *consumed_len)
{
    size_t need;
    int converted;

    if (buf == NULL || wide == NULL || wide_len == NULL || consumed_len == NULL || len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    *wide_len = 0u;
    *consumed_len = 0u;

    if (buf[0] < 0x80u) {
        wide[0] = (WCHAR)buf[0];
        *wide_len = 1u;
        *consumed_len = 1u;
        return SSH_OK;
    }
    if (buf[0] >= 0xc2u && buf[0] <= 0xdfu) {
        need = 2u;
    } else if (buf[0] >= 0xe0u && buf[0] <= 0xefu) {
        need = 3u;
    } else if (buf[0] >= 0xf0u && buf[0] <= 0xf4u) {
        need = 4u;
    } else {
        return SSH_ERR_NOT_FOUND;
    }
    if (len < need) {
        return SSH_ERR_NOT_FOUND;
    }

    converted = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        (const char *)buf,
        (int)need,
        wide,
        2);
    if (converted <= 0) {
        return SSH_ERR_NOT_FOUND;
    }

    *wide_len = (size_t)converted;
    *consumed_len = need;
    return SSH_OK;
}

static int emtask_write_conpty_virtual_key(HANDLE handle, WORD virtual_key, DWORD control_state)
{
    WORD scan_code;
    int status;

    if (handle == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    scan_code = (WORD)MapVirtualKeyW((UINT)virtual_key, MAPVK_VK_TO_VSC);
    status = emtask_write_conpty_key_event(handle, virtual_key, scan_code, 0u, 1, control_state);
    if (status != SSH_OK) {
        return status;
    }
    return emtask_write_conpty_key_event(handle, virtual_key, scan_code, 0u, 0, control_state);
}

static DWORD emtask_conpty_csi_modifier_to_control_state(unsigned modifier)
{
    DWORD control_state = 0u;

    if (modifier == 0u) {
        modifier = 1u;
    }
    if ((modifier & 1u) != 0u) {
        control_state |= SHIFT_PRESSED;
    }
    if ((modifier & 2u) != 0u) {
        control_state |= LEFT_ALT_PRESSED;
    }
    if ((modifier & 4u) != 0u) {
        control_state |= LEFT_CTRL_PRESSED;
    }
    return control_state;
}

static WORD emtask_conpty_csi_final_to_vk(unsigned parameter, uint8_t final_ch)
{
    switch (final_ch) {
    case 'A': return VK_UP;
    case 'B': return VK_DOWN;
    case 'C': return VK_RIGHT;
    case 'D': return VK_LEFT;
    case 'H': return VK_HOME;
    case 'F': return VK_END;
    case '~':
        switch (parameter) {
        case 1u: return VK_HOME;
        case 2u: return VK_INSERT;
        case 3u: return VK_DELETE;
        case 4u: return VK_END;
        case 5u: return VK_PRIOR;
        case 6u: return VK_NEXT;
        case 7u: return VK_HOME;
        case 8u: return VK_END;
        case 11u: return VK_F1;
        case 12u: return VK_F2;
        case 13u: return VK_F3;
        case 14u: return VK_F4;
        case 15u: return VK_F5;
        case 17u: return VK_F6;
        case 18u: return VK_F7;
        case 19u: return VK_F8;
        case 20u: return VK_F9;
        case 21u: return VK_F10;
        case 23u: return VK_F11;
        case 24u: return VK_F12;
        default: return 0u;
        }
    default:
        return 0u;
    }
}

static int emtask_try_write_conpty_vt_key_sequence(
    HANDLE handle,
    const uint8_t *buf,
    size_t len,
    size_t *consumed_len)
{
    unsigned params[4] = {0u, 0u, 0u, 0u};
    unsigned param_count = 0u;
    unsigned current = 0u;
    int have_digit = 0;
    size_t i;
    WORD virtual_key = 0u;
    DWORD control_state = 0u;

    if (consumed_len == NULL) {
        return SSH_ERR_INVALID_ARGUMENT;
    }
    *consumed_len = 0u;
    if (handle == NULL || buf == NULL || len == 0u) {
        return SSH_ERR_INVALID_ARGUMENT;
    }

    if (buf[0] == 0x7fu) {
        *consumed_len = 1u;
        return emtask_write_conpty_virtual_key(handle, VK_BACK, 0u);
    }
    if (buf[0] >= 1u && buf[0] <= 26u) {
        WCHAR ch = (WCHAR)(L'a' + (WCHAR)buf[0] - 1u);
        SHORT vk_state = VkKeyScanW(ch);
        WORD vk = vk_state != (SHORT)-1 ? (WORD)(vk_state & 0xff) : 0u;
        if (vk != 0u) {
            *consumed_len = 1u;
            return emtask_write_conpty_codepoint(handle, (WCHAR)buf[0]);
        }
    }
    if (buf[0] != 0x1bu) {
        return SSH_ERR_NOT_FOUND;
    }
    if (len == 1u) {
        *consumed_len = 1u;
        return emtask_write_conpty_virtual_key(handle, VK_ESCAPE, 0u);
    }

    if (buf[1] == 'O' && len >= 3u) {
        switch (buf[2]) {
        case 'P': virtual_key = VK_F1; break;
        case 'Q': virtual_key = VK_F2; break;
        case 'R': virtual_key = VK_F3; break;
        case 'S': virtual_key = VK_F4; break;
        case 'A': virtual_key = VK_UP; break;
        case 'B': virtual_key = VK_DOWN; break;
        case 'C': virtual_key = VK_RIGHT; break;
        case 'D': virtual_key = VK_LEFT; break;
        case 'H': virtual_key = VK_HOME; break;
        case 'F': virtual_key = VK_END; break;
        default: virtual_key = 0u; break;
        }
        if (virtual_key != 0u) {
            *consumed_len = 3u;
            return emtask_write_conpty_virtual_key(handle, virtual_key, 0u);
        }
        return SSH_ERR_NOT_FOUND;
    }

    if (buf[1] != '[') {
        *consumed_len = 1u;
        return emtask_write_conpty_virtual_key(handle, VK_ESCAPE, 0u);
    }

    for (i = 2u; i < len && i < 32u; ++i) {
        uint8_t ch = buf[i];
        if (ch >= '0' && ch <= '9') {
            current = (current * 10u) + (unsigned)(ch - '0');
            have_digit = 1;
            continue;
        }
        if (ch == ';') {
            if (param_count < 4u) {
                params[param_count++] = have_digit ? current : 0u;
            }
            current = 0u;
            have_digit = 0;
            continue;
        }

        if (param_count < 4u) {
            params[param_count++] = have_digit ? current : 0u;
        }
        if (param_count == 0u || params[0] == 0u) {
            params[0] = 1u;
        }
        if (param_count >= 2u && params[1] > 1u) {
            control_state = emtask_conpty_csi_modifier_to_control_state(params[1] - 1u);
        }
        virtual_key = emtask_conpty_csi_final_to_vk(params[0], ch);
        if (virtual_key != 0u) {
            *consumed_len = i + 1u;
            return emtask_write_conpty_virtual_key(handle, virtual_key, control_state);
        }
        return SSH_ERR_NOT_FOUND;
    }

    return SSH_ERR_NOT_FOUND;
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
    status = emtask_window_start_joinable_thread(&platform->monitor_thread, emtask_term_monitor_thread_entry, term);
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
        emtask_window_join_joinable_thread(&platform->monitor_thread);
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
    WCHAR *working_dir = NULL;
    WCHAR *working_dir_arg = NULL;
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
    command_line = emtask_build_windows_command_line(term->command, create_pseudo_console == NULL);
#endif
    if (command_line == NULL) {
        status = SSH_ERR_PLATFORM;
        goto cleanup;
    }
    if (term->working_dir[0] != '\0') {
        working_dir = emtask_utf8_to_wide_alloc(term->working_dir);
        if (working_dir == NULL) {
            status = SSH_ERR_PLATFORM;
            goto cleanup;
        }
        working_dir_arg = working_dir;
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
                        working_dir_arg,
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
                working_dir_arg,
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
    free(working_dir);
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
    free(working_dir);
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
                size_t consumed_len = 0u;

                status = emtask_try_write_conpty_vt_key_sequence(
                    platform->input_write,
                    buf + i,
                    len - i,
                    &consumed_len);
                if (status == SSH_OK && consumed_len != 0u) {
                    i += consumed_len - 1u;
                    continue;
                }
                if (status != SSH_OK && status != SSH_ERR_NOT_FOUND) {
                    return status;
                }
                if (buf[i] == '\n' && i != 0u && buf[i - 1u] == '\r') {
                    continue;
                }
                {
                    WCHAR wide[2] = {0u, 0u};
                    size_t wide_len = 0u;
                    size_t utf8_consumed_len = 0u;
                    size_t j;

                    status = emtask_try_decode_utf8_wide_char(
                        buf + i,
                        len - i,
                        wide,
                        &wide_len,
                        &utf8_consumed_len);
                    if (status == SSH_OK && wide_len != 0u && utf8_consumed_len != 0u) {
                        for (j = 0u; j < wide_len; ++j) {
                            status = emtask_write_conpty_codepoint(platform->input_write, wide[j]);
                            if (status != SSH_OK) {
                                return status;
                            }
                        }
                        i += utf8_consumed_len - 1u;
                        continue;
                    }
                    status = emtask_write_conpty_codepoint(platform->input_write, (WCHAR)buf[i]);
                    if (status != SSH_OK) {
                        return status;
                    }
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

