#ifndef EMTASK_INTERNAL_H
#define EMTASK_INTERNAL_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "emssh/platform_stdio_fs.h"
#if defined(EMSSH_BUILD_POSIX_PASSWD_AUTH)
#include "emssh/platform_posix_passwd_auth.h"
#endif

#include "emssh/platform_tcp.h"
#include "emssh/ssh_error.h"
#include "emssh/ssh_server.h"

#define EMTASK_MAX_TEXT 1024u
#define EMTASK_MAX_PATH 512u
#define EMTASK_MAX_USERNAME 128u
#define EMTASK_MAX_HOSTKEY_PRIVATE 4096u
#define EMTASK_MAX_RESTART_HISTORY 64u
#define EMTASK_MAX_TASKS 32u
#define EMTASK_MAX_TASK_NAME 64u
#define EMTASK_DEFAULT_PORT 2222u
#define EMTASK_DEFAULT_TIMEOUT_MS 30000u
#define EMTASK_DEFAULT_MAX_WORKERS 8u
#define EMTASK_DEFAULT_PANEL_LISTEN_ADDRESS "127.0.0.1"
#define EMTASK_DEFAULT_PANEL_PORT 6024u
#define EMTASK_DEFAULT_PANEL_AUTH_FILE "emtask_panel_auth.keys"
#define EMTASK_DEFAULT_PANEL_QR_FILE "emtask_panel_connect.svg"
#define EMTASK_DEFAULT_PANEL_TASKS_DB_FILE "emtask_tasks.sqlite3"
#define EMTASK_DEFAULT_AUTHORIZED_KEYS_FILE "authorized_keys"
#define EMTASK_DEFAULT_PANEL_QR_HOST "127.0.0.1"
#define EMTASK_PANEL_AUTH_TOKEN 0x01u
#define EMTASK_PANEL_AUTH_OTP 0x02u
#define EMTASK_DEFAULT_PANEL_OTP_DIGITS 6u
#define EMTASK_DEFAULT_PANEL_OTP_STEP_SEC 60u
#define EMTASK_DEFAULT_PANEL_OTP_WINDOW 1u
#define EMTASK_DEFAULT_BIND_RETRY_MAX_SEC 300u
#define EMTASK_DEFAULT_RESTART_LIMIT 8u
#define EMTASK_DEFAULT_RESTART_WINDOW_SEC 60u
#define EMTASK_DEFAULT_TERM_COLS 80u
#define EMTASK_DEFAULT_TERM_ROWS 24u
#define EMTASK_DEFAULT_REPLAY_BUFFER_BYTES 1048576u
#define EMTASK_DEFAULT_SCREEN_SNAPSHOT 1
#define EMTASK_NET_IO_TIMEOUT (-2)

typedef enum emtask_auth_backend {
    EMTASK_AUTH_BACKEND_INTERNAL = 0,
    EMTASK_AUTH_BACKEND_PASSWD = 1
} emtask_auth_backend_t;

typedef enum emtask_panel_qr_mode {
    EMTASK_PANEL_QR_DISABLED = 0,
    EMTASK_PANEL_QR_IF_MISSING = 1,
    EMTASK_PANEL_QR_ALWAYS = 2
} emtask_panel_qr_mode_t;

typedef struct emtask_global_config {
    char config_path[EMTASK_MAX_PATH];
    char config_dir[EMTASK_MAX_PATH];
    char username[EMTASK_MAX_USERNAME];
    char password[EMTASK_MAX_TEXT];
    char hostkey_file[EMTASK_MAX_PATH];
    char authorized_keys_file[EMTASK_MAX_PATH];
    char panel_listen_address[EMTASK_MAX_TEXT];
    char panel_token[EMTASK_MAX_TEXT];
    char panel_otp_secret[EMTASK_MAX_TEXT];
    char panel_auth_file[EMTASK_MAX_PATH];
    char panel_qr_file[EMTASK_MAX_PATH];
    char panel_tasks_db_file[EMTASK_MAX_PATH];
    char panel_name[EMTASK_MAX_TEXT];
    char panel_qr_host[EMTASK_MAX_TEXT];
    uint32_t timeout_ms;
    unsigned max_workers;
    unsigned panel_auth;
    unsigned panel_otp_digits;
    unsigned panel_otp_step_sec;
    unsigned panel_otp_window;
    unsigned bind_retry_max_sec;
    uint16_t panel_port;
    int use_conpty;
    int panel_enabled;
    int bind_retry_enabled;
    int panel_qr_include_username;
    int panel_qr_include_password;
    emtask_panel_qr_mode_t panel_qr_mode;
    emtask_auth_backend_t auth_backend;
} emtask_global_config_t;

typedef struct emtask_task_config {
    char name[EMTASK_MAX_TASK_NAME];
    char listen_address[EMTASK_MAX_TEXT];
    char command[EMTASK_MAX_TEXT];
    char working_dir[EMTASK_MAX_PATH];
    uint16_t port;
    unsigned restart_limit;
    unsigned restart_window_sec;
    size_t replay_buffer_bytes;
    int use_conpty;
    int replay_on_attach;
    int repaint_on_attach;
    int screen_snapshot;
    int use_sftp;
} emtask_task_config_t;

typedef struct emtask_config {
    emtask_global_config_t global;
    emtask_task_config_t tasks[EMTASK_MAX_TASKS];
    size_t task_count;
} emtask_config_t;

typedef struct emtask_mutex {
    void *impl;
} emtask_mutex_t;

typedef struct emtask_cond {
    void *impl;
} emtask_cond_t;

typedef struct emtask_term_platform emtask_term_platform_t;

typedef struct emtask_endpoint {
    uintptr_t socket_handle;
    char peer_address[64];
    volatile int open;
    volatile int shutdown_requested;
} emtask_endpoint_t;

typedef struct emtask_worker_pool {
    emtask_mutex_t lock;
    emtask_cond_t cv;
    unsigned max_workers;
    unsigned active_workers;
    int initialized;
} emtask_worker_pool_t;

struct emtask_worker;
struct emtask_task;

typedef struct emtask_session_manager {
    emtask_mutex_t lock;
    emtask_cond_t cv;
    struct emtask_worker *active_worker;
    int initialized;
} emtask_session_manager_t;

typedef struct emtask_term_attachment {
    struct emtask_term *term;
    size_t replay_offset;
    size_t replay_remaining;
    size_t screen_snapshot_offset;
    unsigned screen_snapshot_phase;
    int screen_snapshot_pending;
    int active;
} emtask_term_attachment_t;

typedef struct emtask_term {
    ssh_term_api_t api;
    emtask_mutex_t lock;
    char command[EMTASK_MAX_TEXT];
    char working_dir[EMTASK_MAX_PATH];
    char last_error[EMTASK_MAX_TEXT];
    char term_type[64];
    uint64_t restart_history[EMTASK_MAX_RESTART_HISTORY];
    uint64_t last_error_ms;
    size_t restart_history_len;
    uint32_t cols;
    uint32_t rows;
    uint32_t width_px;
    uint32_t height_px;
    uint32_t last_exit_status;
    int last_error_status;
    unsigned restart_limit;
    uint64_t restart_window_ms;
    uint64_t interrupt_restart_deadline_ms;
    uint8_t *replay_buffer;
    size_t replay_capacity;
    size_t replay_start;
    size_t replay_len;
    uint32_t screen_cols;
    uint32_t screen_rows;
    uint32_t screen_cursor_col;
    uint32_t screen_cursor_row;
    uint32_t screen_saved_col;
    uint32_t screen_saved_row;
    uint32_t screen_scroll_top;
    uint32_t screen_scroll_bottom;
    uint16_t *screen_cells;
    size_t screen_cell_count;
    int screen_snapshot;
    int screen_dirty;
    int screen_wrap_pending;
    int screen_esc_state;
    char screen_csi[64];
    size_t screen_csi_len;
    int replay_on_attach;
    int repaint_on_attach;
    int initialized;
    int attached;
    int exited;
    int started_once;
    int running;
    int faulted;
    int stop_monitor;
    emtask_term_platform_t *platform;
} emtask_term_t;

typedef struct emtask_app {
    emtask_config_t config;
    ssh_tcp_platform_t tcp;
    ssh_tcp_listener_t panel_listener;
    emtask_worker_pool_t pool;
    emtask_mutex_t task_lock;
    struct emtask_task *tasks;
    size_t task_count;
    size_t task_capacity;
    uint64_t started_ms;
    int panel_listener_open;
    int task_lock_initialized;
    uint8_t hostkey_private[EMTASK_MAX_HOSTKEY_PRIVATE];
    size_t hostkey_private_len;
#if defined(EMSSH_BUILD_POSIX_PASSWD_AUTH)
    ssh_stdio_fs_t passwd_fs;
    ssh_posix_passwd_auth_t passwd_auth;
    int passwd_auth_initialized;
#endif
} emtask_app_t;

typedef struct emtask_task {
    emtask_app_t *app;
    emtask_task_config_t config;
    ssh_tcp_listener_t listener;
    emtask_session_manager_t session_manager;
    emtask_term_t term;
    int initialized;
    int listener_open;
    int stop_requested;
    int deleted;
    int listener_thread_running;
    unsigned worker_count;
} emtask_task_t;

typedef struct emtask_worker {
    emtask_app_t *app;
    emtask_task_t *task;
    emtask_endpoint_t endpoint;
} emtask_worker_t;

void emtask_logf(const char *fmt, ...);
void emtask_term_default_size(emtask_term_t *term);
int emtask_term_monitor_step(emtask_term_t *term);
void emtask_worker_thread_main(emtask_worker_t *worker);
void emtask_listener_thread_main(emtask_task_t *task);
void emtask_panel_thread_main(emtask_app_t *app);

int emtask_platform_key_equals(const char *lhs, const char *rhs);
int emtask_platform_path_is_absolute(const char *path);
int emtask_platform_join_path(const char *base_dir, const char *value, char out[EMTASK_MAX_PATH]);
int emtask_platform_default_use_conpty(void);
int emtask_platform_net_is_peer_closed_error(void);
int emtask_platform_net_wait(uintptr_t socket_handle, int for_write, uint32_t timeout_ms);
int emtask_platform_net_shutdown(uintptr_t socket_handle);
int emtask_platform_net_close(uintptr_t socket_handle);
int emtask_platform_net_recv(uintptr_t socket_handle, uint8_t *buf, size_t len);
int emtask_platform_net_send(uintptr_t socket_handle, const uint8_t *buf, size_t len);
uint64_t emtask_platform_monotonic_ms(void);
int emtask_platform_library_open(const char *path, void **handle_out);
void emtask_platform_library_close(void *handle);
void *emtask_platform_library_symbol(void *handle, const char *name);
int emtask_platform_sqlite_library_open(void **handle_out, int *using_system_out);
void emtask_platform_sleep_ms(uint32_t timeout_ms);

int emtask_mutex_init(emtask_mutex_t *lock);
void emtask_mutex_deinit(emtask_mutex_t *lock);
void emtask_mutex_lock(emtask_mutex_t *lock);
void emtask_mutex_unlock(emtask_mutex_t *lock);
int emtask_cond_init(emtask_cond_t *cv);
void emtask_cond_deinit(emtask_cond_t *cv);
void emtask_cond_wait(emtask_cond_t *cv, emtask_mutex_t *lock);
void emtask_cond_broadcast(emtask_cond_t *cv);

int emtask_platform_term_init(emtask_term_t *term, const emtask_task_config_t *task_config);
void emtask_platform_term_deinit(emtask_term_t *term);
void emtask_platform_term_close_handles_locked(emtask_term_t *term, int terminate_child);
int emtask_platform_term_spawn_locked(emtask_term_t *term);
int emtask_platform_term_poll_exit_locked(emtask_term_t *term, int *exited, uint32_t *exit_status);
int emtask_platform_term_write_locked(emtask_term_t *term, const uint8_t *buf, size_t len, size_t *written_len);
int emtask_platform_term_read_locked(emtask_term_t *term, uint8_t *buf, size_t len, size_t *read_len);
int emtask_platform_term_resize_locked(emtask_term_t *term);
int emtask_platform_term_signal_locked(emtask_term_t *term, const char *signal_name);
int emtask_platform_start_worker_thread(emtask_worker_t *worker);
int emtask_platform_start_listener_thread(emtask_task_t *task);
int emtask_platform_start_panel_thread(emtask_app_t *app);

#endif
