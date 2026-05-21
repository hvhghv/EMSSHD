#ifndef EMSSH_PLATFORM_WINDOW_TERM_H
#define EMSSH_PLATFORM_WINDOW_TERM_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef WINVER
#define WINVER _WIN32_WINNT
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#ifdef __CYGWIN__
#include <pthread.h>
#else
#include <process.h>
#endif

#include "emtask_internal.h"

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

BOOLEAN NTAPI SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);

#ifdef __CYGWIN__
int emtask_window_start_joinable_thread(
    emtask_thread_handle_t *handle_out,
    void *(*entry)(void *),
    void *arg);
#else
int emtask_window_start_joinable_thread(
    emtask_thread_handle_t *handle_out,
    unsigned(__stdcall *entry)(void *),
    void *arg);
#endif

void emtask_window_join_joinable_thread(emtask_thread_handle_t *handle);

#endif /* EMSSH_PLATFORM_WINDOW_TERM_H */
