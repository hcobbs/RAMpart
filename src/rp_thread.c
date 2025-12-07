/**
 * @file rp_thread.c
 * @brief RAMpart thread management implementation
 *
 * Provides platform-independent thread identification, mutex operations,
 * and thread-local error storage.
 */

#include "internal/rp_thread.h"
#include "internal/rp_types.h"
#include <string.h>

/* ============================================================================
 * Thread-Local Storage
 * ============================================================================
 * C89 doesn't have _Thread_local, so we use platform-specific mechanisms.
 * Windows uses TLS with proper atomic initialization to prevent races.
 * POSIX uses pthread_once for thread-safe initialization.
 */

#ifdef RP_PLATFORM_WINDOWS
    static DWORD g_tls_index = TLS_OUT_OF_INDEXES;
    static volatile LONG g_tls_init_state = 0;  /* 0=uninit, 1=initing, 2=done */
#else
    static pthread_key_t g_tls_key;
    static int g_tls_initialized = 0;
    static pthread_once_t g_tls_once = PTHREAD_ONCE_INIT;
#endif

/* Fallback for environments without proper TLS */
static rampart_error_t g_last_error_fallback = RAMPART_OK;

/* ============================================================================
 * TLS Initialization (Internal)
 * ============================================================================ */

#ifndef RP_PLATFORM_WINDOWS
/**
 * init_tls_key - Initialize POSIX TLS key (called once)
 */
static void init_tls_key(void) {
    if (pthread_key_create(&g_tls_key, NULL) == 0) {
        g_tls_initialized = 1;
    }
}
#endif

/**
 * ensure_tls_initialized - Ensure TLS is set up (thread-safe)
 */
static void ensure_tls_initialized(void) {
#ifdef RP_PLATFORM_WINDOWS
    /* Use InterlockedCompareExchange for atomic initialization */
    if (g_tls_init_state == 2) {
        return;  /* Already initialized */
    }

    /* Try to claim initialization rights (0 -> 1) */
    if (InterlockedCompareExchange(&g_tls_init_state, 1, 0) == 0) {
        /* We won the race, do initialization */
        g_tls_index = TlsAlloc();
        /* Mark complete (1 -> 2), even if TlsAlloc failed */
        InterlockedExchange(&g_tls_init_state, 2);
    } else {
        /* Another thread is initializing, spin until done */
        while (g_tls_init_state != 2) {
            Sleep(0);  /* Yield to other threads */
        }
    }
#else
    pthread_once(&g_tls_once, init_tls_key);
#endif
}

/* ============================================================================
 * Thread Identification Functions
 * ============================================================================ */

rp_thread_id_t rp_thread_get_current_id(void) {
#ifdef RP_PLATFORM_WINDOWS
    return GetCurrentThreadId();
#else
    return pthread_self();
#endif
}

int rp_thread_ids_equal(rp_thread_id_t a, rp_thread_id_t b) {
#ifdef RP_PLATFORM_WINDOWS
    return (a == b);
#else
    return pthread_equal(a, b);
#endif
}

unsigned long rp_thread_id_to_ulong(rp_thread_id_t id) {
#ifdef RP_PLATFORM_WINDOWS
    return (unsigned long)id;
#else
    /*
     * pthread_t may be a pointer or integer depending on platform.
     * Cast through void* to avoid warnings on some systems.
     */
    return (unsigned long)(size_t)id;
#endif
}

/* ============================================================================
 * Ownership Verification Functions
 * ============================================================================ */

rampart_error_t rp_thread_verify_owner(const rp_block_header_t *block) {
    rp_thread_id_t current;

    if (block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    current = rp_thread_get_current_id();

    if (!rp_thread_ids_equal(current, block->owner_thread)) {
        return RAMPART_ERR_WRONG_THREAD;
    }

    return RAMPART_OK;
}

rampart_error_t rp_thread_set_owner(rp_block_header_t *block) {
    if (block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    block->owner_thread = rp_thread_get_current_id();
    return RAMPART_OK;
}

rp_thread_id_t rp_thread_get_owner(const rp_block_header_t *block) {
    if (block == NULL) {
        /* Return a zeroed thread ID */
        rp_thread_id_t zero;
        memset(&zero, 0, sizeof(zero));
        return zero;
    }

    return block->owner_thread;
}

/* ============================================================================
 * Mutex Functions
 * ============================================================================ */

rampart_error_t rp_mutex_init(rp_mutex_t *mutex) {
    if (mutex == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

#ifdef RP_PLATFORM_WINDOWS
    InitializeCriticalSection(mutex);
    return RAMPART_OK;
#else
    {
        int result = pthread_mutex_init(mutex, NULL);
        if (result != 0) {
            return RAMPART_ERR_INTERNAL;
        }
        return RAMPART_OK;
    }
#endif
}

rampart_error_t rp_mutex_destroy(rp_mutex_t *mutex) {
    if (mutex == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

#ifdef RP_PLATFORM_WINDOWS
    DeleteCriticalSection(mutex);
    return RAMPART_OK;
#else
    {
        int result = pthread_mutex_destroy(mutex);
        if (result != 0) {
            return RAMPART_ERR_INTERNAL;
        }
        return RAMPART_OK;
    }
#endif
}

rampart_error_t rp_mutex_lock(rp_mutex_t *mutex) {
    if (mutex == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

#ifdef RP_PLATFORM_WINDOWS
    EnterCriticalSection(mutex);
    return RAMPART_OK;
#else
    {
        int result = pthread_mutex_lock(mutex);
        if (result != 0) {
            return RAMPART_ERR_INTERNAL;
        }
        return RAMPART_OK;
    }
#endif
}

rampart_error_t rp_mutex_unlock(rp_mutex_t *mutex) {
    if (mutex == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

#ifdef RP_PLATFORM_WINDOWS
    LeaveCriticalSection(mutex);
    return RAMPART_OK;
#else
    {
        int result = pthread_mutex_unlock(mutex);
        if (result != 0) {
            return RAMPART_ERR_INTERNAL;
        }
        return RAMPART_OK;
    }
#endif
}

rampart_error_t rp_mutex_trylock(rp_mutex_t *mutex) {
    if (mutex == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

#ifdef RP_PLATFORM_WINDOWS
    if (TryEnterCriticalSection(mutex)) {
        return RAMPART_OK;
    }
    return RAMPART_ERR_INTERNAL;
#else
    {
        int result = pthread_mutex_trylock(mutex);
        if (result == 0) {
            return RAMPART_OK;
        }
        return RAMPART_ERR_INTERNAL;
    }
#endif
}

/* ============================================================================
 * Thread-Local Error Storage
 * ============================================================================ */

void rp_thread_set_last_error(rampart_error_t error) {
    ensure_tls_initialized();

#ifdef RP_PLATFORM_WINDOWS
    if (g_tls_index != TLS_OUT_OF_INDEXES) {
        TlsSetValue(g_tls_index, (LPVOID)(size_t)error);
    } else {
        g_last_error_fallback = error;
    }
#else
    if (g_tls_initialized) {
        pthread_setspecific(g_tls_key, (void *)(size_t)error);
    } else {
        g_last_error_fallback = error;
    }
#endif
}

rampart_error_t rp_thread_get_last_error(void) {
    rampart_error_t error;

    ensure_tls_initialized();

#ifdef RP_PLATFORM_WINDOWS
    if (g_tls_index != TLS_OUT_OF_INDEXES) {
        error = (rampart_error_t)(size_t)TlsGetValue(g_tls_index);
        TlsSetValue(g_tls_index, (LPVOID)RAMPART_OK);
    } else {
        error = g_last_error_fallback;
        g_last_error_fallback = RAMPART_OK;
    }
#else
    if (g_tls_initialized) {
        error = (rampart_error_t)(size_t)pthread_getspecific(g_tls_key);
        pthread_setspecific(g_tls_key, (void *)RAMPART_OK);
    } else {
        error = g_last_error_fallback;
        g_last_error_fallback = RAMPART_OK;
    }
#endif

    return error;
}
