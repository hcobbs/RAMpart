/**
 * @file rp_thread.c
 * @brief RAMpart thread management implementation (POSIX only)
 *
 * Provides thread identification, mutex operations, and thread-local
 * error storage using POSIX threads.
 */

#include "internal/rp_thread.h"
#include "internal/rp_types.h"
#include <string.h>

/* ============================================================================
 * Thread-Local Storage
 * ============================================================================
 * C89 doesn't have _Thread_local, so we use POSIX pthread_key_t.
 * pthread_once ensures thread-safe initialization.
 */

static pthread_key_t g_tls_key;
static int g_tls_initialized = 0;
static pthread_once_t g_tls_once = PTHREAD_ONCE_INIT;

/*
 * Fallback for environments without proper TLS.
 * Protected by mutex to prevent race conditions when TLS is unavailable.
 * Note: This fallback is only used if pthread_key_create() fails, which
 * should not happen on any modern POSIX system.
 */
static pthread_mutex_t g_fallback_mutex = PTHREAD_MUTEX_INITIALIZER;
static rampart_error_t g_last_error_fallback = RAMPART_OK;

/* ============================================================================
 * TLS Initialization (Internal)
 * ============================================================================ */

/**
 * init_tls_key - Initialize POSIX TLS key (called once)
 */
static void init_tls_key(void) {
    if (pthread_key_create(&g_tls_key, NULL) == 0) {
        g_tls_initialized = 1;
    }
}

/**
 * ensure_tls_initialized - Ensure TLS is set up (thread-safe)
 */
static void ensure_tls_initialized(void) {
    pthread_once(&g_tls_once, init_tls_key);
}

/* ============================================================================
 * Thread Identification Functions
 * ============================================================================ */

rp_thread_id_t rp_thread_get_current_id(void) {
    return pthread_self();
}

int rp_thread_ids_equal(rp_thread_id_t a, rp_thread_id_t b) {
    return pthread_equal(a, b);
}

unsigned long rp_thread_id_to_ulong(rp_thread_id_t id) {
    /*
     * pthread_t may be a pointer or integer depending on platform.
     * Cast through size_t to avoid warnings on some systems.
     */
    return (unsigned long)(size_t)id;
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
    int result;

    if (mutex == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    result = pthread_mutex_init(mutex, NULL);
    if (result != 0) {
        return RAMPART_ERR_INTERNAL;
    }
    return RAMPART_OK;
}

rampart_error_t rp_mutex_destroy(rp_mutex_t *mutex) {
    int result;

    if (mutex == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    result = pthread_mutex_destroy(mutex);
    if (result != 0) {
        return RAMPART_ERR_INTERNAL;
    }
    return RAMPART_OK;
}

rampart_error_t rp_mutex_lock(rp_mutex_t *mutex) {
    int result;

    if (mutex == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    result = pthread_mutex_lock(mutex);
    if (result != 0) {
        return RAMPART_ERR_INTERNAL;
    }
    return RAMPART_OK;
}

rampart_error_t rp_mutex_unlock(rp_mutex_t *mutex) {
    int result;

    if (mutex == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    result = pthread_mutex_unlock(mutex);
    if (result != 0) {
        return RAMPART_ERR_INTERNAL;
    }
    return RAMPART_OK;
}

rampart_error_t rp_mutex_trylock(rp_mutex_t *mutex) {
    int result;

    if (mutex == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    result = pthread_mutex_trylock(mutex);
    if (result == 0) {
        return RAMPART_OK;
    }
    return RAMPART_ERR_INTERNAL;
}

/* ============================================================================
 * Thread-Local Error Storage
 * ============================================================================ */

void rp_thread_set_last_error(rampart_error_t error) {
    ensure_tls_initialized();

    if (g_tls_initialized) {
        pthread_setspecific(g_tls_key, (void *)(size_t)error);
    } else {
        /* Fallback path: protect with mutex to prevent race conditions */
        pthread_mutex_lock(&g_fallback_mutex);
        g_last_error_fallback = error;
        pthread_mutex_unlock(&g_fallback_mutex);
    }
}

rampart_error_t rp_thread_get_last_error(void) {
    rampart_error_t error;

    ensure_tls_initialized();

    if (g_tls_initialized) {
        error = (rampart_error_t)(size_t)pthread_getspecific(g_tls_key);
        pthread_setspecific(g_tls_key, (void *)RAMPART_OK);
    } else {
        /* Fallback path: protect with mutex to prevent race conditions */
        pthread_mutex_lock(&g_fallback_mutex);
        error = g_last_error_fallback;
        g_last_error_fallback = RAMPART_OK;
        pthread_mutex_unlock(&g_fallback_mutex);
    }

    return error;
}
