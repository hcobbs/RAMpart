/**
 * @file rp_thread.h
 * @brief RAMpart thread management internals
 *
 * Provides platform-independent thread identification and ownership
 * tracking. Supports POSIX (Linux, macOS) and Windows platforms.
 *
 * @internal
 *
 * Copyright (C) 2024 Hunter Cobbs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef RP_THREAD_H
#define RP_THREAD_H

#include "rp_types.h"

/* ============================================================================
 * Thread Identification Functions
 * ============================================================================ */

/**
 * rp_thread_get_current_id - Get current thread's ID
 *
 * Returns the thread ID of the calling thread. The ID type is
 * platform-dependent but abstracted through rp_thread_id_t.
 *
 * @return Current thread's ID
 *
 * @note On POSIX: returns pthread_self()
 * @note On Windows: returns GetCurrentThreadId()
 */
rp_thread_id_t rp_thread_get_current_id(void);

/**
 * rp_thread_ids_equal - Compare two thread IDs
 *
 * Determines if two thread IDs refer to the same thread.
 *
 * @param a     First thread ID
 * @param b     Second thread ID
 *
 * @return Non-zero if IDs are equal, zero if different
 *
 * @note On POSIX: uses pthread_equal()
 * @note On Windows: direct comparison
 */
int rp_thread_ids_equal(rp_thread_id_t a, rp_thread_id_t b);

/**
 * rp_thread_id_to_ulong - Convert thread ID to unsigned long
 *
 * Converts a thread ID to an unsigned long for display purposes.
 * The result may not be unique across all possible thread IDs
 * but is suitable for logging.
 *
 * @param id    Thread ID to convert
 *
 * @return Thread ID as unsigned long
 */
unsigned long rp_thread_id_to_ulong(rp_thread_id_t id);

/* ============================================================================
 * Ownership Verification Functions
 * ============================================================================ */

/**
 * rp_thread_verify_owner - Verify block ownership
 *
 * Checks if the current thread is the owner of the specified block.
 *
 * @param block     Pointer to block header
 *
 * @return RAMPART_OK if owner matches, RAMPART_ERR_WRONG_THREAD if not
 *
 * @retval RAMPART_OK               Current thread is owner
 * @retval RAMPART_ERR_NULL_PARAM   block is NULL
 * @retval RAMPART_ERR_WRONG_THREAD Current thread is not owner
 */
rampart_error_t rp_thread_verify_owner(const rp_block_header_t *block);

/**
 * rp_thread_set_owner - Set block owner to current thread
 *
 * Sets the block's owner thread ID to the current thread.
 *
 * @param block     Pointer to block header
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_OK               Owner set successfully
 * @retval RAMPART_ERR_NULL_PARAM   block is NULL
 */
rampart_error_t rp_thread_set_owner(rp_block_header_t *block);

/**
 * rp_thread_get_owner - Get block owner thread ID
 *
 * Returns the thread ID stored in the block header.
 *
 * @param block     Pointer to block header
 *
 * @return Owner thread ID, or 0 if block is NULL
 */
rp_thread_id_t rp_thread_get_owner(const rp_block_header_t *block);

/* ============================================================================
 * Mutex Functions
 * ============================================================================ */

/**
 * rp_mutex_init - Initialize a mutex
 *
 * Initializes a platform-specific mutex.
 *
 * @param mutex     Pointer to mutex
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_OK               Mutex initialized
 * @retval RAMPART_ERR_NULL_PARAM   mutex is NULL
 * @retval RAMPART_ERR_INTERNAL     Platform mutex init failed
 */
rampart_error_t rp_mutex_init(rp_mutex_t *mutex);

/**
 * rp_mutex_destroy - Destroy a mutex
 *
 * Releases resources associated with the mutex.
 *
 * @param mutex     Pointer to mutex
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_OK               Mutex destroyed
 * @retval RAMPART_ERR_NULL_PARAM   mutex is NULL
 */
rampart_error_t rp_mutex_destroy(rp_mutex_t *mutex);

/**
 * rp_mutex_lock - Acquire a mutex
 *
 * Blocks until the mutex is acquired.
 *
 * @param mutex     Pointer to mutex
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_OK               Mutex acquired
 * @retval RAMPART_ERR_NULL_PARAM   mutex is NULL
 * @retval RAMPART_ERR_INTERNAL     Platform lock failed
 */
rampart_error_t rp_mutex_lock(rp_mutex_t *mutex);

/**
 * rp_mutex_unlock - Release a mutex
 *
 * Releases a previously acquired mutex.
 *
 * @param mutex     Pointer to mutex
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_OK               Mutex released
 * @retval RAMPART_ERR_NULL_PARAM   mutex is NULL
 * @retval RAMPART_ERR_INTERNAL     Platform unlock failed
 */
rampart_error_t rp_mutex_unlock(rp_mutex_t *mutex);

/**
 * rp_mutex_trylock - Try to acquire a mutex
 *
 * Attempts to acquire the mutex without blocking.
 *
 * @param mutex     Pointer to mutex
 *
 * @return RAMPART_OK if acquired, RAMPART_ERR_INTERNAL if busy
 *
 * @retval RAMPART_OK               Mutex acquired
 * @retval RAMPART_ERR_NULL_PARAM   mutex is NULL
 * @retval RAMPART_ERR_INTERNAL     Mutex busy or error
 */
rampart_error_t rp_mutex_trylock(rp_mutex_t *mutex);

/* ============================================================================
 * Thread-Local Storage
 * ============================================================================ */

/**
 * rp_thread_set_last_error - Set thread-local last error
 *
 * Stores the error code in thread-local storage for later retrieval.
 *
 * @param error     Error code to store
 *
 * @note Uses platform-specific TLS mechanism.
 */
void rp_thread_set_last_error(rampart_error_t error);

/**
 * rp_thread_get_last_error - Get thread-local last error
 *
 * Retrieves and clears the last error for the current thread.
 *
 * @return Last error code, or RAMPART_OK if none
 */
rampart_error_t rp_thread_get_last_error(void);

#endif /* RP_THREAD_H */
