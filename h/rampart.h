/**
 * @file rampart.h
 * @brief RAMpart Secure Memory Pool Manager - Public API
 *
 * RAMpart is a secure memory pool management library providing:
 * - Guard bands for buffer overflow/underflow detection
 * - Thread ownership enforcement
 * - Optional encryption of data at rest
 * - Secure wiping of freed memory
 * - Worst-fit allocation strategy
 * - Memory leak detection and prevention
 *
 * All allocated memory is zero-initialized before returning to the caller.
 *
 * @version 1.0.0
 * @date 2024
 *
 * @section usage Basic Usage
 * @code
 * #include "rampart.h"
 *
 * rampart_pool_t *pool;
 * rampart_config_t config;
 * void *ptr;
 *
 * rampart_config_default(&config);
 * config.pool_size = 1024 * 1024;
 *
 * pool = rampart_init(&config);
 * ptr = rampart_alloc(pool, 256);
 * rampart_free(pool, ptr);
 * rampart_shutdown(pool);
 * @endcode
 *
 * @section thread_safety Thread Safety
 * All RAMpart functions are thread-safe. Each pool has its own mutex.
 * By default, memory blocks can only be accessed by their allocating thread.
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

#ifndef RAMPART_H
#define RAMPART_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/* ============================================================================
 * Version Information
 * ============================================================================ */

/**
 * @def RAMPART_VERSION_MAJOR
 * @brief Major version number
 *
 * Incremented for incompatible API changes.
 */
#define RAMPART_VERSION_MAJOR 1

/**
 * @def RAMPART_VERSION_MINOR
 * @brief Minor version number
 *
 * Incremented for backwards-compatible feature additions.
 */
#define RAMPART_VERSION_MINOR 0

/**
 * @def RAMPART_VERSION_PATCH
 * @brief Patch version number
 *
 * Incremented for backwards-compatible bug fixes.
 */
#define RAMPART_VERSION_PATCH 0

/**
 * @def RAMPART_VERSION_STRING
 * @brief Version as a string literal
 */
#define RAMPART_VERSION_STRING "1.0.0"

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */

/**
 * @def RAMPART_MAX_KEY_SIZE
 * @brief Maximum encryption key size in bytes
 *
 * The Feistel cipher implementation supports keys up to this size.
 * Recommended key size is 16 bytes (128 bits).
 */
#define RAMPART_MAX_KEY_SIZE 32

/**
 * @def RAMPART_MIN_POOL_SIZE
 * @brief Minimum pool size in bytes
 *
 * Pools smaller than this cannot hold even a single allocation
 * after accounting for pool header and block overhead.
 */
#define RAMPART_MIN_POOL_SIZE 4096

/**
 * @def RAMPART_DEFAULT_ALIGNMENT
 * @brief Default memory alignment in bytes
 *
 * All allocations are aligned to at least this boundary.
 * This ensures compatibility with SIMD instructions and cache lines.
 */
#define RAMPART_DEFAULT_ALIGNMENT 16

/* ============================================================================
 * Error Codes
 * ============================================================================ */

/**
 * @enum rampart_error_t
 * @brief Error codes returned by RAMpart functions
 *
 * Functions that can fail return rampart_error_t directly or set it
 * as the last error retrievable via rampart_get_last_error().
 */
typedef enum rampart_error_e {
    /**
     * @brief Operation completed successfully
     */
    RAMPART_OK = 0,

    /**
     * @brief NULL pointer passed where not permitted
     *
     * Returned when a required pointer parameter is NULL.
     */
    RAMPART_ERR_NULL_PARAM = -1,

    /**
     * @brief Invalid size parameter
     *
     * Returned when size is 0 or exceeds the pool's capacity.
     */
    RAMPART_ERR_INVALID_SIZE = -2,

    /**
     * @brief Pool memory exhausted
     *
     * Returned when no free block large enough exists in the pool.
     */
    RAMPART_ERR_OUT_OF_MEMORY = -3,

    /**
     * @brief Block validation failed
     *
     * Returned when a pointer does not reference a valid allocated block.
     * This may indicate the pointer was never allocated, was already freed,
     * or memory corruption has occurred.
     */
    RAMPART_ERR_INVALID_BLOCK = -4,

    /**
     * @brief Guard band corruption detected
     *
     * Returned when front or rear guard bands have been overwritten.
     * This indicates a buffer overflow or underflow has occurred.
     */
    RAMPART_ERR_GUARD_CORRUPTED = -5,

    /**
     * @brief Cross-thread access attempted
     *
     * Returned when a thread other than the allocating thread attempts
     * to access or free a memory block. Only occurs if strict_thread_mode
     * is enabled (the default).
     */
    RAMPART_ERR_WRONG_THREAD = -6,

    /**
     * @brief Block has already been freed
     *
     * Returned when rampart_free() is called on an already-freed block.
     */
    RAMPART_ERR_DOUBLE_FREE = -7,

    /**
     * @brief Pool not initialized
     *
     * Returned when operations are attempted on a NULL or invalid pool.
     */
    RAMPART_ERR_NOT_INITIALIZED = -8,

    /**
     * @brief Invalid configuration
     *
     * Returned from rampart_init() when configuration values are invalid.
     */
    RAMPART_ERR_INVALID_CONFIG = -9,

    /**
     * @brief Internal error
     *
     * Returned when an unexpected internal condition occurs.
     * This should not happen in normal operation.
     */
    RAMPART_ERR_INTERNAL = -10
} rampart_error_t;

/* ============================================================================
 * Opaque Types
 * ============================================================================ */

/**
 * @struct rampart_pool_t
 * @brief Opaque pool handle
 *
 * Represents a RAMpart memory pool. The internal structure is hidden
 * from library users. Obtain a handle via rampart_init() and release
 * it via rampart_shutdown().
 *
 * Multiple pools may exist simultaneously. Each pool has independent
 * memory, configuration, and thread safety.
 */
typedef struct rampart_pool_s rampart_pool_t;

/* ============================================================================
 * Callback Types
 * ============================================================================ */

/**
 * @typedef rampart_error_callback_t
 * @brief Callback function for error notification
 *
 * Called when security-relevant errors occur, such as guard band
 * corruption or cross-thread access attempts. The callback is invoked
 * with the pool mutex released to prevent deadlocks.
 *
 * @param pool      The pool where the error occurred
 * @param error     The error code
 * @param block     Pointer to the affected block (may be NULL)
 * @param user_data User-provided context pointer
 *
 * @note Callbacks must not call RAMpart functions on the same pool
 *       to avoid potential reentrancy issues.
 */
typedef void (*rampart_error_callback_t)(
    rampart_pool_t *pool,
    rampart_error_t error,
    void *block,
    void *user_data
);

/* ============================================================================
 * Configuration Structure
 * ============================================================================ */

/**
 * @struct rampart_config_t
 * @brief Pool configuration options
 *
 * Passed to rampart_init() to configure pool behavior. Use
 * rampart_config_default() to initialize with default values,
 * then modify as needed.
 *
 * @code
 * rampart_config_t config;
 * rampart_config_default(&config);
 * config.pool_size = 10 * 1024 * 1024;
 * config.encryption_enabled = 1;
 * @endcode
 */
typedef struct rampart_config_s {
    /**
     * @brief Total pool size in bytes
     *
     * Must be at least RAMPART_MIN_POOL_SIZE. Larger pools can
     * service more allocations but consume more memory.
     *
     * @note Some memory is consumed by pool overhead and block
     *       metadata. Effective usable memory is approximately
     *       pool_size - 512 bytes - (96 bytes per allocation).
     */
    size_t pool_size;

    /**
     * @brief Enable encryption of data at rest
     *
     * When set to non-zero, user data in allocated blocks is encrypted
     * using the configured encryption key. Data is decrypted when
     * accessed through RAMpart accessor functions.
     *
     * Default: 0 (disabled)
     */
    int encryption_enabled;

    /**
     * @brief Encryption key data
     *
     * Pointer to the encryption key. Must be non-NULL if
     * encryption_enabled is set. The key is copied during
     * rampart_init(); the original may be freed afterward.
     *
     * Recommended key size: 16 bytes (128 bits).
     *
     * Default: NULL
     */
    const unsigned char *encryption_key;

    /**
     * @brief Encryption key size in bytes
     *
     * Must be between 1 and RAMPART_MAX_KEY_SIZE if encryption
     * is enabled. Recommended: 16 bytes.
     *
     * Default: 0
     */
    size_t encryption_key_size;

    /**
     * @brief Enforce thread ownership
     *
     * When set to non-zero, only the thread that allocated a block
     * may free it or access it through accessor functions. Attempts
     * from other threads result in RAMPART_ERR_WRONG_THREAD.
     *
     * Default: 1 (enabled)
     */
    int strict_thread_mode;

    /**
     * @brief Validate guard bands on free
     *
     * When set to non-zero, rampart_free() validates guard bands
     * before freeing. If corruption is detected, the free fails
     * and the error callback is invoked.
     *
     * Default: 1 (enabled)
     */
    int validate_on_free;

    /**
     * @brief Error callback function
     *
     * Called when security-relevant errors occur. May be NULL
     * to disable callbacks.
     *
     * Default: NULL
     */
    rampart_error_callback_t error_callback;

    /**
     * @brief User data for error callback
     *
     * Passed as the user_data parameter to the error callback.
     *
     * Default: NULL
     */
    void *callback_user_data;
} rampart_config_t;

/* ============================================================================
 * Statistics Structure
 * ============================================================================ */

/**
 * @struct rampart_stats_t
 * @brief Pool statistics
 *
 * Contains current state and metrics for a pool. Obtain via
 * rampart_get_stats().
 */
typedef struct rampart_stats_s {
    /**
     * @brief Total pool size in bytes
     *
     * Same as the pool_size configuration value.
     */
    size_t total_size;

    /**
     * @brief Bytes currently in use by allocations
     *
     * Includes block overhead (headers, guards).
     */
    size_t used_size;

    /**
     * @brief Bytes available for new allocations
     */
    size_t free_size;

    /**
     * @brief Bytes consumed by RAMpart overhead
     *
     * Pool header plus per-block metadata and guards.
     */
    size_t overhead_size;

    /**
     * @brief Number of active allocations
     *
     * Blocks currently allocated and not freed.
     */
    size_t allocation_count;

    /**
     * @brief Number of free blocks
     *
     * Blocks available in the free list.
     */
    size_t free_block_count;

    /**
     * @brief Size of largest free block
     *
     * Maximum allocation size currently possible.
     */
    size_t largest_free_block;

    /**
     * @brief Fragmentation percentage (0-100)
     *
     * Calculated as: 100 * (1 - largest_free_block / free_size)
     * Higher values indicate more fragmentation.
     */
    double fragmentation_percent;
} rampart_stats_t;

/* ============================================================================
 * Block Information Structure
 * ============================================================================ */

/**
 * @struct rampart_block_info_t
 * @brief Information about an allocated block
 *
 * Contains metadata about a specific allocation. Obtain via
 * rampart_get_block_info().
 */
typedef struct rampart_block_info_s {
    /**
     * @brief User-requested allocation size
     */
    size_t user_size;

    /**
     * @brief Total block size including overhead
     */
    size_t total_size;

    /**
     * @brief Thread ID of the allocating thread
     *
     * Platform-dependent type stored as unsigned long.
     */
    unsigned long owner_thread;

    /**
     * @brief Non-zero if block data is encrypted
     */
    int is_encrypted;

    /**
     * @brief Non-zero if front guard band is intact
     */
    int front_guard_valid;

    /**
     * @brief Non-zero if rear guard band is intact
     */
    int rear_guard_valid;
} rampart_block_info_t;

/* ============================================================================
 * Shutdown Result Structure
 * ============================================================================ */

/**
 * @struct rampart_shutdown_result_t
 * @brief Results from pool shutdown
 *
 * Returned by rampart_shutdown() to report leak information.
 */
typedef struct rampart_shutdown_result_s {
    /**
     * @brief Number of blocks not freed before shutdown
     */
    size_t leaked_blocks;

    /**
     * @brief Total bytes in leaked blocks
     */
    size_t leaked_bytes;
} rampart_shutdown_result_t;

/* ============================================================================
 * Leak Information Structure
 * ============================================================================ */

/**
 * @struct rampart_leak_info_t
 * @brief Information about a leaked block
 *
 * Used by rampart_get_leaks() to report unfree blocks.
 */
typedef struct rampart_leak_info_s {
    /**
     * @brief Address of the leaked block
     */
    void *address;

    /**
     * @brief Size of the leaked block (user size)
     */
    size_t size;

    /**
     * @brief Thread ID that allocated the block
     */
    unsigned long thread_id;
} rampart_leak_info_t;

/* ============================================================================
 * Validation Result Structure
 * ============================================================================ */

/**
 * @struct rampart_validation_result_t
 * @brief Results from pool-wide validation
 *
 * Returned by rampart_validate_pool().
 */
typedef struct rampart_validation_result_s {
    /**
     * @brief Total blocks checked
     */
    size_t checked_count;

    /**
     * @brief Number of corrupted blocks found
     */
    size_t corrupted_count;
} rampart_validation_result_t;

/* ============================================================================
 * Initialization and Shutdown Functions
 * ============================================================================ */

/**
 * rampart_config_default - Initialize configuration with defaults
 *
 * Populates the configuration structure with default values. Call this
 * before modifying specific fields to ensure all fields are initialized.
 *
 * Default values:
 * - pool_size: 0 (must be set before calling rampart_init)
 * - encryption_enabled: 0 (disabled)
 * - encryption_key: NULL
 * - encryption_key_size: 0
 * - strict_thread_mode: 1 (enabled)
 * - validate_on_free: 1 (enabled)
 * - error_callback: NULL
 * - callback_user_data: NULL
 *
 * @param config    Pointer to configuration structure to initialize
 *
 * @return RAMPART_OK on success, RAMPART_ERR_NULL_PARAM if config is NULL
 *
 * @note This function does not allocate memory.
 *
 * @see rampart_init
 */
rampart_error_t rampart_config_default(rampart_config_t *config);

/**
 * rampart_init - Create and initialize a memory pool
 *
 * Allocates and initializes a new memory pool according to the provided
 * configuration. The pool is ready for allocations upon successful return.
 *
 * The pool's memory is allocated from the system heap. The entire pool_size
 * is allocated upfront; no additional system allocations occur during
 * rampart_alloc() or rampart_free() operations.
 *
 * @param config    Pointer to configuration structure
 *
 * @return Pointer to initialized pool on success, NULL on failure
 *
 * @retval NULL     Initialization failed. Call rampart_get_last_error(NULL)
 *                  for details. Possible errors:
 *                  - RAMPART_ERR_NULL_PARAM: config is NULL
 *                  - RAMPART_ERR_INVALID_CONFIG: invalid configuration values
 *                  - RAMPART_ERR_OUT_OF_MEMORY: system allocation failed
 *
 * @note The returned pool must be released with rampart_shutdown().
 * @note Thread-safe: multiple pools may be created from different threads.
 *
 * @see rampart_shutdown
 * @see rampart_config_default
 */
rampart_pool_t *rampart_init(const rampart_config_t *config);

/**
 * rampart_shutdown - Destroy a memory pool
 *
 * Releases all resources associated with the pool. Any blocks still
 * allocated are reported as leaks. All memory is securely wiped before
 * release.
 *
 * After this call, the pool pointer is invalid and must not be used.
 *
 * @param pool      Pointer to pool to shut down
 *
 * @return Structure containing leak information
 *
 * @note If pool is NULL, returns a zeroed result structure.
 * @note All remaining allocations are securely wiped before release.
 * @note Thread-safe with respect to other pools, but the pool being
 *       shut down must not be in use by other threads.
 *
 * @see rampart_init
 * @see rampart_get_leaks
 */
rampart_shutdown_result_t rampart_shutdown(rampart_pool_t *pool);

/* ============================================================================
 * Allocation Functions
 * ============================================================================ */

/**
 * rampart_alloc - Allocate memory from the pool
 *
 * Allocates a block of memory from the managed pool. The returned memory
 * is zero-initialized (all bytes set to 0x00), protected by guard bands,
 * and owned by the calling thread.
 *
 * Uses worst-fit allocation: selects the largest available free block
 * and splits off the remainder.
 *
 * If encryption is enabled in the pool configuration, data written to
 * the block will be encrypted at rest.
 *
 * @param pool      Pointer to an initialized pool
 * @param size      Number of bytes to allocate (must be > 0)
 *
 * @return Pointer to zero-initialized memory on success, NULL on failure
 *
 * @retval NULL     Allocation failed. Call rampart_get_last_error(pool)
 *                  for details. Possible errors:
 *                  - RAMPART_ERR_NULL_PARAM: pool is NULL
 *                  - RAMPART_ERR_INVALID_SIZE: size is 0 or too large
 *                  - RAMPART_ERR_OUT_OF_MEMORY: insufficient free space
 *                  - RAMPART_ERR_NOT_INITIALIZED: pool is invalid
 *
 * @note Thread-safe. Multiple threads may allocate from the same pool.
 * @note Memory is always zero-initialized before returning.
 * @note Only the calling thread may free this block (if strict_thread_mode).
 *
 * @see rampart_free
 * @see rampart_calloc
 */
void *rampart_alloc(rampart_pool_t *pool, size_t size);

/**
 * rampart_calloc - Allocate zero-initialized array from the pool
 *
 * Allocates memory for an array of nmemb elements of elem_size bytes each.
 * Equivalent to rampart_alloc(pool, nmemb * elem_size) with overflow checking.
 *
 * Since rampart_alloc() already zero-initializes memory, this function
 * is provided for API compatibility with standard calloc().
 *
 * @param pool      Pointer to an initialized pool
 * @param nmemb     Number of elements
 * @param elem_size Size of each element in bytes
 *
 * @return Pointer to zero-initialized memory on success, NULL on failure
 *
 * @retval NULL     Allocation failed. Possible errors same as rampart_alloc,
 *                  plus RAMPART_ERR_INVALID_SIZE if nmemb * elem_size overflows.
 *
 * @note Thread-safe.
 * @note Checks for size_t overflow when computing total size.
 *
 * @see rampart_alloc
 * @see rampart_free
 */
void *rampart_calloc(rampart_pool_t *pool, size_t nmemb, size_t elem_size);

/**
 * rampart_free - Free allocated memory back to the pool
 *
 * Returns a previously allocated block to the pool's free list. The block
 * is securely wiped before being made available for reuse.
 *
 * If validate_on_free is enabled (default), guard bands are checked before
 * freeing. If corruption is detected, the free fails and the error callback
 * is invoked.
 *
 * If strict_thread_mode is enabled (default), only the thread that allocated
 * the block may free it.
 *
 * @param pool      Pointer to the pool the block was allocated from
 * @param ptr       Pointer to memory to free (as returned by rampart_alloc)
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_OK                   Block freed successfully
 * @retval RAMPART_ERR_NULL_PARAM       pool or ptr is NULL
 * @retval RAMPART_ERR_INVALID_BLOCK    ptr is not a valid allocation
 * @retval RAMPART_ERR_GUARD_CORRUPTED  Buffer overflow/underflow detected
 * @retval RAMPART_ERR_WRONG_THREAD     Called from non-owning thread
 * @retval RAMPART_ERR_DOUBLE_FREE      Block was already freed
 *
 * @note Thread-safe if called from the owning thread.
 * @note Memory is securely wiped (multi-pass) before returning to free list.
 * @note Adjacent free blocks are coalesced to reduce fragmentation.
 *
 * @see rampart_alloc
 * @see rampart_validate
 */
rampart_error_t rampart_free(rampart_pool_t *pool, void *ptr);

/* ============================================================================
 * Validation Functions
 * ============================================================================ */

/**
 * rampart_validate - Validate a single block's guard bands
 *
 * Checks that the front and rear guard bands of the specified block
 * have not been overwritten. This can detect buffer overflows and
 * underflows that occurred since allocation.
 *
 * @param pool      Pointer to the pool the block was allocated from
 * @param ptr       Pointer to block to validate
 *
 * @return RAMPART_OK if guards are intact, error code otherwise
 *
 * @retval RAMPART_OK                   Guards are intact
 * @retval RAMPART_ERR_NULL_PARAM       pool or ptr is NULL
 * @retval RAMPART_ERR_INVALID_BLOCK    ptr is not a valid allocation
 * @retval RAMPART_ERR_GUARD_CORRUPTED  Corruption detected
 *
 * @note Thread-safe.
 * @note Does not check thread ownership for validation.
 *
 * @see rampart_validate_pool
 */
rampart_error_t rampart_validate(rampart_pool_t *pool, void *ptr);

/**
 * rampart_validate_pool - Validate all allocated blocks in a pool
 *
 * Checks guard bands on every currently allocated block. This is useful
 * for periodic integrity checks in debug builds.
 *
 * @param pool      Pointer to the pool to validate
 * @param result    Pointer to structure to receive results
 *
 * @return RAMPART_OK on success (even if corruption found), error code on
 *         invalid parameters
 *
 * @retval RAMPART_OK               Validation completed (check result)
 * @retval RAMPART_ERR_NULL_PARAM   pool or result is NULL
 *
 * @note Thread-safe. Acquires pool mutex during validation.
 * @note Error callback is invoked for each corrupted block found.
 *
 * @see rampart_validate
 */
rampart_error_t rampart_validate_pool(rampart_pool_t *pool,
                                       rampart_validation_result_t *result);

/* ============================================================================
 * Statistics and Information Functions
 * ============================================================================ */

/**
 * rampart_get_stats - Get pool statistics
 *
 * Retrieves current statistics about pool usage, including allocation
 * counts, memory usage, and fragmentation.
 *
 * @param pool      Pointer to the pool
 * @param stats     Pointer to structure to receive statistics
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_OK               Statistics retrieved successfully
 * @retval RAMPART_ERR_NULL_PARAM   pool or stats is NULL
 *
 * @note Thread-safe. Statistics represent a consistent snapshot.
 *
 * @see rampart_stats_t
 */
rampart_error_t rampart_get_stats(rampart_pool_t *pool, rampart_stats_t *stats);

/**
 * rampart_get_block_info - Get information about an allocated block
 *
 * Retrieves metadata about a specific allocation, including size,
 * ownership, and guard band status.
 *
 * @param pool      Pointer to the pool
 * @param ptr       Pointer to the allocated block
 * @param info      Pointer to structure to receive information
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_OK               Information retrieved successfully
 * @retval RAMPART_ERR_NULL_PARAM   pool, ptr, or info is NULL
 * @retval RAMPART_ERR_INVALID_BLOCK    ptr is not a valid allocation
 *
 * @note Thread-safe.
 *
 * @see rampart_block_info_t
 */
rampart_error_t rampart_get_block_info(rampart_pool_t *pool,
                                        void *ptr,
                                        rampart_block_info_t *info);

/**
 * rampart_get_leaks - Get information about allocated (leaked) blocks
 *
 * Returns an array of information about all currently allocated blocks.
 * Primarily useful before shutdown to identify memory leaks.
 *
 * The returned array must be freed with rampart_free_leak_info().
 *
 * @param pool          Pointer to the pool
 * @param leaks         Pointer to receive array of leak information
 * @param leak_count    Pointer to receive number of entries in array
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_OK               Leaks retrieved (may be empty)
 * @retval RAMPART_ERR_NULL_PARAM   Any parameter is NULL
 * @retval RAMPART_ERR_OUT_OF_MEMORY    Failed to allocate result array
 *
 * @note Thread-safe.
 * @note If there are no leaks, *leaks is set to NULL and *leak_count to 0.
 *
 * @see rampart_free_leak_info
 * @see rampart_leak_info_t
 */
rampart_error_t rampart_get_leaks(rampart_pool_t *pool,
                                   rampart_leak_info_t **leaks,
                                   size_t *leak_count);

/**
 * rampart_free_leak_info - Free leak information array
 *
 * Releases memory allocated by rampart_get_leaks().
 *
 * @param leaks     Pointer to array returned by rampart_get_leaks()
 *
 * @note Safe to call with NULL pointer.
 * @note Uses system free(), not pool allocation.
 *
 * @see rampart_get_leaks
 */
void rampart_free_leak_info(rampart_leak_info_t *leaks);

/* ============================================================================
 * Error Handling Functions
 * ============================================================================ */

/**
 * rampart_get_last_error - Get last error for a pool
 *
 * Returns the most recent error code for the specified pool. If pool
 * is NULL, returns the most recent global error (from rampart_init).
 *
 * @param pool      Pointer to pool, or NULL for global errors
 *
 * @return Most recent error code
 *
 * @note Thread-specific: each thread has its own last error.
 * @note Error is cleared after being read.
 *
 * @see rampart_error_string
 */
rampart_error_t rampart_get_last_error(rampart_pool_t *pool);

/**
 * rampart_error_string - Get human-readable error description
 *
 * Returns a static string describing the error code. The returned
 * string should not be modified or freed.
 *
 * @param error     Error code to describe
 *
 * @return Pointer to static string describing the error
 *
 * @note Thread-safe. Returns pointer to static data.
 * @note Unknown error codes return "Unknown error".
 *
 * @see rampart_get_last_error
 */
const char *rampart_error_string(rampart_error_t error);

/**
 * rampart_set_error_callback - Set or change error callback
 *
 * Registers a callback function to be invoked when security-relevant
 * errors occur. Replaces any previously registered callback.
 *
 * @param pool          Pointer to the pool
 * @param callback      Callback function, or NULL to disable
 * @param user_data     User data passed to callback
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_OK               Callback set successfully
 * @retval RAMPART_ERR_NULL_PARAM   pool is NULL
 *
 * @note Thread-safe.
 * @note Callback is invoked with pool mutex released.
 *
 * @see rampart_error_callback_t
 */
rampart_error_t rampart_set_error_callback(rampart_pool_t *pool,
                                            rampart_error_callback_t callback,
                                            void *user_data);

/* ============================================================================
 * Version Functions
 * ============================================================================ */

/**
 * rampart_version - Get library version
 *
 * Returns the library version as a packed integer:
 * (major * 10000) + (minor * 100) + patch
 *
 * For example, version 1.2.3 returns 10203.
 *
 * @return Packed version number
 *
 * @note Thread-safe.
 *
 * @see rampart_version_string
 */
int rampart_version(void);

/**
 * rampart_version_string - Get library version as string
 *
 * Returns the library version as a human-readable string
 * in the format "major.minor.patch".
 *
 * @return Pointer to static version string
 *
 * @note Thread-safe. Returns pointer to static data.
 *
 * @see rampart_version
 */
const char *rampart_version_string(void);

#ifdef __cplusplus
}
#endif

#endif /* RAMPART_H */
