/**
 * @file rampart.c
 * @brief RAMpart public API implementation
 *
 * Implements the public-facing API for the RAMpart secure memory pool.
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

#include "rampart.h"
#include "internal/rp_types.h"
#include "internal/rp_pool.h"
#include "internal/rp_block.h"
#include "internal/rp_thread.h"
#include "internal/rp_wipe.h"
#include "internal/rp_crypto.h"
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Pool Validation (VULN-019 fix)
 * ============================================================================ */

/**
 * validate_pool - Verify pool handle is valid before use
 *
 * Checks that the pool pointer is non-NULL and contains the correct
 * magic number. This prevents use of garbage/corrupted pool handles.
 *
 * IMPORTANT: This check must happen BEFORE any pool fields are accessed
 * (including the mutex lock), otherwise we may crash or be exploited.
 *
 * @param pool  Pool handle to validate
 *
 * @return 1 if valid, 0 if invalid
 */
static int validate_pool(rampart_pool_t *pool) {
    rp_pool_header_t *p;

    if (pool == NULL) {
        return 0;
    }

    p = (rp_pool_header_t *)pool;

    if (p->pool_magic != RP_POOL_MAGIC) {
        return 0;
    }

    return 1;
}

/* ============================================================================
 * Error Strings
 * ============================================================================ */

static const char *ERROR_STRINGS[] = {
    "Success",                              /* RAMPART_OK = 0 */
    "NULL parameter",                       /* RAMPART_ERR_NULL_PARAM = -1 */
    "Invalid size",                         /* RAMPART_ERR_INVALID_SIZE = -2 */
    "Out of memory",                        /* RAMPART_ERR_OUT_OF_MEMORY = -3 */
    "Invalid block",                        /* RAMPART_ERR_INVALID_BLOCK = -4 */
    "Guard band corrupted",                 /* RAMPART_ERR_GUARD_CORRUPTED = -5 */
    "Wrong thread",                         /* RAMPART_ERR_WRONG_THREAD = -6 */
    "Double free",                          /* RAMPART_ERR_DOUBLE_FREE = -7 */
    "Pool not initialized",                 /* RAMPART_ERR_NOT_INITIALIZED = -8 */
    "Invalid configuration",                /* RAMPART_ERR_INVALID_CONFIG = -9 */
    "Internal error",                       /* RAMPART_ERR_INTERNAL = -10 */
    "Block is parked",                      /* RAMPART_ERR_BLOCK_PARKED = -11 */
    "Block is not parked",                  /* RAMPART_ERR_NOT_PARKED = -12 */
    "Parking not enabled"                   /* RAMPART_ERR_PARKING_DISABLED = -13 */
};

#define NUM_ERROR_STRINGS (sizeof(ERROR_STRINGS) / sizeof(ERROR_STRINGS[0]))

/* ============================================================================
 * Helper: Invoke Error Callback
 * ============================================================================ */

/**
 * invoke_callback - Invoke error callback with reentrancy protection
 *
 * IMPORTANT (VULN-011 fix): The pool mutex remains LOCKED during callback
 * invocation to prevent reentrancy attacks. If a callback attempts to call
 * any RAMpart function on the same pool, it will deadlock.
 *
 * Callback implementations MUST NOT call rampart_alloc, rampart_free,
 * rampart_realloc, rampart_validate, or any other RAMpart function on the
 * pool that triggered the callback. Violation will cause deadlock.
 *
 * Safe callback operations:
 * - Logging the error
 * - Setting flags for later handling
 * - Signaling other threads
 * - Operations on OTHER pools (not the one that triggered callback)
 */
static void invoke_callback(rp_pool_header_t *pool,
                             rampart_error_t error,
                             void *block) {
    rampart_error_callback_t callback;
    void *user_data;

    if (pool == NULL) {
        return;
    }

    callback = pool->error_callback;
    user_data = pool->callback_user_data;

    if (callback != NULL) {
        /*
         * VULN-011 fix: Mutex stays locked during callback.
         * This prevents reentrancy attacks where malicious callbacks
         * call rampart_alloc/free to corrupt pool state.
         *
         * Consequence: callbacks cannot call RAMpart on this pool
         * (will deadlock). This is intentional and documented.
         */
        callback((rampart_pool_t *)pool, error, block, user_data);
    }
}

/* ============================================================================
 * Version Functions
 * ============================================================================ */

int rampart_version(void) {
    return (RAMPART_VERSION_MAJOR * 10000) +
           (RAMPART_VERSION_MINOR * 100) +
           RAMPART_VERSION_PATCH;
}

const char *rampart_version_string(void) {
    return RAMPART_VERSION_STRING;
}

/* ============================================================================
 * Error Handling Functions
 * ============================================================================ */

rampart_error_t rampart_get_last_error(rampart_pool_t *pool) {
    (void)pool;  /* Pool-specific errors not yet implemented */
    return rp_thread_get_last_error();
}

const char *rampart_error_string(rampart_error_t error) {
    int index;

    if (error == RAMPART_OK) {
        return ERROR_STRINGS[0];
    }

    /* Convert negative error to positive index */
    index = -(int)error;

    if (index < 1 || index >= (int)NUM_ERROR_STRINGS) {
        return "Unknown error";
    }

    return ERROR_STRINGS[index];
}

rampart_error_t rampart_set_error_callback(rampart_pool_t *pool,
                                            rampart_error_callback_t callback,
                                            void *user_data) {
    rp_pool_header_t *p;

    /* VULN-019 fix: Validate pool before accessing any fields */
    if (!validate_pool(pool)) {
        return RAMPART_ERR_NOT_INITIALIZED;
    }

    p = (rp_pool_header_t *)pool;

    rp_pool_lock(p);
    p->error_callback = callback;
    p->callback_user_data = user_data;
    rp_pool_unlock(p);

    return RAMPART_OK;
}

/* ============================================================================
 * Configuration Functions
 * ============================================================================ */

rampart_error_t rampart_config_default(rampart_config_t *config) {
    if (config == NULL) {
        rp_thread_set_last_error(RAMPART_ERR_NULL_PARAM);
        return RAMPART_ERR_NULL_PARAM;
    }

    memset(config, 0, sizeof(rampart_config_t));

    config->pool_size = 0;
    config->strict_thread_mode = 1;
    config->validate_on_free = 1;
    config->error_callback = NULL;
    config->callback_user_data = NULL;
    config->enable_parking = 0;
    config->parking_key = NULL;
    config->parking_key_len = 0;

    return RAMPART_OK;
}

/* ============================================================================
 * Pool Initialization and Shutdown
 * ============================================================================ */

rampart_pool_t *rampart_init(const rampart_config_t *config) {
    void *pool_memory;
    rp_pool_header_t *pool;

    if (config == NULL) {
        rp_thread_set_last_error(RAMPART_ERR_NULL_PARAM);
        return NULL;
    }

    /* Validate configuration */
    if (config->pool_size < RAMPART_MIN_POOL_SIZE) {
        rp_thread_set_last_error(RAMPART_ERR_INVALID_CONFIG);
        return NULL;
    }

    /* Allocate pool memory from system */
    pool_memory = malloc(config->pool_size);
    if (pool_memory == NULL) {
        rp_thread_set_last_error(RAMPART_ERR_OUT_OF_MEMORY);
        return NULL;
    }

    /* Zero the memory */
    memset(pool_memory, 0, config->pool_size);

    /* Initialize pool internals */
    pool = rp_pool_init(pool_memory, config->pool_size, config);
    if (pool == NULL) {
        free(pool_memory);
        rp_thread_set_last_error(RAMPART_ERR_INTERNAL);
        return NULL;
    }

    return (rampart_pool_t *)pool;
}

rampart_shutdown_result_t rampart_shutdown(rampart_pool_t *pool) {
    rampart_shutdown_result_t result;
    rp_pool_header_t *p;
    rp_block_header_t *current;
    void *pool_memory;

    memset(&result, 0, sizeof(result));

    /* VULN-019 fix: Validate pool before accessing any fields */
    if (!validate_pool(pool)) {
        return result;
    }

    p = (rp_pool_header_t *)pool;
    pool_memory = p;

    /* Count leaked blocks */
    rp_pool_lock(p);

    current = p->alloc_list;
    while (current != NULL) {
        result.leaked_blocks++;
        result.leaked_bytes += current->user_size;

        /* VULN-022 fix: Wipe leaked block data AND guard bands */
        rp_wipe_block_user_and_guards(current);

        current = current->next;
    }

    rp_pool_unlock(p);

    /* Destroy pool (wipes all memory) */
    rp_pool_destroy(p);

    /* Free system memory */
    free(pool_memory);

    return result;
}

/* ============================================================================
 * Allocation Functions
 * ============================================================================ */

void *rampart_alloc(rampart_pool_t *pool, size_t size) {
    rp_pool_header_t *p;
    rp_block_header_t *block;
    rampart_error_t err;
    void *user_ptr;

    /* VULN-019 fix: Validate pool before accessing any fields */
    if (!validate_pool(pool)) {
        rp_thread_set_last_error(RAMPART_ERR_NOT_INITIALIZED);
        return NULL;
    }

    if (size == 0) {
        rp_thread_set_last_error(RAMPART_ERR_INVALID_SIZE);
        return NULL;
    }

    p = (rp_pool_header_t *)pool;

    rp_pool_lock(p);

    /* Allocate block */
    err = rp_pool_alloc(p, size, &block);
    if (err != RAMPART_OK) {
        rp_pool_unlock(p);
        rp_thread_set_last_error(err);
        return NULL;
    }

    /* Initialize guard bands with pool-specific patterns */
    rp_block_init_guards(p, block);

    /* Set owner canary (VULN-005 fix) */
    rp_block_set_canary(p, block);

    /* Zero-initialize user data */
    rp_block_zero_user_data(block);

    user_ptr = rp_block_get_user_ptr(block);

    rp_pool_unlock(p);

    return user_ptr;
}

void *rampart_calloc(rampart_pool_t *pool, size_t nmemb, size_t elem_size) {
    size_t total_size;

    /* VULN-019 fix: Validate pool before accessing any fields */
    if (!validate_pool(pool)) {
        rp_thread_set_last_error(RAMPART_ERR_NOT_INITIALIZED);
        return NULL;
    }

    /* Check for overflow */
    if (nmemb != 0 && elem_size > (size_t)-1 / nmemb) {
        rp_thread_set_last_error(RAMPART_ERR_INVALID_SIZE);
        return NULL;
    }

    total_size = nmemb * elem_size;

    /* rampart_alloc already zero-initializes */
    return rampart_alloc(pool, total_size);
}

/* ============================================================================
 * Deallocation Functions
 * ============================================================================ */

rampart_error_t rampart_free(rampart_pool_t *pool, void *ptr) {
    rp_pool_header_t *p;
    rp_block_header_t *block;
    rampart_error_t err;

    if (ptr == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    /* VULN-019 fix: Validate pool before accessing any fields */
    if (!validate_pool(pool)) {
        return RAMPART_ERR_NOT_INITIALIZED;
    }

    p = (rp_pool_header_t *)pool;

    rp_pool_lock(p);

    /* Get block header with bounds validation */
    block = rp_block_from_user_ptr_safe(p, ptr);
    if (block == NULL) {
        invoke_callback(p, RAMPART_ERR_INVALID_BLOCK, ptr);
        rp_pool_unlock(p);
        return RAMPART_ERR_INVALID_BLOCK;
    }

    /* Validate block */
    err = rp_block_validate_magic(block);
    if (err != RAMPART_OK) {
        if (block->magic == RP_BLOCK_FREED_MAGIC) {
            invoke_callback(p, RAMPART_ERR_DOUBLE_FREE, ptr);
            rp_pool_unlock(p);
            return RAMPART_ERR_DOUBLE_FREE;
        }
        invoke_callback(p, RAMPART_ERR_INVALID_BLOCK, ptr);
        rp_pool_unlock(p);
        return RAMPART_ERR_INVALID_BLOCK;
    }

    /* Verify owner canary before trusting owner_thread (VULN-005 fix) */
    if (p->strict_thread_mode) {
        err = rp_block_verify_canary(p, block);
        if (err != RAMPART_OK) {
            invoke_callback(p, RAMPART_ERR_INVALID_BLOCK, ptr);
            rp_pool_unlock(p);
            return RAMPART_ERR_INVALID_BLOCK;
        }

        /* Check thread ownership */
        err = rp_thread_verify_owner(block);
        if (err != RAMPART_OK) {
            invoke_callback(p, RAMPART_ERR_WRONG_THREAD, ptr);
            rp_pool_unlock(p);
            return RAMPART_ERR_WRONG_THREAD;
        }
    }

    /* Check if block is parked (encrypted). Must unpark before freeing. */
    if (block->flags & RP_FLAG_PARKED) {
        invoke_callback(p, RAMPART_ERR_BLOCK_PARKED, ptr);
        rp_pool_unlock(p);
        return RAMPART_ERR_BLOCK_PARKED;
    }

    /*
     * Always validate guard bands on free (VULN-013 fix).
     *
     * Previously this was optional via validate_on_free config, but allowing
     * corrupted blocks to be freed silently defeats the purpose of guard bands.
     * Validation is now mandatory for security. The config field is retained
     * for API compatibility but is ignored.
     */
    err = rp_block_validate_guards(p, block);
    if (err != RAMPART_OK) {
        invoke_callback(p, RAMPART_ERR_GUARD_CORRUPTED, ptr);
        rp_pool_unlock(p);
        return RAMPART_ERR_GUARD_CORRUPTED;
    }

    /* VULN-022 fix: Securely wipe user data AND guard bands */
    rp_wipe_block_user_and_guards(block);

    /* Return block to pool */
    err = rp_pool_free(p, block);

    rp_pool_unlock(p);

    return err;
}

/* ============================================================================
 * Block Parking Functions (Encryption at Rest)
 * ============================================================================
 *
 * SECURITY NOTICE:
 *
 * Block parking encrypts data in RAM using ChaCha20 but provides LIMITED
 * protection against sophisticated attackers. The encryption key resides
 * in pool memory. Any attacker who can read your encrypted data can also
 * read your key.
 *
 * This feature protects against:
 * - Data leaking to swap (when combined with mlock)
 * - Data in core dumps (when combined with MADV_DONTDUMP)
 * - Casual memory inspection
 *
 * This feature does NOT protect against:
 * - Cold boot attacks
 * - DMA attacks
 * - Root-level attackers with memory read access
 * - Attackers who can read /proc/pid/mem or equivalent
 *
 * For genuine memory encryption, use hardware solutions (AMD SEV, Intel TME).
 */

rampart_error_t rampart_park(rampart_pool_t *pool, void *ptr) {
    rp_pool_header_t *p;
    rp_block_header_t *block;
    rp_chacha20_ctx_t ctx;
    unsigned char nonce[RP_CHACHA20_NONCE_SIZE];
    rampart_error_t err;
    void *user_ptr;

    if (ptr == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    /* VULN-019 fix: Validate pool before accessing any fields */
    if (!validate_pool(pool)) {
        return RAMPART_ERR_NOT_INITIALIZED;
    }

    p = (rp_pool_header_t *)pool;

    /* Check if parking is enabled */
    if (!p->parking_enabled) {
        return RAMPART_ERR_PARKING_DISABLED;
    }

    rp_pool_lock(p);

    /* Get block header with bounds validation */
    block = rp_block_from_user_ptr_safe(p, ptr);
    if (block == NULL) {
        invoke_callback(p, RAMPART_ERR_INVALID_BLOCK, ptr);
        rp_pool_unlock(p);
        return RAMPART_ERR_INVALID_BLOCK;
    }

    /* Validate block magic */
    err = rp_block_validate_magic(block);
    if (err != RAMPART_OK) {
        invoke_callback(p, RAMPART_ERR_INVALID_BLOCK, ptr);
        rp_pool_unlock(p);
        return RAMPART_ERR_INVALID_BLOCK;
    }

    /* Check if already parked */
    if (block->flags & RP_FLAG_PARKED) {
        rp_pool_unlock(p);
        return RAMPART_ERR_BLOCK_PARKED;
    }

    /* Verify thread ownership if strict mode enabled */
    if (p->strict_thread_mode) {
        err = rp_block_verify_canary(p, block);
        if (err != RAMPART_OK) {
            invoke_callback(p, RAMPART_ERR_INVALID_BLOCK, ptr);
            rp_pool_unlock(p);
            return RAMPART_ERR_INVALID_BLOCK;
        }

        err = rp_thread_verify_owner(block);
        if (err != RAMPART_OK) {
            invoke_callback(p, RAMPART_ERR_WRONG_THREAD, ptr);
            rp_pool_unlock(p);
            return RAMPART_ERR_WRONG_THREAD;
        }
    }

    /* Validate guard bands before parking */
    err = rp_block_validate_guards(p, block);
    if (err != RAMPART_OK) {
        invoke_callback(p, RAMPART_ERR_GUARD_CORRUPTED, ptr);
        rp_pool_unlock(p);
        return RAMPART_ERR_GUARD_CORRUPTED;
    }

    /* Increment generation counter for unique nonce */
    block->park_generation++;

    /* Generate nonce for this parking operation */
    err = rp_crypto_generate_block_nonce(p, block, block->park_generation,
                                          nonce);
    if (err != RAMPART_OK) {
        rp_pool_unlock(p);
        return err;
    }

    /* Initialize ChaCha20 context with pool key */
    ctx.initialized = 0;
    ctx.key[0] = p->parking_key[0];
    ctx.key[1] = p->parking_key[1];
    ctx.key[2] = p->parking_key[2];
    ctx.key[3] = p->parking_key[3];
    ctx.key[4] = p->parking_key[4];
    ctx.key[5] = p->parking_key[5];
    ctx.key[6] = p->parking_key[6];
    ctx.key[7] = p->parking_key[7];
    ctx.initialized = 1;

    /* Get user data pointer */
    user_ptr = rp_block_get_user_ptr(block);

    /* Encrypt user data in place (ChaCha20 XOR) */
    err = rp_chacha20_crypt(&ctx, nonce, RP_CHACHA20_NONCE_SIZE, 0,
                             (unsigned char *)user_ptr, block->user_size);

    /* Wipe context from stack */
    rp_chacha20_wipe(&ctx);
    rp_wipe_memory(nonce, sizeof(nonce));

    if (err != RAMPART_OK) {
        rp_pool_unlock(p);
        return err;
    }

    /* Mark block as parked */
    block->flags |= RP_FLAG_PARKED;
    p->parked_count++;

    rp_pool_unlock(p);

    return RAMPART_OK;
}

rampart_error_t rampart_unpark(rampart_pool_t *pool, void *ptr) {
    rp_pool_header_t *p;
    rp_block_header_t *block;
    rp_chacha20_ctx_t ctx;
    unsigned char nonce[RP_CHACHA20_NONCE_SIZE];
    rampart_error_t err;
    void *user_ptr;

    if (ptr == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    /* VULN-019 fix: Validate pool before accessing any fields */
    if (!validate_pool(pool)) {
        return RAMPART_ERR_NOT_INITIALIZED;
    }

    p = (rp_pool_header_t *)pool;

    /* Check if parking is enabled */
    if (!p->parking_enabled) {
        return RAMPART_ERR_PARKING_DISABLED;
    }

    rp_pool_lock(p);

    /* Get block header with bounds validation */
    block = rp_block_from_user_ptr_safe(p, ptr);
    if (block == NULL) {
        invoke_callback(p, RAMPART_ERR_INVALID_BLOCK, ptr);
        rp_pool_unlock(p);
        return RAMPART_ERR_INVALID_BLOCK;
    }

    /* Validate block magic */
    err = rp_block_validate_magic(block);
    if (err != RAMPART_OK) {
        invoke_callback(p, RAMPART_ERR_INVALID_BLOCK, ptr);
        rp_pool_unlock(p);
        return RAMPART_ERR_INVALID_BLOCK;
    }

    /* Check if block is actually parked */
    if (!(block->flags & RP_FLAG_PARKED)) {
        rp_pool_unlock(p);
        return RAMPART_ERR_NOT_PARKED;
    }

    /* Verify thread ownership if strict mode enabled */
    if (p->strict_thread_mode) {
        err = rp_block_verify_canary(p, block);
        if (err != RAMPART_OK) {
            invoke_callback(p, RAMPART_ERR_INVALID_BLOCK, ptr);
            rp_pool_unlock(p);
            return RAMPART_ERR_INVALID_BLOCK;
        }

        err = rp_thread_verify_owner(block);
        if (err != RAMPART_OK) {
            invoke_callback(p, RAMPART_ERR_WRONG_THREAD, ptr);
            rp_pool_unlock(p);
            return RAMPART_ERR_WRONG_THREAD;
        }
    }

    /* Generate the same nonce used for parking (uses stored generation) */
    err = rp_crypto_generate_block_nonce(p, block, block->park_generation,
                                          nonce);
    if (err != RAMPART_OK) {
        rp_pool_unlock(p);
        return err;
    }

    /* Initialize ChaCha20 context with pool key */
    ctx.initialized = 0;
    ctx.key[0] = p->parking_key[0];
    ctx.key[1] = p->parking_key[1];
    ctx.key[2] = p->parking_key[2];
    ctx.key[3] = p->parking_key[3];
    ctx.key[4] = p->parking_key[4];
    ctx.key[5] = p->parking_key[5];
    ctx.key[6] = p->parking_key[6];
    ctx.key[7] = p->parking_key[7];
    ctx.initialized = 1;

    /* Get user data pointer */
    user_ptr = rp_block_get_user_ptr(block);

    /* Decrypt user data in place (ChaCha20 XOR is symmetric) */
    err = rp_chacha20_crypt(&ctx, nonce, RP_CHACHA20_NONCE_SIZE, 0,
                             (unsigned char *)user_ptr, block->user_size);

    /* Wipe context from stack */
    rp_chacha20_wipe(&ctx);
    rp_wipe_memory(nonce, sizeof(nonce));

    if (err != RAMPART_OK) {
        rp_pool_unlock(p);
        return err;
    }

    /* Clear parked flag */
    block->flags &= (unsigned int)~RP_FLAG_PARKED;
    p->parked_count--;

    rp_pool_unlock(p);

    return RAMPART_OK;
}

int rampart_is_parked(rampart_pool_t *pool, void *ptr) {
    rp_pool_header_t *p;
    rp_block_header_t *block;
    rampart_error_t err;
    int result;

    if (ptr == NULL) {
        return 0;
    }

    /* VULN-019 fix: Validate pool before accessing any fields */
    if (!validate_pool(pool)) {
        return 0;
    }

    p = (rp_pool_header_t *)pool;

    rp_pool_lock(p);

    /* Get block header with bounds validation */
    block = rp_block_from_user_ptr_safe(p, ptr);
    if (block == NULL) {
        rp_pool_unlock(p);
        return 0;
    }

    /* Validate block magic */
    err = rp_block_validate_magic(block);
    if (err != RAMPART_OK) {
        rp_pool_unlock(p);
        return 0;
    }

    result = (block->flags & RP_FLAG_PARKED) ? 1 : 0;

    rp_pool_unlock(p);

    return result;
}

/* ============================================================================
 * Validation Functions
 * ============================================================================ */

rampart_error_t rampart_validate(rampart_pool_t *pool, void *ptr) {
    rp_pool_header_t *p;
    rp_block_header_t *block;
    rampart_error_t err;

    if (ptr == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    /* VULN-019 fix: Validate pool before accessing any fields */
    if (!validate_pool(pool)) {
        return RAMPART_ERR_NOT_INITIALIZED;
    }

    p = (rp_pool_header_t *)pool;

    rp_pool_lock(p);

    /* Get block header with bounds validation */
    block = rp_block_from_user_ptr_safe(p, ptr);
    if (block == NULL) {
        rp_pool_unlock(p);
        return RAMPART_ERR_INVALID_BLOCK;
    }

    err = rp_block_validate(p, block);

    rp_pool_unlock(p);

    return err;
}

rampart_error_t rampart_validate_pool(rampart_pool_t *pool,
                                       rampart_validation_result_t *result) {
    rp_pool_header_t *p;
    rp_block_header_t *current;
    rampart_error_t err;

    if (result == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    memset(result, 0, sizeof(rampart_validation_result_t));

    /* VULN-019 fix: Validate pool before accessing any fields */
    if (!validate_pool(pool)) {
        return RAMPART_ERR_NOT_INITIALIZED;
    }

    p = (rp_pool_header_t *)pool;

    rp_pool_lock(p);

    current = p->alloc_list;
    while (current != NULL) {
        result->checked_count++;

        err = rp_block_validate_guards(p, current);
        if (err != RAMPART_OK) {
            result->corrupted_count++;
            invoke_callback(p, err, rp_block_get_user_ptr(current));
        }

        current = current->next;
    }

    rp_pool_unlock(p);

    return RAMPART_OK;
}

/* ============================================================================
 * Statistics Functions
 * ============================================================================ */

rampart_error_t rampart_get_stats(rampart_pool_t *pool,
                                   rampart_stats_t *stats) {
    rp_pool_header_t *p;

    if (stats == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    memset(stats, 0, sizeof(rampart_stats_t));

    /* VULN-019 fix: Validate pool before accessing any fields */
    if (!validate_pool(pool)) {
        return RAMPART_ERR_NOT_INITIALIZED;
    }

    p = (rp_pool_header_t *)pool;

    rp_pool_lock(p);

    stats->total_size = p->total_size;
    stats->used_size = p->total_size - p->free_size;
    stats->free_size = p->free_size;
    stats->overhead_size = RP_POOL_HEADER_SIZE +
                           (p->allocation_count * RP_BLOCK_OVERHEAD);
    stats->allocation_count = p->allocation_count;
    stats->free_block_count = p->free_block_count;
    stats->largest_free_block = rp_pool_get_largest_free(p);
    stats->fragmentation_percent = rp_pool_calculate_fragmentation(p);

    rp_pool_unlock(p);

    return RAMPART_OK;
}

rampart_error_t rampart_get_block_info(rampart_pool_t *pool,
                                        void *ptr,
                                        rampart_block_info_t *info) {
    rp_pool_header_t *p;
    rp_block_header_t *block;
    rampart_error_t err;

    if (ptr == NULL || info == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    memset(info, 0, sizeof(rampart_block_info_t));

    /* VULN-019 fix: Validate pool before accessing any fields */
    if (!validate_pool(pool)) {
        return RAMPART_ERR_NOT_INITIALIZED;
    }

    p = (rp_pool_header_t *)pool;

    rp_pool_lock(p);

    /* Get block header with bounds validation */
    block = rp_block_from_user_ptr_safe(p, ptr);
    if (block == NULL) {
        rp_pool_unlock(p);
        return RAMPART_ERR_INVALID_BLOCK;
    }

    err = rp_block_validate_magic(block);
    if (err != RAMPART_OK) {
        rp_pool_unlock(p);
        return RAMPART_ERR_INVALID_BLOCK;
    }

    info->user_size = block->user_size;
    info->total_size = block->total_size;
    info->owner_thread = rp_thread_id_to_ulong(block->owner_thread);
    info->front_guard_valid =
        (rp_block_validate_front_guard(p, block) == RAMPART_OK);
    info->rear_guard_valid =
        (rp_block_validate_rear_guard(p, block) == RAMPART_OK);

    rp_pool_unlock(p);

    return RAMPART_OK;
}

/* ============================================================================
 * Leak Information Functions
 * ============================================================================
 *
 * VULN-020 fix: Leak info array now includes a hidden size header so that
 * rampart_free_leak_info() can securely wipe the sensitive data before freeing.
 * This prevents address, size, and thread ID information from persisting in
 * unprotected system heap memory.
 *
 * Memory layout:
 *   [size_t count][leak_info_t[0]][leak_info_t[1]]...
 *   ^              ^
 *   base           returned pointer
 */

rampart_error_t rampart_get_leaks(rampart_pool_t *pool,
                                   rampart_leak_info_t **leaks,
                                   size_t *leak_count) {
    rp_pool_header_t *p;
    rp_block_header_t *current;
    rampart_leak_info_t *leak_array;
    unsigned char *base;
    size_t alloc_size;
    size_t count;
    size_t i;

    if (leaks == NULL || leak_count == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    *leaks = NULL;
    *leak_count = 0;

    /* VULN-019 fix: Validate pool before accessing any fields */
    if (!validate_pool(pool)) {
        return RAMPART_ERR_NOT_INITIALIZED;
    }

    p = (rp_pool_header_t *)pool;

    rp_pool_lock(p);

    /* Count allocations */
    count = p->allocation_count;

    if (count == 0) {
        rp_pool_unlock(p);
        return RAMPART_OK;
    }

    /*
     * VULN-020 fix: Allocate with hidden header to store count.
     * This allows rampart_free_leak_info() to wipe the data before freeing.
     */
    alloc_size = sizeof(size_t) + (count * sizeof(rampart_leak_info_t));
    base = (unsigned char *)malloc(alloc_size);

    if (base == NULL) {
        rp_pool_unlock(p);
        return RAMPART_ERR_OUT_OF_MEMORY;
    }

    /* Store count in header */
    *((size_t *)base) = count;

    /* Leak array follows the count header */
    leak_array = (rampart_leak_info_t *)(base + sizeof(size_t));

    /* Fill array */
    i = 0;
    current = p->alloc_list;
    while (current != NULL && i < count) {
        leak_array[i].address = rp_block_get_user_ptr(current);
        leak_array[i].size = current->user_size;
        leak_array[i].thread_id = rp_thread_id_to_ulong(current->owner_thread);
        i++;
        current = current->next;
    }

    rp_pool_unlock(p);

    *leaks = leak_array;
    *leak_count = i;

    return RAMPART_OK;
}

void rampart_free_leak_info(rampart_leak_info_t *leaks) {
    unsigned char *base;
    size_t count;
    size_t total_size;

    if (leaks == NULL) {
        return;
    }

    /*
     * VULN-020 fix: Recover count from hidden header and wipe before freeing.
     * This prevents sensitive info (addresses, sizes, thread IDs) from
     * persisting in unprotected system heap memory.
     */
    base = (unsigned char *)leaks - sizeof(size_t);
    count = *((size_t *)base);
    total_size = sizeof(size_t) + (count * sizeof(rampart_leak_info_t));

    /* Securely wipe the entire allocation */
    rp_wipe_memory(base, total_size);

    free(base);
}
