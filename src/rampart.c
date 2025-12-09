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
#include <stdlib.h>
#include <string.h>

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
    "Internal error"                        /* RAMPART_ERR_INTERNAL = -10 */
};

#define NUM_ERROR_STRINGS (sizeof(ERROR_STRINGS) / sizeof(ERROR_STRINGS[0]))

/* ============================================================================
 * Helper: Invoke Error Callback
 * ============================================================================ */

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
        /* Unlock pool before callback to prevent deadlock */
        rp_pool_unlock(pool);
        callback((rampart_pool_t *)pool, error, block, user_data);
        rp_pool_lock(pool);
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

    if (pool == NULL) {
        return RAMPART_ERR_NULL_PARAM;
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

    if (pool == NULL) {
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

        /* Wipe leaked block data */
        rp_wipe_block_user_data(current);

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

    if (pool == NULL) {
        rp_thread_set_last_error(RAMPART_ERR_NULL_PARAM);
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

    /* Zero-initialize user data */
    rp_block_zero_user_data(block);

    user_ptr = rp_block_get_user_ptr(block);

    rp_pool_unlock(p);

    return user_ptr;
}

void *rampart_calloc(rampart_pool_t *pool, size_t nmemb, size_t elem_size) {
    size_t total_size;

    if (pool == NULL) {
        rp_thread_set_last_error(RAMPART_ERR_NULL_PARAM);
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

    if (pool == NULL || ptr == NULL) {
        return RAMPART_ERR_NULL_PARAM;
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

    /* Check thread ownership */
    if (p->strict_thread_mode) {
        err = rp_thread_verify_owner(block);
        if (err != RAMPART_OK) {
            invoke_callback(p, RAMPART_ERR_WRONG_THREAD, ptr);
            rp_pool_unlock(p);
            return RAMPART_ERR_WRONG_THREAD;
        }
    }

    /* Validate guard bands if configured */
    if (p->validate_on_free) {
        err = rp_block_validate_guards(p, block);
        if (err != RAMPART_OK) {
            invoke_callback(p, RAMPART_ERR_GUARD_CORRUPTED, ptr);
            rp_pool_unlock(p);
            return RAMPART_ERR_GUARD_CORRUPTED;
        }
    }

    /* Securely wipe user data */
    rp_wipe_block_user_data(block);

    /* Return block to pool */
    err = rp_pool_free(p, block);

    rp_pool_unlock(p);

    return err;
}

/* ============================================================================
 * Validation Functions
 * ============================================================================ */

rampart_error_t rampart_validate(rampart_pool_t *pool, void *ptr) {
    rp_pool_header_t *p;
    rp_block_header_t *block;
    rampart_error_t err;

    if (pool == NULL || ptr == NULL) {
        return RAMPART_ERR_NULL_PARAM;
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

    if (pool == NULL || result == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    memset(result, 0, sizeof(rampart_validation_result_t));

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

    if (pool == NULL || stats == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    memset(stats, 0, sizeof(rampart_stats_t));

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

    if (pool == NULL || ptr == NULL || info == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    memset(info, 0, sizeof(rampart_block_info_t));

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
 * ============================================================================ */

rampart_error_t rampart_get_leaks(rampart_pool_t *pool,
                                   rampart_leak_info_t **leaks,
                                   size_t *leak_count) {
    rp_pool_header_t *p;
    rp_block_header_t *current;
    rampart_leak_info_t *leak_array;
    size_t count;
    size_t i;

    if (pool == NULL || leaks == NULL || leak_count == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    *leaks = NULL;
    *leak_count = 0;

    p = (rp_pool_header_t *)pool;

    rp_pool_lock(p);

    /* Count allocations */
    count = p->allocation_count;

    if (count == 0) {
        rp_pool_unlock(p);
        return RAMPART_OK;
    }

    /* Allocate array */
    leak_array = (rampart_leak_info_t *)malloc(
        count * sizeof(rampart_leak_info_t));

    if (leak_array == NULL) {
        rp_pool_unlock(p);
        return RAMPART_ERR_OUT_OF_MEMORY;
    }

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
    if (leaks != NULL) {
        free(leaks);
    }
}
