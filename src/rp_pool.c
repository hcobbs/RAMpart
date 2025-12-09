/**
 * @file rp_pool.c
 * @brief RAMpart pool management implementation
 *
 * Implements pool initialization, worst-fit allocation strategy,
 * block splitting, coalescing, and free list management.
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

#include "internal/rp_pool.h"
#include "internal/rp_block.h"
#include "internal/rp_thread.h"
#include "internal/rp_wipe.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ============================================================================
 * Random Pattern Generation
 * ============================================================================ */

/**
 * rp_generate_random_ulong - Generate a random unsigned long
 *
 * Uses /dev/urandom on POSIX systems. Falls back to address XOR time
 * if urandom is unavailable.
 *
 * @return Random unsigned long value
 */
static unsigned long rp_generate_random_ulong(void) {
    unsigned long result = 0;
    FILE *urandom;

    urandom = fopen("/dev/urandom", "rb");
    if (urandom != NULL) {
        if (fread(&result, sizeof(result), 1, urandom) != 1) {
            result = 0;  /* Read failed, will use fallback */
        }
        fclose(urandom);
    }

    /* Fallback: use address + time (weak but better than nothing) */
    if (result == 0) {
        result = (unsigned long)(size_t)&result ^ (unsigned long)time(NULL);
    }

    return result;
}

/* ============================================================================
 * Pool Initialization
 * ============================================================================ */

rp_pool_header_t *rp_pool_init(void *pool_memory,
                                size_t pool_size,
                                const rampart_config_t *config) {
    rp_pool_header_t *pool;
    rp_block_header_t *initial_block;
    size_t usable_size;
    rampart_error_t err;

    if (pool_memory == NULL || config == NULL) {
        return NULL;
    }

    if (pool_size < RAMPART_MIN_POOL_SIZE) {
        return NULL;
    }

    /* Pool header at start of memory */
    pool = (rp_pool_header_t *)pool_memory;

    /* Calculate usable size (after pool header) */
    usable_size = pool_size - RP_POOL_HEADER_SIZE;

    /* Initialize pool header */
    pool->pool_magic = RP_POOL_MAGIC;  /* VULN-019 fix: Set pool magic */
    pool->total_size = pool_size;
    pool->usable_size = usable_size;
    pool->free_size = usable_size;
    pool->allocation_count = 0;
    pool->free_block_count = 1;

    /*
     * Copy configuration.
     *
     * VULN-023 fix: Normalize boolean config values to 0 or 1.
     * This prevents semantic confusion from negative values and ensures
     * consistent behavior regardless of the non-zero value provided.
     * Any non-zero input becomes 1, zero stays 0.
     */
    pool->strict_thread_mode = (config->strict_thread_mode != 0);
    pool->validate_on_free = (config->validate_on_free != 0);
    pool->error_callback = config->error_callback;
    pool->callback_user_data = config->callback_user_data;

    /* Generate random guard patterns (VULN-004 fix) */
    pool->guard_front_pattern = rp_generate_random_ulong();
    pool->guard_rear_pattern = rp_generate_random_ulong();

    /* Ensure patterns are non-zero and different */
    if (pool->guard_front_pattern == 0) {
        pool->guard_front_pattern = RP_GUARD_FRONT_PATTERN;
    }
    if (pool->guard_rear_pattern == 0 ||
        pool->guard_rear_pattern == pool->guard_front_pattern) {
        pool->guard_rear_pattern = RP_GUARD_REAR_PATTERN;
    }

    /* Initialize mutex */
    err = rp_mutex_init(&pool->mutex);
    if (err != RAMPART_OK) {
        return NULL;
    }

    /* Set up memory pointers */
    pool->pool_start = (unsigned char *)pool_memory + RP_POOL_HEADER_SIZE;
    pool->pool_end = (unsigned char *)pool_memory + pool_size;

    /* Create initial free block spanning all usable memory */
    initial_block = (rp_block_header_t *)pool->pool_start;
    rp_block_init_as_free(initial_block, usable_size);

    /* Set up lists */
    pool->free_list = initial_block;
    pool->alloc_list = NULL;
    pool->first_block = initial_block;

    return pool;
}

void rp_pool_destroy(rp_pool_header_t *pool) {
    size_t total_size;

    if (pool == NULL) {
        return;
    }

    /* Clear pool magic first (VULN-019 fix) to invalidate pool immediately */
    pool->pool_magic = 0;

    /* Save total_size before any wiping (prevents use-after-wipe) */
    total_size = pool->total_size;

    /* Destroy mutex */
    rp_mutex_destroy(&pool->mutex);

    /* Wipe entire pool memory */
    rp_wipe_memory(pool, total_size);
}

/* ============================================================================
 * Mutex Wrappers
 * ============================================================================ */

rampart_error_t rp_pool_lock(rp_pool_header_t *pool) {
    if (pool == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    return rp_mutex_lock(&pool->mutex);
}

rampart_error_t rp_pool_unlock(rp_pool_header_t *pool) {
    if (pool == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    return rp_mutex_unlock(&pool->mutex);
}

/* ============================================================================
 * Free List Management
 * ============================================================================ */

rp_block_header_t *rp_pool_find_worst_fit(rp_pool_header_t *pool,
                                           size_t min_size) {
    rp_block_header_t *current;
    rp_block_header_t *best;

    if (pool == NULL || pool->free_list == NULL) {
        return NULL;
    }

    best = NULL;
    current = pool->free_list;

    /* Search for largest block that fits */
    while (current != NULL) {
        if (current->total_size >= min_size) {
            if (best == NULL || current->total_size > best->total_size) {
                best = current;
            }
        }
        current = current->next;
    }

    return best;
}

void rp_pool_remove_from_free_list(rp_pool_header_t *pool,
                                    rp_block_header_t *block) {
    if (pool == NULL || block == NULL) {
        return;
    }

    /*
     * Safe unlinking validation (VULN-006 fix)
     *
     * Verify link integrity before modification. If an attacker has
     * corrupted the prev/next pointers via buffer overflow, continuing
     * would allow arbitrary write exploitation.
     *
     * If corruption is detected, invoke error callback for logging
     * and then abort to prevent exploitation.
     */
    if (block->prev != NULL && block->prev->next != block) {
        /* Corrupted list: prev->next doesn't point back to us */
        if (pool->error_callback != NULL) {
            pool->error_callback((rampart_pool_t *)pool,
                                  RAMPART_ERR_INTERNAL,
                                  block,
                                  pool->callback_user_data);
        }
        abort();
    }
    if (block->next != NULL && block->next->prev != block) {
        /* Corrupted list: next->prev doesn't point back to us */
        if (pool->error_callback != NULL) {
            pool->error_callback((rampart_pool_t *)pool,
                                  RAMPART_ERR_INTERNAL,
                                  block,
                                  pool->callback_user_data);
        }
        abort();
    }

    /* Update previous block's next pointer */
    if (block->prev != NULL) {
        block->prev->next = block->next;
    } else {
        /* Block is head of list */
        pool->free_list = block->next;
    }

    /* Update next block's prev pointer */
    if (block->next != NULL) {
        block->next->prev = block->prev;
    }

    block->prev = NULL;
    block->next = NULL;
    pool->free_block_count--;
}

void rp_pool_add_to_free_list(rp_pool_header_t *pool,
                               rp_block_header_t *block) {
    rp_block_header_t *current;
    rp_block_header_t *prev;

    if (pool == NULL || block == NULL) {
        return;
    }

    /* Insert in address order for coalescing */
    if (pool->free_list == NULL) {
        /* Empty list */
        pool->free_list = block;
        block->prev = NULL;
        block->next = NULL;
    } else if ((unsigned char *)block < (unsigned char *)pool->free_list) {
        /* Insert at head */
        block->next = pool->free_list;
        block->prev = NULL;
        pool->free_list->prev = block;
        pool->free_list = block;
    } else {
        /* Find insertion point */
        prev = NULL;
        current = pool->free_list;

        while (current != NULL &&
               (unsigned char *)current < (unsigned char *)block) {
            prev = current;
            current = current->next;
        }

        /* Insert between prev and current */
        block->prev = prev;
        block->next = current;

        if (prev != NULL) {
            prev->next = block;
        }

        if (current != NULL) {
            current->prev = block;
        }
    }

    pool->free_block_count++;
}

void rp_pool_add_to_alloc_list(rp_pool_header_t *pool,
                                rp_block_header_t *block) {
    if (pool == NULL || block == NULL) {
        return;
    }

    /* Add at head of allocated list */
    block->next = pool->alloc_list;
    block->prev = NULL;

    if (pool->alloc_list != NULL) {
        pool->alloc_list->prev = block;
    }

    pool->alloc_list = block;
}

void rp_pool_remove_from_alloc_list(rp_pool_header_t *pool,
                                     rp_block_header_t *block) {
    if (pool == NULL || block == NULL) {
        return;
    }

    /*
     * Safe unlinking validation (VULN-006 fix)
     * Same protection as free list removal.
     */
    if (block->prev != NULL && block->prev->next != block) {
        if (pool->error_callback != NULL) {
            pool->error_callback((rampart_pool_t *)pool,
                                  RAMPART_ERR_INTERNAL,
                                  block,
                                  pool->callback_user_data);
        }
        abort();
    }
    if (block->next != NULL && block->next->prev != block) {
        if (pool->error_callback != NULL) {
            pool->error_callback((rampart_pool_t *)pool,
                                  RAMPART_ERR_INTERNAL,
                                  block,
                                  pool->callback_user_data);
        }
        abort();
    }

    /* Update previous block's next pointer */
    if (block->prev != NULL) {
        block->prev->next = block->next;
    } else {
        /* Block is head of list */
        pool->alloc_list = block->next;
    }

    /* Update next block's prev pointer */
    if (block->next != NULL) {
        block->next->prev = block->prev;
    }

    block->prev = NULL;
    block->next = NULL;
}

/* ============================================================================
 * Block Splitting and Coalescing
 * ============================================================================ */

void rp_pool_split_block(rp_pool_header_t *pool,
                          rp_block_header_t *block,
                          size_t needed_size) {
    rp_block_header_t *remainder;
    size_t remainder_size;

    if (pool == NULL || block == NULL) {
        return;
    }

    /*
     * Check if remainder is large enough (VULN-012 fix).
     *
     * Split into two checks to avoid integer overflow:
     * 1. First ensure total_size >= needed_size (prevents underflow)
     * 2. Then check if remainder would be large enough
     *
     * Previous code: if (total_size < needed_size + RP_MIN_BLOCK_SIZE)
     * was vulnerable to overflow if needed_size was near SIZE_MAX.
     */
    if (block->total_size < needed_size) {
        return;  /* Underflow would occur */
    }

    remainder_size = block->total_size - needed_size;

    if (remainder_size < RP_MIN_BLOCK_SIZE) {
        return;  /* Not enough space to split */
    }

    /* Create remainder block */
    remainder = (rp_block_header_t *)((unsigned char *)block + needed_size);
    rp_block_init_as_free(remainder, remainder_size);

    /* Update original block size */
    block->total_size = needed_size;

    /* Link remainder in address order */
    remainder->next_addr = block->next_addr;
    remainder->prev_addr = block;

    if (block->next_addr != NULL) {
        block->next_addr->prev_addr = remainder;
    }

    block->next_addr = remainder;

    /* Add remainder to free list */
    rp_pool_add_to_free_list(pool, remainder);

    /* Update pool free size */
    pool->free_size += remainder_size;
}

/**
 * rp_pool_is_valid_block_ptr - Check if pointer is valid within pool
 *
 * Validates that a block pointer:
 * 1. Is within pool boundaries
 * 2. Is properly aligned to RP_ALIGNMENT
 *
 * This is a security check (VULN-007 fix) to prevent use-after-free
 * attacks via corrupted prev_addr/next_addr pointers.
 *
 * @param pool  Pool header
 * @param ptr   Pointer to validate
 *
 * @return 1 if valid, 0 if invalid
 */
static int rp_pool_is_valid_block_ptr(const rp_pool_header_t *pool,
                                       const rp_block_header_t *ptr) {
    const unsigned char *addr;

    if (ptr == NULL) {
        return 0;
    }

    addr = (const unsigned char *)ptr;

    /* Check bounds */
    if (addr < pool->pool_start || addr >= pool->pool_end) {
        return 0;
    }

    /* Check alignment */
    if (((size_t)addr % RP_ALIGNMENT) != 0) {
        return 0;
    }

    return 1;
}

rp_block_header_t *rp_pool_coalesce(rp_pool_header_t *pool,
                                     rp_block_header_t *block) {
    rp_block_header_t *prev_block;
    rp_block_header_t *next_block;

    if (pool == NULL || block == NULL) {
        return block;
    }

    /* Try to coalesce with next block (by address) */
    next_block = block->next_addr;

    /*
     * VULN-007 fix: Validate next_addr before accessing.
     * If corrupted via overflow, skip coalescing to prevent UAF.
     */
    if (next_block != NULL && !rp_pool_is_valid_block_ptr(pool, next_block)) {
        next_block = NULL;  /* Treat as no next block */
    }

    if (next_block != NULL && rp_block_is_free(next_block)) {
        /* Remove next block from free list */
        rp_pool_remove_from_free_list(pool, next_block);

        /* Merge sizes */
        block->total_size += next_block->total_size;

        /* Update address links */
        block->next_addr = next_block->next_addr;
        if (next_block->next_addr != NULL &&
            rp_pool_is_valid_block_ptr(pool, next_block->next_addr)) {
            next_block->next_addr->prev_addr = block;
        }
    }

    /* Try to coalesce with previous block (by address) */
    prev_block = block->prev_addr;

    /*
     * VULN-007 fix: Validate prev_addr before accessing.
     * If corrupted via overflow, skip coalescing to prevent UAF.
     */
    if (prev_block != NULL && !rp_pool_is_valid_block_ptr(pool, prev_block)) {
        prev_block = NULL;  /* Treat as no previous block */
    }

    if (prev_block != NULL && rp_block_is_free(prev_block)) {
        /* Remove both blocks from free list */
        rp_pool_remove_from_free_list(pool, block);
        rp_pool_remove_from_free_list(pool, prev_block);

        /* Merge sizes */
        prev_block->total_size += block->total_size;

        /* Update address links */
        prev_block->next_addr = block->next_addr;
        if (block->next_addr != NULL &&
            rp_pool_is_valid_block_ptr(pool, block->next_addr)) {
            block->next_addr->prev_addr = prev_block;
        }

        /* Add merged block back to free list */
        rp_pool_add_to_free_list(pool, prev_block);

        return prev_block;
    }

    return block;
}

/* ============================================================================
 * Allocation and Deallocation
 * ============================================================================ */

rampart_error_t rp_pool_alloc(rp_pool_header_t *pool,
                               size_t size,
                               rp_block_header_t **out_block) {
    rp_block_header_t *block;
    size_t total_size;

    if (pool == NULL || out_block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    if (size == 0) {
        return RAMPART_ERR_INVALID_SIZE;
    }

    *out_block = NULL;

    /* Calculate total block size needed */
    total_size = rp_block_calc_total_size(size);

    /* Check for overflow in size calculation */
    if (total_size == 0) {
        return RAMPART_ERR_INVALID_SIZE;
    }

    /* Find best (largest) fitting block */
    block = rp_pool_find_worst_fit(pool, total_size);

    if (block == NULL) {
        return RAMPART_ERR_OUT_OF_MEMORY;
    }

    /* Remove from free list */
    rp_pool_remove_from_free_list(pool, block);

    /* Update pool free size */
    pool->free_size -= block->total_size;

    /* Split if block is larger than needed */
    rp_pool_split_block(pool, block, total_size);

    /* Initialize block as allocated */
    rp_block_init(block, block->total_size, size,
                   rp_thread_get_current_id());

    /* Add to allocated list */
    rp_pool_add_to_alloc_list(pool, block);

    /* Update statistics */
    pool->allocation_count++;

    *out_block = block;
    return RAMPART_OK;
}

rampart_error_t rp_pool_free(rp_pool_header_t *pool,
                              rp_block_header_t *block) {
    size_t block_size;

    if (pool == NULL || block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    /* Save size before marking free */
    block_size = block->total_size;

    /* Remove from allocated list */
    rp_pool_remove_from_alloc_list(pool, block);

    /* Mark as freed */
    rp_block_mark_freed(block);

    /* Update pool free size */
    pool->free_size += block_size;

    /* Add to free list */
    rp_pool_add_to_free_list(pool, block);

    /* Try to coalesce with neighbors */
    rp_pool_coalesce(pool, block);

    /* Update statistics */
    pool->allocation_count--;

    return RAMPART_OK;
}

/* ============================================================================
 * Statistics Functions
 * ============================================================================ */

size_t rp_pool_get_largest_free(rp_pool_header_t *pool) {
    rp_block_header_t *current;
    size_t largest;
    size_t usable;

    if (pool == NULL) {
        return 0;
    }

    largest = 0;
    current = pool->free_list;

    while (current != NULL) {
        if (current->total_size > largest) {
            largest = current->total_size;
        }
        current = current->next;
    }

    /* Convert to usable size (subtract overhead) */
    usable = rp_block_calc_user_size(largest);

    return usable;
}

double rp_pool_calculate_fragmentation(rp_pool_header_t *pool) {
    size_t largest;
    double frag;

    if (pool == NULL || pool->free_size == 0) {
        return 0.0;
    }

    largest = rp_pool_get_largest_free(pool);

    if (largest == 0) {
        return 100.0;
    }

    /* fragmentation = 100 * (1 - largest_usable / total_free) */
    frag = 100.0 * (1.0 - ((double)largest / (double)pool->free_size));

    if (frag < 0.0) {
        frag = 0.0;
    }

    return frag;
}
