/**
 * @file rp_wipe.c
 * @brief RAMpart secure memory wiping implementation
 *
 * Implements multi-pass memory wiping to prevent data recovery.
 * Uses volatile writes to prevent compiler optimization.
 */

#include "internal/rp_wipe.h"
#include "internal/rp_types.h"

/* ============================================================================
 * Compiler Barrier
 * ============================================================================
 * Prevent the compiler from optimizing away our writes.
 */

void rp_wipe_memory_barrier(void) {
    /*
     * C89 doesn't have standard memory barriers.
     * This volatile access serves as a compiler barrier on most platforms.
     * For production use on specific platforms, platform-specific
     * barriers should be used.
     */
    static volatile int barrier_dummy = 0;
    barrier_dummy = barrier_dummy;
}

/* ============================================================================
 * Volatile Write
 * ============================================================================ */

void rp_wipe_volatile_write(volatile unsigned char *ptr, unsigned char value) {
    *ptr = value;
}

/* ============================================================================
 * Single-Pass Wipe
 * ============================================================================ */

rampart_error_t rp_wipe_memory_single(void *ptr,
                                       size_t size,
                                       unsigned char pattern) {
    volatile unsigned char *p;
    size_t i;

    if (ptr == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    if (size == 0) {
        return RAMPART_OK;
    }

    p = (volatile unsigned char *)ptr;

    for (i = 0; i < size; i++) {
        p[i] = pattern;
    }

    rp_wipe_memory_barrier();

    return RAMPART_OK;
}

/* ============================================================================
 * Multi-Pass Wipe
 * ============================================================================ */

rampart_error_t rp_wipe_memory(void *ptr, size_t size) {
    rampart_error_t err;

    if (ptr == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    if (size == 0) {
        return RAMPART_OK;
    }

    /* Pass 1: All zeros */
    err = rp_wipe_memory_single(ptr, size, RP_WIPE_PATTERN_1);
    if (err != RAMPART_OK) {
        return err;
    }

    /* Pass 2: All ones */
    err = rp_wipe_memory_single(ptr, size, RP_WIPE_PATTERN_2);
    if (err != RAMPART_OK) {
        return err;
    }

    /* Pass 3: Alternating pattern */
    err = rp_wipe_memory_single(ptr, size, RP_WIPE_PATTERN_3);
    if (err != RAMPART_OK) {
        return err;
    }

    /* Final barrier to ensure all writes complete */
    rp_wipe_memory_barrier();

    return RAMPART_OK;
}

/* ============================================================================
 * Block-Specific Wipe Functions
 * ============================================================================ */

rampart_error_t rp_wipe_block_user_data(rp_block_header_t *block) {
    void *user_ptr;

    if (block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    if (block->user_size == 0) {
        return RAMPART_OK;
    }

    user_ptr = RP_BLOCK_TO_USER(block);

    return rp_wipe_memory(user_ptr, block->user_size);
}

rampart_error_t rp_wipe_block_full(rp_block_header_t *block, size_t total_size) {
    if (block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    return rp_wipe_memory(block, total_size);
}

/* ============================================================================
 * Verification (Testing)
 * ============================================================================ */

rampart_error_t rp_wipe_verify(const void *ptr,
                                size_t size,
                                unsigned char pattern) {
    const unsigned char *p;
    size_t i;

    if (ptr == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    p = (const unsigned char *)ptr;

    for (i = 0; i < size; i++) {
        if (p[i] != pattern) {
            return RAMPART_ERR_INTERNAL;
        }
    }

    return RAMPART_OK;
}
