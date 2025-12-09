/**
 * @file rp_wipe.c
 * @brief RAMpart secure memory wiping implementation
 *
 * Implements multi-pass memory wiping to prevent data recovery.
 * Uses volatile writes to prevent compiler optimization.
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

#include "internal/rp_wipe.h"
#include "internal/rp_types.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

/* MSVC intrinsics for memory barrier */
#if defined(_MSC_VER)
#include <intrin.h>
#pragma intrinsic(_ReadWriteBarrier)
#endif

/* ============================================================================
 * Compiler/Memory Barrier (VULN-015 fix)
 * ============================================================================
 * Prevent the compiler from optimizing away our writes and ensure
 * writes are visible to memory.
 *
 * Different compilers require different approaches:
 * - GCC/Clang: inline asm with memory clobber
 * - MSVC: _ReadWriteBarrier() intrinsic
 * - Others: volatile function pointer to force the call
 */

void rp_wipe_memory_barrier(void) {
#if defined(__GNUC__) || defined(__clang__)
    /* GCC/Clang memory barrier (works even in C89 mode) */
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    /* MSVC compiler barrier */
    _ReadWriteBarrier();
#else
    /*
     * Portable fallback using volatile function pointer (VULN-015 fix).
     *
     * The compiler cannot optimize away a call through a volatile function
     * pointer because it cannot prove the pointer always points to the same
     * function. This forces all preceding memory writes to complete.
     *
     * We call memset with size 0, which does nothing but the compiler
     * cannot know that and must preserve all prior writes.
     */
    static void * (*volatile memset_ptr)(void *, int, size_t) = memset;
    static char barrier_buf[1];
    (void)memset_ptr(barrier_buf, 0, 0);
#endif
}

/* ============================================================================
 * Random Data Generation (VULN-021 fix)
 * ============================================================================ */

/**
 * rp_wipe_fill_random - Fill memory with random data
 *
 * Uses /dev/urandom for high-quality random data. Falls back to a simple
 * PRNG if /dev/urandom is unavailable.
 *
 * @param ptr   Pointer to memory region
 * @param size  Size of region in bytes
 */
static void rp_wipe_fill_random(void *ptr, size_t size) {
    volatile unsigned char *p;
    FILE *urandom;
    size_t i;
    unsigned long state;

    if (ptr == NULL || size == 0) {
        return;
    }

    p = (volatile unsigned char *)ptr;

    /* Try /dev/urandom first */
    urandom = fopen("/dev/urandom", "rb");
    if (urandom != NULL) {
        /*
         * Read random data directly from urandom.
         * Cast away volatile for fread (data is immediately used).
         */
        if (fread((void *)p, 1, size, urandom) == size) {
            fclose(urandom);
            return;
        }
        fclose(urandom);
    }

    /*
     * Fallback: Simple PRNG based on address, time, and index.
     * This is not cryptographically secure but still unpredictable
     * enough to prevent pattern-based forensic detection.
     */
    state = (unsigned long)(size_t)ptr ^ (unsigned long)time(NULL);

    for (i = 0; i < size; i++) {
        /* Simple LCG: state = state * 1103515245 + 12345 */
        state = state * 1103515245UL + 12345UL;
        p[i] = (unsigned char)((state >> 16) & 0xFF);
    }
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

    /*
     * Pass 4: Random data (VULN-021 fix)
     *
     * A random final pass prevents forensic detection of wiped memory
     * based on known patterns. This follows DoD 5220.22-M guidance
     * which recommends a random final pass.
     */
    rp_wipe_fill_random(ptr, size);

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
