/**
 * @file rp_wipe.h
 * @brief RAMpart secure memory wiping internals
 *
 * Implements secure memory wiping to prevent data recovery from
 * freed memory. Uses multi-pass overwrite patterns.
 *
 * @internal
 *
 * @section wipe Wipe Strategy
 *
 * The default wipe strategy uses four passes:
 * 1. All zeros (0x00)
 * 2. All ones (0xFF)
 * 3. Alternating pattern (0xAA)
 * 4. Random data (VULN-021 fix)
 *
 * This pattern provides protection against casual data recovery and
 * forensic detection of wiped memory while maintaining C89 compliance.
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

#ifndef RP_WIPE_H
#define RP_WIPE_H

#include "rp_types.h"

/* ============================================================================
 * Wipe Pattern Constants
 * ============================================================================ */

/**
 * @def RP_WIPE_PASS_COUNT
 * @brief Number of wipe passes (4 = zeros + ones + alternating + random)
 */
#define RP_WIPE_PASS_COUNT 4

/**
 * @def RP_WIPE_PATTERN_1
 * @brief First wipe pass pattern (all zeros)
 */
#define RP_WIPE_PATTERN_1 0x00

/**
 * @def RP_WIPE_PATTERN_2
 * @brief Second wipe pass pattern (all ones)
 */
#define RP_WIPE_PATTERN_2 0xFF

/**
 * @def RP_WIPE_PATTERN_3
 * @brief Third wipe pass pattern (alternating)
 */
#define RP_WIPE_PATTERN_3 0xAA

/* Pass 4 is random data (VULN-021 fix) */

/* ============================================================================
 * Secure Wipe Functions
 * ============================================================================ */

/**
 * rp_wipe_memory - Securely wipe memory region
 *
 * Performs a multi-pass overwrite of the specified memory region.
 * Uses compiler barriers to prevent optimization.
 *
 * @param ptr       Pointer to memory region
 * @param size      Size of region in bytes
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_ERR_NULL_PARAM   ptr is NULL
 *
 * @note Uses volatile writes to prevent compiler optimization.
 * @note Performs RP_WIPE_PASS_COUNT passes with different patterns.
 */
rampart_error_t rp_wipe_memory(void *ptr, size_t size);

/**
 * rp_wipe_memory_single - Single-pass memory wipe
 *
 * Performs a single-pass overwrite with the specified pattern.
 * Faster than multi-pass for non-sensitive data.
 *
 * @param ptr       Pointer to memory region
 * @param size      Size of region in bytes
 * @param pattern   Byte pattern to write
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_ERR_NULL_PARAM   ptr is NULL
 *
 * @note Uses volatile writes to prevent compiler optimization.
 */
rampart_error_t rp_wipe_memory_single(void *ptr,
                                       size_t size,
                                       unsigned char pattern);

/**
 * rp_wipe_block_user_data - Wipe block's user data region
 *
 * Securely wipes only the user data portion of a block, leaving
 * headers and guard bands intact.
 *
 * @param block     Pointer to block header
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_ERR_NULL_PARAM   block is NULL
 *
 * @note Block must be initialized (user_size must be valid).
 */
rampart_error_t rp_wipe_block_user_data(rp_block_header_t *block);

/**
 * rp_wipe_block_user_and_guards - Wipe user data and guard bands
 *
 * Securely wipes the user data portion AND the front/rear guard bands.
 * Leaves the block header intact so the block can be reused.
 *
 * VULN-022 fix: Guard bands must be wiped to prevent forensic detection
 * of RAMpart usage and historic allocation boundaries.
 *
 * @param block     Pointer to block header
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_ERR_NULL_PARAM   block is NULL
 *
 * @note Block header remains intact for free list management.
 * @note Use this instead of rp_wipe_block_user_data for proper cleanup.
 */
rampart_error_t rp_wipe_block_user_and_guards(rp_block_header_t *block);

/**
 * rp_wipe_block_full - Wipe entire block including metadata
 *
 * Securely wipes the entire block including headers. Used during
 * pool shutdown.
 *
 * @param block         Pointer to block header
 * @param total_size    Total block size in bytes
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_ERR_NULL_PARAM   block is NULL
 *
 * @note Block cannot be used after this call.
 */
rampart_error_t rp_wipe_block_full(rp_block_header_t *block, size_t total_size);

/* ============================================================================
 * Verification Functions
 * ============================================================================ */

/**
 * rp_wipe_verify - Verify memory was wiped
 *
 * Checks that a memory region contains only the expected pattern.
 * Useful for testing and validation.
 *
 * @param ptr       Pointer to memory region
 * @param size      Size of region in bytes
 * @param pattern   Expected byte pattern
 *
 * @return RAMPART_OK if pattern matches, RAMPART_ERR_INTERNAL if not
 *
 * @note Used for testing; not typically called in production.
 */
rampart_error_t rp_wipe_verify(const void *ptr,
                                size_t size,
                                unsigned char pattern);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * rp_wipe_memory_barrier - Memory barrier
 *
 * Issues a compiler memory barrier to prevent reordering of
 * memory operations around the wipe.
 *
 * @note Implementation is platform-specific but C89 compatible.
 */
void rp_wipe_memory_barrier(void);

#endif /* RP_WIPE_H */
