/**
 * @file rp_block.h
 * @brief RAMpart block management internals
 *
 * Contains functions for block initialization, guard band management,
 * and block validation.
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

#ifndef RP_BLOCK_H
#define RP_BLOCK_H

#include "rp_types.h"

/* ============================================================================
 * Block Initialization Functions
 * ============================================================================ */

/**
 * rp_block_init - Initialize a new block header
 *
 * Sets up the block header with size, flags, and magic number.
 * Does not initialize guard bands or user data.
 *
 * @param block         Pointer to block header memory
 * @param total_size    Total block size (including header and guards)
 * @param user_size     User-requested allocation size
 * @param owner         Thread ID of the allocating thread
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @note Called during allocation before guard band setup.
 */
rampart_error_t rp_block_init(rp_block_header_t *block,
                               size_t total_size,
                               size_t user_size,
                               rp_thread_id_t owner);

/**
 * rp_block_init_as_free - Initialize a block as free
 *
 * Sets up a block header for a free block. Used during pool
 * initialization and block splitting.
 *
 * @param block         Pointer to block header memory
 * @param total_size    Total block size
 *
 * @return RAMPART_OK on success, error code on failure
 */
rampart_error_t rp_block_init_as_free(rp_block_header_t *block,
                                       size_t total_size);

/* ============================================================================
 * Guard Band Functions
 * ============================================================================ */

/**
 * rp_block_init_guards - Initialize guard bands
 *
 * Writes the front and rear guard patterns to the block's guard
 * band regions using pool-specific randomized patterns.
 *
 * @param pool      Pointer to pool header (for randomized patterns)
 * @param block     Pointer to block header
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @note Block header must be initialized first.
 */
rampart_error_t rp_block_init_guards(rp_pool_header_t *pool,
                                      rp_block_header_t *block);

/**
 * rp_block_validate_front_guard - Check front guard band
 *
 * Verifies that the front guard band contains the expected pattern.
 *
 * @param pool      Pointer to pool header (for randomized patterns)
 * @param block     Pointer to block header
 *
 * @return RAMPART_OK if intact, RAMPART_ERR_GUARD_CORRUPTED if not
 */
rampart_error_t rp_block_validate_front_guard(const rp_pool_header_t *pool,
                                               const rp_block_header_t *block);

/**
 * rp_block_validate_rear_guard - Check rear guard band
 *
 * Verifies that the rear guard band contains the expected pattern.
 *
 * @param pool      Pointer to pool header (for randomized patterns)
 * @param block     Pointer to block header
 *
 * @return RAMPART_OK if intact, RAMPART_ERR_GUARD_CORRUPTED if not
 */
rampart_error_t rp_block_validate_rear_guard(const rp_pool_header_t *pool,
                                              const rp_block_header_t *block);

/**
 * rp_block_validate_guards - Check both guard bands
 *
 * Validates both front and rear guard bands.
 *
 * @param pool      Pointer to pool header (for randomized patterns)
 * @param block     Pointer to block header
 *
 * @return RAMPART_OK if both intact, RAMPART_ERR_GUARD_CORRUPTED if either corrupted
 */
rampart_error_t rp_block_validate_guards(const rp_pool_header_t *pool,
                                          const rp_block_header_t *block);

/* ============================================================================
 * Block Validation Functions
 * ============================================================================ */

/**
 * rp_block_validate_magic - Check block magic number
 *
 * Verifies that the block's magic number indicates a valid allocated block.
 *
 * @param block     Pointer to block header
 *
 * @return RAMPART_OK if valid, RAMPART_ERR_INVALID_BLOCK if not
 */
rampart_error_t rp_block_validate_magic(const rp_block_header_t *block);

/**
 * rp_block_validate - Full block validation
 *
 * Performs comprehensive validation: magic number, flags, and guard bands.
 *
 * @param pool      Pointer to pool header (for randomized patterns)
 * @param block     Pointer to block header
 *
 * @return RAMPART_OK if valid, appropriate error code if not
 *
 * @retval RAMPART_ERR_NULL_PARAM       block is NULL
 * @retval RAMPART_ERR_INVALID_BLOCK    Magic number invalid or block not allocated
 * @retval RAMPART_ERR_GUARD_CORRUPTED  Guard band corruption detected
 */
rampart_error_t rp_block_validate(const rp_pool_header_t *pool,
                                   const rp_block_header_t *block);

/**
 * rp_block_is_allocated - Check if block is allocated
 *
 * Returns non-zero if the block is currently allocated (not free).
 *
 * @param block     Pointer to block header
 *
 * @return Non-zero if allocated, zero if free or invalid
 */
int rp_block_is_allocated(const rp_block_header_t *block);

/**
 * rp_block_is_free - Check if block is free
 *
 * Returns non-zero if the block is on the free list.
 *
 * @param block     Pointer to block header
 *
 * @return Non-zero if free, zero if allocated or invalid
 */
int rp_block_is_free(const rp_block_header_t *block);

/* ============================================================================
 * User Data Functions
 * ============================================================================ */

/**
 * rp_block_zero_user_data - Zero-initialize user data region
 *
 * Sets all bytes in the user data region to 0x00.
 *
 * @param block     Pointer to block header
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @note Block must be initialized first.
 */
rampart_error_t rp_block_zero_user_data(rp_block_header_t *block);

/**
 * rp_block_get_user_ptr - Get pointer to user data
 *
 * Returns a pointer to the user-accessible portion of the block.
 *
 * @param block     Pointer to block header
 *
 * @return Pointer to user data region
 */
void *rp_block_get_user_ptr(rp_block_header_t *block);

/**
 * rp_block_from_user_ptr - Get block header from user pointer
 *
 * Given a pointer returned by rampart_alloc(), returns the
 * corresponding block header.
 *
 * @param ptr       User data pointer
 *
 * @return Pointer to block header
 *
 * @note Does not validate the pointer; caller must ensure it's valid.
 */
rp_block_header_t *rp_block_from_user_ptr(void *ptr);

/**
 * rp_block_from_user_ptr_safe - Get block header with bounds validation
 *
 * Given a pointer returned by rampart_alloc(), validates that it falls
 * within the pool boundaries and is properly aligned before returning
 * the corresponding block header.
 *
 * @param pool      Pointer to pool header (for bounds checking)
 * @param ptr       User data pointer
 *
 * @return Pointer to block header if valid, NULL if outside pool or misaligned
 *
 * @note This is the safe version that should be used for external pointers.
 */
rp_block_header_t *rp_block_from_user_ptr_safe(rp_pool_header_t *pool,
                                                void *ptr);

/* ============================================================================
 * Block State Functions
 * ============================================================================ */

/**
 * rp_block_mark_allocated - Mark block as allocated
 *
 * Sets the block's magic number and flags to indicate allocation.
 *
 * @param block     Pointer to block header
 */
void rp_block_mark_allocated(rp_block_header_t *block);

/**
 * rp_block_mark_freed - Mark block as freed
 *
 * Sets the block's magic number and flags to indicate free status.
 * Does not wipe data (caller must do that first).
 *
 * @param block     Pointer to block header
 */
void rp_block_mark_freed(rp_block_header_t *block);

/* ============================================================================
 * Size Calculation Functions
 * ============================================================================ */

/**
 * rp_block_calc_total_size - Calculate total block size
 *
 * Given a user-requested size, calculates the total block size
 * including header, guards, and alignment padding.
 *
 * @param user_size     User-requested allocation size
 *
 * @return Total block size needed
 */
size_t rp_block_calc_total_size(size_t user_size);

/**
 * rp_block_calc_user_size - Calculate maximum user size
 *
 * Given a total block size, calculates the maximum user data size.
 *
 * @param total_size    Total block size
 *
 * @return Maximum user data size
 */
size_t rp_block_calc_user_size(size_t total_size);

#endif /* RP_BLOCK_H */
