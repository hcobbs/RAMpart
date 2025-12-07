/**
 * @file rp_pool.h
 * @brief RAMpart pool management internals
 *
 * Contains functions for pool initialization, worst-fit allocation,
 * block splitting, coalescing, and free list management.
 *
 * @internal
 */

#ifndef RP_POOL_H
#define RP_POOL_H

#include "rp_types.h"

/* ============================================================================
 * Pool Management Functions
 * ============================================================================ */

/**
 * rp_pool_init - Initialize pool internals
 *
 * Sets up the pool header, mutex, and initial free block after
 * memory has been allocated. Called by rampart_init().
 *
 * @param pool_memory   Raw memory for the pool
 * @param pool_size     Total pool size in bytes
 * @param config        User configuration
 *
 * @return Pointer to initialized pool header, or NULL on failure
 *
 * @note Assumes pool_memory is properly aligned.
 * @note Initializes the entire pool as a single free block.
 */
rp_pool_header_t *rp_pool_init(void *pool_memory,
                                size_t pool_size,
                                const rampart_config_t *config);

/**
 * rp_pool_destroy - Clean up pool resources
 *
 * Releases mutex and performs final secure wipe of pool memory.
 * Called by rampart_shutdown().
 *
 * @param pool      Pointer to pool header
 *
 * @note Does not free pool_memory; caller must handle that.
 */
void rp_pool_destroy(rp_pool_header_t *pool);

/**
 * rp_pool_lock - Acquire pool mutex
 *
 * Blocks until the pool mutex is acquired. Must be paired with
 * rp_pool_unlock().
 *
 * @param pool      Pointer to pool header
 *
 * @return RAMPART_OK on success, error code on failure
 */
rampart_error_t rp_pool_lock(rp_pool_header_t *pool);

/**
 * rp_pool_unlock - Release pool mutex
 *
 * Releases the pool mutex. Must be preceded by rp_pool_lock().
 *
 * @param pool      Pointer to pool header
 *
 * @return RAMPART_OK on success, error code on failure
 */
rampart_error_t rp_pool_unlock(rp_pool_header_t *pool);

/* ============================================================================
 * Allocation Functions
 * ============================================================================ */

/**
 * rp_pool_alloc - Allocate block using worst-fit strategy
 *
 * Searches the free list for the largest block that can satisfy
 * the request. Splits the block if the remainder is large enough.
 *
 * @param pool          Pointer to pool header
 * @param size          User-requested size in bytes
 * @param out_block     Receives pointer to allocated block header
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @note Caller must hold pool mutex.
 * @note Does not initialize block contents (caller responsibility).
 */
rampart_error_t rp_pool_alloc(rp_pool_header_t *pool,
                               size_t size,
                               rp_block_header_t **out_block);

/**
 * rp_pool_free - Return block to free list
 *
 * Adds the block to the free list in address order and attempts
 * to coalesce with adjacent free blocks.
 *
 * @param pool      Pointer to pool header
 * @param block     Pointer to block header to free
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @note Caller must hold pool mutex.
 * @note Assumes block has already been validated and wiped.
 */
rampart_error_t rp_pool_free(rp_pool_header_t *pool, rp_block_header_t *block);

/* ============================================================================
 * Free List Functions
 * ============================================================================ */

/**
 * rp_pool_find_worst_fit - Find largest free block
 *
 * Searches the free list for the largest block with size >= requested.
 *
 * @param pool          Pointer to pool header
 * @param min_size      Minimum required size (including overhead)
 *
 * @return Pointer to largest suitable block, or NULL if none found
 *
 * @note Caller must hold pool mutex.
 */
rp_block_header_t *rp_pool_find_worst_fit(rp_pool_header_t *pool,
                                           size_t min_size);

/**
 * rp_pool_split_block - Split a block after allocation
 *
 * If the block is larger than needed, creates a new free block
 * from the remainder.
 *
 * @param pool          Pointer to pool header
 * @param block         Pointer to block to split
 * @param needed_size   Size needed for allocation (including overhead)
 *
 * @note Caller must hold pool mutex.
 * @note Does nothing if remainder is too small.
 */
void rp_pool_split_block(rp_pool_header_t *pool,
                          rp_block_header_t *block,
                          size_t needed_size);

/**
 * rp_pool_coalesce - Merge adjacent free blocks
 *
 * Attempts to merge the given block with its address-adjacent
 * neighbors if they are free.
 *
 * @param pool      Pointer to pool header
 * @param block     Pointer to block to coalesce
 *
 * @return Pointer to the resulting (possibly merged) block
 *
 * @note Caller must hold pool mutex.
 */
rp_block_header_t *rp_pool_coalesce(rp_pool_header_t *pool,
                                     rp_block_header_t *block);

/**
 * rp_pool_remove_from_free_list - Remove block from free list
 *
 * Unlinks a block from the free list. Called when allocating.
 *
 * @param pool      Pointer to pool header
 * @param block     Pointer to block to remove
 *
 * @note Caller must hold pool mutex.
 */
void rp_pool_remove_from_free_list(rp_pool_header_t *pool,
                                    rp_block_header_t *block);

/**
 * rp_pool_add_to_free_list - Add block to free list
 *
 * Inserts a block into the free list in address order.
 *
 * @param pool      Pointer to pool header
 * @param block     Pointer to block to add
 *
 * @note Caller must hold pool mutex.
 */
void rp_pool_add_to_free_list(rp_pool_header_t *pool, rp_block_header_t *block);

/**
 * rp_pool_add_to_alloc_list - Add block to allocated list
 *
 * Inserts a block into the allocated block list. Used for
 * tracking active allocations.
 *
 * @param pool      Pointer to pool header
 * @param block     Pointer to block to add
 *
 * @note Caller must hold pool mutex.
 */
void rp_pool_add_to_alloc_list(rp_pool_header_t *pool, rp_block_header_t *block);

/**
 * rp_pool_remove_from_alloc_list - Remove block from allocated list
 *
 * Unlinks a block from the allocated list. Called when freeing.
 *
 * @param pool      Pointer to pool header
 * @param block     Pointer to block to remove
 *
 * @note Caller must hold pool mutex.
 */
void rp_pool_remove_from_alloc_list(rp_pool_header_t *pool,
                                     rp_block_header_t *block);

/* ============================================================================
 * Statistics Functions
 * ============================================================================ */

/**
 * rp_pool_get_largest_free - Get size of largest free block
 *
 * Returns the usable size (excluding overhead) of the largest
 * free block in the pool.
 *
 * @param pool      Pointer to pool header
 *
 * @return Largest allocatable size, or 0 if pool is full
 *
 * @note Caller must hold pool mutex.
 */
size_t rp_pool_get_largest_free(rp_pool_header_t *pool);

/**
 * rp_pool_calculate_fragmentation - Calculate fragmentation percentage
 *
 * Calculates fragmentation as: 100 * (1 - largest_free / total_free)
 *
 * @param pool      Pointer to pool header
 *
 * @return Fragmentation percentage (0.0 to 100.0)
 *
 * @note Caller must hold pool mutex.
 * @note Returns 0.0 if no free space exists.
 */
double rp_pool_calculate_fragmentation(rp_pool_header_t *pool);

#endif /* RP_POOL_H */
