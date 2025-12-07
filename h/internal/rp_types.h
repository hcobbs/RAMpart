/**
 * @file rp_types.h
 * @brief RAMpart internal type definitions
 *
 * Contains internal structure definitions and constants used across
 * RAMpart modules. These types are not exposed to library users.
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

#ifndef RP_TYPES_H
#define RP_TYPES_H

#include <stddef.h>
#include "rampart.h"

/* ============================================================================
 * Platform Detection (POSIX only)
 * ============================================================================ */

#if defined(__linux__)
    #define RP_PLATFORM_LINUX 1
#elif defined(__APPLE__) && defined(__MACH__)
    #define RP_PLATFORM_MACOS 1
#elif defined(__unix__) || defined(__unix)
    #define RP_PLATFORM_POSIX 1
#else
    #error "Unsupported platform: RAMpart requires POSIX (Linux, macOS, or Unix)"
#endif

/* ============================================================================
 * POSIX Threading Types
 * ============================================================================ */

#include <pthread.h>
typedef pthread_mutex_t rp_mutex_t;
typedef pthread_t rp_thread_id_t;

/* ============================================================================
 * Internal Constants
 * ============================================================================ */

/**
 * @def RP_ALIGNMENT
 * @brief Memory alignment boundary in bytes
 */
#define RP_ALIGNMENT 16

/**
 * @def RP_GUARD_SIZE
 * @brief Size of guard bands in bytes
 */
#define RP_GUARD_SIZE 16

/**
 * @def RP_GUARD_FRONT_PATTERN
 * @brief Pattern written to front guard band (0xDEADBEEF)
 */
#define RP_GUARD_FRONT_PATTERN 0xDEADBEEFUL

/**
 * @def RP_GUARD_REAR_PATTERN
 * @brief Pattern written to rear guard band (0xFEEDFACE)
 */
#define RP_GUARD_REAR_PATTERN 0xFEEDFACEUL

/**
 * @def RP_BLOCK_MAGIC
 * @brief Magic number for block validation (0xB10CB10C)
 */
#define RP_BLOCK_MAGIC 0xB10CB10CUL

/**
 * @def RP_BLOCK_FREED_MAGIC
 * @brief Magic number indicating freed block (0xF4EED000)
 */
#define RP_BLOCK_FREED_MAGIC 0xF4EED000UL

/**
 * @def RP_MIN_BLOCK_SIZE
 * @brief Minimum block size after splitting
 *
 * A block must be at least this size to be split during allocation.
 */
#define RP_MIN_BLOCK_SIZE 64

/**
 * @def RP_POOL_HEADER_SIZE
 * @brief Size of pool header structure (aligned)
 */
#define RP_POOL_HEADER_SIZE 512

/**
 * @def RP_CRYPTO_BLOCK_SIZE
 * @brief Feistel cipher block size in bytes
 */
#define RP_CRYPTO_BLOCK_SIZE 8

/**
 * @def RP_CRYPTO_ROUNDS
 * @brief Number of Feistel cipher rounds
 */
#define RP_CRYPTO_ROUNDS 16

/* ============================================================================
 * Block Flags
 * ============================================================================ */

/**
 * @def RP_FLAG_ALLOCATED
 * @brief Block is currently allocated
 */
#define RP_FLAG_ALLOCATED  0x01

/**
 * @def RP_FLAG_ENCRYPTED
 * @brief Block data is currently encrypted
 */
#define RP_FLAG_ENCRYPTED  0x02

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

/**
 * @struct rp_block_header_t
 * @brief Internal block header structure
 *
 * Precedes every allocated and free block in the pool. Contains
 * metadata for block management, ownership, and validation.
 */
typedef struct rp_block_header_s {
    /**
     * @brief Magic number for validation (RP_BLOCK_MAGIC or RP_BLOCK_FREED_MAGIC)
     */
    unsigned long magic;

    /**
     * @brief Total block size including header and guards
     */
    size_t total_size;

    /**
     * @brief User-requested allocation size
     */
    size_t user_size;

    /**
     * @brief Block flags (RP_FLAG_*)
     */
    unsigned int flags;

    /**
     * @brief Thread ID of the allocating thread
     */
    rp_thread_id_t owner_thread;

    /**
     * @brief Pointer to previous block in list (allocated or free)
     */
    struct rp_block_header_s *prev;

    /**
     * @brief Pointer to next block in list (allocated or free)
     */
    struct rp_block_header_s *next;

    /**
     * @brief Pointer to previous block in address order
     */
    struct rp_block_header_s *prev_addr;

    /**
     * @brief Pointer to next block in address order
     */
    struct rp_block_header_s *next_addr;
} rp_block_header_t;

/*
 * Block header alignment verification.
 * The structure should be naturally aligned by the compiler.
 * We verify at runtime in debug builds that sizeof is a multiple of RP_ALIGNMENT.
 * If not, the compiler will add implicit padding which is acceptable.
 */
#define RP_BLOCK_HEADER_ALIGNED \
    ((sizeof(rp_block_header_t) % RP_ALIGNMENT) == 0)

/**
 * @struct rp_pool_header_t
 * @brief Internal pool header structure
 *
 * Located at the start of the pool memory region. Contains pool
 * configuration, state, and the free list head.
 */
typedef struct rp_pool_header_s {
    /**
     * @brief Total pool size in bytes
     */
    size_t total_size;

    /**
     * @brief Usable pool size (total minus header)
     */
    size_t usable_size;

    /**
     * @brief Bytes currently free
     */
    size_t free_size;

    /**
     * @brief Number of active allocations
     */
    size_t allocation_count;

    /**
     * @brief Number of free blocks
     */
    size_t free_block_count;

    /**
     * @brief Configuration flags (copied from rampart_config_t)
     */
    int encryption_enabled;
    int strict_thread_mode;
    int validate_on_free;

    /**
     * @brief Encryption key (if enabled)
     */
    unsigned char encryption_key[RAMPART_MAX_KEY_SIZE];
    size_t encryption_key_size;

    /**
     * @brief Error callback
     */
    rampart_error_callback_t error_callback;
    void *callback_user_data;

    /**
     * @brief Pool mutex for thread safety
     */
    rp_mutex_t mutex;

    /**
     * @brief Head of free block list (sorted by size, descending)
     */
    rp_block_header_t *free_list;

    /**
     * @brief Head of allocated block list
     */
    rp_block_header_t *alloc_list;

    /**
     * @brief First block in address order
     */
    rp_block_header_t *first_block;

    /**
     * @brief Start of usable pool memory (after header)
     */
    unsigned char *pool_start;

    /**
     * @brief End of pool memory
     */
    unsigned char *pool_end;
} rp_pool_header_t;

/* ============================================================================
 * Utility Macros
 * ============================================================================ */

/**
 * @def RP_ALIGN_UP
 * @brief Align a value up to the next alignment boundary
 *
 * @param x     Value to align
 * @param a     Alignment (must be power of 2)
 */
#define RP_ALIGN_UP(x, a) (((x) + ((size_t)(a) - 1)) & ~((size_t)(a) - 1))

/**
 * @def RP_BLOCK_TO_USER
 * @brief Get user data pointer from block header
 *
 * @param hdr   Pointer to block header
 */
#define RP_BLOCK_TO_USER(hdr) \
    ((void *)((unsigned char *)(hdr) + sizeof(rp_block_header_t) + RP_GUARD_SIZE))

/**
 * @def RP_USER_TO_BLOCK
 * @brief Get block header from user data pointer
 *
 * @param ptr   Pointer to user data
 */
#define RP_USER_TO_BLOCK(ptr) \
    ((rp_block_header_t *)((unsigned char *)(ptr) - sizeof(rp_block_header_t) - RP_GUARD_SIZE))

/**
 * @def RP_FRONT_GUARD
 * @brief Get pointer to front guard band
 *
 * @param hdr   Pointer to block header
 */
#define RP_FRONT_GUARD(hdr) \
    ((unsigned char *)(hdr) + sizeof(rp_block_header_t))

/**
 * @def RP_REAR_GUARD
 * @brief Get pointer to rear guard band
 *
 * Note: Uses a local variable to avoid double evaluation of hdr argument.
 *
 * @param hdr   Pointer to block header
 */
#define RP_REAR_GUARD(hdr) \
    ((unsigned char *)(hdr) + sizeof(rp_block_header_t) + RP_GUARD_SIZE + \
     ((const rp_block_header_t *)(hdr))->user_size)

/**
 * @def RP_BLOCK_OVERHEAD
 * @brief Total overhead per block (header + both guards)
 */
#define RP_BLOCK_OVERHEAD (sizeof(rp_block_header_t) + (RP_GUARD_SIZE * 2))

#endif /* RP_TYPES_H */
