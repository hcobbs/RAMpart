/**
 * @file rp_block.c
 * @brief RAMpart block management implementation
 *
 * Handles block initialization, guard band management, and validation.
 */

#include "internal/rp_block.h"
#include "internal/rp_types.h"
#include "internal/rp_thread.h"
#include <string.h>

/* ============================================================================
 * Guard Band Pattern Writing
 * ============================================================================ */

/**
 * write_guard_pattern - Fill memory with a 4-byte pattern
 */
static void write_guard_pattern(unsigned char *ptr,
                                 size_t size,
                                 unsigned long pattern) {
    size_t i;
    unsigned char bytes[4];

    /* Extract pattern bytes (big-endian) */
    bytes[0] = (unsigned char)((pattern >> 24) & 0xFF);
    bytes[1] = (unsigned char)((pattern >> 16) & 0xFF);
    bytes[2] = (unsigned char)((pattern >> 8) & 0xFF);
    bytes[3] = (unsigned char)(pattern & 0xFF);

    /* Write pattern repeatedly */
    for (i = 0; i < size; i++) {
        ptr[i] = bytes[i % 4];
    }
}

/**
 * verify_guard_pattern - Check memory contains expected pattern
 */
static int verify_guard_pattern(const unsigned char *ptr,
                                 size_t size,
                                 unsigned long pattern) {
    size_t i;
    unsigned char bytes[4];

    /* Extract pattern bytes (big-endian) */
    bytes[0] = (unsigned char)((pattern >> 24) & 0xFF);
    bytes[1] = (unsigned char)((pattern >> 16) & 0xFF);
    bytes[2] = (unsigned char)((pattern >> 8) & 0xFF);
    bytes[3] = (unsigned char)(pattern & 0xFF);

    /* Verify pattern */
    for (i = 0; i < size; i++) {
        if (ptr[i] != bytes[i % 4]) {
            return 0;  /* Mismatch */
        }
    }

    return 1;  /* Match */
}

/* ============================================================================
 * Block Initialization
 * ============================================================================ */

rampart_error_t rp_block_init(rp_block_header_t *block,
                               size_t total_size,
                               size_t user_size,
                               rp_thread_id_t owner) {
    if (block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    /* Initialize header fields */
    block->magic = RP_BLOCK_MAGIC;
    block->total_size = total_size;
    block->user_size = user_size;
    block->flags = RP_FLAG_ALLOCATED;
    block->owner_thread = owner;
    block->prev = NULL;
    block->next = NULL;
    block->prev_addr = NULL;
    block->next_addr = NULL;

    /* Clear padding */
    memset(block->padding, 0, sizeof(block->padding));

    return RAMPART_OK;
}

rampart_error_t rp_block_init_as_free(rp_block_header_t *block,
                                       size_t total_size) {
    rp_thread_id_t zero_thread;

    if (block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    /* Zero out thread ID */
    memset(&zero_thread, 0, sizeof(zero_thread));

    /* Initialize as free block */
    block->magic = RP_BLOCK_FREED_MAGIC;
    block->total_size = total_size;
    block->user_size = 0;
    block->flags = 0;  /* Not allocated */
    block->owner_thread = zero_thread;
    block->prev = NULL;
    block->next = NULL;
    block->prev_addr = NULL;
    block->next_addr = NULL;

    /* Clear padding */
    memset(block->padding, 0, sizeof(block->padding));

    return RAMPART_OK;
}

/* ============================================================================
 * Guard Band Functions
 * ============================================================================ */

rampart_error_t rp_block_init_guards(rp_block_header_t *block) {
    unsigned char *front;
    unsigned char *rear;

    if (block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    front = RP_FRONT_GUARD(block);
    rear = RP_REAR_GUARD(block);

    write_guard_pattern(front, RP_GUARD_SIZE, RP_GUARD_FRONT_PATTERN);
    write_guard_pattern(rear, RP_GUARD_SIZE, RP_GUARD_REAR_PATTERN);

    return RAMPART_OK;
}

rampart_error_t rp_block_validate_front_guard(const rp_block_header_t *block) {
    const unsigned char *front;

    if (block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    front = (const unsigned char *)block + sizeof(rp_block_header_t);

    if (!verify_guard_pattern(front, RP_GUARD_SIZE, RP_GUARD_FRONT_PATTERN)) {
        return RAMPART_ERR_GUARD_CORRUPTED;
    }

    return RAMPART_OK;
}

rampart_error_t rp_block_validate_rear_guard(const rp_block_header_t *block) {
    const unsigned char *rear;

    if (block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    rear = (const unsigned char *)block +
           sizeof(rp_block_header_t) +
           RP_GUARD_SIZE +
           block->user_size;

    if (!verify_guard_pattern(rear, RP_GUARD_SIZE, RP_GUARD_REAR_PATTERN)) {
        return RAMPART_ERR_GUARD_CORRUPTED;
    }

    return RAMPART_OK;
}

rampart_error_t rp_block_validate_guards(const rp_block_header_t *block) {
    rampart_error_t err;

    if (block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    err = rp_block_validate_front_guard(block);
    if (err != RAMPART_OK) {
        return err;
    }

    err = rp_block_validate_rear_guard(block);
    if (err != RAMPART_OK) {
        return err;
    }

    return RAMPART_OK;
}

/* ============================================================================
 * Block Validation
 * ============================================================================ */

rampart_error_t rp_block_validate_magic(const rp_block_header_t *block) {
    if (block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    if (block->magic != RP_BLOCK_MAGIC) {
        return RAMPART_ERR_INVALID_BLOCK;
    }

    return RAMPART_OK;
}

rampart_error_t rp_block_validate(const rp_block_header_t *block) {
    rampart_error_t err;

    if (block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    /* Check magic number */
    err = rp_block_validate_magic(block);
    if (err != RAMPART_OK) {
        return err;
    }

    /* Check that block is allocated */
    if (!(block->flags & RP_FLAG_ALLOCATED)) {
        return RAMPART_ERR_INVALID_BLOCK;
    }

    /* Check guard bands */
    err = rp_block_validate_guards(block);
    if (err != RAMPART_OK) {
        return err;
    }

    return RAMPART_OK;
}

int rp_block_is_allocated(const rp_block_header_t *block) {
    if (block == NULL) {
        return 0;
    }

    return (block->magic == RP_BLOCK_MAGIC) &&
           (block->flags & RP_FLAG_ALLOCATED);
}

int rp_block_is_free(const rp_block_header_t *block) {
    if (block == NULL) {
        return 0;
    }

    return (block->magic == RP_BLOCK_FREED_MAGIC) &&
           !(block->flags & RP_FLAG_ALLOCATED);
}

/* ============================================================================
 * User Data Functions
 * ============================================================================ */

rampart_error_t rp_block_zero_user_data(rp_block_header_t *block) {
    void *user_ptr;

    if (block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    if (block->user_size == 0) {
        return RAMPART_OK;
    }

    user_ptr = RP_BLOCK_TO_USER(block);
    memset(user_ptr, 0x00, block->user_size);

    return RAMPART_OK;
}

void *rp_block_get_user_ptr(rp_block_header_t *block) {
    if (block == NULL) {
        return NULL;
    }

    return RP_BLOCK_TO_USER(block);
}

rp_block_header_t *rp_block_from_user_ptr(void *ptr) {
    if (ptr == NULL) {
        return NULL;
    }

    return RP_USER_TO_BLOCK(ptr);
}

/* ============================================================================
 * Block State Functions
 * ============================================================================ */

void rp_block_mark_allocated(rp_block_header_t *block) {
    if (block == NULL) {
        return;
    }

    block->magic = RP_BLOCK_MAGIC;
    block->flags |= RP_FLAG_ALLOCATED;
}

void rp_block_mark_freed(rp_block_header_t *block) {
    rp_thread_id_t zero_thread;

    if (block == NULL) {
        return;
    }

    memset(&zero_thread, 0, sizeof(zero_thread));

    block->magic = RP_BLOCK_FREED_MAGIC;
    block->flags &= ~(unsigned int)RP_FLAG_ALLOCATED;
    block->owner_thread = zero_thread;
}

void rp_block_set_encrypted(rp_block_header_t *block, int encrypted) {
    if (block == NULL) {
        return;
    }

    if (encrypted) {
        block->flags |= RP_FLAG_ENCRYPTED;
    } else {
        block->flags &= ~(unsigned int)RP_FLAG_ENCRYPTED;
    }
}

int rp_block_is_encrypted(const rp_block_header_t *block) {
    if (block == NULL) {
        return 0;
    }

    return (block->flags & RP_FLAG_ENCRYPTED) != 0;
}

/* ============================================================================
 * Size Calculation Functions
 * ============================================================================ */

size_t rp_block_calc_total_size(size_t user_size) {
    size_t total;

    total = sizeof(rp_block_header_t) +
            RP_GUARD_SIZE +
            user_size +
            RP_GUARD_SIZE;

    /* Align to RP_ALIGNMENT */
    total = RP_ALIGN_UP(total, RP_ALIGNMENT);

    return total;
}

size_t rp_block_calc_user_size(size_t total_size) {
    size_t overhead;

    overhead = sizeof(rp_block_header_t) + (RP_GUARD_SIZE * 2);

    if (total_size <= overhead) {
        return 0;
    }

    return total_size - overhead;
}
