/**
 * @file test_wipe.c
 * @brief RAMpart secure memory wiping tests
 *
 * Verifies that memory is properly wiped after free to prevent
 * data recovery.
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

#include <stdio.h>
#include <string.h>
#include "test_framework.h"
#include "rampart.h"
#include "internal/rp_wipe.h"
#include "internal/rp_types.h"

/* External test state from test_main.c */
extern test_state_t g_test_state;

/* Forward declaration for this module's test suite runner */
void run_wipe_tests(void);

/* ============================================================================
 * Direct Wipe Function Tests
 * ============================================================================ */

/**
 * test_wipe_memory_single_zeros - Test single pass wipe with zeros
 */
static void test_wipe_memory_single_zeros(void) {
    unsigned char buffer[64];
    rampart_error_t err;
    int i;

    /* Fill with non-zero data */
    memset(buffer, 0xAB, sizeof(buffer));

    /* Wipe with zeros */
    err = rp_wipe_memory_single(buffer, sizeof(buffer), RP_WIPE_PATTERN_1);
    TEST_ASSERT_OK(err);

    /* Verify all zeros */
    for (i = 0; i < 64; i++) {
        TEST_ASSERT_EQ(0x00, buffer[i]);
    }
}

/**
 * test_wipe_memory_single_ones - Test single pass wipe with ones
 */
static void test_wipe_memory_single_ones(void) {
    unsigned char buffer[64];
    rampart_error_t err;
    int i;

    /* Fill with zeros */
    memset(buffer, 0x00, sizeof(buffer));

    /* Wipe with ones */
    err = rp_wipe_memory_single(buffer, sizeof(buffer), RP_WIPE_PATTERN_2);
    TEST_ASSERT_OK(err);

    /* Verify all 0xFF */
    for (i = 0; i < 64; i++) {
        TEST_ASSERT_EQ(0xFF, buffer[i]);
    }
}

/**
 * test_wipe_memory_single_alternating - Test wipe with alternating pattern
 */
static void test_wipe_memory_single_alternating(void) {
    unsigned char buffer[64];
    rampart_error_t err;
    int i;

    memset(buffer, 0x00, sizeof(buffer));

    /* Wipe with alternating pattern (0xAA) */
    err = rp_wipe_memory_single(buffer, sizeof(buffer), RP_WIPE_PATTERN_3);
    TEST_ASSERT_OK(err);

    /* Verify pattern */
    for (i = 0; i < 64; i++) {
        TEST_ASSERT_EQ(0xAA, buffer[i]);
    }
}

/**
 * test_wipe_memory_multi_pass - Test 3-pass wipe
 */
static void test_wipe_memory_multi_pass(void) {
    unsigned char buffer[128];
    rampart_error_t err;

    /* Fill with sensitive data pattern */
    memset(buffer, 0xDE, sizeof(buffer));

    /* Multi-pass wipe */
    err = rp_wipe_memory(buffer, sizeof(buffer));
    TEST_ASSERT_OK(err);

    /* After 3-pass wipe, final pattern should be RP_WIPE_PATTERN_3 (0xAA) */
    err = rp_wipe_verify(buffer, sizeof(buffer), RP_WIPE_PATTERN_3);
    TEST_ASSERT_OK(err);
}

/**
 * test_wipe_verify_function - Test verification function
 */
static void test_wipe_verify_function(void) {
    unsigned char buffer[32];
    rampart_error_t err;

    /* Fill with pattern */
    memset(buffer, 0x55, sizeof(buffer));

    /* Verify should succeed */
    err = rp_wipe_verify(buffer, sizeof(buffer), 0x55);
    TEST_ASSERT_OK(err);

    /* Corrupt one byte */
    buffer[16] = 0xAA;

    /* Verify should fail */
    err = rp_wipe_verify(buffer, sizeof(buffer), 0x55);
    TEST_ASSERT_ERR(RAMPART_ERR_INTERNAL, err);
}

/**
 * test_wipe_null_params - Test wipe with null parameters
 */
static void test_wipe_null_params(void) {
    unsigned char buffer[32];
    rampart_error_t err;

    err = rp_wipe_memory(NULL, 32);
    TEST_ASSERT_ERR(RAMPART_ERR_NULL_PARAM, err);

    err = rp_wipe_memory_single(NULL, 32, 0x00);
    TEST_ASSERT_ERR(RAMPART_ERR_NULL_PARAM, err);

    err = rp_wipe_verify(NULL, 32, 0x00);
    TEST_ASSERT_ERR(RAMPART_ERR_NULL_PARAM, err);

    /* Zero size should succeed (no-op) */
    err = rp_wipe_memory(buffer, 0);
    TEST_ASSERT_OK(err);

    err = rp_wipe_memory_single(buffer, 0, 0x00);
    TEST_ASSERT_OK(err);
}

/**
 * test_wipe_various_sizes - Test wipe with various buffer sizes
 */
static void test_wipe_various_sizes(void) {
    unsigned char buffer[1024];
    size_t sizes[] = {1, 7, 8, 15, 16, 17, 31, 32, 63, 64, 128, 256, 512, 1024};
    int num_sizes = (int)(sizeof(sizes) / sizeof(sizes[0]));
    int i;
    rampart_error_t err;

    for (i = 0; i < num_sizes; i++) {
        memset(buffer, 0xCD, sizes[i]);

        err = rp_wipe_memory(buffer, sizes[i]);
        TEST_ASSERT_OK(err);

        err = rp_wipe_verify(buffer, sizes[i], RP_WIPE_PATTERN_3);
        TEST_ASSERT_OK(err);
    }
}

/* ============================================================================
 * Integration Tests - Wipe on Free
 * ============================================================================ */

/**
 * test_freed_memory_wiped - Verify memory is wiped after rampart_free
 *
 * Note: This test relies on implementation details and may be fragile.
 * The purpose is to verify the wipe actually occurs.
 */
static void test_freed_memory_wiped(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    unsigned char *ptr;
    unsigned char *raw_ptr;
    size_t alloc_size = 256;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Allocate and write sensitive data */
    ptr = (unsigned char *)rampart_alloc(pool, alloc_size);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Write a distinctive pattern */
    memset(ptr, 0xDE, alloc_size);

    /* Save pointer before free (for post-free inspection) */
    raw_ptr = ptr;

    /* Free the block - should trigger wipe */
    rampart_free(pool, ptr);

    /*
     * After free, the memory should be wiped.
     * The final wipe pattern is 0xAA (RP_WIPE_PATTERN_3).
     * Note: This accesses freed memory which is normally undefined behavior,
     * but in RAMpart the memory is still within the pool.
     */
    TEST_ASSERT_EQ(0xAA, raw_ptr[0]);
    TEST_ASSERT_EQ(0xAA, raw_ptr[alloc_size / 2]);
    TEST_ASSERT_EQ(0xAA, raw_ptr[alloc_size - 1]);

    rampart_shutdown(pool);
}

/**
 * test_wipe_with_reallocation - Verify wipe persists through reallocation
 */
static void test_wipe_with_reallocation(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    unsigned char *ptr1;
    unsigned char *ptr2;
    size_t i;
    int found_old_data = 0;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* First allocation - write distinctive data */
    ptr1 = (unsigned char *)rampart_alloc(pool, 128);
    TEST_ASSERT_NOT_NULL(ptr1);
    memset(ptr1, 0xBE, 128);

    /* Free it */
    rampart_free(pool, ptr1);

    /* Allocate again - should get same memory */
    ptr2 = (unsigned char *)rampart_alloc(pool, 128);
    TEST_ASSERT_NOT_NULL(ptr2);

    /* New allocation should be zero-initialized, not contain old data */
    for (i = 0; i < 128; i++) {
        if (ptr2[i] == 0xBE) {
            found_old_data = 1;
            break;
        }
    }
    TEST_ASSERT_EQ(0, found_old_data);

    rampart_free(pool, ptr2);
    rampart_shutdown(pool);
}

/* ============================================================================
 * Run All Wipe Tests
 * ============================================================================ */

void run_wipe_tests(void) {
    TEST_SUITE_BEGIN("Memory Wipe Tests");

    RUN_TEST(test_wipe_memory_single_zeros);
    RUN_TEST(test_wipe_memory_single_ones);
    RUN_TEST(test_wipe_memory_single_alternating);
    RUN_TEST(test_wipe_memory_multi_pass);
    RUN_TEST(test_wipe_verify_function);
    RUN_TEST(test_wipe_null_params);
    RUN_TEST(test_wipe_various_sizes);
    RUN_TEST(test_freed_memory_wiped);
    RUN_TEST(test_wipe_with_reallocation);

    TEST_SUITE_END();
}
