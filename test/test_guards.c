/**
 * @file test_guards.c
 * @brief RAMpart guard band corruption detection tests
 *
 * Verifies that buffer overflows and underflows are properly detected
 * via guard band corruption.
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
#include "internal/rp_block.h"
#include "internal/rp_types.h"
#include "internal/rp_pool.h"

/* External test state from test_main.c */
extern test_state_t g_test_state;

/* Forward declaration for this module's test suite runner */
void run_guard_tests(void);

/* ============================================================================
 * Guard Pattern Tests
 * ============================================================================ */

/**
 * test_front_guard_pattern - Verify front guard is correctly initialized
 *
 * Note: With VULN-004 fix, patterns are randomized per-pool, so we verify
 * that the guard matches the pool's pattern rather than a fixed value.
 */
static void test_front_guard_pattern(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rp_pool_header_t *p;
    unsigned char *ptr;
    unsigned char *front_guard;
    rp_block_header_t *block;
    rampart_error_t err;
    unsigned char expected[4];

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    p = (rp_pool_header_t *)pool;

    ptr = (unsigned char *)rampart_alloc(pool, 128);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Get block header and front guard */
    block = RP_USER_TO_BLOCK(ptr);
    front_guard = RP_FRONT_GUARD(block);

    /* Verify front guard matches pool's randomized pattern */
    expected[0] = (unsigned char)((p->guard_front_pattern >> 24) & 0xFF);
    expected[1] = (unsigned char)((p->guard_front_pattern >> 16) & 0xFF);
    expected[2] = (unsigned char)((p->guard_front_pattern >> 8) & 0xFF);
    expected[3] = (unsigned char)(p->guard_front_pattern & 0xFF);

    TEST_ASSERT_EQ(expected[0], front_guard[0]);
    TEST_ASSERT_EQ(expected[1], front_guard[1]);
    TEST_ASSERT_EQ(expected[2], front_guard[2]);
    TEST_ASSERT_EQ(expected[3], front_guard[3]);

    /* Validate via function */
    err = rp_block_validate_front_guard(p, block);
    TEST_ASSERT_OK(err);

    rampart_free(pool, ptr);
    rampart_shutdown(pool);
}

/**
 * test_rear_guard_pattern - Verify rear guard is correctly initialized
 *
 * Note: With VULN-004 fix, patterns are randomized per-pool, so we verify
 * that the guard matches the pool's pattern rather than a fixed value.
 */
static void test_rear_guard_pattern(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rp_pool_header_t *p;
    unsigned char *ptr;
    unsigned char *rear_guard;
    rp_block_header_t *block;
    rampart_error_t err;
    unsigned char expected[4];

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    p = (rp_pool_header_t *)pool;

    ptr = (unsigned char *)rampart_alloc(pool, 128);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Get block header and rear guard */
    block = RP_USER_TO_BLOCK(ptr);
    rear_guard = RP_REAR_GUARD(block);

    /* Verify rear guard matches pool's randomized pattern */
    expected[0] = (unsigned char)((p->guard_rear_pattern >> 24) & 0xFF);
    expected[1] = (unsigned char)((p->guard_rear_pattern >> 16) & 0xFF);
    expected[2] = (unsigned char)((p->guard_rear_pattern >> 8) & 0xFF);
    expected[3] = (unsigned char)(p->guard_rear_pattern & 0xFF);

    TEST_ASSERT_EQ(expected[0], rear_guard[0]);
    TEST_ASSERT_EQ(expected[1], rear_guard[1]);
    TEST_ASSERT_EQ(expected[2], rear_guard[2]);
    TEST_ASSERT_EQ(expected[3], rear_guard[3]);

    /* Validate via function */
    err = rp_block_validate_rear_guard(p, block);
    TEST_ASSERT_OK(err);

    rampart_free(pool, ptr);
    rampart_shutdown(pool);
}

/* ============================================================================
 * Guard Corruption Detection Tests
 * ============================================================================ */

/**
 * test_front_guard_corruption_detected - Detect corruption of front guard
 */
static void test_front_guard_corruption_detected(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rp_pool_header_t *p;
    unsigned char *ptr;
    unsigned char *front_guard;
    rp_block_header_t *block;
    rampart_error_t err;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.validate_on_free = 1;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    p = (rp_pool_header_t *)pool;

    ptr = (unsigned char *)rampart_alloc(pool, 128);
    TEST_ASSERT_NOT_NULL(ptr);

    block = RP_USER_TO_BLOCK(ptr);
    front_guard = RP_FRONT_GUARD(block);

    /* Corrupt the front guard (simulate buffer underflow) */
    front_guard[0] = 0x00;

    /* Validation should fail */
    err = rp_block_validate_front_guard(p, block);
    TEST_ASSERT_ERR(RAMPART_ERR_GUARD_CORRUPTED, err);

    /* Free should detect corruption */
    err = rampart_free(pool, ptr);
    TEST_ASSERT_ERR(RAMPART_ERR_GUARD_CORRUPTED, err);

    /* Clean up - shutdown handles the corrupted block */
    rampart_shutdown(pool);
}

/**
 * test_rear_guard_corruption_detected - Detect corruption of rear guard
 */
static void test_rear_guard_corruption_detected(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rp_pool_header_t *p;
    unsigned char *ptr;
    unsigned char *rear_guard;
    rp_block_header_t *block;
    rampart_error_t err;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.validate_on_free = 1;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    p = (rp_pool_header_t *)pool;

    ptr = (unsigned char *)rampart_alloc(pool, 128);
    TEST_ASSERT_NOT_NULL(ptr);

    block = RP_USER_TO_BLOCK(ptr);
    rear_guard = RP_REAR_GUARD(block);

    /* Corrupt the rear guard (simulate buffer overflow) */
    rear_guard[RP_GUARD_SIZE - 1] = 0xFF;

    /* Validation should fail */
    err = rp_block_validate_rear_guard(p, block);
    TEST_ASSERT_ERR(RAMPART_ERR_GUARD_CORRUPTED, err);

    /* Free should detect corruption */
    err = rampart_free(pool, ptr);
    TEST_ASSERT_ERR(RAMPART_ERR_GUARD_CORRUPTED, err);

    rampart_shutdown(pool);
}

/**
 * test_buffer_overflow_detected - Simulate actual buffer overflow
 */
static void test_buffer_overflow_detected(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    unsigned char *ptr;
    rampart_error_t err;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.validate_on_free = 1;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    ptr = (unsigned char *)rampart_alloc(pool, 64);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Write past the allocated size (overflow into rear guard) */
    ptr[64] = 0xBA;  /* This corrupts the rear guard */
    ptr[65] = 0xAD;

    /* Free should detect the overflow */
    err = rampart_free(pool, ptr);
    TEST_ASSERT_ERR(RAMPART_ERR_GUARD_CORRUPTED, err);

    rampart_shutdown(pool);
}

/**
 * test_buffer_underflow_detected - Simulate buffer underflow
 */
static void test_buffer_underflow_detected(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    unsigned char *ptr;
    rampart_error_t err;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.validate_on_free = 1;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    ptr = (unsigned char *)rampart_alloc(pool, 64);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Write before the allocated region (underflow into front guard) */
    ptr[-1] = 0xBA;  /* This corrupts the front guard */
    ptr[-2] = 0xAD;

    /* Free should detect the underflow */
    err = rampart_free(pool, ptr);
    TEST_ASSERT_ERR(RAMPART_ERR_GUARD_CORRUPTED, err);

    rampart_shutdown(pool);
}

/**
 * test_partial_guard_corruption - Corrupt single byte in guard
 */
static void test_partial_guard_corruption(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rp_pool_header_t *p;
    unsigned char *ptr;
    unsigned char *front_guard;
    rp_block_header_t *block;
    rampart_error_t err;
    int i;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    p = (rp_pool_header_t *)pool;

    /* Test corruption at each position in front guard */
    for (i = 0; i < (int)RP_GUARD_SIZE; i++) {
        ptr = (unsigned char *)rampart_alloc(pool, 32);
        TEST_ASSERT_NOT_NULL(ptr);

        block = RP_USER_TO_BLOCK(ptr);
        front_guard = RP_FRONT_GUARD(block);

        /* Corrupt single byte at position i */
        front_guard[i] ^= 0xFF;

        /* Should be detected */
        err = rp_block_validate_front_guard(p, block);
        TEST_ASSERT_ERR(RAMPART_ERR_GUARD_CORRUPTED, err);

        /* Restore for clean free (avoid cascading failures) */
        front_guard[i] ^= 0xFF;
        rampart_free(pool, ptr);
    }

    rampart_shutdown(pool);
}

/**
 * test_validate_on_free_always_enabled - Validation cannot be disabled (VULN-013 fix)
 *
 * As of version 1.0.1, validate_on_free is always enabled for security.
 * Setting it to 0 has no effect. This test verifies corruption is still detected.
 */
static void test_validate_on_free_always_enabled(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    unsigned char *ptr;
    rampart_error_t err;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.validate_on_free = 0;  /* Attempt to disable (ignored since VULN-013 fix) */

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    ptr = (unsigned char *)rampart_alloc(pool, 64);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Corrupt rear guard */
    ptr[64] = 0xBA;

    /* Free should FAIL because validation is now always enabled */
    err = rampart_free(pool, ptr);
    TEST_ASSERT_ERR(RAMPART_ERR_GUARD_CORRUPTED, err);

    /* Block is still allocated (free failed), so shutdown will clean it up */
    rampart_shutdown(pool);
}

/**
 * test_guard_sizes_various_allocs - Guards work with various allocation sizes
 */
static void test_guard_sizes_various_allocs(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rp_pool_header_t *p;
    unsigned char *ptr;
    rp_block_header_t *block;
    rampart_error_t err;
    size_t sizes[] = {1, 7, 8, 15, 16, 17, 31, 32, 63, 64, 127, 128, 256, 512};
    int num_sizes = (int)(sizeof(sizes) / sizeof(sizes[0]));
    int i;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    p = (rp_pool_header_t *)pool;

    for (i = 0; i < num_sizes; i++) {
        ptr = (unsigned char *)rampart_alloc(pool, sizes[i]);
        TEST_ASSERT_NOT_NULL(ptr);

        block = RP_USER_TO_BLOCK(ptr);

        /* Both guards should be valid */
        err = rp_block_validate_guards(p, block);
        TEST_ASSERT_OK(err);

        rampart_free(pool, ptr);
    }

    rampart_shutdown(pool);
}

/* ============================================================================
 * Run All Guard Tests
 * ============================================================================ */

void run_guard_tests(void) {
    TEST_SUITE_BEGIN("Guard Band Tests");

    RUN_TEST(test_front_guard_pattern);
    RUN_TEST(test_rear_guard_pattern);
    RUN_TEST(test_front_guard_corruption_detected);
    RUN_TEST(test_rear_guard_corruption_detected);
    RUN_TEST(test_buffer_overflow_detected);
    RUN_TEST(test_buffer_underflow_detected);
    RUN_TEST(test_partial_guard_corruption);
    RUN_TEST(test_validate_on_free_always_enabled);
    RUN_TEST(test_guard_sizes_various_allocs);

    TEST_SUITE_END();
}
