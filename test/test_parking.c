/**
 * @file test_parking.c
 * @brief RAMpart block parking (encryption at rest) tests
 *
 * Tests for the park/unpark functionality that provides limited
 * encryption protection for data at rest in memory.
 *
 * Copyright (C) 2024 Hunter Cobbs
 */

#include "rampart.h"
#include "test_framework.h"
#include <string.h>
#include <stdio.h>

/* Forward declaration */
void register_parking_tests(void);

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static rampart_pool_t *create_parking_pool(void) {
    rampart_config_t config;
    rampart_config_default(&config);
    config.pool_size = 64 * 1024;  /* 64KB */
    config.enable_parking = 1;
    return rampart_init(&config);
}

static rampart_pool_t *create_non_parking_pool(void) {
    rampart_config_t config;
    rampart_config_default(&config);
    config.pool_size = 64 * 1024;  /* 64KB */
    config.enable_parking = 0;
    return rampart_init(&config);
}

/* ============================================================================
 * Test: Parking Disabled Pool
 * ============================================================================ */

static void test_parking_disabled(void) {
    rampart_pool_t *pool;
    void *ptr;
    rampart_error_t err;

    pool = create_non_parking_pool();
    TEST_ASSERT_NOT_NULL(pool);

    ptr = rampart_alloc(pool, 100);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Parking should fail on non-parking pool */
    err = rampart_park(pool, ptr);
    TEST_ASSERT_ERR(RAMPART_ERR_PARKING_DISABLED, err);

    /* Unpark should also fail */
    err = rampart_unpark(pool, ptr);
    TEST_ASSERT_ERR(RAMPART_ERR_PARKING_DISABLED, err);

    /* is_parked should return 0 */
    TEST_ASSERT_EQ(0, rampart_is_parked(pool, ptr));

    rampart_free(pool, ptr);
    rampart_shutdown(pool);
}

/* ============================================================================
 * Test: Basic Park/Unpark
 * ============================================================================ */

static void test_park_unpark_basic(void) {
    rampart_pool_t *pool;
    unsigned char *ptr;
    unsigned char original[100];
    rampart_error_t err;
    size_t i;
    int different;

    pool = create_parking_pool();
    TEST_ASSERT_NOT_NULL(pool);

    ptr = (unsigned char *)rampart_alloc(pool, 100);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Write known pattern */
    for (i = 0; i < 100; i++) {
        ptr[i] = (unsigned char)(i & 0xFF);
        original[i] = ptr[i];
    }

    /* Verify not parked initially */
    TEST_ASSERT_EQ(0, rampart_is_parked(pool, ptr));

    /* Park the block */
    err = rampart_park(pool, ptr);
    TEST_ASSERT_OK(err);

    /* Verify parked */
    TEST_ASSERT_EQ(1, rampart_is_parked(pool, ptr));

    /* Data should be encrypted (different from original) */
    different = 0;
    for (i = 0; i < 100; i++) {
        if (ptr[i] != original[i]) {
            different = 1;
            break;
        }
    }
    TEST_ASSERT_MSG(different, "Parked data should be encrypted");

    /* Unpark the block */
    err = rampart_unpark(pool, ptr);
    TEST_ASSERT_OK(err);

    /* Verify not parked */
    TEST_ASSERT_EQ(0, rampart_is_parked(pool, ptr));

    /* Data should be restored */
    for (i = 0; i < 100; i++) {
        TEST_ASSERT_EQ(original[i], ptr[i]);
    }

    rampart_free(pool, ptr);
    rampart_shutdown(pool);
}

/* ============================================================================
 * Test: Double Park Error
 * ============================================================================ */

static void test_double_park_error(void) {
    rampart_pool_t *pool;
    void *ptr;
    rampart_error_t err;

    pool = create_parking_pool();
    TEST_ASSERT_NOT_NULL(pool);

    ptr = rampart_alloc(pool, 100);
    TEST_ASSERT_NOT_NULL(ptr);

    /* First park should succeed */
    err = rampart_park(pool, ptr);
    TEST_ASSERT_OK(err);

    /* Second park should fail */
    err = rampart_park(pool, ptr);
    TEST_ASSERT_ERR(RAMPART_ERR_BLOCK_PARKED, err);

    /* Unpark to clean up */
    err = rampart_unpark(pool, ptr);
    TEST_ASSERT_OK(err);

    rampart_free(pool, ptr);
    rampart_shutdown(pool);
}

/* ============================================================================
 * Test: Unpark Not Parked Error
 * ============================================================================ */

static void test_unpark_not_parked_error(void) {
    rampart_pool_t *pool;
    void *ptr;
    rampart_error_t err;

    pool = create_parking_pool();
    TEST_ASSERT_NOT_NULL(pool);

    ptr = rampart_alloc(pool, 100);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Unpark without parking should fail */
    err = rampart_unpark(pool, ptr);
    TEST_ASSERT_ERR(RAMPART_ERR_NOT_PARKED, err);

    rampart_free(pool, ptr);
    rampart_shutdown(pool);
}

/* ============================================================================
 * Test: Free Parked Block Error
 * ============================================================================ */

static void test_free_parked_block_error(void) {
    rampart_pool_t *pool;
    void *ptr;
    rampart_error_t err;

    pool = create_parking_pool();
    TEST_ASSERT_NOT_NULL(pool);

    ptr = rampart_alloc(pool, 100);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Park the block */
    err = rampart_park(pool, ptr);
    TEST_ASSERT_OK(err);

    /* Try to free parked block (should fail) */
    err = rampart_free(pool, ptr);
    TEST_ASSERT_ERR(RAMPART_ERR_BLOCK_PARKED, err);

    /* Unpark then free */
    err = rampart_unpark(pool, ptr);
    TEST_ASSERT_OK(err);

    err = rampart_free(pool, ptr);
    TEST_ASSERT_OK(err);

    rampart_shutdown(pool);
}

/* ============================================================================
 * Test: Multiple Park/Unpark Cycles
 * ============================================================================ */

static void test_multiple_park_cycles(void) {
    rampart_pool_t *pool;
    unsigned char *ptr;
    unsigned char original[256];
    rampart_error_t err;
    size_t i;
    int cycle;

    pool = create_parking_pool();
    TEST_ASSERT_NOT_NULL(pool);

    ptr = (unsigned char *)rampart_alloc(pool, 256);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Write pattern */
    for (i = 0; i < 256; i++) {
        ptr[i] = (unsigned char)i;
        original[i] = (unsigned char)i;
    }

    /* Multiple park/unpark cycles */
    for (cycle = 0; cycle < 5; cycle++) {
        /* Park */
        err = rampart_park(pool, ptr);
        TEST_ASSERT_OK(err);
        TEST_ASSERT_EQ(1, rampart_is_parked(pool, ptr));

        /* Unpark */
        err = rampart_unpark(pool, ptr);
        TEST_ASSERT_OK(err);
        TEST_ASSERT_EQ(0, rampart_is_parked(pool, ptr));

        /* Verify data integrity */
        for (i = 0; i < 256; i++) {
            TEST_ASSERT_EQ(original[i], ptr[i]);
        }
    }

    rampart_free(pool, ptr);
    rampart_shutdown(pool);
}

/* ============================================================================
 * Test: Park Multiple Blocks
 * ============================================================================ */

static void test_park_multiple_blocks(void) {
    rampart_pool_t *pool;
    unsigned char *ptr1;
    unsigned char *ptr2;
    unsigned char *ptr3;
    unsigned char orig1[100];
    unsigned char orig2[200];
    unsigned char orig3[50];
    rampart_error_t err;
    size_t i;

    pool = create_parking_pool();
    TEST_ASSERT_NOT_NULL(pool);

    ptr1 = (unsigned char *)rampart_alloc(pool, 100);
    ptr2 = (unsigned char *)rampart_alloc(pool, 200);
    ptr3 = (unsigned char *)rampart_alloc(pool, 50);

    TEST_ASSERT_NOT_NULL(ptr1);
    TEST_ASSERT_NOT_NULL(ptr2);
    TEST_ASSERT_NOT_NULL(ptr3);

    /* Write different patterns */
    for (i = 0; i < 100; i++) {
        ptr1[i] = (unsigned char)(i + 1);
        orig1[i] = ptr1[i];
    }
    for (i = 0; i < 200; i++) {
        ptr2[i] = (unsigned char)(i + 100);
        orig2[i] = ptr2[i];
    }
    for (i = 0; i < 50; i++) {
        ptr3[i] = (unsigned char)(255 - i);
        orig3[i] = ptr3[i];
    }

    /* Park all blocks */
    err = rampart_park(pool, ptr1);
    TEST_ASSERT_OK(err);
    err = rampart_park(pool, ptr2);
    TEST_ASSERT_OK(err);
    err = rampart_park(pool, ptr3);
    TEST_ASSERT_OK(err);

    /* Verify all parked */
    TEST_ASSERT_EQ(1, rampart_is_parked(pool, ptr1));
    TEST_ASSERT_EQ(1, rampart_is_parked(pool, ptr2));
    TEST_ASSERT_EQ(1, rampart_is_parked(pool, ptr3));

    /* Unpark in different order */
    err = rampart_unpark(pool, ptr2);
    TEST_ASSERT_OK(err);
    err = rampart_unpark(pool, ptr1);
    TEST_ASSERT_OK(err);
    err = rampart_unpark(pool, ptr3);
    TEST_ASSERT_OK(err);

    /* Verify data integrity for all */
    for (i = 0; i < 100; i++) {
        TEST_ASSERT_EQ(orig1[i], ptr1[i]);
    }
    for (i = 0; i < 200; i++) {
        TEST_ASSERT_EQ(orig2[i], ptr2[i]);
    }
    for (i = 0; i < 50; i++) {
        TEST_ASSERT_EQ(orig3[i], ptr3[i]);
    }

    rampart_free(pool, ptr1);
    rampart_free(pool, ptr2);
    rampart_free(pool, ptr3);
    rampart_shutdown(pool);
}

/* ============================================================================
 * Test: Park with User-Provided Key
 * ============================================================================ */

static void test_park_with_user_key(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    unsigned char *ptr;
    unsigned char original[100];
    unsigned char key[32];
    rampart_error_t err;
    size_t i;

    /* Create a deterministic key */
    for (i = 0; i < 32; i++) {
        key[i] = (unsigned char)(i * 7 + 13);
    }

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.enable_parking = 1;
    config.parking_key = key;
    config.parking_key_len = 32;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    ptr = (unsigned char *)rampart_alloc(pool, 100);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Write pattern */
    for (i = 0; i < 100; i++) {
        ptr[i] = (unsigned char)i;
        original[i] = (unsigned char)i;
    }

    /* Park and unpark */
    err = rampart_park(pool, ptr);
    TEST_ASSERT_OK(err);

    err = rampart_unpark(pool, ptr);
    TEST_ASSERT_OK(err);

    /* Verify data */
    for (i = 0; i < 100; i++) {
        TEST_ASSERT_EQ(original[i], ptr[i]);
    }

    rampart_free(pool, ptr);
    rampart_shutdown(pool);
}

/* ============================================================================
 * Test: Park NULL Parameters
 * ============================================================================ */

static void test_park_null_params(void) {
    rampart_pool_t *pool;
    void *ptr;
    rampart_error_t err;

    pool = create_parking_pool();
    TEST_ASSERT_NOT_NULL(pool);

    ptr = rampart_alloc(pool, 100);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Park with NULL pool */
    err = rampart_park(NULL, ptr);
    TEST_ASSERT_ERR(RAMPART_ERR_NOT_INITIALIZED, err);

    /* Park with NULL ptr */
    err = rampart_park(pool, NULL);
    TEST_ASSERT_ERR(RAMPART_ERR_NULL_PARAM, err);

    /* Unpark with NULL pool */
    err = rampart_unpark(NULL, ptr);
    TEST_ASSERT_ERR(RAMPART_ERR_NOT_INITIALIZED, err);

    /* Unpark with NULL ptr */
    err = rampart_unpark(pool, NULL);
    TEST_ASSERT_ERR(RAMPART_ERR_NULL_PARAM, err);

    /* is_parked with NULL */
    TEST_ASSERT_EQ(0, rampart_is_parked(NULL, ptr));
    TEST_ASSERT_EQ(0, rampart_is_parked(pool, NULL));

    rampart_free(pool, ptr);
    rampart_shutdown(pool);
}

/* ============================================================================
 * Test: Park Large Block
 * ============================================================================ */

static void test_park_large_block(void) {
    rampart_pool_t *pool;
    unsigned char *ptr;
    rampart_error_t err;
    size_t i;
    size_t size = 4096;  /* 4KB block */

    pool = create_parking_pool();
    TEST_ASSERT_NOT_NULL(pool);

    ptr = (unsigned char *)rampart_alloc(pool, size);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Write pattern */
    for (i = 0; i < size; i++) {
        ptr[i] = (unsigned char)(i % 256);
    }

    /* Park */
    err = rampart_park(pool, ptr);
    TEST_ASSERT_OK(err);

    /* Unpark */
    err = rampart_unpark(pool, ptr);
    TEST_ASSERT_OK(err);

    /* Verify data */
    for (i = 0; i < size; i++) {
        TEST_ASSERT_EQ((unsigned char)(i % 256), ptr[i]);
    }

    rampart_free(pool, ptr);
    rampart_shutdown(pool);
}

/* ============================================================================
 * Test Suite Registration
 * ============================================================================ */

void register_parking_tests(void) {
    TEST_SUITE_BEGIN("Block Parking Tests");

    RUN_TEST(test_parking_disabled);
    RUN_TEST(test_park_unpark_basic);
    RUN_TEST(test_double_park_error);
    RUN_TEST(test_unpark_not_parked_error);
    RUN_TEST(test_free_parked_block_error);
    RUN_TEST(test_multiple_park_cycles);
    RUN_TEST(test_park_multiple_blocks);
    RUN_TEST(test_park_with_user_key);
    RUN_TEST(test_park_null_params);
    RUN_TEST(test_park_large_block);

    TEST_SUITE_END();
}
