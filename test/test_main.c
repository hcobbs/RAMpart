/**
 * @file test_main.c
 * @brief RAMpart test suite main entry point
 *
 * Runs all RAMpart unit tests and reports results.
 */

#include <stdio.h>
#include "test_framework.h"
#include "rampart.h"

/* Define global test state */
DEFINE_TEST_STATE();

/* ============================================================================
 * External Test Suite Declarations
 * ============================================================================ */

/* Test suites defined in separate files */
extern void run_pool_tests(void);
extern void run_block_tests(void);
extern void run_crypto_tests(void);
extern void run_wipe_tests(void);
extern void run_thread_tests(void);
extern void run_integration_tests(void);

/* ============================================================================
 * Version and Smoke Tests
 * ============================================================================ */

/**
 * test_version - Verify version functions work
 */
static void test_version(void) {
    int version;
    const char *version_str;

    version = rampart_version();
    TEST_ASSERT(version > 0);
    TEST_ASSERT_EQ(RAMPART_VERSION_MAJOR * 10000 +
                   RAMPART_VERSION_MINOR * 100 +
                   RAMPART_VERSION_PATCH, version);

    version_str = rampart_version_string();
    TEST_ASSERT_NOT_NULL(version_str);
    TEST_ASSERT_STR_EQ(RAMPART_VERSION_STRING, version_str);
}

/**
 * test_error_strings - Verify error string function
 */
static void test_error_strings(void) {
    const char *str;

    str = rampart_error_string(RAMPART_OK);
    TEST_ASSERT_NOT_NULL(str);

    str = rampart_error_string(RAMPART_ERR_NULL_PARAM);
    TEST_ASSERT_NOT_NULL(str);

    str = rampart_error_string(RAMPART_ERR_INVALID_SIZE);
    TEST_ASSERT_NOT_NULL(str);

    str = rampart_error_string(RAMPART_ERR_OUT_OF_MEMORY);
    TEST_ASSERT_NOT_NULL(str);

    str = rampart_error_string(RAMPART_ERR_INVALID_BLOCK);
    TEST_ASSERT_NOT_NULL(str);

    str = rampart_error_string(RAMPART_ERR_GUARD_CORRUPTED);
    TEST_ASSERT_NOT_NULL(str);

    str = rampart_error_string(RAMPART_ERR_WRONG_THREAD);
    TEST_ASSERT_NOT_NULL(str);

    str = rampart_error_string(RAMPART_ERR_DOUBLE_FREE);
    TEST_ASSERT_NOT_NULL(str);

    str = rampart_error_string(RAMPART_ERR_NOT_INITIALIZED);
    TEST_ASSERT_NOT_NULL(str);

    str = rampart_error_string(RAMPART_ERR_INVALID_CONFIG);
    TEST_ASSERT_NOT_NULL(str);

    /* Unknown error should still return something */
    str = rampart_error_string((rampart_error_t)9999);
    TEST_ASSERT_NOT_NULL(str);
}

/**
 * test_config_default - Verify default configuration
 */
static void test_config_default(void) {
    rampart_config_t config;
    rampart_error_t err;

    /* Should fail with NULL */
    err = rampart_config_default(NULL);
    TEST_ASSERT_ERR(RAMPART_ERR_NULL_PARAM, err);

    /* Should succeed with valid pointer */
    err = rampart_config_default(&config);
    TEST_ASSERT_OK(err);

    /* Verify defaults */
    TEST_ASSERT_EQ(0, config.pool_size);
    TEST_ASSERT_EQ(0, config.encryption_enabled);
    TEST_ASSERT_NULL(config.encryption_key);
    TEST_ASSERT_EQ(0, config.encryption_key_size);
    TEST_ASSERT_EQ(1, config.strict_thread_mode);
    TEST_ASSERT_EQ(1, config.validate_on_free);
    TEST_ASSERT_NULL(config.error_callback);
    TEST_ASSERT_NULL(config.callback_user_data);
}

/**
 * test_init_null_config - Verify init fails with NULL config
 */
static void test_init_null_config(void) {
    rampart_pool_t *pool;

    pool = rampart_init(NULL);
    TEST_ASSERT_NULL(pool);
}

/**
 * test_init_zero_size - Verify init fails with zero pool size
 */
static void test_init_zero_size(void) {
    rampart_config_t config;
    rampart_pool_t *pool;

    rampart_config_default(&config);
    config.pool_size = 0;

    pool = rampart_init(&config);
    TEST_ASSERT_NULL(pool);
}

/**
 * test_init_small_size - Verify init fails with too-small pool size
 */
static void test_init_small_size(void) {
    rampart_config_t config;
    rampart_pool_t *pool;

    rampart_config_default(&config);
    config.pool_size = 100;  /* Too small */

    pool = rampart_init(&config);
    TEST_ASSERT_NULL(pool);
}

/**
 * test_basic_init_shutdown - Basic pool lifecycle
 */
static void test_basic_init_shutdown(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;  /* 64 KB */

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    result = rampart_shutdown(pool);
    TEST_ASSERT_EQ(0, result.leaked_blocks);
    TEST_ASSERT_EQ(0, result.leaked_bytes);
}

/**
 * test_alloc_free_basic - Basic allocation and free
 */
static void test_alloc_free_basic(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;
    void *ptr;
    rampart_error_t err;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Allocate */
    ptr = rampart_alloc(pool, 256);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Free */
    err = rampart_free(pool, ptr);
    TEST_ASSERT_OK(err);

    /* Shutdown should show no leaks */
    result = rampart_shutdown(pool);
    TEST_ASSERT_EQ(0, result.leaked_blocks);
}

/**
 * test_alloc_zero_initialized - Verify memory is zero-initialized
 */
static void test_alloc_zero_initialized(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    unsigned char *ptr;
    size_t i;
    int all_zero;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    ptr = (unsigned char *)rampart_alloc(pool, 1024);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Check all bytes are zero */
    all_zero = 1;
    for (i = 0; i < 1024; i++) {
        if (ptr[i] != 0x00) {
            all_zero = 0;
            break;
        }
    }
    TEST_ASSERT(all_zero);

    rampart_free(pool, ptr);
    rampart_shutdown(pool);
}

/**
 * test_multiple_allocs - Multiple allocations
 */
static void test_multiple_allocs(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;
    void *ptrs[10];
    int i;
    rampart_error_t err;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Allocate multiple blocks */
    for (i = 0; i < 10; i++) {
        ptrs[i] = rampart_alloc(pool, 128);
        TEST_ASSERT_NOT_NULL(ptrs[i]);
    }

    /* Free all */
    for (i = 0; i < 10; i++) {
        err = rampart_free(pool, ptrs[i]);
        TEST_ASSERT_OK(err);
    }

    result = rampart_shutdown(pool);
    TEST_ASSERT_EQ(0, result.leaked_blocks);
}

/**
 * test_leak_detection - Verify leak detection works
 */
static void test_leak_detection(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;
    void *ptr;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Allocate but don't free */
    ptr = rampart_alloc(pool, 256);
    TEST_ASSERT_NOT_NULL(ptr);
    (void)ptr;  /* Suppress unused warning */

    /* Shutdown should detect leak */
    result = rampart_shutdown(pool);
    TEST_ASSERT_EQ(1, result.leaked_blocks);
    TEST_ASSERT(result.leaked_bytes >= 256);
}

/**
 * test_stats_basic - Basic statistics
 */
static void test_stats_basic(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_stats_t stats;
    rampart_error_t err;
    void *ptr;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Get initial stats */
    err = rampart_get_stats(pool, &stats);
    TEST_ASSERT_OK(err);
    TEST_ASSERT_EQ(64 * 1024, stats.total_size);
    TEST_ASSERT_EQ(0, stats.allocation_count);

    /* Allocate and check stats */
    ptr = rampart_alloc(pool, 1024);
    TEST_ASSERT_NOT_NULL(ptr);

    err = rampart_get_stats(pool, &stats);
    TEST_ASSERT_OK(err);
    TEST_ASSERT_EQ(1, stats.allocation_count);
    TEST_ASSERT(stats.used_size > 0);

    rampart_free(pool, ptr);
    rampart_shutdown(pool);
}

/* ============================================================================
 * Main Entry Point
 * ============================================================================ */

int main(void) {
    int result = 0;

    printf("\n");
    printf("################################################\n");
    printf("#           RAMpart Test Suite                 #\n");
    printf("#           Version %s                       #\n", RAMPART_VERSION_STRING);
    printf("################################################\n");

    /* Core API Tests */
    TEST_SUITE_BEGIN("Core API Tests");
    RUN_TEST(test_version);
    RUN_TEST(test_error_strings);
    RUN_TEST(test_config_default);
    RUN_TEST(test_init_null_config);
    RUN_TEST(test_init_zero_size);
    RUN_TEST(test_init_small_size);
    RUN_TEST(test_basic_init_shutdown);
    RUN_TEST(test_alloc_free_basic);
    RUN_TEST(test_alloc_zero_initialized);
    RUN_TEST(test_multiple_allocs);
    RUN_TEST(test_leak_detection);
    RUN_TEST(test_stats_basic);
    TEST_SUITE_END();
    result |= TEST_SUITE_RESULT();

    /* Module-specific tests (when implemented) */
    /* Uncomment as modules are implemented:
    run_pool_tests();
    result |= TEST_SUITE_RESULT();

    run_block_tests();
    result |= TEST_SUITE_RESULT();

    run_crypto_tests();
    result |= TEST_SUITE_RESULT();

    run_wipe_tests();
    result |= TEST_SUITE_RESULT();

    run_thread_tests();
    result |= TEST_SUITE_RESULT();

    run_integration_tests();
    result |= TEST_SUITE_RESULT();
    */

    printf("\n################################################\n");
    if (result == 0) {
        printf("#           ALL TEST SUITES PASSED            #\n");
    } else {
        printf("#          SOME TEST SUITES FAILED            #\n");
    }
    printf("################################################\n\n");

    return result;
}
