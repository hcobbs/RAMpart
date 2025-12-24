/**
 * @file test_main.c
 * @brief RAMpart test suite main entry point
 *
 * Runs all RAMpart unit tests and reports results.
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

/* POSIX threading support */
#include <pthread.h>
#include <unistd.h>

/* Define global test state */
DEFINE_TEST_STATE();

/* ============================================================================
 * External Test Suite Declarations
 * ============================================================================ */

/* Test suites defined in separate files */
extern void run_pool_tests(void);
extern void run_block_tests(void);
extern void run_wipe_tests(void);
extern void run_guard_tests(void);
extern void run_thread_tests(void);
extern void run_integration_tests(void);
extern void register_parking_tests(void);

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

    str = rampart_error_string(RAMPART_ERR_INTERNAL);
    TEST_ASSERT_NOT_NULL(str);

    str = rampart_error_string(RAMPART_ERR_BLOCK_PARKED);
    TEST_ASSERT_NOT_NULL(str);

    str = rampart_error_string(RAMPART_ERR_NOT_PARKED);
    TEST_ASSERT_NOT_NULL(str);

    str = rampart_error_string(RAMPART_ERR_PARKING_DISABLED);
    TEST_ASSERT_NOT_NULL(str);

    str = rampart_error_string(RAMPART_ERR_ENTROPY_SOURCE);
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
 * Thread Safety Tests
 * ============================================================================ */

#define THREAD_COUNT 4
#define ALLOCS_PER_THREAD 100

typedef struct thread_test_data_s {
    rampart_pool_t *pool;
    int thread_id;
    int success_count;
    int error_count;
} thread_test_data_t;

static void *thread_alloc_free_worker(void *arg) {
    thread_test_data_t *data = (thread_test_data_t *)arg;
    void *ptrs[ALLOCS_PER_THREAD];
    int i;

    data->success_count = 0;
    data->error_count = 0;

    /* Allocate all */
    for (i = 0; i < ALLOCS_PER_THREAD; i++) {
        ptrs[i] = rampart_alloc(data->pool, 64);
        if (ptrs[i] != NULL) {
            data->success_count++;
        } else {
            data->error_count++;
            ptrs[i] = NULL;
        }
    }

    /* Free all (disable strict thread mode for this test) */
    for (i = 0; i < ALLOCS_PER_THREAD; i++) {
        if (ptrs[i] != NULL) {
            rampart_free(data->pool, ptrs[i]);
        }
    }

    return NULL;
}

/**
 * test_thread_safety_basic - Multiple threads allocating concurrently
 */
static void test_thread_safety_basic(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;
    pthread_t threads[THREAD_COUNT];
    thread_test_data_t thread_data[THREAD_COUNT];
    int i;
    int total_success = 0;

    rampart_config_default(&config);
    config.pool_size = 256 * 1024;  /* 256 KB */
    config.strict_thread_mode = 0;  /* Allow cross-thread free for test */

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Launch threads */
    for (i = 0; i < THREAD_COUNT; i++) {
        thread_data[i].pool = pool;
        thread_data[i].thread_id = i;
        thread_data[i].success_count = 0;
        thread_data[i].error_count = 0;
        pthread_create(&threads[i], NULL, thread_alloc_free_worker, &thread_data[i]);
    }

    /* Wait for completion */
    for (i = 0; i < THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
        total_success += thread_data[i].success_count;
    }

    /* Verify some allocations succeeded */
    TEST_ASSERT(total_success > 0);

    result = rampart_shutdown(pool);
    TEST_ASSERT_EQ(0, result.leaked_blocks);
}

/* ============================================================================
 * Stress Tests
 * ============================================================================ */

#define STRESS_ITERATIONS 1000
#define STRESS_MAX_ALLOCS 50

/**
 * test_stress_alloc_free - Rapid allocation and deallocation
 */
static void test_stress_alloc_free(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;
    void *ptrs[STRESS_MAX_ALLOCS];
    int i, j;
    int active_count = 0;

    rampart_config_default(&config);
    config.pool_size = 512 * 1024;  /* 512 KB */

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    memset(ptrs, 0, sizeof(ptrs));

    for (i = 0; i < STRESS_ITERATIONS; i++) {
        /* Randomly allocate or free */
        if (active_count < STRESS_MAX_ALLOCS && (i % 3 != 0 || active_count == 0)) {
            /* Find empty slot and allocate */
            for (j = 0; j < STRESS_MAX_ALLOCS; j++) {
                if (ptrs[j] == NULL) {
                    ptrs[j] = rampart_alloc(pool, (size_t)(64 + (i % 256)));
                    if (ptrs[j] != NULL) {
                        active_count++;
                    }
                    break;
                }
            }
        } else if (active_count > 0) {
            /* Find allocated slot and free */
            for (j = 0; j < STRESS_MAX_ALLOCS; j++) {
                if (ptrs[j] != NULL) {
                    rampart_free(pool, ptrs[j]);
                    ptrs[j] = NULL;
                    active_count--;
                    break;
                }
            }
        }
    }

    /* Clean up remaining */
    for (j = 0; j < STRESS_MAX_ALLOCS; j++) {
        if (ptrs[j] != NULL) {
            rampart_free(pool, ptrs[j]);
        }
    }

    result = rampart_shutdown(pool);
    TEST_ASSERT_EQ(0, result.leaked_blocks);
}

/**
 * test_stress_varying_sizes - Allocate varying sizes rapidly
 */
static void test_stress_varying_sizes(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;
    void *ptr;
    size_t sizes[] = {1, 7, 16, 31, 64, 127, 256, 511, 1024, 2048, 4096};
    int num_sizes = (int)(sizeof(sizes) / sizeof(sizes[0]));
    int i, j;

    rampart_config_default(&config);
    config.pool_size = 256 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    for (i = 0; i < 100; i++) {
        for (j = 0; j < num_sizes; j++) {
            ptr = rampart_alloc(pool, sizes[j]);
            if (ptr != NULL) {
                rampart_free(pool, ptr);
            }
        }
    }

    result = rampart_shutdown(pool);
    TEST_ASSERT_EQ(0, result.leaked_blocks);
}

/* ============================================================================
 * Out of Memory Tests
 * ============================================================================ */

/**
 * test_pool_exhaustion - Fill pool until out of memory
 */
static void test_pool_exhaustion(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;
    void *ptrs[1000];
    int count = 0;
    int i;

    rampart_config_default(&config);
    config.pool_size = 16 * 1024;  /* Small pool: 16 KB */

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Allocate until failure */
    for (i = 0; i < 1000; i++) {
        ptrs[i] = rampart_alloc(pool, 256);
        if (ptrs[i] == NULL) {
            break;
        }
        count++;
    }

    /* Should have failed at some point */
    TEST_ASSERT(count > 0);
    TEST_ASSERT(count < 1000);

    /* Free all */
    for (i = 0; i < count; i++) {
        rampart_free(pool, ptrs[i]);
    }

    result = rampart_shutdown(pool);
    TEST_ASSERT_EQ(0, result.leaked_blocks);
}

/**
 * test_large_allocation_failure - Request more than pool size
 */
static void test_large_allocation_failure(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    void *ptr;

    rampart_config_default(&config);
    config.pool_size = 16 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Try to allocate more than the pool can hold */
    ptr = rampart_alloc(pool, 32 * 1024);
    TEST_ASSERT_NULL(ptr);

    rampart_shutdown(pool);
}

/**
 * test_recovery_after_oom - Pool usable after OOM
 */
static void test_recovery_after_oom(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;
    void *ptr1;
    void *ptr2;
    void *ptr3;

    rampart_config_default(&config);
    config.pool_size = 4 * 1024;  /* Very small pool */

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Fill the pool */
    ptr1 = rampart_alloc(pool, 1024);
    TEST_ASSERT_NOT_NULL(ptr1);

    ptr2 = rampart_alloc(pool, 1024);
    /* May or may not succeed depending on overhead */

    /* Try allocation that should fail */
    ptr3 = rampart_alloc(pool, 8 * 1024);
    TEST_ASSERT_NULL(ptr3);

    /* Free and reallocate - pool should recover */
    if (ptr2 != NULL) {
        rampart_free(pool, ptr2);
    }
    rampart_free(pool, ptr1);

    ptr1 = rampart_alloc(pool, 512);
    TEST_ASSERT_NOT_NULL(ptr1);

    rampart_free(pool, ptr1);

    result = rampart_shutdown(pool);
    TEST_ASSERT_EQ(0, result.leaked_blocks);
}

/* ============================================================================
 * Allocation/Deallocation Edge Cases
 * ============================================================================ */

/**
 * test_double_free_detection - Detect double free
 */
static void test_double_free_detection(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    void *ptr;
    rampart_error_t err;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    ptr = rampart_alloc(pool, 256);
    TEST_ASSERT_NOT_NULL(ptr);

    /* First free should succeed */
    err = rampart_free(pool, ptr);
    TEST_ASSERT_OK(err);

    /* Second free should fail with double free error */
    err = rampart_free(pool, ptr);
    TEST_ASSERT_ERR(RAMPART_ERR_DOUBLE_FREE, err);

    rampart_shutdown(pool);
}

/**
 * test_alloc_sizes - Various allocation sizes
 */
static void test_alloc_sizes(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;
    void *ptr;
    size_t sizes[] = {1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33,
                      63, 64, 65, 127, 128, 129, 255, 256, 257,
                      511, 512, 513, 1023, 1024, 1025};
    int num_sizes = (int)(sizeof(sizes) / sizeof(sizes[0]));
    int i;
    int success_count = 0;

    rampart_config_default(&config);
    config.pool_size = 256 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    for (i = 0; i < num_sizes; i++) {
        ptr = rampart_alloc(pool, sizes[i]);
        if (ptr != NULL) {
            success_count++;
            rampart_free(pool, ptr);
        }
    }

    TEST_ASSERT_EQ(num_sizes, success_count);

    result = rampart_shutdown(pool);
    TEST_ASSERT_EQ(0, result.leaked_blocks);
}

/**
 * test_calloc_overflow - Test calloc overflow protection
 */
static void test_calloc_overflow(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    void *ptr;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* This should trigger overflow detection */
    ptr = rampart_calloc(pool, (size_t)-1, 2);
    TEST_ASSERT_NULL(ptr);

    /* Normal calloc should work */
    ptr = rampart_calloc(pool, 10, 10);
    TEST_ASSERT_NOT_NULL(ptr);
    rampart_free(pool, ptr);

    rampart_shutdown(pool);
}

/* ============================================================================
 * Memory Leak Detection Tests
 * ============================================================================ */

/**
 * test_leak_multiple_blocks - Detect multiple leaked blocks
 */
static void test_leak_multiple_blocks(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;
    void *ptr1;
    void *ptr2;
    void *ptr3;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Allocate three blocks */
    ptr1 = rampart_alloc(pool, 100);
    ptr2 = rampart_alloc(pool, 200);
    ptr3 = rampart_alloc(pool, 300);

    TEST_ASSERT_NOT_NULL(ptr1);
    TEST_ASSERT_NOT_NULL(ptr2);
    TEST_ASSERT_NOT_NULL(ptr3);

    /* Free only one */
    rampart_free(pool, ptr2);

    /* Suppress unused warnings */
    (void)ptr1;
    (void)ptr3;

    /* Shutdown should detect 2 leaks */
    result = rampart_shutdown(pool);
    TEST_ASSERT_EQ(2, result.leaked_blocks);
    TEST_ASSERT(result.leaked_bytes >= 400);
}

/**
 * test_get_leaks_api - Test rampart_get_leaks function
 */
static void test_get_leaks_api(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_leak_info_t *leaks;
    size_t leak_count;
    rampart_error_t err;
    void *ptr1;
    void *ptr2;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Initially no leaks */
    err = rampart_get_leaks(pool, &leaks, &leak_count);
    TEST_ASSERT_OK(err);
    TEST_ASSERT_EQ(0, leak_count);
    TEST_ASSERT_NULL(leaks);

    /* Create some allocations */
    ptr1 = rampart_alloc(pool, 128);
    ptr2 = rampart_alloc(pool, 256);
    (void)ptr1;
    (void)ptr2;

    /* Should show 2 potential leaks */
    err = rampart_get_leaks(pool, &leaks, &leak_count);
    TEST_ASSERT_OK(err);
    TEST_ASSERT_EQ(2, leak_count);
    TEST_ASSERT_NOT_NULL(leaks);

    rampart_free_leak_info(leaks);
    rampart_shutdown(pool);
}

/* ============================================================================
 * Orphan Memory Tests (Unexpected Shutdown)
 * ============================================================================ */

/**
 * test_orphan_on_shutdown - Memory orphaned by abrupt shutdown
 */
static void test_orphan_on_shutdown(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;
    void *ptrs[20];
    int i;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Allocate many blocks without freeing */
    for (i = 0; i < 20; i++) {
        ptrs[i] = rampart_alloc(pool, 128);
        TEST_ASSERT_NOT_NULL(ptrs[i]);
    }

    /* Suppress unused warning */
    (void)ptrs;

    /* Shutdown without freeing - simulates unexpected termination */
    result = rampart_shutdown(pool);

    /* All blocks should be detected as leaked */
    TEST_ASSERT_EQ(20, result.leaked_blocks);
    TEST_ASSERT(result.leaked_bytes >= 20 * 128);
}

/**
 * test_partial_cleanup_orphan - Some blocks freed, some orphaned
 */
static void test_partial_cleanup_orphan(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;
    void *ptrs[10];
    int i;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Allocate 10 blocks */
    for (i = 0; i < 10; i++) {
        ptrs[i] = rampart_alloc(pool, 100);
        TEST_ASSERT_NOT_NULL(ptrs[i]);
    }

    /* Free only even-indexed blocks */
    for (i = 0; i < 10; i += 2) {
        rampart_free(pool, ptrs[i]);
    }

    /* Shutdown - should detect 5 orphaned blocks */
    result = rampart_shutdown(pool);
    TEST_ASSERT_EQ(5, result.leaked_blocks);
    TEST_ASSERT(result.leaked_bytes >= 5 * 100);
}

/* ============================================================================
 * Multi-Thread Stress Test
 * ============================================================================ */

#define MT_STRESS_THREADS 8
#define MT_STRESS_OPS 500

static void *mt_stress_worker(void *arg) {
    thread_test_data_t *data = (thread_test_data_t *)arg;
    void *ptrs[10];
    int i, j;
    int slot = 0;

    memset(ptrs, 0, sizeof(ptrs));
    data->success_count = 0;
    data->error_count = 0;

    for (i = 0; i < MT_STRESS_OPS; i++) {
        /* Alternate between alloc and free */
        if (i % 2 == 0) {
            /* Allocate */
            for (j = 0; j < 10; j++) {
                slot = (slot + 1) % 10;
                if (ptrs[slot] == NULL) {
                    ptrs[slot] = rampart_alloc(data->pool, 32 + (size_t)(i % 64));
                    if (ptrs[slot] != NULL) {
                        data->success_count++;
                    }
                    break;
                }
            }
        } else {
            /* Free */
            for (j = 0; j < 10; j++) {
                slot = (slot + 1) % 10;
                if (ptrs[slot] != NULL) {
                    rampart_free(data->pool, ptrs[slot]);
                    ptrs[slot] = NULL;
                    break;
                }
            }
        }
    }

    /* Cleanup remaining */
    for (j = 0; j < 10; j++) {
        if (ptrs[j] != NULL) {
            rampart_free(data->pool, ptrs[j]);
        }
    }

    return NULL;
}

/**
 * test_multithread_stress - Heavy multi-threaded stress test
 */
static void test_multithread_stress(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;
    pthread_t threads[MT_STRESS_THREADS];
    thread_test_data_t thread_data[MT_STRESS_THREADS];
    int i;
    int total_success = 0;

    rampart_config_default(&config);
    config.pool_size = 1024 * 1024;  /* 1 MB */
    config.strict_thread_mode = 0;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Launch stress threads */
    for (i = 0; i < MT_STRESS_THREADS; i++) {
        thread_data[i].pool = pool;
        thread_data[i].thread_id = i;
        pthread_create(&threads[i], NULL, mt_stress_worker, &thread_data[i]);
    }

    /* Wait for completion */
    for (i = 0; i < MT_STRESS_THREADS; i++) {
        pthread_join(threads[i], NULL);
        total_success += thread_data[i].success_count;
    }

    TEST_ASSERT(total_success > 0);

    result = rampart_shutdown(pool);
    TEST_ASSERT_EQ(0, result.leaked_blocks);
}

/* ============================================================================
 * Main Entry Point
 * ============================================================================ */

int main(int argc, char *argv[]) {
    int i;

    /* Parse command line arguments */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            TEST_SET_VERBOSE(1);
        }
    }

    printf("\n");
    printf("################################################\n");
    printf("#           RAMpart Test Suite                 #\n");
    printf("#           Version %s                       #\n", RAMPART_VERSION_STRING);
    printf("################################################\n");
    if (g_test_state.extra_verbose) {
        printf("#           (VERBOSE MODE ENABLED)            #\n");
        printf("################################################\n");
    }

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

    /* Thread Safety Tests */
    TEST_SUITE_BEGIN("Thread Safety Tests");
    RUN_TEST(test_thread_safety_basic);
    TEST_SUITE_END();

    /* Stress Tests */
    TEST_SUITE_BEGIN("Stress Tests");
    RUN_TEST(test_stress_alloc_free);
    RUN_TEST(test_stress_varying_sizes);
    TEST_SUITE_END();

    /* Out of Memory Tests */
    TEST_SUITE_BEGIN("Out of Memory Tests");
    RUN_TEST(test_pool_exhaustion);
    RUN_TEST(test_large_allocation_failure);
    RUN_TEST(test_recovery_after_oom);
    TEST_SUITE_END();

    /* Allocation/Deallocation Tests */
    TEST_SUITE_BEGIN("Allocation/Deallocation Tests");
    RUN_TEST(test_double_free_detection);
    RUN_TEST(test_alloc_sizes);
    RUN_TEST(test_calloc_overflow);
    TEST_SUITE_END();

    /* Memory Leak Detection Tests */
    TEST_SUITE_BEGIN("Memory Leak Tests");
    RUN_TEST(test_leak_multiple_blocks);
    RUN_TEST(test_get_leaks_api);
    TEST_SUITE_END();

    /* Orphan Memory Tests */
    TEST_SUITE_BEGIN("Orphan Memory Tests");
    RUN_TEST(test_orphan_on_shutdown);
    RUN_TEST(test_partial_cleanup_orphan);
    TEST_SUITE_END();

    /* Multi-Thread Stress Test */
    TEST_SUITE_BEGIN("Multi-Thread Stress Tests");
    RUN_TEST(test_multithread_stress);
    TEST_SUITE_END();

    /* External Test Suites */
    run_wipe_tests();

    run_guard_tests();

    run_thread_tests();

    register_parking_tests();

    /* Print grand summary with totals across all suites */
    TEST_PRINT_GRAND_SUMMARY();

    return TEST_GRAND_RESULT();
}
