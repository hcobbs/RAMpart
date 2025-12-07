/**
 * @file test_threads.c
 * @brief RAMpart thread safety and strict mode tests
 *
 * Tests thread ownership enforcement, strict mode, and
 * concurrent access patterns.
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
#include <pthread.h>
#include <unistd.h>
#include "test_framework.h"
#include "rampart.h"
#include "internal/rp_thread.h"
#include "internal/rp_types.h"

/* External test state from test_main.c */
extern test_state_t g_test_state;

/* Forward declaration for this module's test suite runner */
void run_thread_tests(void);

/* ============================================================================
 * Thread ID Function Tests
 * ============================================================================ */

/**
 * test_thread_id_self - Get current thread ID
 */
static void test_thread_id_self(void) {
    rp_thread_id_t id1;
    rp_thread_id_t id2;

    id1 = rp_thread_get_current_id();
    id2 = rp_thread_get_current_id();

    /* Same thread should get same ID */
    TEST_ASSERT(rp_thread_ids_equal(id1, id2));
}

/**
 * test_thread_id_to_ulong - Convert thread ID to unsigned long
 */
static void test_thread_id_to_ulong(void) {
    rp_thread_id_t id;
    unsigned long val;

    id = rp_thread_get_current_id();
    val = rp_thread_id_to_ulong(id);

    /* Should produce non-zero value */
    TEST_ASSERT(val != 0);
}

/* ============================================================================
 * Strict Thread Mode Tests
 * ============================================================================ */

/* Data for cross-thread free test */
typedef struct strict_mode_data_s {
    rampart_pool_t *pool;
    void *ptr;
    rampart_error_t result;
} strict_mode_data_t;

static void *cross_thread_free_worker(void *arg) {
    strict_mode_data_t *data = (strict_mode_data_t *)arg;

    /* Try to free memory allocated by main thread */
    data->result = rampart_free(data->pool, data->ptr);

    return NULL;
}

/**
 * test_strict_mode_enforced - Strict mode prevents cross-thread free
 */
static void test_strict_mode_enforced(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    void *ptr;
    pthread_t thread;
    strict_mode_data_t data;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.strict_thread_mode = 1;  /* Enable strict mode */

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Allocate in main thread */
    ptr = rampart_alloc(pool, 128);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Try to free in another thread */
    data.pool = pool;
    data.ptr = ptr;
    data.result = RAMPART_OK;

    pthread_create(&thread, NULL, cross_thread_free_worker, &data);
    pthread_join(thread, NULL);

    /* Should have failed with WRONG_THREAD error */
    TEST_ASSERT_ERR(RAMPART_ERR_WRONG_THREAD, data.result);

    /* Free from correct thread should work */
    TEST_ASSERT_OK(rampart_free(pool, ptr));

    rampart_shutdown(pool);
}

/**
 * test_strict_mode_disabled - Cross-thread free allowed when disabled
 */
static void test_strict_mode_disabled(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    void *ptr;
    pthread_t thread;
    strict_mode_data_t data;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.strict_thread_mode = 0;  /* Disable strict mode */

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Allocate in main thread */
    ptr = rampart_alloc(pool, 128);
    TEST_ASSERT_NOT_NULL(ptr);

    /* Free in another thread (should succeed) */
    data.pool = pool;
    data.ptr = ptr;
    data.result = RAMPART_ERR_INTERNAL;

    pthread_create(&thread, NULL, cross_thread_free_worker, &data);
    pthread_join(thread, NULL);

    /* Should have succeeded */
    TEST_ASSERT_OK(data.result);

    rampart_shutdown(pool);
}

/* ============================================================================
 * Thread-Local Error Storage Tests
 * ============================================================================ */

typedef struct tls_test_data_s {
    rampart_error_t set_error;
    rampart_error_t got_error;
} tls_test_data_t;

static void *tls_worker(void *arg) {
    tls_test_data_t *data = (tls_test_data_t *)arg;

    /* Set error in this thread */
    rp_thread_set_last_error(data->set_error);

    /* Small delay to ensure main thread has set its error */
    usleep(1000);

    /* Get error - should be what we set, not main thread's */
    data->got_error = rp_thread_get_last_error();

    return NULL;
}

/**
 * test_thread_local_error_isolation - Errors are thread-local
 */
static void test_thread_local_error_isolation(void) {
    pthread_t thread;
    tls_test_data_t data;
    rampart_error_t main_error;

    /* Set up child thread to use different error */
    data.set_error = RAMPART_ERR_INVALID_SIZE;
    data.got_error = RAMPART_OK;

    /* Start child thread */
    pthread_create(&thread, NULL, tls_worker, &data);

    /* Set error in main thread */
    rp_thread_set_last_error(RAMPART_ERR_NULL_PARAM);

    /* Wait for child */
    pthread_join(thread, NULL);

    /* Child should have gotten its own error */
    TEST_ASSERT_ERR(RAMPART_ERR_INVALID_SIZE, data.got_error);

    /* Main thread should get its own error */
    main_error = rp_thread_get_last_error();
    TEST_ASSERT_ERR(RAMPART_ERR_NULL_PARAM, main_error);

    /* Error should be cleared after get */
    main_error = rp_thread_get_last_error();
    TEST_ASSERT_ERR(RAMPART_OK, main_error);
}

/* ============================================================================
 * Mutex Function Tests
 * ============================================================================ */

/**
 * test_mutex_init_destroy - Test mutex lifecycle
 */
static void test_mutex_init_destroy(void) {
    rp_mutex_t mutex;
    rampart_error_t err;

    err = rp_mutex_init(&mutex);
    TEST_ASSERT_OK(err);

    err = rp_mutex_destroy(&mutex);
    TEST_ASSERT_OK(err);
}

/**
 * test_mutex_null_params - Mutex functions reject NULL
 */
static void test_mutex_null_params(void) {
    rampart_error_t err;

    err = rp_mutex_init(NULL);
    TEST_ASSERT_ERR(RAMPART_ERR_NULL_PARAM, err);

    err = rp_mutex_destroy(NULL);
    TEST_ASSERT_ERR(RAMPART_ERR_NULL_PARAM, err);

    err = rp_mutex_lock(NULL);
    TEST_ASSERT_ERR(RAMPART_ERR_NULL_PARAM, err);

    err = rp_mutex_unlock(NULL);
    TEST_ASSERT_ERR(RAMPART_ERR_NULL_PARAM, err);

    err = rp_mutex_trylock(NULL);
    TEST_ASSERT_ERR(RAMPART_ERR_NULL_PARAM, err);
}

/**
 * test_mutex_lock_unlock - Basic lock/unlock
 */
static void test_mutex_lock_unlock(void) {
    rp_mutex_t mutex;
    rampart_error_t err;

    err = rp_mutex_init(&mutex);
    TEST_ASSERT_OK(err);

    err = rp_mutex_lock(&mutex);
    TEST_ASSERT_OK(err);

    err = rp_mutex_unlock(&mutex);
    TEST_ASSERT_OK(err);

    err = rp_mutex_destroy(&mutex);
    TEST_ASSERT_OK(err);
}

/**
 * test_mutex_trylock - Test non-blocking lock
 */
static void test_mutex_trylock(void) {
    rp_mutex_t mutex;
    rampart_error_t err;

    err = rp_mutex_init(&mutex);
    TEST_ASSERT_OK(err);

    /* First trylock should succeed */
    err = rp_mutex_trylock(&mutex);
    TEST_ASSERT_OK(err);

    /* Unlock and cleanup */
    rp_mutex_unlock(&mutex);
    rp_mutex_destroy(&mutex);
}

/* ============================================================================
 * Concurrent Access Tests
 * ============================================================================ */

#define CONCURRENT_THREADS 16
#define OPS_PER_THREAD 100

typedef struct concurrent_data_s {
    rampart_pool_t *pool;
    int thread_id;
    int success_count;
    int error_count;
} concurrent_data_t;

static void *concurrent_alloc_worker(void *arg) {
    concurrent_data_t *data = (concurrent_data_t *)arg;
    void *ptrs[OPS_PER_THREAD];
    int i;

    data->success_count = 0;
    data->error_count = 0;
    memset(ptrs, 0, sizeof(ptrs));

    /* Allocate all */
    for (i = 0; i < OPS_PER_THREAD; i++) {
        ptrs[i] = rampart_alloc(data->pool, 32);
        if (ptrs[i] != NULL) {
            data->success_count++;
        } else {
            data->error_count++;
        }
    }

    /* Free all */
    for (i = 0; i < OPS_PER_THREAD; i++) {
        if (ptrs[i] != NULL) {
            rampart_free(data->pool, ptrs[i]);
        }
    }

    return NULL;
}

/**
 * test_concurrent_allocations - Many threads allocating simultaneously
 */
static void test_concurrent_allocations(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;
    pthread_t threads[CONCURRENT_THREADS];
    concurrent_data_t data[CONCURRENT_THREADS];
    int i;
    int total_success = 0;

    rampart_config_default(&config);
    config.pool_size = 1024 * 1024;  /* 1 MB */
    config.strict_thread_mode = 0;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Launch threads */
    for (i = 0; i < CONCURRENT_THREADS; i++) {
        data[i].pool = pool;
        data[i].thread_id = i;
        pthread_create(&threads[i], NULL, concurrent_alloc_worker, &data[i]);
    }

    /* Wait for completion */
    for (i = 0; i < CONCURRENT_THREADS; i++) {
        pthread_join(threads[i], NULL);
        total_success += data[i].success_count;
    }

    /* Verify most allocations succeeded */
    TEST_ASSERT(total_success > CONCURRENT_THREADS * OPS_PER_THREAD / 2);

    result = rampart_shutdown(pool);
    TEST_ASSERT_EQ(0, result.leaked_blocks);
}

/**
 * test_ownership_tracking - Verify ownership is correctly tracked
 */
static void test_ownership_tracking(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    void *ptr;
    rp_block_header_t *block;
    rp_thread_id_t current;
    rampart_error_t err;

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    ptr = rampart_alloc(pool, 64);
    TEST_ASSERT_NOT_NULL(ptr);

    block = RP_USER_TO_BLOCK(ptr);
    current = rp_thread_get_current_id();

    /* Block should be owned by current thread */
    TEST_ASSERT(rp_thread_ids_equal(current, rp_thread_get_owner(block)));

    /* Verify owner should succeed */
    err = rp_thread_verify_owner(block);
    TEST_ASSERT_OK(err);

    rampart_free(pool, ptr);
    rampart_shutdown(pool);
}

/* ============================================================================
 * Run All Thread Tests
 * ============================================================================ */

void run_thread_tests(void) {
    TEST_SUITE_BEGIN("Thread Safety Tests (Extended)");

    RUN_TEST(test_thread_id_self);
    RUN_TEST(test_thread_id_to_ulong);
    RUN_TEST(test_strict_mode_enforced);
    RUN_TEST(test_strict_mode_disabled);
    RUN_TEST(test_thread_local_error_isolation);
    RUN_TEST(test_mutex_init_destroy);
    RUN_TEST(test_mutex_null_params);
    RUN_TEST(test_mutex_lock_unlock);
    RUN_TEST(test_mutex_trylock);
    RUN_TEST(test_concurrent_allocations);
    RUN_TEST(test_ownership_tracking);

    TEST_SUITE_END();
}
