/**
 * @file test_framework.h
 * @brief RAMpart test framework
 *
 * A minimal, C89-compliant unit testing framework for RAMpart.
 * Provides assertion macros and test suite management.
 *
 * @section usage Usage Example
 * @code
 * #include "test_framework.h"
 *
 * void test_example(void) {
 *     TEST_ASSERT(1 == 1);
 *     TEST_ASSERT_EQ(42, 42);
 *     TEST_ASSERT_STR_EQ("hello", "hello");
 * }
 *
 * int main(void) {
 *     TEST_SUITE_BEGIN("Example Suite");
 *     RUN_TEST(test_example);
 *     TEST_SUITE_END();
 *     return TEST_SUITE_RESULT();
 * }
 * @endcode
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ============================================================================
 * Test Counters (Global State)
 * ============================================================================ */

/**
 * @brief Global test state structure
 */
typedef struct test_state_s {
    int tests_run;
    int tests_passed;
    int tests_failed;
    int assertions_run;
    int assertions_passed;
    int assertions_failed;
    const char *current_test;
    const char *suite_name;
    int verbose;
    int extra_verbose;  /* Show each assertion */
} test_state_t;

/**
 * @brief Global test state instance
 */
extern test_state_t g_test_state;

/* ============================================================================
 * Test Suite Macros
 * ============================================================================ */

/**
 * @def TEST_SUITE_BEGIN
 * @brief Begin a test suite
 *
 * @param name  Name of the test suite
 */
#define TEST_SUITE_BEGIN(name) \
    do { \
        g_test_state.suite_name = (name); \
        g_test_state.tests_run = 0; \
        g_test_state.tests_passed = 0; \
        g_test_state.tests_failed = 0; \
        g_test_state.assertions_run = 0; \
        g_test_state.assertions_passed = 0; \
        g_test_state.assertions_failed = 0; \
        g_test_state.verbose = 1; \
        printf("\n========================================\n"); \
        printf("Test Suite: %s\n", (name)); \
        printf("========================================\n\n"); \
    } while (0)

/**
 * @def TEST_SUITE_END
 * @brief End a test suite and print summary
 */
#define TEST_SUITE_END() \
    do { \
        printf("\n========================================\n"); \
        printf("Suite: %s - Results\n", g_test_state.suite_name); \
        printf("========================================\n"); \
        printf("Tests:      %d passed, %d failed, %d total\n", \
               g_test_state.tests_passed, \
               g_test_state.tests_failed, \
               g_test_state.tests_run); \
        printf("Assertions: %d passed, %d failed, %d total\n", \
               g_test_state.assertions_passed, \
               g_test_state.assertions_failed, \
               g_test_state.assertions_run); \
        printf("========================================\n"); \
        if (g_test_state.tests_failed == 0) { \
            printf("ALL TESTS PASSED\n"); \
        } else { \
            printf("SOME TESTS FAILED\n"); \
        } \
        printf("========================================\n\n"); \
    } while (0)

/**
 * @def TEST_SUITE_RESULT
 * @brief Get test suite result
 *
 * @return 0 if all tests passed, 1 if any failed
 */
#define TEST_SUITE_RESULT() \
    (g_test_state.tests_failed > 0)

/* ============================================================================
 * Test Case Macros
 * ============================================================================ */

/**
 * @def RUN_TEST
 * @brief Run a test function
 *
 * @param test_fn   Function to run (void (*)(void))
 */
#define RUN_TEST(test_fn) \
    do { \
        int _prev_failed = g_test_state.assertions_failed; \
        g_test_state.current_test = #test_fn; \
        g_test_state.tests_run++; \
        if (g_test_state.verbose) { \
            printf("Running: %s... ", #test_fn); \
            fflush(stdout); \
        } \
        (test_fn)(); \
        if (g_test_state.assertions_failed == _prev_failed) { \
            g_test_state.tests_passed++; \
            if (g_test_state.verbose) { \
                printf("PASSED\n"); \
            } \
        } else { \
            g_test_state.tests_failed++; \
            if (g_test_state.verbose) { \
                printf("FAILED\n"); \
            } \
        } \
    } while (0)

/**
 * @def SKIP_TEST
 * @brief Skip a test with a reason
 *
 * @param test_fn   Function name
 * @param reason    Reason for skipping
 */
#define SKIP_TEST(test_fn, reason) \
    do { \
        g_test_state.tests_run++; \
        printf("Skipping: %s - %s\n", #test_fn, (reason)); \
    } while (0)

/* ============================================================================
 * Assertion Macros
 * ============================================================================ */

/**
 * @def TEST_ASSERT
 * @brief Assert a condition is true
 *
 * @param cond  Condition to test
 */
#define TEST_ASSERT(cond) \
    do { \
        g_test_state.assertions_run++; \
        if (cond) { \
            g_test_state.assertions_passed++; \
            if (g_test_state.extra_verbose) { \
                printf("    [PASS] %s\n", #cond); \
            } \
        } else { \
            g_test_state.assertions_failed++; \
            printf("\n  ASSERTION FAILED: %s\n", #cond); \
            printf("    at %s:%d in %s\n", \
                   __FILE__, __LINE__, g_test_state.current_test); \
        } \
    } while (0)

/**
 * @def TEST_ASSERT_MSG
 * @brief Assert with custom message
 *
 * @param cond  Condition to test
 * @param msg   Message to print on failure
 */
#define TEST_ASSERT_MSG(cond, msg) \
    do { \
        g_test_state.assertions_run++; \
        if (cond) { \
            g_test_state.assertions_passed++; \
            if (g_test_state.extra_verbose) { \
                printf("    [PASS] %s\n", #cond); \
            } \
        } else { \
            g_test_state.assertions_failed++; \
            printf("\n  ASSERTION FAILED: %s\n", #cond); \
            printf("    Message: %s\n", (msg)); \
            printf("    at %s:%d in %s\n", \
                   __FILE__, __LINE__, g_test_state.current_test); \
        } \
    } while (0)

/**
 * @def TEST_ASSERT_EQ
 * @brief Assert two values are equal
 *
 * @param expected  Expected value
 * @param actual    Actual value
 */
#define TEST_ASSERT_EQ(expected, actual) \
    do { \
        long _exp_val = (long)(expected); \
        long _act_val = (long)(actual); \
        g_test_state.assertions_run++; \
        if (_exp_val == _act_val) { \
            g_test_state.assertions_passed++; \
            if (g_test_state.extra_verbose) { \
                printf("    [PASS] %s == %s (value: %ld)\n", \
                       #expected, #actual, _act_val); \
            } \
        } else { \
            g_test_state.assertions_failed++; \
            printf("\n  ASSERTION FAILED: %s == %s\n", \
                   #expected, #actual); \
            printf("    Expected: %ld, Actual: %ld\n", _exp_val, _act_val); \
            printf("    at %s:%d in %s\n", \
                   __FILE__, __LINE__, g_test_state.current_test); \
        } \
    } while (0)

/**
 * @def TEST_ASSERT_NE
 * @brief Assert two values are not equal
 *
 * @param not_expected  Value that should not match
 * @param actual        Actual value
 */
#define TEST_ASSERT_NE(not_expected, actual) \
    do { \
        long _nexp_val = (long)(not_expected); \
        long _act_val = (long)(actual); \
        g_test_state.assertions_run++; \
        if (_nexp_val != _act_val) { \
            g_test_state.assertions_passed++; \
            if (g_test_state.extra_verbose) { \
                printf("    [PASS] %s != %s (%ld != %ld)\n", \
                       #not_expected, #actual, _nexp_val, _act_val); \
            } \
        } else { \
            g_test_state.assertions_failed++; \
            printf("\n  ASSERTION FAILED: %s != %s\n", \
                   #not_expected, #actual); \
            printf("    Both are: %ld\n", _act_val); \
            printf("    at %s:%d in %s\n", \
                   __FILE__, __LINE__, g_test_state.current_test); \
        } \
    } while (0)

/**
 * @def TEST_ASSERT_NULL
 * @brief Assert pointer is NULL
 *
 * @param ptr   Pointer to test
 */
#define TEST_ASSERT_NULL(ptr) \
    do { \
        void *_ptr_val = (void *)(ptr); \
        g_test_state.assertions_run++; \
        if (_ptr_val == NULL) { \
            g_test_state.assertions_passed++; \
            if (g_test_state.extra_verbose) { \
                printf("    [PASS] %s == NULL\n", #ptr); \
            } \
        } else { \
            g_test_state.assertions_failed++; \
            printf("\n  ASSERTION FAILED: %s is NULL\n", #ptr); \
            printf("    Actual: %p\n", _ptr_val); \
            printf("    at %s:%d in %s\n", \
                   __FILE__, __LINE__, g_test_state.current_test); \
        } \
    } while (0)

/**
 * @def TEST_ASSERT_NOT_NULL
 * @brief Assert pointer is not NULL
 *
 * @param ptr   Pointer to test
 */
#define TEST_ASSERT_NOT_NULL(ptr) \
    do { \
        void *_ptr_val = (void *)(ptr); \
        g_test_state.assertions_run++; \
        if (_ptr_val != NULL) { \
            g_test_state.assertions_passed++; \
            if (g_test_state.extra_verbose) { \
                printf("    [PASS] %s != NULL (ptr: %p)\n", #ptr, _ptr_val); \
            } \
        } else { \
            g_test_state.assertions_failed++; \
            printf("\n  ASSERTION FAILED: %s is not NULL\n", #ptr); \
            printf("    at %s:%d in %s\n", \
                   __FILE__, __LINE__, g_test_state.current_test); \
        } \
    } while (0)

/**
 * @def TEST_ASSERT_STR_EQ
 * @brief Assert two strings are equal
 *
 * @param expected  Expected string
 * @param actual    Actual string
 */
#define TEST_ASSERT_STR_EQ(expected, actual) \
    do { \
        const char *_exp = (expected); \
        const char *_act = (actual); \
        const char *_exp_disp = "(null)"; \
        const char *_act_disp = "(null)"; \
        g_test_state.assertions_run++; \
        if (_exp != NULL) { _exp_disp = _exp; } \
        if (_act != NULL) { _act_disp = _act; } \
        if (_exp != NULL && _act != NULL && \
            strcmp(_exp, _act) == 0) { \
            g_test_state.assertions_passed++; \
            if (g_test_state.extra_verbose) { \
                printf("    [PASS] %s == %s (\"%s\")\n", \
                       #expected, #actual, _act_disp); \
            } \
        } else { \
            g_test_state.assertions_failed++; \
            printf("\n  ASSERTION FAILED: strings equal\n"); \
            printf("    Expected: \"%s\"\n", _exp_disp); \
            printf("    Actual:   \"%s\"\n", _act_disp); \
            printf("    at %s:%d in %s\n", \
                   __FILE__, __LINE__, g_test_state.current_test); \
        } \
    } while (0)

/**
 * @def TEST_ASSERT_MEM_EQ
 * @brief Assert two memory regions are equal
 *
 * @param expected  Expected data
 * @param actual    Actual data
 * @param size      Size in bytes
 */
#define TEST_ASSERT_MEM_EQ(expected, actual, size) \
    do { \
        size_t _size = (size); \
        g_test_state.assertions_run++; \
        if (memcmp((expected), (actual), _size) == 0) { \
            g_test_state.assertions_passed++; \
            if (g_test_state.extra_verbose) { \
                printf("    [PASS] %s == %s (%lu bytes)\n", \
                       #expected, #actual, (unsigned long)_size); \
            } \
        } else { \
            g_test_state.assertions_failed++; \
            printf("\n  ASSERTION FAILED: memory equal\n"); \
            printf("    Size: %lu bytes\n", (unsigned long)_size); \
            printf("    at %s:%d in %s\n", \
                   __FILE__, __LINE__, g_test_state.current_test); \
        } \
    } while (0)

/**
 * @def TEST_ASSERT_OK
 * @brief Assert rampart_error_t is RAMPART_OK
 *
 * @param err   Error code to test
 */
#define TEST_ASSERT_OK(err) \
    do { \
        rampart_error_t _err_val = (err); \
        g_test_state.assertions_run++; \
        if (_err_val == RAMPART_OK) { \
            g_test_state.assertions_passed++; \
            if (g_test_state.extra_verbose) { \
                printf("    [PASS] %s == RAMPART_OK\n", #err); \
            } \
        } else { \
            g_test_state.assertions_failed++; \
            printf("\n  ASSERTION FAILED: %s == RAMPART_OK\n", #err); \
            printf("    Actual: %d\n", (int)_err_val); \
            printf("    at %s:%d in %s\n", \
                   __FILE__, __LINE__, g_test_state.current_test); \
        } \
    } while (0)

/**
 * @def TEST_ASSERT_ERR
 * @brief Assert rampart_error_t matches expected error
 *
 * @param expected  Expected error code
 * @param actual    Actual error code
 */
#define TEST_ASSERT_ERR(expected, actual) \
    do { \
        int _exp_err = (int)(expected); \
        int _act_err = (int)(actual); \
        g_test_state.assertions_run++; \
        if (_exp_err == _act_err) { \
            g_test_state.assertions_passed++; \
            if (g_test_state.extra_verbose) { \
                printf("    [PASS] %s == %s (error: %d)\n", \
                       #expected, #actual, _act_err); \
            } \
        } else { \
            g_test_state.assertions_failed++; \
            printf("\n  ASSERTION FAILED: %s == %s\n", \
                   #expected, #actual); \
            printf("    Expected: %d, Actual: %d\n", _exp_err, _act_err); \
            printf("    at %s:%d in %s\n", \
                   __FILE__, __LINE__, g_test_state.current_test); \
        } \
    } while (0)

/**
 * @def TEST_FAIL
 * @brief Unconditionally fail with message
 *
 * @param msg   Failure message
 */
#define TEST_FAIL(msg) \
    do { \
        g_test_state.assertions_run++; \
        g_test_state.assertions_failed++; \
        printf("\n  TEST FAILED: %s\n", (msg)); \
        printf("    at %s:%d in %s\n", \
               __FILE__, __LINE__, g_test_state.current_test); \
    } while (0)

/* ============================================================================
 * Test Initialization
 * ============================================================================ */

/**
 * @def DEFINE_TEST_STATE
 * @brief Define the global test state (use once in main test file)
 */
#define DEFINE_TEST_STATE() \
    test_state_t g_test_state = {0, 0, 0, 0, 0, 0, NULL, NULL, 1, 0}

/**
 * @def TEST_SET_VERBOSE
 * @brief Enable extra verbose mode (shows each assertion)
 */
#define TEST_SET_VERBOSE(level) \
    do { \
        g_test_state.extra_verbose = (level); \
    } while (0)

/**
 * @def TEST_VERBOSE_PASS
 * @brief Print verbose pass message if extra_verbose is enabled
 */
#define TEST_VERBOSE_PASS(msg) \
    do { \
        if (g_test_state.extra_verbose) { \
            printf("    [PASS] %s\n", (msg)); \
        } \
    } while (0)

#endif /* TEST_FRAMEWORK_H */
