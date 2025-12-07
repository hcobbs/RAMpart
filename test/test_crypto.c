/**
 * @file test_crypto.c
 * @brief RAMpart encryption subsystem tests
 *
 * Tests the encryption functionality including key handling,
 * encrypt/decrypt roundtrips, and data protection.
 */

#include <stdio.h>
#include <string.h>
#include "test_framework.h"
#include "rampart.h"
#include "internal/rp_crypto.h"
#include "internal/rp_types.h"

/* External test state from test_main.c */
extern test_state_t g_test_state;

/* Forward declaration for this module's test suite runner */
void run_crypto_tests(void);

/* ============================================================================
 * Encryption Configuration Tests
 * ============================================================================ */

/**
 * test_encryption_disabled_by_default - Verify encryption off by default
 */
static void test_encryption_disabled_by_default(void) {
    rampart_config_t config;
    rampart_error_t err;

    err = rampart_config_default(&config);
    TEST_ASSERT_OK(err);
    TEST_ASSERT_EQ(0, config.encryption_enabled);
    TEST_ASSERT_NULL(config.encryption_key);
    TEST_ASSERT_EQ(0, config.encryption_key_size);
}

/**
 * test_encryption_config_validation - Test config validation for encryption
 */
static void test_encryption_config_validation(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    unsigned char key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    /* Encryption enabled but no key - should fail */
    config.encryption_enabled = 1;
    config.encryption_key = NULL;
    config.encryption_key_size = 0;

    pool = rampart_init(&config);
    TEST_ASSERT_NULL(pool);

    /* Encryption enabled with valid key - should succeed */
    config.encryption_key = key;
    config.encryption_key_size = 16;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    rampart_shutdown(pool);
}

/**
 * test_encryption_key_sizes - Test various key sizes
 */
static void test_encryption_key_sizes(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    unsigned char key[RAMPART_MAX_KEY_SIZE];
    size_t key_sizes[] = {8, 16, 24, 32};
    int i;
    int num_sizes = (int)(sizeof(key_sizes) / sizeof(key_sizes[0]));

    /* Fill key with test pattern */
    for (i = 0; i < RAMPART_MAX_KEY_SIZE; i++) {
        key[i] = (unsigned char)i;
    }

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.encryption_enabled = 1;
    config.encryption_key = key;

    /* Test each valid key size */
    for (i = 0; i < num_sizes; i++) {
        config.encryption_key_size = key_sizes[i];
        pool = rampart_init(&config);
        TEST_ASSERT_NOT_NULL(pool);
        if (pool != NULL) {
            rampart_shutdown(pool);
        }
    }
}

/* ============================================================================
 * Cipher Context Tests
 * ============================================================================ */

/**
 * test_cipher_context_init - Test cipher context initialization
 */
static void test_cipher_context_init(void) {
    rp_cipher_ctx_t ctx;
    rampart_error_t err;
    unsigned char key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                              0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    /* NULL context should fail */
    err = rp_crypto_init_ctx(NULL, key, 16);
    TEST_ASSERT_ERR(RAMPART_ERR_NULL_PARAM, err);

    /* NULL key should fail */
    err = rp_crypto_init_ctx(&ctx, NULL, 16);
    TEST_ASSERT_ERR(RAMPART_ERR_NULL_PARAM, err);

    /* Zero key size should fail */
    err = rp_crypto_init_ctx(&ctx, key, 0);
    TEST_ASSERT_ERR(RAMPART_ERR_INVALID_SIZE, err);

    /* Valid init should succeed */
    err = rp_crypto_init_ctx(&ctx, key, 16);
    TEST_ASSERT_OK(err);

    /* Cleanup */
    rp_crypto_destroy_ctx(&ctx);
}

/**
 * test_cipher_context_destroy - Test cipher context cleanup
 */
static void test_cipher_context_destroy(void) {
    rp_cipher_ctx_t ctx;
    rampart_error_t err;
    unsigned char key[16] = {0};

    /* Initialize context */
    err = rp_crypto_init_ctx(&ctx, key, 16);
    TEST_ASSERT_OK(err);

    /* Destroy should succeed (void function, just call it) */
    rp_crypto_destroy_ctx(&ctx);

    /* NULL destroy should handle gracefully (void function) */
    rp_crypto_destroy_ctx(NULL);

    /* If we got here without crashing, the test passes */
    TEST_ASSERT(1);
}

/* ============================================================================
 * Encrypt/Decrypt Block Tests
 * ============================================================================ */

/**
 * test_encrypt_decrypt_block - Test single block encrypt/decrypt roundtrip
 */
static void test_encrypt_decrypt_block(void) {
    rp_cipher_ctx_t ctx;
    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                              0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char plaintext[RP_CRYPTO_BLOCK_SIZE] = "TestData";
    unsigned char original[RP_CRYPTO_BLOCK_SIZE];
    unsigned char ciphertext[RP_CRYPTO_BLOCK_SIZE];
    rampart_error_t err;

    /* Save original */
    memcpy(original, plaintext, RP_CRYPTO_BLOCK_SIZE);

    /* Initialize cipher */
    err = rp_crypto_init_ctx(&ctx, key, 16);
    TEST_ASSERT_OK(err);

    /* Encrypt */
    memcpy(ciphertext, plaintext, RP_CRYPTO_BLOCK_SIZE);
    err = rp_crypto_encrypt_block(&ctx, ciphertext);
    TEST_ASSERT_OK(err);

    /* Ciphertext should differ from plaintext */
    TEST_ASSERT(memcmp(ciphertext, original, RP_CRYPTO_BLOCK_SIZE) != 0);

    /* Decrypt */
    err = rp_crypto_decrypt_block(&ctx, ciphertext);
    TEST_ASSERT_OK(err);

    /* Should match original */
    TEST_ASSERT_MEM_EQ(original, ciphertext, RP_CRYPTO_BLOCK_SIZE);

    rp_crypto_destroy_ctx(&ctx);
}

/**
 * test_encrypt_decrypt_buffer - Test multi-block buffer encryption
 */
static void test_encrypt_decrypt_buffer(void) {
    rp_cipher_ctx_t ctx;
    unsigned char key[32];
    unsigned char data[128];
    unsigned char original[128];
    rampart_error_t err;
    int i;

    /* Initialize key and data with patterns */
    for (i = 0; i < 32; i++) {
        key[i] = (unsigned char)(i * 7);
    }
    for (i = 0; i < 128; i++) {
        data[i] = (unsigned char)(i);
    }
    memcpy(original, data, 128);

    /* Initialize cipher with 32-byte key */
    err = rp_crypto_init_ctx(&ctx, key, 32);
    TEST_ASSERT_OK(err);

    /* Encrypt buffer */
    err = rp_crypto_encrypt(&ctx, data, 128);
    TEST_ASSERT_OK(err);

    /* Data should be different */
    TEST_ASSERT(memcmp(data, original, 128) != 0);

    /* Decrypt buffer */
    err = rp_crypto_decrypt(&ctx, data, 128);
    TEST_ASSERT_OK(err);

    /* Should match original */
    TEST_ASSERT_MEM_EQ(original, data, 128);

    rp_crypto_destroy_ctx(&ctx);
}

/**
 * test_encrypt_partial_block - Test encryption of non-block-aligned data
 */
static void test_encrypt_partial_block(void) {
    rp_cipher_ctx_t ctx;
    unsigned char key[16] = {0};
    unsigned char data[13];  /* Not a multiple of block size */
    unsigned char original[13];
    rampart_error_t err;
    int i;

    for (i = 0; i < 13; i++) {
        data[i] = (unsigned char)('A' + i);
    }
    memcpy(original, data, 13);

    err = rp_crypto_init_ctx(&ctx, key, 16);
    TEST_ASSERT_OK(err);

    /* Encrypt */
    err = rp_crypto_encrypt(&ctx, data, 13);
    TEST_ASSERT_OK(err);

    /* Decrypt */
    err = rp_crypto_decrypt(&ctx, data, 13);
    TEST_ASSERT_OK(err);

    /* Should match original */
    TEST_ASSERT_MEM_EQ(original, data, 13);

    rp_crypto_destroy_ctx(&ctx);
}

/* ============================================================================
 * Encrypted Allocation Tests
 * ============================================================================ */

/**
 * test_encrypted_allocation - Test allocation with encryption enabled
 */
static void test_encrypted_allocation(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;
    unsigned char key[16] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                              0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    unsigned char *ptr;
    unsigned char pattern[64];
    int i;
    rampart_error_t err;

    /* Create pattern */
    for (i = 0; i < 64; i++) {
        pattern[i] = (unsigned char)i;
    }

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.encryption_enabled = 1;
    config.encryption_key = key;
    config.encryption_key_size = 16;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Allocate and write data */
    ptr = (unsigned char *)rampart_alloc(pool, 64);
    TEST_ASSERT_NOT_NULL(ptr);

    memcpy(ptr, pattern, 64);

    /* Free - data should be encrypted before wipe */
    err = rampart_free(pool, ptr);
    TEST_ASSERT_OK(err);

    result = rampart_shutdown(pool);
    TEST_ASSERT_EQ(0, result.leaked_blocks);
}

/**
 * test_multiple_encrypted_blocks - Multiple allocations with encryption
 */
static void test_multiple_encrypted_blocks(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_shutdown_result_t result;
    unsigned char key[24] = {0};
    void *ptrs[10];
    int i;
    rampart_error_t err;

    rampart_config_default(&config);
    config.pool_size = 128 * 1024;
    config.encryption_enabled = 1;
    config.encryption_key = key;
    config.encryption_key_size = 24;

    pool = rampart_init(&config);
    TEST_ASSERT_NOT_NULL(pool);

    /* Allocate multiple blocks */
    for (i = 0; i < 10; i++) {
        ptrs[i] = rampart_alloc(pool, (size_t)(64 + i * 32));
        TEST_ASSERT_NOT_NULL(ptrs[i]);
    }

    /* Free in reverse order */
    for (i = 9; i >= 0; i--) {
        err = rampart_free(pool, ptrs[i]);
        TEST_ASSERT_OK(err);
    }

    result = rampart_shutdown(pool);
    TEST_ASSERT_EQ(0, result.leaked_blocks);
}

/* ============================================================================
 * Run All Crypto Tests
 * ============================================================================ */

void run_crypto_tests(void) {
    TEST_SUITE_BEGIN("Encryption Tests");

    RUN_TEST(test_encryption_disabled_by_default);
    RUN_TEST(test_encryption_config_validation);
    RUN_TEST(test_encryption_key_sizes);
    RUN_TEST(test_cipher_context_init);
    RUN_TEST(test_cipher_context_destroy);
    RUN_TEST(test_encrypt_decrypt_block);
    RUN_TEST(test_encrypt_decrypt_buffer);
    RUN_TEST(test_encrypt_partial_block);
    RUN_TEST(test_encrypted_allocation);
    RUN_TEST(test_multiple_encrypted_blocks);

    TEST_SUITE_END();
}
