/**
 * @file rp_crypto.h
 * @brief RAMpart encryption internals
 *
 * Implements a Feistel block cipher for data-at-rest encryption.
 * The cipher is designed for C89 compliance with no external
 * dependencies.
 *
 * @internal
 *
 * @section cipher Cipher Design
 *
 * The Feistel cipher uses:
 * - Block size: 8 bytes (64 bits)
 * - Key size: up to 32 bytes (256 bits)
 * - Rounds: 16
 *
 * This provides reasonable security for data-at-rest obfuscation
 * while maintaining simplicity and C89 compliance.
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

#ifndef RP_CRYPTO_H
#define RP_CRYPTO_H

#include "rp_types.h"

/* ============================================================================
 * Cipher Context
 * ============================================================================ */

/**
 * @struct rp_cipher_ctx_t
 * @brief Feistel cipher context
 *
 * Contains the expanded key schedule for encryption/decryption.
 */
typedef struct rp_cipher_ctx_s {
    /**
     * @brief Round keys derived from the user key
     */
    unsigned long round_keys[RP_CRYPTO_ROUNDS];

    /**
     * @brief Non-zero if context is initialized
     */
    int initialized;
} rp_cipher_ctx_t;

/* ============================================================================
 * Key Management Functions
 * ============================================================================ */

/**
 * rp_crypto_init_ctx - Initialize cipher context with key
 *
 * Derives round keys from the provided key and stores them in the
 * context. The original key is not stored.
 *
 * @param ctx           Pointer to cipher context
 * @param key           Encryption key data
 * @param key_size      Key size in bytes (1 to RAMPART_MAX_KEY_SIZE)
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_ERR_NULL_PARAM   ctx or key is NULL
 * @retval RAMPART_ERR_INVALID_SIZE key_size is 0 or too large
 */
rampart_error_t rp_crypto_init_ctx(rp_cipher_ctx_t *ctx,
                                    const unsigned char *key,
                                    size_t key_size);

/**
 * rp_crypto_destroy_ctx - Securely destroy cipher context
 *
 * Overwrites round keys and marks context as uninitialized.
 *
 * @param ctx       Pointer to cipher context
 */
void rp_crypto_destroy_ctx(rp_cipher_ctx_t *ctx);

/* ============================================================================
 * Block Cipher Functions
 * ============================================================================ */

/**
 * rp_crypto_encrypt_block - Encrypt a single 8-byte block
 *
 * Encrypts an 8-byte block in place using the Feistel cipher.
 *
 * @param ctx       Pointer to initialized cipher context
 * @param block     Pointer to 8-byte block (modified in place)
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_ERR_NULL_PARAM       ctx or block is NULL
 * @retval RAMPART_ERR_NOT_INITIALIZED  ctx not initialized
 */
rampart_error_t rp_crypto_encrypt_block(const rp_cipher_ctx_t *ctx,
                                         unsigned char *block);

/**
 * rp_crypto_decrypt_block - Decrypt a single 8-byte block
 *
 * Decrypts an 8-byte block in place using the Feistel cipher.
 *
 * @param ctx       Pointer to initialized cipher context
 * @param block     Pointer to 8-byte block (modified in place)
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_ERR_NULL_PARAM       ctx or block is NULL
 * @retval RAMPART_ERR_NOT_INITIALIZED  ctx not initialized
 */
rampart_error_t rp_crypto_decrypt_block(const rp_cipher_ctx_t *ctx,
                                         unsigned char *block);

/* ============================================================================
 * Data Encryption Functions
 * ============================================================================ */

/**
 * rp_crypto_encrypt - Encrypt arbitrary-length data
 *
 * Encrypts data of any length using Electronic Codebook (ECB) mode.
 * Data length does not need to be a multiple of the block size;
 * the final partial block is handled specially.
 *
 * @param ctx       Pointer to initialized cipher context
 * @param data      Pointer to data buffer (modified in place)
 * @param size      Size of data in bytes
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_ERR_NULL_PARAM       ctx or data is NULL
 * @retval RAMPART_ERR_NOT_INITIALIZED  ctx not initialized
 *
 * @note ECB mode is used for simplicity. Each block is encrypted
 *       independently.
 */
rampart_error_t rp_crypto_encrypt(const rp_cipher_ctx_t *ctx,
                                   unsigned char *data,
                                   size_t size);

/**
 * rp_crypto_decrypt - Decrypt arbitrary-length data
 *
 * Decrypts data of any length using Electronic Codebook (ECB) mode.
 *
 * @param ctx       Pointer to initialized cipher context
 * @param data      Pointer to data buffer (modified in place)
 * @param size      Size of data in bytes
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_ERR_NULL_PARAM       ctx or data is NULL
 * @retval RAMPART_ERR_NOT_INITIALIZED  ctx not initialized
 */
rampart_error_t rp_crypto_decrypt(const rp_cipher_ctx_t *ctx,
                                   unsigned char *data,
                                   size_t size);

/* ============================================================================
 * Internal Functions (Exposed for Testing)
 * ============================================================================ */

/**
 * rp_crypto_round_function - Feistel round function
 *
 * The F function used in each Feistel round. Combines the input
 * half-block with a round key.
 *
 * @param half      32-bit half-block value
 * @param round_key Round key for this round
 *
 * @return Transformed 32-bit value
 *
 * @note Exposed for unit testing purposes.
 */
unsigned long rp_crypto_round_function(unsigned long half,
                                        unsigned long round_key);

/**
 * rp_crypto_key_schedule - Derive round keys from user key
 *
 * Expands the user key into per-round keys.
 *
 * @param key           User key data
 * @param key_size      Key size in bytes
 * @param round_keys    Array to receive round keys (RP_CRYPTO_ROUNDS elements)
 *
 * @note Exposed for unit testing purposes.
 */
void rp_crypto_key_schedule(const unsigned char *key,
                             size_t key_size,
                             unsigned long *round_keys);

#endif /* RP_CRYPTO_H */
