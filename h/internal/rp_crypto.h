/**
 * @file rp_crypto.h
 * @brief RAMpart cryptographic primitives
 *
 * Implements ChaCha20 stream cipher for secure block parking.
 * Pure ANSI-C (C89) implementation with no external dependencies.
 *
 * @internal
 *
 * @section design Design Notes
 *
 * ChaCha20 was chosen over AES for the following reasons:
 * - No lookup tables, eliminating timing side-channel attacks
 * - Faster in software without hardware acceleration
 * - Simpler implementation, easier to audit
 * - Stream cipher: natural support for arbitrary-length data
 *
 * @section threat_model Security Limitations
 *
 * This encryption protects against:
 * - Data leaking to swap (when combined with mlock)
 * - Data in core dumps (when combined with MADV_DONTDUMP)
 * - Casual memory inspection
 *
 * This encryption does NOT protect against:
 * - Cold boot attacks (key is in RAM)
 * - DMA attacks (key is in RAM)
 * - Attackers with read access to process memory
 * - Root-level memory imaging
 *
 * The encryption key resides in pool memory. Any attacker who can read
 * the encrypted data can also read the key.
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
 * Constants
 * ============================================================================ */

/**
 * @def RP_CHACHA20_KEY_SIZE
 * @brief ChaCha20 key size in bytes (256 bits)
 */
#define RP_CHACHA20_KEY_SIZE 32

/**
 * @def RP_CHACHA20_NONCE_SIZE
 * @brief ChaCha20 nonce size in bytes (96 bits)
 */
#define RP_CHACHA20_NONCE_SIZE 12

/**
 * @def RP_CHACHA20_BLOCK_SIZE
 * @brief ChaCha20 block size in bytes (512 bits)
 */
#define RP_CHACHA20_BLOCK_SIZE 64

/* ============================================================================
 * ChaCha20 Context
 * ============================================================================ */

/**
 * @struct rp_chacha20_ctx_t
 * @brief ChaCha20 cipher context
 *
 * Holds the key and supports streaming encryption/decryption.
 * The context can be reused for multiple operations with the same key
 * but different nonces.
 */
typedef struct rp_chacha20_ctx_s {
    /**
     * @brief 256-bit key (8 x 32-bit words)
     */
    unsigned long key[8];

    /**
     * @brief Indicates if context is initialized
     */
    int initialized;
} rp_chacha20_ctx_t;

/* ============================================================================
 * Key Generation
 * ============================================================================ */

/**
 * rp_crypto_generate_key - Generate a random key
 *
 * Generates a cryptographically random key using /dev/urandom.
 * Falls back to a PRNG seeded with time and address if unavailable.
 *
 * @param key       Buffer to receive the key (RP_CHACHA20_KEY_SIZE bytes)
 * @param key_len   Size of key buffer (must be RP_CHACHA20_KEY_SIZE)
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_ERR_NULL_PARAM   key is NULL
 * @retval RAMPART_ERR_INVALID_SIZE key_len is wrong
 */
rampart_error_t rp_crypto_generate_key(unsigned char *key, size_t key_len);

/* ============================================================================
 * ChaCha20 Context Management
 * ============================================================================ */

/**
 * rp_chacha20_init - Initialize ChaCha20 context with key
 *
 * Sets up the cipher context with the provided key. The context can
 * then be used for multiple encrypt/decrypt operations.
 *
 * @param ctx       Pointer to context structure
 * @param key       256-bit key (RP_CHACHA20_KEY_SIZE bytes)
 * @param key_len   Size of key (must be RP_CHACHA20_KEY_SIZE)
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_ERR_NULL_PARAM   ctx or key is NULL
 * @retval RAMPART_ERR_INVALID_SIZE key_len is wrong
 */
rampart_error_t rp_chacha20_init(rp_chacha20_ctx_t *ctx,
                                  const unsigned char *key,
                                  size_t key_len);

/**
 * rp_chacha20_wipe - Securely wipe ChaCha20 context
 *
 * Clears all key material from the context.
 *
 * @param ctx       Pointer to context structure
 *
 * @return RAMPART_OK on success, error code on failure
 */
rampart_error_t rp_chacha20_wipe(rp_chacha20_ctx_t *ctx);

/* ============================================================================
 * Encryption/Decryption
 * ============================================================================ */

/**
 * rp_chacha20_crypt - Encrypt or decrypt data
 *
 * ChaCha20 is a stream cipher where encryption and decryption are the
 * same operation (XOR with keystream). This function can be used for both.
 *
 * @param ctx           Initialized ChaCha20 context
 * @param nonce         96-bit nonce (RP_CHACHA20_NONCE_SIZE bytes)
 * @param nonce_len     Size of nonce (must be RP_CHACHA20_NONCE_SIZE)
 * @param counter       Initial block counter (usually 0)
 * @param data          Data to encrypt/decrypt (modified in place)
 * @param data_len      Length of data in bytes
 *
 * @return RAMPART_OK on success, error code on failure
 *
 * @retval RAMPART_ERR_NULL_PARAM       ctx, nonce, or data is NULL
 * @retval RAMPART_ERR_INVALID_SIZE     nonce_len is wrong
 * @retval RAMPART_ERR_NOT_INITIALIZED  ctx not initialized
 *
 * @note The same nonce must NEVER be used twice with the same key.
 * @note Thread-safe if different contexts are used per thread.
 */
rampart_error_t rp_chacha20_crypt(const rp_chacha20_ctx_t *ctx,
                                   const unsigned char *nonce,
                                   size_t nonce_len,
                                   unsigned long counter,
                                   unsigned char *data,
                                   size_t data_len);

/* ============================================================================
 * Nonce Generation for Block Parking
 * ============================================================================ */

/**
 * rp_crypto_generate_block_nonce - Generate nonce for a block
 *
 * Creates a unique nonce for encrypting a specific block. The nonce is
 * derived from the block address and a generation counter to ensure
 * uniqueness even if the same memory is reused.
 *
 * @param pool          Pool header (for pool-specific salt)
 * @param block         Block header
 * @param generation    Parking generation counter (incremented each park)
 * @param nonce         Buffer to receive nonce (RP_CHACHA20_NONCE_SIZE bytes)
 *
 * @return RAMPART_OK on success, error code on failure
 */
rampart_error_t rp_crypto_generate_block_nonce(const rp_pool_header_t *pool,
                                                const rp_block_header_t *block,
                                                unsigned long generation,
                                                unsigned char *nonce);

#endif /* RP_CRYPTO_H */
