/**
 * @file rp_crypto.c
 * @brief RAMpart ChaCha20 stream cipher implementation
 *
 * Pure ANSI-C (C89) implementation of ChaCha20 as specified in RFC 8439.
 * Designed to be timing-safe with no lookup tables.
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

#include "internal/rp_crypto.h"
#include "internal/rp_wipe.h"
#include <stdio.h>
#include <time.h>
#include <string.h>

/* ============================================================================
 * Constants
 * ============================================================================ */

/**
 * ChaCha20 "expand 32-byte k" constants (little-endian)
 */
#define CHACHA20_CONST_0 0x61707865UL  /* "expa" */
#define CHACHA20_CONST_1 0x3320646eUL  /* "nd 3" */
#define CHACHA20_CONST_2 0x79622d32UL  /* "2-by" */
#define CHACHA20_CONST_3 0x6b206574UL  /* "te k" */

/**
 * Mask for 32-bit operations (C89 unsigned long may be 64-bit)
 */
#define U32_MASK 0xFFFFFFFFUL

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/**
 * Left rotate a 32-bit value
 */
static unsigned long rotl32(unsigned long v, unsigned int n) {
    v &= U32_MASK;
    return ((v << n) | (v >> (32 - n))) & U32_MASK;
}

/**
 * Load 32-bit little-endian value from byte array
 */
static unsigned long load32_le(const unsigned char *p) {
    return ((unsigned long)p[0]) |
           ((unsigned long)p[1] << 8) |
           ((unsigned long)p[2] << 16) |
           ((unsigned long)p[3] << 24);
}

/**
 * Store 32-bit little-endian value to byte array
 */
static void store32_le(unsigned char *p, unsigned long v) {
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF);
    p[3] = (unsigned char)((v >> 24) & 0xFF);
}

/* ============================================================================
 * ChaCha20 Quarter Round
 * ============================================================================ */

/**
 * ChaCha20 quarter round operating on 4 words of state
 *
 * a += b; d ^= a; d <<<= 16;
 * c += d; b ^= c; b <<<= 12;
 * a += b; d ^= a; d <<<= 8;
 * c += d; b ^= c; b <<<= 7;
 */
static void quarter_round(unsigned long *state,
                          unsigned int a,
                          unsigned int b,
                          unsigned int c,
                          unsigned int d) {
    state[a] = (state[a] + state[b]) & U32_MASK;
    state[d] ^= state[a];
    state[d] = rotl32(state[d], 16);

    state[c] = (state[c] + state[d]) & U32_MASK;
    state[b] ^= state[c];
    state[b] = rotl32(state[b], 12);

    state[a] = (state[a] + state[b]) & U32_MASK;
    state[d] ^= state[a];
    state[d] = rotl32(state[d], 8);

    state[c] = (state[c] + state[d]) & U32_MASK;
    state[b] ^= state[c];
    state[b] = rotl32(state[b], 7);
}

/* ============================================================================
 * ChaCha20 Block Function
 * ============================================================================ */

/**
 * Generate a 64-byte keystream block
 *
 * @param ctx       ChaCha20 context with key
 * @param nonce     12-byte nonce
 * @param counter   Block counter
 * @param output    64-byte output buffer
 */
static void chacha20_block(const rp_chacha20_ctx_t *ctx,
                           const unsigned char *nonce,
                           unsigned long counter,
                           unsigned char *output) {
    unsigned long state[16];
    unsigned long working[16];
    int i;
    int round;

    /*
     * Initialize state:
     * [0-3]   = constants
     * [4-11]  = key (8 words)
     * [12]    = counter
     * [13-15] = nonce (3 words)
     */
    state[0] = CHACHA20_CONST_0;
    state[1] = CHACHA20_CONST_1;
    state[2] = CHACHA20_CONST_2;
    state[3] = CHACHA20_CONST_3;

    for (i = 0; i < 8; i++) {
        state[4 + i] = ctx->key[i];
    }

    state[12] = counter & U32_MASK;
    state[13] = load32_le(nonce);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);

    /* Copy state to working buffer */
    for (i = 0; i < 16; i++) {
        working[i] = state[i];
    }

    /* 20 rounds = 10 double-rounds */
    for (round = 0; round < 10; round++) {
        /* Column rounds */
        quarter_round(working, 0, 4, 8, 12);
        quarter_round(working, 1, 5, 9, 13);
        quarter_round(working, 2, 6, 10, 14);
        quarter_round(working, 3, 7, 11, 15);

        /* Diagonal rounds */
        quarter_round(working, 0, 5, 10, 15);
        quarter_round(working, 1, 6, 11, 12);
        quarter_round(working, 2, 7, 8, 13);
        quarter_round(working, 3, 4, 9, 14);
    }

    /* Add original state to working state and serialize */
    for (i = 0; i < 16; i++) {
        store32_le(output + (i * 4), (working[i] + state[i]) & U32_MASK);
    }

    /* Wipe sensitive data from stack */
    rp_wipe_memory(state, sizeof(state));
    rp_wipe_memory(working, sizeof(working));
}

/* ============================================================================
 * Key Generation
 * ============================================================================ */

rampart_error_t rp_crypto_generate_key(unsigned char *key, size_t key_len) {
    FILE *urandom;

    if (key == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    if (key_len != RP_CHACHA20_KEY_SIZE) {
        return RAMPART_ERR_INVALID_SIZE;
    }

    /*
     * VULN-001 fix: Use /dev/urandom exclusively.
     *
     * There is no acceptable fallback for cryptographic key generation.
     * If /dev/urandom is unavailable, fail loudly rather than silently
     * generating a predictable key that provides false security.
     */
    urandom = fopen("/dev/urandom", "rb");
    if (urandom == NULL) {
        return RAMPART_ERR_ENTROPY_SOURCE;
    }

    if (fread(key, 1, key_len, urandom) != key_len) {
        fclose(urandom);
        return RAMPART_ERR_ENTROPY_SOURCE;
    }

    fclose(urandom);
    return RAMPART_OK;
}

/* ============================================================================
 * Context Management
 * ============================================================================ */

rampart_error_t rp_chacha20_init(rp_chacha20_ctx_t *ctx,
                                  const unsigned char *key,
                                  size_t key_len) {
    int i;

    if (ctx == NULL || key == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    if (key_len != RP_CHACHA20_KEY_SIZE) {
        return RAMPART_ERR_INVALID_SIZE;
    }

    /* Load key as 8 little-endian 32-bit words */
    for (i = 0; i < 8; i++) {
        ctx->key[i] = load32_le(key + (i * 4));
    }

    ctx->initialized = 1;

    return RAMPART_OK;
}

rampart_error_t rp_chacha20_wipe(rp_chacha20_ctx_t *ctx) {
    if (ctx == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    rp_wipe_memory(ctx->key, sizeof(ctx->key));
    ctx->initialized = 0;

    return RAMPART_OK;
}

/* ============================================================================
 * Encryption/Decryption
 * ============================================================================ */

rampart_error_t rp_chacha20_crypt(const rp_chacha20_ctx_t *ctx,
                                   const unsigned char *nonce,
                                   size_t nonce_len,
                                   unsigned long counter,
                                   unsigned char *data,
                                   size_t data_len) {
    unsigned char keystream[RP_CHACHA20_BLOCK_SIZE];
    size_t blocks;
    size_t remaining;
    size_t i;
    size_t offset;

    if (ctx == NULL || nonce == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    if (nonce_len != RP_CHACHA20_NONCE_SIZE) {
        return RAMPART_ERR_INVALID_SIZE;
    }

    if (!ctx->initialized) {
        return RAMPART_ERR_NOT_INITIALIZED;
    }

    /* Handle NULL data with zero length (valid no-op) */
    if (data == NULL) {
        if (data_len == 0) {
            return RAMPART_OK;
        }
        return RAMPART_ERR_NULL_PARAM;
    }

    if (data_len == 0) {
        return RAMPART_OK;
    }

    /* Process full blocks */
    blocks = data_len / RP_CHACHA20_BLOCK_SIZE;
    offset = 0;

    for (i = 0; i < blocks; i++) {
        chacha20_block(ctx, nonce, counter + (unsigned long)i, keystream);

        /* XOR keystream with data */
        {
            size_t j;
            for (j = 0; j < RP_CHACHA20_BLOCK_SIZE; j++) {
                data[offset + j] ^= keystream[j];
            }
        }

        offset += RP_CHACHA20_BLOCK_SIZE;
    }

    /* Process final partial block */
    remaining = data_len - offset;
    if (remaining > 0) {
        chacha20_block(ctx, nonce, counter + (unsigned long)blocks, keystream);

        for (i = 0; i < remaining; i++) {
            data[offset + i] ^= keystream[i];
        }
    }

    /* Wipe keystream from stack */
    rp_wipe_memory(keystream, sizeof(keystream));

    return RAMPART_OK;
}

/* ============================================================================
 * Nonce Generation
 * ============================================================================ */

rampart_error_t rp_crypto_generate_block_nonce(const rp_pool_header_t *pool,
                                                const rp_block_header_t *block,
                                                unsigned long generation,
                                                unsigned char *nonce) {
    FILE *urandom;

    (void)pool;   /* Unused after VULN-004 fix */
    (void)block;  /* Unused after VULN-004 fix */

    if (nonce == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    /*
     * VULN-004 fix: Use fresh randomness for nonce generation.
     *
     * Previous implementation derived the nonce from predictable values:
     * block address, generation counter, and pool guard patterns. If any
     * of these were known or predictable, nonce reuse could occur.
     *
     * New approach:
     * - [0-7]  = 8 bytes of fresh randomness from /dev/urandom
     * - [8-11] = Generation counter (provides ordering/uniqueness guarantee)
     *
     * The random component ensures nonce uniqueness even if the generation
     * counter wraps or is predicted. The counter provides a backup uniqueness
     * guarantee if urandom produces a collision (astronomically unlikely).
     */
    urandom = fopen("/dev/urandom", "rb");
    if (urandom == NULL) {
        return RAMPART_ERR_ENTROPY_SOURCE;
    }

    /* Read 8 bytes of randomness for nonce[0-7] */
    if (fread(nonce, 1, 8, urandom) != 8) {
        fclose(urandom);
        return RAMPART_ERR_ENTROPY_SOURCE;
    }
    fclose(urandom);

    /* Append generation counter as nonce[8-11] */
    store32_le(nonce + 8, generation);

    return RAMPART_OK;
}
