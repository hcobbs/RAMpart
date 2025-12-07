/**
 * @file rp_crypto.c
 * @brief RAMpart Feistel cipher implementation
 *
 * Implements a 16-round Feistel block cipher for data-at-rest encryption.
 * Block size is 8 bytes (64 bits), key size up to 32 bytes (256 bits).
 *
 * This is a custom cipher designed for simplicity and C89 compliance,
 * not for cryptographic security against sophisticated attacks.
 */

#include "internal/rp_crypto.h"
#include "internal/rp_wipe.h"
#include <string.h>

/* ============================================================================
 * S-Box (Substitution Box)
 * ============================================================================
 * This S-box is the AES Rijndael S-box, providing good non-linearity
 * and resistance to linear/differential cryptanalysis. It is a well-studied
 * public construction and does not contain any known backdoors.
 *
 * Source: FIPS-197 (AES specification)
 * Each byte is transformed via: S(x) = A * x^(-1) + b (in GF(2^8))
 */

static const unsigned char SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * rotate_left - Rotate 32-bit value left by n bits
 */
static unsigned long rotate_left(unsigned long val, int n) {
    n = n & 31;  /* Ensure n is in range 0-31 */
    if (n == 0) {
        return val & 0xFFFFFFFFUL;
    }
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFFUL;
}

/**
 * bytes_to_ulong - Convert 4 bytes to unsigned long (big-endian)
 */
static unsigned long bytes_to_ulong(const unsigned char *bytes) {
    return ((unsigned long)bytes[0] << 24) |
           ((unsigned long)bytes[1] << 16) |
           ((unsigned long)bytes[2] << 8) |
           ((unsigned long)bytes[3]);
}

/**
 * ulong_to_bytes - Convert unsigned long to 4 bytes (big-endian)
 */
static void ulong_to_bytes(unsigned long val, unsigned char *bytes) {
    bytes[0] = (unsigned char)((val >> 24) & 0xFF);
    bytes[1] = (unsigned char)((val >> 16) & 0xFF);
    bytes[2] = (unsigned char)((val >> 8) & 0xFF);
    bytes[3] = (unsigned char)(val & 0xFF);
}

/* ============================================================================
 * Round Function
 * ============================================================================ */

unsigned long rp_crypto_round_function(unsigned long half,
                                        unsigned long round_key) {
    unsigned char bytes[4];
    unsigned long result;

    /* XOR with round key */
    half ^= round_key;

    /* Convert to bytes for S-box substitution */
    ulong_to_bytes(half, bytes);

    /* S-box substitution */
    bytes[0] = SBOX[bytes[0]];
    bytes[1] = SBOX[bytes[1]];
    bytes[2] = SBOX[bytes[2]];
    bytes[3] = SBOX[bytes[3]];

    /* Convert back to unsigned long */
    result = bytes_to_ulong(bytes);

    /* Rotation for diffusion */
    result = rotate_left(result, 7);

    /* Additional mixing */
    result ^= rotate_left(result, 13);
    result ^= rotate_left(result, 22);

    return result & 0xFFFFFFFFUL;
}

/* ============================================================================
 * Key Schedule
 * ============================================================================ */

void rp_crypto_key_schedule(const unsigned char *key,
                             size_t key_size,
                             unsigned long *round_keys) {
    unsigned char padded_key[RAMPART_MAX_KEY_SIZE];
    unsigned long temp;
    int i;

    /* Pad or truncate key to 32 bytes */
    memset(padded_key, 0, sizeof(padded_key));
    if (key_size > RAMPART_MAX_KEY_SIZE) {
        key_size = RAMPART_MAX_KEY_SIZE;
    }
    memcpy(padded_key, key, key_size);

    /* Generate round keys */
    for (i = 0; i < RP_CRYPTO_ROUNDS; i++) {
        /* Extract 4 bytes from padded key with rotation */
        temp = bytes_to_ulong(&padded_key[(i * 4) % RAMPART_MAX_KEY_SIZE]);

        /* Mix with round constant */
        temp ^= (unsigned long)(i + 1) * 0x9E3779B9UL;

        /* Apply S-box to parts */
        temp = rp_crypto_round_function(temp, (unsigned long)i);

        round_keys[i] = temp;
    }

    /* Securely wipe temporary key material */
    rp_wipe_memory(padded_key, sizeof(padded_key));
}

/* ============================================================================
 * Context Management
 * ============================================================================ */

rampart_error_t rp_crypto_init_ctx(rp_cipher_ctx_t *ctx,
                                    const unsigned char *key,
                                    size_t key_size) {
    if (ctx == NULL || key == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    if (key_size == 0 || key_size > RAMPART_MAX_KEY_SIZE) {
        return RAMPART_ERR_INVALID_SIZE;
    }

    /* Generate round keys */
    rp_crypto_key_schedule(key, key_size, ctx->round_keys);
    ctx->initialized = 1;

    return RAMPART_OK;
}

void rp_crypto_destroy_ctx(rp_cipher_ctx_t *ctx) {
    if (ctx == NULL) {
        return;
    }

    /* Securely wipe round keys */
    rp_wipe_memory(ctx->round_keys, sizeof(ctx->round_keys));
    ctx->initialized = 0;
}

/* ============================================================================
 * Block Cipher Operations
 * ============================================================================ */

rampart_error_t rp_crypto_encrypt_block(const rp_cipher_ctx_t *ctx,
                                         unsigned char *block) {
    unsigned long left, right, temp;
    int i;

    if (ctx == NULL || block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    if (!ctx->initialized) {
        return RAMPART_ERR_NOT_INITIALIZED;
    }

    /* Split block into left and right halves */
    left = bytes_to_ulong(&block[0]);
    right = bytes_to_ulong(&block[4]);

    /* Feistel rounds */
    for (i = 0; i < RP_CRYPTO_ROUNDS; i++) {
        temp = right;
        right = left ^ rp_crypto_round_function(right, ctx->round_keys[i]);
        left = temp;
    }

    /* Final swap (undo last swap from loop) */
    temp = left;
    left = right;
    right = temp;

    /* Combine halves back into block */
    ulong_to_bytes(left, &block[0]);
    ulong_to_bytes(right, &block[4]);

    return RAMPART_OK;
}

rampart_error_t rp_crypto_decrypt_block(const rp_cipher_ctx_t *ctx,
                                         unsigned char *block) {
    unsigned long left, right, temp;
    int i;

    if (ctx == NULL || block == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    if (!ctx->initialized) {
        return RAMPART_ERR_NOT_INITIALIZED;
    }

    /* Split block into left and right halves */
    left = bytes_to_ulong(&block[0]);
    right = bytes_to_ulong(&block[4]);

    /* Feistel rounds in reverse */
    for (i = RP_CRYPTO_ROUNDS - 1; i >= 0; i--) {
        temp = left;
        left = right ^ rp_crypto_round_function(left, ctx->round_keys[i]);
        right = temp;
    }

    /* Final swap (undo last swap from loop) */
    temp = left;
    left = right;
    right = temp;

    /* Combine halves back into block */
    ulong_to_bytes(left, &block[0]);
    ulong_to_bytes(right, &block[4]);

    return RAMPART_OK;
}

/* ============================================================================
 * Data Encryption (Arbitrary Length)
 * ============================================================================ */

rampart_error_t rp_crypto_encrypt(const rp_cipher_ctx_t *ctx,
                                   unsigned char *data,
                                   size_t size) {
    size_t full_blocks;
    size_t remainder;
    size_t i;
    rampart_error_t err;

    if (ctx == NULL || data == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    if (!ctx->initialized) {
        return RAMPART_ERR_NOT_INITIALIZED;
    }

    if (size == 0) {
        return RAMPART_OK;
    }

    /* Process full blocks */
    full_blocks = size / RP_CRYPTO_BLOCK_SIZE;
    for (i = 0; i < full_blocks; i++) {
        err = rp_crypto_encrypt_block(ctx, &data[i * RP_CRYPTO_BLOCK_SIZE]);
        if (err != RAMPART_OK) {
            return err;
        }
    }

    /* Handle partial final block using keystream XOR (CTR-like mode) */
    remainder = size % RP_CRYPTO_BLOCK_SIZE;
    if (remainder > 0) {
        unsigned char keystream[RP_CRYPTO_BLOCK_SIZE];
        size_t offset = full_blocks * RP_CRYPTO_BLOCK_SIZE;
        size_t j;

        /* Generate keystream by encrypting block counter */
        memset(keystream, 0, RP_CRYPTO_BLOCK_SIZE);
        ulong_to_bytes((unsigned long)full_blocks, &keystream[4]);

        err = rp_crypto_encrypt_block(ctx, keystream);
        if (err != RAMPART_OK) {
            rp_wipe_memory(keystream, RP_CRYPTO_BLOCK_SIZE);
            return err;
        }

        /* XOR data with keystream (reversible) */
        for (j = 0; j < remainder; j++) {
            data[offset + j] ^= keystream[j];
        }
        rp_wipe_memory(keystream, RP_CRYPTO_BLOCK_SIZE);
    }

    return RAMPART_OK;
}

rampart_error_t rp_crypto_decrypt(const rp_cipher_ctx_t *ctx,
                                   unsigned char *data,
                                   size_t size) {
    size_t full_blocks;
    size_t remainder;
    size_t i;
    rampart_error_t err;

    if (ctx == NULL || data == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }

    if (!ctx->initialized) {
        return RAMPART_ERR_NOT_INITIALIZED;
    }

    if (size == 0) {
        return RAMPART_OK;
    }

    /* Process full blocks */
    full_blocks = size / RP_CRYPTO_BLOCK_SIZE;
    for (i = 0; i < full_blocks; i++) {
        err = rp_crypto_decrypt_block(ctx, &data[i * RP_CRYPTO_BLOCK_SIZE]);
        if (err != RAMPART_OK) {
            return err;
        }
    }

    /* Handle partial final block using keystream XOR (CTR-like mode) */
    remainder = size % RP_CRYPTO_BLOCK_SIZE;
    if (remainder > 0) {
        unsigned char keystream[RP_CRYPTO_BLOCK_SIZE];
        size_t offset = full_blocks * RP_CRYPTO_BLOCK_SIZE;
        size_t j;

        /* Generate keystream by encrypting block counter (same as encrypt) */
        memset(keystream, 0, RP_CRYPTO_BLOCK_SIZE);
        ulong_to_bytes((unsigned long)full_blocks, &keystream[4]);

        err = rp_crypto_encrypt_block(ctx, keystream);
        if (err != RAMPART_OK) {
            rp_wipe_memory(keystream, RP_CRYPTO_BLOCK_SIZE);
            return err;
        }

        /* XOR data with keystream (reversible - same as encrypt) */
        for (j = 0; j < remainder; j++) {
            data[offset + j] ^= keystream[j];
        }
        rp_wipe_memory(keystream, RP_CRYPTO_BLOCK_SIZE);
    }

    return RAMPART_OK;
}
