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
 *
 * STATUS: FIXED - Guard patterns are now randomized per-pool at init time.
 *         The attacker no longer knows the expected pattern values.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rampart.h"

/*
 * OLD Guard patterns from rp_types.h (before fix):
 * #define RP_GUARD_FRONT_PATTERN 0xDEADBEEFUL
 * #define RP_GUARD_REAR_PATTERN  0xFEEDFACEUL
 * #define RP_GUARD_SIZE 16
 *
 * With VULN-004 fix, these are still defined but only used as fallbacks.
 * Each pool now generates random patterns at initialization time.
 */

#define RP_GUARD_SIZE 16
#define OLD_GUARD_REAR_PATTERN 0xFEEDFACEUL

/* Write the OLD expected rear guard pattern (pre-fix attack) */
static void write_fake_guard_old_pattern(unsigned char *ptr) {
    unsigned char pattern[4];
    int i;

    /* Big-endian byte order (as used in rp_block.c) */
    pattern[0] = (unsigned char)((OLD_GUARD_REAR_PATTERN >> 24) & 0xFF);
    pattern[1] = (unsigned char)((OLD_GUARD_REAR_PATTERN >> 16) & 0xFF);
    pattern[2] = (unsigned char)((OLD_GUARD_REAR_PATTERN >> 8) & 0xFF);
    pattern[3] = (unsigned char)(OLD_GUARD_REAR_PATTERN & 0xFF);

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

    /*
     * NOW: Try to repair the rear guard with OLD known pattern!
     * With the VULN-004 fix, this should FAIL because the pool uses
     * randomized patterns that the attacker doesn't know.
     */
    printf("[*] Attempting to repair rear guard with OLD pattern 0xFEEDFACE...\n");
    write_fake_guard_old_pattern((unsigned char *)(next_block + 64));

    /* Try to free - should FAIL because attacker doesn't know the actual pattern */
    err = rampart_free(pool, next_block);
    printf("[*] rampart_free() returned: %s\n", rampart_error_string(err));

    if (err == RAMPART_OK) {
        printf("\n[VULNERABLE] Guard bypass successful!\n");
        printf("[!] Buffer overflow went UNDETECTED!\n");
        printf("[!] Attacker wrote 20 bytes beyond allocation.\n");
        printf("[!] Memory corruption occurred silently.\n");
    } else if (err == RAMPART_ERR_GUARD_CORRUPTED) {
        printf("\n[FIXED] Guard bypass BLOCKED!\n");
        printf("[+] Attack failed - attacker's fake pattern didn't match.\n");
        printf("[+] Per-pool randomized patterns prevent this attack.\n");
    } else {
        printf("[?] Unexpected error: %s\n", rampart_error_string(err));
    }

    /*
     * IMPACT DEMONSTRATION (pre-fix)
     */
    printf("\n=== Attack Impact (before fix) ===\n");
    printf("With predictable guards, attacker could:\n");
    printf("  1. Overflow heap buffers undetected\n");
    printf("  2. Corrupt adjacent block headers\n");
    printf("  3. Achieve arbitrary write on next free/alloc\n");
    printf("  4. Execute arbitrary code\n");

    printf("\n=== Fix Applied ===\n");
    printf("  Guard patterns are now randomized per-pool at init time.\n");
    printf("  Attacker cannot predict the expected pattern values.\n");
    printf("  OLD patterns (0xDEADBEEF, 0xFEEDFACE) only used as fallback.\n");

    rampart_shutdown(pool);

    printf("\n=== PoC Complete ===\n");

    /*
     * REMEDIATION (APPLIED):
     * Per-pool randomized guard patterns via /dev/urandom:
     *
     * In rp_pool_init():
     *     pool->guard_front_pattern = rp_generate_random_ulong();
     *     pool->guard_rear_pattern = rp_generate_random_ulong();
     *
     * Guard functions now use pool->guard_*_pattern instead of constants.
     *
     * This makes each pool's guards unique and unpredictable.
     */

    return 0;
}
