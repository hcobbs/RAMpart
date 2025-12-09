/**
 * @file poc_12_split_underflow.c
 * @brief PoC for VULN-012: Block Split Size Underflow
 *
 * VULNERABILITY: rp_pool_split_block() calculates remainder_size without
 *                checking for underflow if total_size is corrupted.
 *
 * CVSS 3.1: 6.5 (Medium)
 * CWE-191: Integer Underflow
 *
 * LOCATION: src/rp_pool.c:305-308
 *
 * STATUS: FIXED - Split check now uses two-step validation to prevent
 *         integer overflow. First checks total_size >= needed_size,
 *         then checks if remainder is large enough separately.
 */

#include <stdio.h>
#include <stdlib.h>
#include "rampart.h"

int main(void) {
    rampart_config_t config;
    rampart_pool_t *pool;

    printf("=== VULN-012: Block Split Size Underflow ===\n\n");

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    if (pool == NULL) {
        printf("[!] Pool creation failed\n");
        return 1;
    }

    printf("[*] Vulnerability analysis:\n\n");
    printf("In rp_pool_split_block():\n");
    printf("    remainder_size = block->total_size - needed_size;\n\n");

    printf("If total_size is corrupted to be smaller than needed_size:\n");
    printf("    remainder_size wraps to huge value (SIZE_MAX - delta)\n\n");

    printf("Attack scenario:\n");
    printf("1. Overflow to corrupt block's total_size field\n");
    printf("2. Set total_size to small value (e.g., 16)\n");
    printf("3. Next allocation tries to split this block\n");
    printf("4. remainder_size = 16 - 128 = SIZE_MAX - 112\n");
    printf("5. Remainder block initialized with huge size\n");
    printf("6. Pool state corrupted\n");

    printf("\n[*] Demonstrative only, no execution.\n");

    rampart_shutdown(pool);

    printf("\n=== PoC Complete ===\n");
    printf("Remediation: Check total_size >= needed_size before subtraction.\n");

    return 0;
}
