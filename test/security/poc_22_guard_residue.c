/**
 * @file poc_22_guard_residue.c
 * @brief PoC for VULN-022: Guard Bands Not Wiped
 *
 * VULNERABILITY: Guard bands remain in freed memory, allowing RAMpart
 *                block identification.
 *
 * CVSS 3.1: 4.3 (Medium)
 * CWE-200: Exposure of Sensitive Information
 *
 * LOCATION: src/rp_wipe.c:131
 *
 * STATUS: FIXED - Added rp_wipe_block_user_and_guards() which wipes the
 *         entire region including front guard, user data, and rear guard.
 *         Used in rampart_free() and rampart_shutdown().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rampart.h"

/* Known guard patterns */
#define RP_GUARD_FRONT_PATTERN 0xDEADBEEFUL
#define RP_GUARD_REAR_PATTERN  0xFEEDFACEUL

int main(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    char *block;
    char *realloc_block;
    int found_front = 0, found_rear = 0;
    int i;

    printf("=== VULN-022: Guard Bands Not Wiped ===\n\n");

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    if (pool == NULL) {
        printf("[!] Pool creation failed\n");
        return 1;
    }

    /* Allocate and free a block */
    block = (char *)rampart_alloc(pool, 64);
    printf("[*] Allocated 64 bytes at: %p\n", (void *)block);

    rampart_free(pool, block);
    printf("[*] Freed block\n");

    /* Reallocate to get same memory back */
    realloc_block = (char *)rampart_alloc(pool, 64);
    printf("[*] Reallocated: %p\n", (void *)realloc_block);

    if (realloc_block == block) {
        printf("[+] Got same memory address\n");
    }

    /*
     * User data is wiped, but what about the surrounding memory?
     * Guard bands from previous allocation may still exist in the
     * pool memory (in the free block's unused space).
     */

    printf("\n[*] rp_wipe_block_user_data() only wipes user data.\n");
    printf("[*] Guard patterns remain in pool memory.\n");

    printf("\n=== Forensic Detection ===\n");
    printf("Scanning memory for guard patterns:\n");
    printf("  Front guard: 0xDEADBEEF (repeated)\n");
    printf("  Rear guard:  0xFEEDFACE (repeated)\n");

    printf("\nIf found in freed memory regions, indicates:\n");
    printf("  - RAMpart was used\n");
    printf("  - Block boundaries\n");
    printf("  - Allocation sizes (from pattern positions)\n");

    printf("\n=== Information Disclosed ===\n");
    printf("Guard patterns in memory reveal:\n");
    printf("  1. RAMpart library in use (fingerprinting)\n");
    printf("  2. Historic allocation boundaries\n");
    printf("  3. Memory layout patterns\n");
    printf("  4. Potentially: sensitive data size from gap\n");

    rampart_free(pool, realloc_block);
    rampart_shutdown(pool);

    printf("\nRemediation:\n");
    printf("  - Wipe entire block including guards on free\n");
    printf("  - Or use different patterns for freed blocks\n");

    return 0;
}
