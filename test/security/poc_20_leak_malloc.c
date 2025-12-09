/**
 * @file poc_20_leak_malloc.c
 * @brief PoC for VULN-020: Leak Info Uses System Malloc
 *
 * VULNERABILITY: rampart_get_leaks() allocates result via system malloc,
 *                exposing sensitive info outside secure pool.
 *
 * CVSS 3.1: 4.8 (Medium)
 * CWE-212: Improper Removal of Sensitive Information
 *
 * LOCATION: src/rampart.c:546-547
 *
 * STATUS: FIXED - Leak info array now includes a hidden size header.
 *         rampart_free_leak_info() recovers the count and securely wipes
 *         the entire allocation (addresses, sizes, thread IDs) before freeing.
 */

#include <stdio.h>
#include <stdlib.h>
#include "rampart.h"

int main(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    char *block1, *block2;
    rampart_leak_info_t *leaks;
    size_t leak_count;
    size_t i;

    printf("=== VULN-020: Leak Info Uses System Malloc ===\n\n");

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    if (pool == NULL) {
        printf("[!] Pool creation failed\n");
        return 1;
    }

    /* Create some allocations */
    block1 = (char *)rampart_alloc(pool, 128);
    block2 = (char *)rampart_alloc(pool, 256);

    printf("[*] Created 2 allocations (intentional leaks)\n");

    /* Get leak info */
    rampart_get_leaks(pool, &leaks, &leak_count);

    printf("[*] rampart_get_leaks() returned %zu leaks\n", leak_count);
    printf("[*] Leak array address: %p\n\n", (void *)leaks);

    printf("=== Security Issue ===\n");
    printf("The leak array was allocated via system malloc():\n");
    printf("    leak_array = (rampart_leak_info_t *)malloc(...)\n\n");

    printf("This array contains:\n");
    for (i = 0; i < leak_count; i++) {
        printf("  Leak %zu: addr=%p size=%zu thread=%lu\n",
               i, leaks[i].address, leaks[i].size, leaks[i].thread_id);
    }

    printf("\n[VULNERABLE] Sensitive information exposed!\n");
    printf("  - Block addresses (heap layout)\n");
    printf("  - Allocation sizes (program behavior)\n");
    printf("  - Thread IDs (threading model)\n");

    printf("\n=== Why This Matters ===\n");
    printf("System malloc memory:\n");
    printf("  - May be swapped to disk\n");
    printf("  - Not securely wiped on free\n");
    printf("  - Visible in core dumps\n");
    printf("  - Accessible via other vulnerabilities\n");

    printf("\nThe whole point of RAMpart is secure memory.\n");
    printf("Leaking info via system heap defeats the purpose.\n");

    rampart_free_leak_info(leaks);
    rampart_free(pool, block1);
    rampart_free(pool, block2);
    rampart_shutdown(pool);

    printf("\nRemediation:\n");
    printf("  - Allocate from the secure pool itself\n");
    printf("  - Or require caller to provide buffer\n");
    printf("  - Or wipe the array before free\n");

    return 0;
}
