/**
 * @file poc_07_coalesce_uaf.c
 * @brief PoC for VULN-007: Use-After-Free in Coalescing
 *
 * VULNERABILITY: Coalescing logic can be tricked into accessing
 *                already-freed memory via corrupted prev_addr pointer.
 *
 * CVSS 3.1: 7.5 (High)
 * CWE-416: Use After Free
 *
 * IMPACT: Memory corruption, potential code execution via
 *         controlled use-after-free.
 *
 * LOCATION: src/rp_pool.c:356-376
 *
 * STATUS: FIXED - Coalescing now validates prev_addr and next_addr pointers.
 *         Before accessing, pointers are checked to be within pool boundaries
 *         and properly aligned. Corrupted pointers are treated as NULL,
 *         preventing use-after-free via controlled coalescing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rampart.h"

int main(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    char *block1;
    char *block2;
    char *block3;

    printf("=== VULN-007: Use-After-Free in Coalescing ===\n\n");

    /* Initialize pool */
    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.validate_on_free = 0;

    pool = rampart_init(&config);
    if (pool == NULL) {
        printf("[!] Pool creation failed\n");
        return 1;
    }

    /*
     * Coalescing logic (rp_pool_coalesce):
     *
     * 1. Check if next_addr block is free
     *    - If yes, merge with current block
     * 2. Check if prev_addr block is free
     *    - If yes, merge current into previous
     *
     * The vulnerability:
     * - prev_addr is stored in block header
     * - Can be corrupted via overflow
     * - Coalescing will access whatever prev_addr points to
     * - If prev_addr points to already-freed memory, UAF!
     */

    printf("[*] Allocating test blocks...\n");

    block1 = (char *)rampart_alloc(pool, 128);
    block2 = (char *)rampart_alloc(pool, 128);
    block3 = (char *)rampart_alloc(pool, 128);

    if (!block1 || !block2 || !block3) {
        printf("[!] Allocation failed\n");
        rampart_shutdown(pool);
        return 1;
    }

    printf("[*] block1: %p\n", (void *)block1);
    printf("[*] block2: %p\n", (void *)block2);
    printf("[*] block3: %p\n", (void *)block3);

    /*
     * Attack scenario:
     *
     * 1. Allocate blocks: A, B, C
     * 2. Free block A (goes to free list)
     * 3. Reallocate A (same memory returned)
     * 4. Overflow new A to corrupt B's prev_addr
     * 5. Set B's prev_addr to point to controlled data
     * 6. Free B
     * 7. Coalescing checks rp_block_is_free(prev_addr)
     * 8. If prev_addr is crafted, we control the check
     *
     * More dangerous:
     * - Point prev_addr to freed block
     * - Coalescing accesses freed memory
     * - If freed memory reallocated with attacker data, UAF!
     */

    printf("\n=== Coalescing Logic Analysis ===\n");
    printf("[*] rp_pool_coalesce() pseudo-code:\n");
    printf("\n    prev_block = block->prev_addr;\n");
    printf("    if (prev_block != NULL && rp_block_is_free(prev_block)) {\n");
    printf("        // Remove both from free list\n");
    printf("        // Merge sizes\n");
    printf("        // Update pointers\n");
    printf("    }\n");

    printf("\n[*] Attack vector:\n");
    printf("    1. Corrupt block->prev_addr via overflow\n");
    printf("    2. Point prev_addr to controlled memory\n");
    printf("    3. When block is freed, coalescing reads prev_addr\n");
    printf("    4. rp_block_is_free() checks magic at that address\n");
    printf("    5. If magic = 0xF4EED000, coalescing proceeds!\n");
    printf("    6. prev_block->total_size is added to block\n");
    printf("    7. Attacker controls total_size = arbitrary write\n");

    printf("\n=== Demonstrating Concept ===\n");

    /* Free block1 to get it on free list */
    printf("[*] Freeing block1...\n");
    rampart_free(pool, block1);

    /* Now reallocate to get block1's memory back */
    printf("[*] Reallocating (should get block1's memory)...\n");
    block1 = (char *)rampart_alloc(pool, 128);
    printf("[*] New allocation: %p\n", (void *)block1);

    /*
     * At this point, if we overflow block1, we can corrupt block2's
     * header, including prev_addr.
     *
     * If we set prev_addr to a memory location we control with:
     * - magic = RP_BLOCK_FREED_MAGIC (0xF4EED000)
     * - total_size = controlled value
     *
     * Then freeing block2 will coalesce with our fake block!
     */

    printf("\n[!] Not executing actual UAF to avoid crash.\n");
    printf("[*] The vulnerability exists in coalescing logic.\n");

    /* Clean up */
    rampart_free(pool, block1);
    rampart_free(pool, block2);
    rampart_free(pool, block3);
    rampart_shutdown(pool);

    printf("\n=== PoC Complete ===\n");

    /*
     * REMEDIATION:
     * 1. Validate prev_addr is within pool boundaries
     * 2. Use separate canaries for address-order pointers
     * 3. Verify block addresses before coalescing:
     *    if (prev_addr < pool_start || prev_addr >= pool_end)
     *        return block;  // Don't coalesce
     * 4. Check that addresses are properly aligned
     */

    return 0;
}
