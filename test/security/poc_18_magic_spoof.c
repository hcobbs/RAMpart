/**
 * @file poc_18_magic_spoof.c
 * @brief PoC for VULN-018: Magic Number Spoofing
 *
 * VULNERABILITY: Magic numbers are known constants, allowing fake blocks.
 *
 * CVSS 3.1: 5.1 (Medium)
 * CWE-345: Insufficient Verification of Data Authenticity
 *
 * LOCATION: h/internal/rp_types.h:83-92
 *
 * STATUS: MITIGATED - Pool boundary validation (VULN-003 fix) now rejects
 *         fake blocks outside the pool. Within-pool attacks are mitigated by
 *         owner canary (VULN-005), safe unlinking (VULN-006), and coalesce
 *         validation (VULN-007). Randomizing magic numbers per-pool was
 *         considered but deemed unnecessary given these defenses.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rampart.h"

/* Known magic values from rp_types.h */
#define RP_BLOCK_MAGIC 0xB10CB10CUL
#define RP_BLOCK_FREED_MAGIC 0xF4EED000UL

int main(void) {
    unsigned long fake_block[32];  /* Simulated fake block on stack */

    printf("=== VULN-018: Magic Number Spoofing ===\n\n");

    printf("[*] Known magic numbers:\n");
    printf("    RP_BLOCK_MAGIC      = 0x%08lX\n", RP_BLOCK_MAGIC);
    printf("    RP_BLOCK_FREED_MAGIC = 0x%08lX\n", RP_BLOCK_FREED_MAGIC);

    printf("\n[*] Creating fake block structure...\n");

    memset(fake_block, 0, sizeof(fake_block));
    fake_block[0] = RP_BLOCK_MAGIC;  /* Magic number */

    printf("    Fake block at: %p\n", (void *)fake_block);
    printf("    Magic field:   0x%08lX\n", fake_block[0]);

    printf("\n=== Attack Scenarios ===\n");

    printf("\n1. Fake allocated block:\n");
    printf("   - Write magic 0xB10CB10C at controlled address\n");
    printf("   - Set total_size, user_size to desired values\n");
    printf("   - Pass fake user pointer to rampart_free()\n");
    printf("   - Library accepts it as valid block\n");
    printf("   - Potential arbitrary free\n");

    printf("\n2. Fake freed block:\n");
    printf("   - Write magic 0xF4EED000 at controlled address\n");
    printf("   - Corrupt a block's prev_addr to point here\n");
    printf("   - Coalescing treats fake block as free\n");
    printf("   - Merges real block with fake block\n");
    printf("   - Pool corruption\n");

    printf("\n=== Why This Matters ===\n");
    printf("Magic numbers provide WEAK validation.\n");
    printf("Attacker with write primitive can craft fake blocks.\n");
    printf("Combined with other vulns, enables exploitation.\n");

    printf("\n[*] Note: rp_block_from_user_ptr() has no bounds check,\n");
    printf("    so fake blocks outside pool are accepted if magic matches.\n");

    printf("\nRemediation:\n");
    printf("  - Add pool boundary validation\n");
    printf("  - Use per-pool randomized magic\n");
    printf("  - Include cryptographic MAC on block headers\n");

    return 0;
}
