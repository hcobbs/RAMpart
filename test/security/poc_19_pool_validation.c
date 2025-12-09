/**
 * @file poc_19_pool_validation.c
 * @brief PoC for VULN-019: No Pool Handle Validation
 *
 * VULNERABILITY: Pool handle is cast directly without validation.
 *
 * CVSS 3.1: 5.0 (Medium)
 * CWE-476: NULL Pointer Dereference (and related)
 *
 * LOCATION: src/rampart.c:269
 *
 * STATUS: FIXED - Pool magic number validation added. All public API functions
 *         now verify pool_magic == RP_POOL_MAGIC before accessing any pool
 *         fields. Invalid handles return RAMPART_ERR_NOT_INITIALIZED.
 */

#include <stdio.h>
#include <stdlib.h>
#include "rampart.h"

int main(void) {
    rampart_pool_t *fake_pool;
    void *result;

    printf("=== VULN-019: No Pool Handle Validation ===\n\n");

    printf("[*] In rampart_alloc():\n");
    printf("    p = (rp_pool_header_t *)pool;\n");
    printf("    rp_pool_lock(p);  // Accesses p->mutex\n");

    printf("\n[*] No validation that 'pool' is actually a valid pool.\n");

    printf("\n=== Attack Scenario ===\n");
    printf("If attacker can control pool pointer:\n");
    printf("  1. Pass garbage pointer as pool\n");
    printf("  2. Library casts it to rp_pool_header_t*\n");
    printf("  3. Tries to lock mutex at fake address\n");
    printf("  4. May crash, or worse, succeed\n");

    printf("\n[*] Demonstrating with stack address...\n");

    /* Create fake pool pointer */
    fake_pool = (rampart_pool_t *)0xDEADBEEF;

    printf("    Fake pool: %p\n", (void *)fake_pool);
    printf("    (Not executing call to avoid crash)\n");

    printf("\n=== Potential Impacts ===\n");
    printf("  - NULL dereference -> crash\n");
    printf("  - Arbitrary read/write at attacker address\n");
    printf("  - If attacker crafts fake pool header:\n");
    printf("    - Control mutex address\n");
    printf("    - Control free_list, alloc_list pointers\n");
    printf("    - Achieve arbitrary memory access\n");

    printf("\n=== Why This Happens ===\n");
    printf("rampart_pool_t is opaque to users.\n");
    printf("Library trusts that handle came from rampart_init().\n");
    printf("No way to verify without additional bookkeeping.\n");

    printf("\nRemediation:\n");
    printf("  - Add pool magic number at start of header\n");
    printf("  - Maintain global list of valid pools\n");
    printf("  - Validate pool pointer is in known range\n");

    return 0;
}
