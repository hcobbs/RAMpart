/**
 * @file poc_16_sbox_timing.c
 * @brief PoC for VULN-016: S-Box Cache Timing Side-Channel
 *
 * VULNERABILITY: S-box lookups cause cache hits/misses that leak key info.
 *
 * CVSS 3.1: 5.5 (Medium)
 * CWE-208: Observable Timing Discrepancy
 *
 * LOCATION: src/rp_crypto.c:128-131
 */

#include <stdio.h>
#include <stdlib.h>
#include "rampart.h"

int main(void) {
    printf("=== VULN-016: S-Box Cache Timing ===\n\n");

    printf("[*] The Feistel cipher uses AES S-box:\n\n");
    printf("    bytes[0] = SBOX[bytes[0]];\n");
    printf("    bytes[1] = SBOX[bytes[1]];\n");
    printf("    ...\n");

    printf("\n[*] Classic cache timing attack:\n");
    printf("    1. S-box is 256-byte lookup table\n");
    printf("    2. Table spans multiple cache lines (64 bytes each)\n");
    printf("    3. Accessing SBOX[x] loads cache line containing x\n");
    printf("    4. Attacker measures which cache lines are loaded\n");
    printf("    5. Reveals which S-box indices were accessed\n");
    printf("    6. Indices depend on key XOR plaintext\n");
    printf("    7. Key bytes recovered!\n");

    printf("\n=== Attack Variants ===\n");
    printf("PRIME+PROBE: Fill cache, let victim run, probe what's evicted\n");
    printf("FLUSH+RELOAD: Flush cache, let victim run, check what's loaded\n");
    printf("EVICT+TIME: Evict specific lines, measure encryption time\n");

    printf("\n=== Practical Exploitability ===\n");
    printf("Requires:\n");
    printf("  - Shared CPU cache with victim\n");
    printf("  - Ability to trigger many encryptions\n");
    printf("  - High-resolution timing (rdtsc or similar)\n");
    printf("\nMost practical in:\n");
    printf("  - Cloud multi-tenant environments\n");
    printf("  - Same-machine attacks\n");
    printf("  - SGX enclave attacks\n");

    printf("\n[*] Note: Encryption is unimplemented (VULN-001),\n");
    printf("    so this is theoretical for current RAMpart.\n");

    printf("\nRemediation:\n");
    printf("  - Use bitsliced S-box implementation\n");
    printf("  - Use constant-time AES-NI instructions\n");
    printf("  - Avoid table lookups entirely (algebraic S-box)\n");

    return 0;
}
