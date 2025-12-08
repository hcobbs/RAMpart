/**
 * @file poc_17_counter_overflow.c
 * @brief PoC for VULN-017: CTR Counter Overflow
 *
 * VULNERABILITY: CTR mode uses 32-bit counter, overflowing after 4GB.
 *
 * CVSS 3.1: 5.3 (Medium)
 * CWE-330: Use of Insufficiently Random Values
 *
 * LOCATION: src/rp_crypto.c:331-332
 */

#include <stdio.h>
#include <stdlib.h>
#include "rampart.h"

int main(void) {
    printf("=== VULN-017: CTR Counter Overflow ===\n\n");

    printf("[*] For partial blocks, RAMpart uses CTR-like mode:\n\n");
    printf("    ulong_to_bytes(full_blocks, &keystream[4]);\n");
    printf("    rp_crypto_feistel_encrypt(ctx, keystream, keystream);\n");
    printf("    // XOR keystream with data\n");

    printf("\n[*] Counter is only 32 bits (unsigned long on some systems)\n");
    printf("    Max value: 2^32 - 1 = 4,294,967,295\n");
    printf("    Block size: 8 bytes\n");
    printf("    Max unique keystream: 4GB\n");

    printf("\n=== Attack Scenario ===\n");
    printf("If encrypting more than 4GB with same key:\n");
    printf("  1. Counter overflows back to 0\n");
    printf("  2. Same keystream reused!\n");
    printf("  3. C1 = P1 XOR KS, C2 = P2 XOR KS (same KS)\n");
    printf("  4. C1 XOR C2 = P1 XOR P2\n");
    printf("  5. Known-plaintext attack trivial\n");

    printf("\n=== Exploitation ===\n");
    printf("Attacker who can:\n");
    printf("  - Observe >4GB encrypted data\n");
    printf("  - Know some plaintext blocks\n");
    printf("Can recover other plaintext via XOR.\n");

    printf("\n=== Pool Size Consideration ===\n");
    printf("Typical RAMpart pools are <1GB.\n");
    printf("Counter overflow unlikely in normal use.\n");
    printf("Risk increases if:\n");
    printf("  - Very large pools (>4GB)\n");
    printf("  - Same key used across multiple pools\n");
    printf("  - Long-running applications\n");

    printf("\n[*] Note: Encryption is unimplemented (VULN-001),\n");
    printf("    so this is theoretical for current RAMpart.\n");

    printf("\nRemediation:\n");
    printf("  - Use 64-bit counter (or 96-bit nonce + 32-bit counter)\n");
    printf("  - Include pool ID in counter\n");
    printf("  - Re-key after 2^32 blocks\n");

    return 0;
}
