/**
 * @file poc_15_barrier_fallback.c
 * @brief PoC for VULN-015: Weak Memory Barrier Fallback
 *
 * VULNERABILITY: Non-GCC compilers use ineffective memory barrier,
 *                potentially allowing wipe optimization.
 *
 * CVSS 3.1: 5.9 (Medium)
 * CWE-14: Compiler Removal of Code to Clear Buffers
 *
 * LOCATION: src/rp_wipe.c:43-44
 *
 * STATUS: FIXED - Proper memory barriers added for all major compilers.
 *         GCC/Clang: inline asm with memory clobber
 *         MSVC: _ReadWriteBarrier() intrinsic
 *         Others: volatile function pointer technique prevents optimization
 */

#include <stdio.h>
#include <stdlib.h>
#include "rampart.h"

int main(void) {
    printf("=== VULN-015: Weak Memory Barrier Fallback ===\n\n");

    printf("[*] In rp_wipe.c, memory barrier is:\n\n");

    printf("#if defined(__GNUC__)\n");
    printf("    __asm__ __volatile__(\"\" ::: \"memory\");\n");
    printf("#else\n");
    printf("    volatile int barrier_dummy = 0;\n");
    printf("    barrier_dummy = barrier_dummy;  /* NO-OP! */\n");
    printf("#endif\n");

    printf("\n[*] The GCC version is correct.\n");
    printf("[!] The fallback is essentially a no-op!\n");

    printf("\n=== Impact ===\n");
    printf("On non-GCC compilers (MSVC, Intel, etc.):\n");
    printf("  1. Compiler may optimize away wipe loops\n");
    printf("  2. Sensitive data may remain in memory\n");
    printf("  3. Core dumps expose 'wiped' data\n");

    printf("\n=== Compiler Behavior ===\n");
    printf("The fallback code:\n");
    printf("    volatile int x = 0; x = x;\n");
    printf("Creates a data dependency but NOT a memory barrier.\n");
    printf("Compiler is still free to reorder/remove other memory ops.\n");

    printf("\n=== Current Compiler ===\n");
#if defined(__GNUC__)
    printf("Compiled with GCC/compatible - proper barrier used.\n");
#elif defined(_MSC_VER)
    printf("Compiled with MSVC - WEAK barrier in use!\n");
#elif defined(__INTEL_COMPILER)
    printf("Compiled with Intel - WEAK barrier in use!\n");
#else
    printf("Unknown compiler - WEAK barrier likely in use!\n");
#endif

    printf("\nRemediation: Use platform-specific barriers:\n");
    printf("  MSVC: _ReadWriteBarrier() or MemoryBarrier()\n");
    printf("  C11+: atomic_signal_fence(memory_order_seq_cst)\n");
    printf("  Portable: explicit_bzero() or memset_s()\n");

    return 0;
}
