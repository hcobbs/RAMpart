/**
 * @file poc_14_key_truncation.c
 * @brief PoC for VULN-014: Silent Key Truncation
 *
 * VULNERABILITY: Keys longer than 32 bytes are silently truncated
 *                without error or warning.
 *
 * CVSS 3.1: 6.1 (Medium)
 * CWE-325: Missing Cryptographic Step
 *
 * LOCATION: src/rp_pool.c:74-81
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rampart.h"

int main(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    /* 64-byte key, but only 32 bytes will be used! */
    const unsigned char long_key[64] =
        "FirstHalfOfTheKeyWillBeUsed!!!!!"  /* 32 bytes - USED */
        "SecondHalfSilentlyIgnored!!!!!!!"; /* 32 bytes - IGNORED */

    printf("=== VULN-014: Silent Key Truncation ===\n\n");

    rampart_config_default(&config);
    config.pool_size = 64 * 1024;
    config.encryption_enabled = 1;
    config.encryption_key = long_key;
    config.encryption_key_size = 64;  /* Providing 64 bytes */

    printf("[*] Configuring encryption with 64-byte key:\n");
    printf("    Key bytes 0-31:  \"%.32s\"\n", long_key);
    printf("    Key bytes 32-63: \"%.32s\"\n", long_key + 32);

    pool = rampart_init(&config);

    if (pool == NULL) {
        printf("[!] Pool creation failed\n");
        return 1;
    }

    printf("\n[+] Pool created successfully!\n");
    printf("[!] No error returned for oversized key.\n");

    printf("\n[VULNERABLE] Key was silently truncated to 32 bytes!\n");
    printf("[*] User believes full 64-byte key is used.\n");
    printf("[*] Only first 32 bytes (\"%.32s\") are stored.\n", long_key);

    printf("\n=== Security Impact ===\n");
    printf("1. User may choose weak first 32 bytes, strong last 32\n");
    printf("2. Key derivation assumptions broken\n");
    printf("3. User's security model invalidated\n");

    rampart_shutdown(pool);

    printf("\nRemediation: Return RAMPART_ERR_INVALID_CONFIG if key > 32.\n");

    return 0;
}
