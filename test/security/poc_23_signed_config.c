/**
 * @file poc_23_signed_config.c
 * @brief PoC for VULN-023: Signed Config Values
 *
 * VULNERABILITY: Boolean config fields use int type, accepting negative
 *                values which behave unexpectedly.
 *
 * CVSS 3.1: 4.0 (Medium)
 * CWE-20: Improper Input Validation
 *
 * LOCATION: h/rampart.h:308,342,353
 *
 * STATUS: FIXED - Boolean config values are normalized to 0 or 1 in
 *         rp_pool_init(). Any non-zero value becomes 1, zero stays 0.
 *         This prevents semantic confusion from negative values.
 */

#include <stdio.h>
#include <stdlib.h>
#include "rampart.h"

int main(void) {
    rampart_config_t config;
    rampart_pool_t *pool;

    printf("=== VULN-023: Signed Config Values ===\n\n");

    printf("[*] Boolean config fields in rampart_config_t:\n");
    printf("    int strict_thread_mode;\n");
    printf("    int validate_on_free;\n");

    printf("\n[*] These accept ANY int value, including negative.\n");

    /* Test with negative values */
    rampart_config_default(&config);
    config.pool_size = 64 * 1024;

    printf("\n=== Testing Negative Values ===\n");

    config.strict_thread_mode = -1;
    config.validate_on_free = -999;

    printf("[*] Setting:\n");
    printf("    strict_thread_mode = -1\n");
    printf("    validate_on_free = -999\n");

    pool = rampart_init(&config);

    if (pool != NULL) {
        printf("\n[+] Pool created successfully with negative config!\n");

        /* Test if negative values behave as true */
        printf("\n[*] C truthiness: any non-zero is true\n");
        printf("    strict_thread_mode (-1) is %s\n",
               config.strict_thread_mode ? "TRUE" : "FALSE");
        printf("    validate_on_free (-999) is %s\n",
               config.validate_on_free ? "TRUE" : "FALSE");

        rampart_shutdown(pool);
    } else {
        printf("[!] Pool creation failed\n");
    }

    printf("\n=== Potential Issues ===\n");
    printf("1. Semantic confusion:\n");
    printf("   User sets -1 thinking it means 'default'\n");
    printf("   Library interprets as 'enabled'\n");

    printf("\n2. Bitwise operations:\n");
    printf("   If code uses (flag & 0x01) instead of truthiness:\n");
    printf("     -1 & 0x01 = 1 (true)\n");
    printf("     -2 & 0x01 = 0 (false!)\n");

    printf("\n3. Comparison bugs:\n");
    printf("   if (flag == 1) vs if (flag != 0)\n");
    printf("   -1 fails first check, passes second\n");

    printf("\n=== Current Behavior ===\n");
    printf("RAMpart uses truthiness checks: if (flag)\n");
    printf("So negative values WORK but are semantically wrong.\n");

    printf("\nRemediation:\n");
    printf("  - Use unsigned char for booleans\n");
    printf("  - Validate: if (val != 0 && val != 1) error\n");
    printf("  - Normalize: flag = (val != 0)\n");

    return 0;
}
