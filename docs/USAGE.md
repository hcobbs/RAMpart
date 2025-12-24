# RAMpart Usage Guide

## Table of Contents

1. [Quick Start](#quick-start)
2. [Pool Initialization](#pool-initialization)
3. [Memory Allocation](#memory-allocation)
4. [Memory Deallocation](#memory-deallocation)
5. [Pool Shutdown](#pool-shutdown)
6. [Configuration Options](#configuration-options)
7. [Error Handling](#error-handling)
8. [Security Features](#security-features)
9. [Block Parking (Encryption at Rest)](#block-parking-encryption-at-rest)
10. [Debugging and Diagnostics](#debugging-and-diagnostics)
11. [Best Practices](#best-practices)
12. [Common Patterns](#common-patterns)

## Quick Start

### Basic Usage

```c
#include "rampart.h"

int main(void) {
    rampart_pool_t *pool;
    rampart_config_t config;
    void *ptr;

    /* Initialize with default configuration */
    rampart_config_default(&config);
    config.pool_size = 1024 * 1024;  /* 1 MB pool */

    /* Create the pool */
    pool = rampart_init(&config);
    if (pool == NULL) {
        fprintf(stderr, "Failed to initialize pool\n");
        return 1;
    }

    /* Allocate memory */
    ptr = rampart_alloc(pool, 256);
    if (ptr == NULL) {
        fprintf(stderr, "Allocation failed\n");
        rampart_shutdown(pool);
        return 1;
    }

    /* Use the memory (it's zero-initialized) */
    memset(ptr, 'A', 256);

    /* Free the memory */
    rampart_free(pool, ptr);

    /* Shutdown the pool */
    rampart_shutdown(pool);

    return 0;
}
```

### Building with RAMpart

```bash
# Compile your application
gcc -I/path/to/rampart/h -c myapp.c -o myapp.o

# Link with librampart
gcc myapp.o -L/path/to/rampart/lib -lrampart -lpthread -o myapp
```

## Pool Initialization

### Configuration Structure

```c
typedef struct {
    size_t pool_size;           /* Total pool size in bytes */
    int strict_thread_mode;     /* Enforce thread ownership (0 or 1) */
    int validate_on_free;       /* Validate guards on free (0 or 1) */
    rampart_error_callback_t error_callback;  /* Error callback */
    void *callback_user_data;   /* User data for callback */
    int enable_parking;         /* Enable block parking (0 or 1) */
    const unsigned char *parking_key;  /* 32-byte parking key (or NULL) */
    size_t parking_key_len;     /* Parking key length (32 if provided) */
} rampart_config_t;
```

### Default Configuration

```c
rampart_config_t config;
rampart_config_default(&config);

/* Defaults:
 * - pool_size: 0 (must be set)
 * - strict_thread_mode: 1
 * - validate_on_free: 1
 * - error_callback: NULL
 * - enable_parking: 0
 * - parking_key: NULL (auto-generate)
 */
```

### Creating a Pool

```c
rampart_pool_t *pool;
rampart_config_t config;

rampart_config_default(&config);
config.pool_size = 10 * 1024 * 1024;  /* 10 MB */

pool = rampart_init(&config);
if (pool == NULL) {
    rampart_error_t err = rampart_get_last_error(NULL);
    fprintf(stderr, "Init failed: %s\n", rampart_error_string(err));
}
```

## Memory Allocation

### Basic Allocation

```c
void *ptr = rampart_alloc(pool, 1024);
if (ptr == NULL) {
    /* Handle allocation failure */
}
/* Memory is zero-initialized */
```

### Allocation Guarantees

1. Returned memory is always zero-initialized (0x00)
2. Memory is protected by guard bands
3. Memory is owned by the calling thread
4. If parking is enabled, blocks can be encrypted when not in use

### Checking Available Memory

```c
rampart_stats_t stats;
rampart_get_stats(pool, &stats);

printf("Total: %zu bytes\n", stats.total_size);
printf("Used: %zu bytes\n", stats.used_size);
printf("Free: %zu bytes\n", stats.free_size);
printf("Allocations: %zu\n", stats.allocation_count);
printf("Largest free block: %zu bytes\n", stats.largest_free_block);
```

## Memory Deallocation

### Basic Free

```c
rampart_error_t err = rampart_free(pool, ptr);
if (err != RAMPART_OK) {
    fprintf(stderr, "Free failed: %s\n", rampart_error_string(err));
}
```

### What Happens on Free

1. Guard bands are validated (if `validate_on_free` is enabled)
2. Thread ownership is verified (if `strict_thread_mode` is enabled)
3. User data is securely wiped (multi-pass overwrite)
4. Block is returned to the free list
5. Adjacent free blocks are coalesced

### Error Conditions

- `RAMPART_ERR_NULL_PARAM`: NULL pointer passed
- `RAMPART_ERR_INVALID_BLOCK`: Block not recognized as valid allocation
- `RAMPART_ERR_GUARD_CORRUPTED`: Buffer overflow/underflow detected
- `RAMPART_ERR_WRONG_THREAD`: Called from non-owning thread
- `RAMPART_ERR_DOUBLE_FREE`: Block already freed

## Pool Shutdown

### Normal Shutdown

```c
rampart_shutdown_result_t result;
result = rampart_shutdown(pool);

if (result.leaked_blocks > 0) {
    fprintf(stderr, "Warning: %zu blocks were not freed\n",
            result.leaked_blocks);
    fprintf(stderr, "Leaked bytes: %zu\n", result.leaked_bytes);
}
```

### Shutdown Behavior

1. All remaining allocations are reported as leaks
2. All memory is securely wiped
3. Pool resources are released
4. Pool pointer becomes invalid

### Leak Detection

```c
/* Get leak information before shutdown */
rampart_stats_t stats;
rampart_get_stats(pool, &stats);

if (stats.allocation_count > 0) {
    /* Iterate through leaked blocks for debugging */
    rampart_leak_info_t *leaks;
    size_t leak_count;

    rampart_get_leaks(pool, &leaks, &leak_count);
    for (size_t i = 0; i < leak_count; i++) {
        printf("Leak: %zu bytes at %p (thread %lu)\n",
               leaks[i].size,
               leaks[i].address,
               (unsigned long)leaks[i].thread_id);
    }
    rampart_free_leak_info(leaks);
}
```

## Configuration Options

### Enabling Block Parking

```c
/* With auto-generated key */
rampart_config_t config;
rampart_config_default(&config);
config.pool_size = 1024 * 1024;
config.enable_parking = 1;
/* parking_key = NULL means auto-generate */

pool = rampart_init(&config);

/* With user-provided key */
unsigned char key[32] = { /* your 256-bit key */ };

config.enable_parking = 1;
config.parking_key = key;
config.parking_key_len = 32;

pool = rampart_init(&config);
```

### Disabling Thread Enforcement

```c
config.strict_thread_mode = 0;  /* Allow cross-thread access */
```

**Warning**: Disabling thread enforcement removes a security feature. Only do this if your application has its own thread safety mechanisms.

### Custom Error Callback

```c
void my_error_handler(rampart_pool_t *pool,
                      rampart_error_t error,
                      void *block,
                      void *user_data) {
    const char *app_name = (const char *)user_data;
    fprintf(stderr, "[%s] RAMpart error: %s at %p\n",
            app_name, rampart_error_string(error), block);
}

config.error_callback = my_error_handler;
config.callback_user_data = "MyApp";
```

## Error Handling

### Error Codes

| Code | Meaning |
|------|---------|
| `RAMPART_OK` | Operation succeeded |
| `RAMPART_ERR_NULL_PARAM` | NULL parameter where not allowed |
| `RAMPART_ERR_INVALID_SIZE` | Size is 0 or exceeds pool capacity |
| `RAMPART_ERR_OUT_OF_MEMORY` | Pool has insufficient free space |
| `RAMPART_ERR_INVALID_BLOCK` | Pointer is not a valid allocation |
| `RAMPART_ERR_GUARD_CORRUPTED` | Guard band overwritten |
| `RAMPART_ERR_WRONG_THREAD` | Cross-thread access attempted |
| `RAMPART_ERR_DOUBLE_FREE` | Block was already freed |
| `RAMPART_ERR_NOT_INITIALIZED` | Pool not initialized |

### Retrieving Error Information

```c
rampart_error_t err = rampart_get_last_error(pool);
const char *msg = rampart_error_string(err);
```

## Security Features

### Guard Band Validation

```c
/* Explicit validation */
rampart_error_t err = rampart_validate(pool, ptr);
if (err == RAMPART_ERR_GUARD_CORRUPTED) {
    /* Buffer overflow detected! */
}
```

### Validating All Blocks

```c
/* Check all allocations for corruption */
rampart_validation_result_t result;
rampart_validate_pool(pool, &result);

if (result.corrupted_count > 0) {
    printf("Found %zu corrupted blocks\n", result.corrupted_count);
}
```

## Block Parking (Encryption at Rest)

Block parking provides limited encryption protection for sensitive data at rest in RAM. When a block is "parked," its contents are encrypted using ChaCha20. When "unparked," the data is decrypted for use.

### Threat Model

**Block parking protects against:**

- Data leaking to swap (when combined with OS memory protection like mlock)
- Data appearing in core dumps (when combined with MADV_DONTDUMP)
- Casual memory inspection by unsophisticated attackers
- Residual data disclosure if memory is freed and reallocated

**Block parking does NOT protect against:**

- Cold boot attacks (the encryption key is in RAM)
- DMA attacks (the key is in RAM)
- Root-level attackers who can read /proc/pid/mem
- Attackers with any mechanism to read your process memory
- Side-channel attacks on the cipher implementation

**Important:** The encryption key resides in pool memory. Any attacker who can read your encrypted data can also read your key. For genuine memory encryption, use hardware solutions like AMD SEV or Intel TME.

### Basic Usage

```c
/* Enable parking during pool initialization */
rampart_config_t config;
rampart_config_default(&config);
config.pool_size = 1024 * 1024;
config.enable_parking = 1;  /* Enable parking */

pool = rampart_init(&config);

/* Allocate and use a block */
unsigned char *secret = rampart_alloc(pool, 256);
memcpy(secret, sensitive_data, 256);

/* Park the block when not in use (encrypts data) */
rampart_park(pool, secret);

/* ... time passes, data is encrypted in memory ... */

/* Unpark when you need to use it again */
rampart_unpark(pool, secret);

/* Now you can read the decrypted data */
process_secret(secret);

/* Must unpark before freeing */
rampart_free(pool, secret);
```

### API Reference

```c
/* Park a block (encrypt its contents) */
rampart_error_t rampart_park(rampart_pool_t *pool, void *ptr);

/* Unpark a block (decrypt its contents) */
rampart_error_t rampart_unpark(rampart_pool_t *pool, void *ptr);

/* Check if a block is parked */
int rampart_is_parked(rampart_pool_t *pool, void *ptr);
```

### Error Conditions

| Error | Cause |
|-------|-------|
| `RAMPART_ERR_PARKING_DISABLED` | Pool was not initialized with `enable_parking` |
| `RAMPART_ERR_BLOCK_PARKED` | Attempted to park an already parked block, or free a parked block |
| `RAMPART_ERR_NOT_PARKED` | Attempted to unpark a block that is not parked |
| `RAMPART_ERR_WRONG_THREAD` | Called from wrong thread (if strict_thread_mode enabled) |

### Parked Block Restrictions

When a block is parked:

1. It cannot be freed (must unpark first)
2. Its contents are encrypted (reading gives encrypted garbage)
3. Guard bands may show different patterns (validated on unpark)

### When to Use Parking

Good use cases:

- Long-lived secrets (API keys, credentials, encryption keys)
- Sensitive data that sits idle between operations
- Data that should be protected during application sleep/hibernate

Not needed for:

- Short-lived temporary buffers (secure wipe on free is sufficient)
- Data that is constantly accessed (parking overhead is wasteful)
- Pools where all data is equally sensitive (just protect the whole pool)

### Cipher Details

- **Algorithm:** ChaCha20 (RFC 8439)
- **Key size:** 256 bits (32 bytes)
- **Nonce:** Derived from block address XOR allocation counter XOR pool salt
- **Properties:** Timing-safe (no lookup tables), stream cipher (arbitrary-length data)

## Debugging and Diagnostics

### Pool Statistics

```c
rampart_stats_t stats;
rampart_get_stats(pool, &stats);

printf("=== RAMpart Pool Statistics ===\n");
printf("Total size:          %zu bytes\n", stats.total_size);
printf("Used size:           %zu bytes\n", stats.used_size);
printf("Free size:           %zu bytes\n", stats.free_size);
printf("Overhead:            %zu bytes\n", stats.overhead_size);
printf("Allocation count:    %zu\n", stats.allocation_count);
printf("Free block count:    %zu\n", stats.free_block_count);
printf("Largest free block:  %zu bytes\n", stats.largest_free_block);
printf("Fragmentation:       %.2f%%\n", stats.fragmentation_percent);
```

### Block Information

```c
rampart_block_info_t info;
rampart_get_block_info(pool, ptr, &info);

printf("Block size:    %zu bytes\n", info.user_size);
printf("Total size:    %zu bytes\n", info.total_size);
printf("Owner thread:  %lu\n", (unsigned long)info.owner_thread);
printf("Parked:        %s\n", rampart_is_parked(pool, ptr) ? "yes" : "no");
printf("Front guard:   %s\n", info.front_guard_valid ? "OK" : "CORRUPTED");
printf("Rear guard:    %s\n", info.rear_guard_valid ? "OK" : "CORRUPTED");
```

## Best Practices

### 1. Always Check Return Values

```c
void *ptr = rampart_alloc(pool, size);
if (ptr == NULL) {
    /* Handle error - don't proceed with NULL */
}
```

### 2. Use Appropriately Sized Pools

- Estimate your maximum memory needs
- Add 20-30% overhead for metadata and fragmentation
- Consider multiple smaller pools for different object types

### 3. Free Memory in the Same Thread

Thread ownership is enforced. Design your application so the allocating thread also frees.

### 4. Register an Error Callback

```c
config.error_callback = my_handler;
```

This catches security violations early.

### 5. Validate Periodically in Debug Builds

```c
#ifdef DEBUG
    rampart_validate_pool(pool, &result);
#endif
```

### 6. Understand Parking Limitations

- Parking encrypts data in RAM but the key is also in RAM
- For true memory encryption, use hardware solutions (AMD SEV, Intel TME)
- Only use parking for long-lived secrets that sit idle
- If you provide your own key, clear it from memory after init

### 7. Check for Leaks Before Shutdown

```c
rampart_stats_t stats;
rampart_get_stats(pool, &stats);
assert(stats.allocation_count == 0);  /* No leaks */
rampart_shutdown(pool);
```

## Common Patterns

### Fixed-Size Object Pool

```c
#define OBJECT_SIZE 128
#define OBJECT_COUNT 1000

/* Size pool for N objects plus overhead */
config.pool_size = OBJECT_COUNT * (OBJECT_SIZE + 128);

/* Allocate objects */
for (int i = 0; i < OBJECT_COUNT; i++) {
    objects[i] = rampart_alloc(pool, OBJECT_SIZE);
}
```

### Temporary Scratch Buffer

```c
void process_data(rampart_pool_t *pool) {
    void *scratch = rampart_alloc(pool, 4096);
    if (scratch == NULL) return;

    /* Use scratch buffer */
    do_work(scratch);

    /* Always free before returning */
    rampart_free(pool, scratch);
}
```

### Multiple Pools for Isolation

```c
/* Separate pools for different security levels */
rampart_pool_t *sensitive_pool;  /* With parking enabled */
rampart_pool_t *general_pool;    /* Standard pool */

/* Sensitive pool configuration */
rampart_config_default(&config);
config.pool_size = 1024 * 1024;
config.enable_parking = 1;
sensitive_pool = rampart_init(&config);

/* General pool configuration */
rampart_config_default(&config);
config.pool_size = 10 * 1024 * 1024;
config.enable_parking = 0;
general_pool = rampart_init(&config);

/* Allocate based on data sensitivity */
void *password = rampart_alloc(sensitive_pool, 256);
void *buffer = rampart_alloc(general_pool, 4096);

/* Park sensitive data when not in use */
rampart_park(sensitive_pool, password);
```

### Graceful Degradation

```c
void *safe_alloc(rampart_pool_t *pool, size_t size) {
    void *ptr = rampart_alloc(pool, size);
    if (ptr == NULL) {
        /* Try to free cached/optional data */
        release_caches(pool);
        ptr = rampart_alloc(pool, size);
    }
    return ptr;
}
```
