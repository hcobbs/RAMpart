# RAMpart Security Remediation Guide

This document provides specific code fixes for each vulnerability identified in the security audit.

---

## Critical Vulnerabilities

### VULN-001: Non-Functional Encryption

**Fix Option A: Document and Warn**

Add to `src/rampart.c` in `rampart_alloc()`:

```c
void *rampart_alloc(rampart_pool_t *pool, size_t size) {
    /* ... existing code ... */

    /*
     * WARNING: If encryption_enabled is set, log a warning.
     * Encryption is not yet implemented for raw pointer access.
     */
#ifndef RAMPART_SUPPRESS_ENCRYPTION_WARNING
    if (p->encryption_enabled) {
        /* Consider: fprintf(stderr, "RAMpart: encryption_enabled has no effect\n"); */
    }
#endif

    return user_ptr;
}
```

**Fix Option B: Reject encryption config until implemented**

In `rampart_init()`:

```c
if (config->encryption_enabled) {
    rp_thread_set_last_error(RAMPART_ERR_INVALID_CONFIG);
    /* Encryption not implemented */
    return NULL;
}
```

---

### VULN-002: Integer Overflow in Size Calculation

**File**: `src/rp_block.c`

**Before**:
```c
size_t rp_block_calc_total_size(size_t user_size) {
    size_t total;
    total = sizeof(rp_block_header_t) + RP_GUARD_SIZE + user_size + RP_GUARD_SIZE;
    total = RP_ALIGN_UP(total, RP_ALIGNMENT);
    return total;
}
```

**After**:
```c
size_t rp_block_calc_total_size(size_t user_size) {
    size_t total;
    size_t overhead;

    overhead = sizeof(rp_block_header_t) + (RP_GUARD_SIZE * 2);

    /* Check for overflow before adding */
    if (user_size > SIZE_MAX - overhead) {
        return 0;  /* Signal overflow */
    }

    total = overhead + user_size;

    /* Check for overflow from alignment */
    if (total > SIZE_MAX - RP_ALIGNMENT) {
        return 0;
    }

    total = RP_ALIGN_UP(total, RP_ALIGNMENT);
    return total;
}
```

**Also update** `rp_pool_alloc()` to check for 0 return:

```c
total_size = rp_block_calc_total_size(size);
if (total_size == 0) {
    return RAMPART_ERR_INVALID_SIZE;  /* Overflow detected */
}
```

---

### VULN-003: Arbitrary Pointer Dereference

**File**: `src/rp_block.c`

**Add new function**:
```c
rp_block_header_t *rp_block_from_user_ptr_safe(rp_pool_header_t *pool,
                                                void *ptr) {
    unsigned char *block_addr;
    size_t offset;

    if (ptr == NULL || pool == NULL) {
        return NULL;
    }

    offset = sizeof(rp_block_header_t) + RP_GUARD_SIZE;
    block_addr = (unsigned char *)ptr - offset;

    /* Bounds check BEFORE any dereference */
    if (block_addr < pool->pool_start ||
        block_addr >= pool->pool_end) {
        return NULL;  /* Outside pool bounds */
    }

    /* Alignment check */
    if (((size_t)block_addr % RP_ALIGNMENT) != 0) {
        return NULL;  /* Misaligned */
    }

    return (rp_block_header_t *)block_addr;
}
```

**Update** `rampart_free()` to use safe version:

```c
block = rp_block_from_user_ptr_safe(p, ptr);
if (block == NULL) {
    rp_pool_unlock(p);
    return RAMPART_ERR_INVALID_BLOCK;
}
```

---

### VULN-004: Predictable Guard Band Patterns

**File**: `h/internal/rp_types.h`

**Add to pool header**:
```c
typedef struct rp_pool_header_s {
    /* ... existing fields ... */

    /**
     * @brief Randomized guard patterns (per-pool)
     */
    unsigned long guard_front_pattern;
    unsigned long guard_rear_pattern;
} rp_pool_header_t;
```

**File**: `src/rp_pool.c`

**In** `rp_pool_init()`:
```c
/* Generate random guard patterns */
pool->guard_front_pattern = rp_generate_random_ulong();
pool->guard_rear_pattern = rp_generate_random_ulong();

/* Ensure patterns are different and non-zero */
if (pool->guard_front_pattern == 0) {
    pool->guard_front_pattern = 0xDEADBEEFUL;
}
if (pool->guard_rear_pattern == 0 ||
    pool->guard_rear_pattern == pool->guard_front_pattern) {
    pool->guard_rear_pattern = 0xFEEDFACEUL;
}
```

**Add random generation** (platform-specific):
```c
static unsigned long rp_generate_random_ulong(void) {
    unsigned long result = 0;
    FILE *urandom;

    urandom = fopen("/dev/urandom", "rb");
    if (urandom != NULL) {
        fread(&result, sizeof(result), 1, urandom);
        fclose(urandom);
    }

    /* Fallback: use address + time (weak but better than nothing) */
    if (result == 0) {
        result = (unsigned long)&result ^ (unsigned long)time(NULL);
    }

    return result;
}
```

---

## High Vulnerabilities

### VULN-005: Thread Ownership Bypass

**Mitigation**: The owner_thread field is inherently exposed. Best protection is defense-in-depth with guard bands and canaries.

**Add canary before owner_thread**:
```c
typedef struct rp_block_header_s {
    unsigned long magic;
    size_t total_size;
    size_t user_size;
    unsigned int flags;
    unsigned long owner_canary;  /* NEW: Canary value */
    rp_thread_id_t owner_thread;
    /* ... */
} rp_block_header_t;
```

---

### VULN-006: Free List Pointer Corruption

**Add safe unlinking** in `rp_pool_remove_from_free_list()`:

```c
void rp_pool_remove_from_free_list(rp_pool_header_t *pool,
                                    rp_block_header_t *block) {
    /* Validate link integrity before modification */
    if (block->prev != NULL && block->prev->next != block) {
        /* Corrupted list detected */
        abort();  /* Or invoke error callback */
    }
    if (block->next != NULL && block->next->prev != block) {
        abort();
    }

    /* ... existing unlinking code ... */
}
```

---

### VULN-008: Timing Side-Channel in Guards

**File**: `src/rp_block.c`

**Replace** `verify_guard_pattern()` with constant-time version:

```c
static int verify_guard_pattern(const unsigned char *ptr,
                                 size_t size,
                                 unsigned long pattern) {
    size_t i;
    unsigned char bytes[4];
    unsigned char diff = 0;

    bytes[0] = (unsigned char)((pattern >> 24) & 0xFF);
    bytes[1] = (unsigned char)((pattern >> 16) & 0xFF);
    bytes[2] = (unsigned char)((pattern >> 8) & 0xFF);
    bytes[3] = (unsigned char)(pattern & 0xFF);

    /* Constant-time comparison: always check all bytes */
    for (i = 0; i < size; i++) {
        diff |= ptr[i] ^ bytes[i % 4];
    }

    /* Return 1 if all bytes matched (diff == 0) */
    return (diff == 0);
}
```

---

### VULN-009: Metadata Leak from Freed Blocks

**File**: `src/rampart.c`

**In** `rampart_free()`, wipe entire block:

```c
/* Save size before wiping */
size_t block_total = block->total_size;

/* Wipe ALL block memory, including header */
rp_wipe_memory(block, block_total);

/* Re-initialize as free block */
rp_block_init_as_free(block, block_total);
```

---

### VULN-011: Reentrancy via Error Callback

**File**: `src/rampart.c`

**Add reentrancy detection**:

```c
static __thread int g_in_callback = 0;

static void invoke_callback(rp_pool_header_t *pool,
                             rampart_error_t error,
                             void *block) {
    rampart_error_callback_t callback;
    void *user_data;

    if (pool == NULL || g_in_callback) {
        return;  /* Prevent reentrancy */
    }

    callback = pool->error_callback;
    user_data = pool->callback_user_data;

    if (callback != NULL) {
        g_in_callback = 1;
        rp_pool_unlock(pool);
        callback((rampart_pool_t *)pool, error, block, user_data);
        rp_pool_lock(pool);
        g_in_callback = 0;
    }
}
```

---

## Medium Vulnerabilities

### VULN-012: Block Split Size Underflow

**File**: `src/rp_pool.c`

**Add check in** `rp_pool_split_block()`:

```c
void rp_pool_split_block(rp_pool_header_t *pool,
                          rp_block_header_t *block,
                          size_t needed_size) {
    /* Additional safety check */
    if (block->total_size < needed_size) {
        return;  /* Would underflow, abort split */
    }

    if (block->total_size < needed_size + RP_MIN_BLOCK_SIZE) {
        return;
    }

    /* ... rest of function ... */
}
```

---

### VULN-014: Silent Key Truncation

**File**: `src/rampart.c`

**In** `rampart_init()`:

```c
if (config->encryption_enabled) {
    if (config->encryption_key == NULL ||
        config->encryption_key_size == 0 ||
        config->encryption_key_size > RAMPART_MAX_KEY_SIZE) {
        rp_thread_set_last_error(RAMPART_ERR_INVALID_CONFIG);
        return NULL;
    }
    /* REMOVED: Silent truncation */
    /* Key size is already validated to be <= MAX */
}
```

---

### VULN-015: Weak Memory Barrier Fallback

**File**: `src/rp_wipe.c`

**Replace fallback with better alternatives**:

```c
static void rp_memory_barrier(void) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    atomic_signal_fence(memory_order_seq_cst);
#else
    /* Last resort: volatile function pointer call */
    void (*volatile barrier_func)(void) = NULL;
    (void)barrier_func;
#endif
}
```

---

### VULN-019: No Pool Handle Validation

**Add pool magic to header**:

```c
#define RP_POOL_MAGIC 0x504F4F4CUL  /* "POOL" */

typedef struct rp_pool_header_s {
    unsigned long pool_magic;  /* NEW: Must be first field */
    /* ... existing fields ... */
} rp_pool_header_t;
```

**Validate in all API functions**:

```c
static int rp_pool_validate(rp_pool_header_t *pool) {
    if (pool == NULL) return 0;
    if (pool->pool_magic != RP_POOL_MAGIC) return 0;
    return 1;
}
```

---

### VULN-023: Signed Config Values

**File**: `h/rampart.h`

**Change boolean fields to unsigned**:

```c
typedef struct rampart_config_s {
    size_t pool_size;
    unsigned char encryption_enabled;    /* Changed from int */
    const unsigned char *encryption_key;
    size_t encryption_key_size;
    unsigned char strict_thread_mode;    /* Changed from int */
    unsigned char validate_on_free;      /* Changed from int */
    rampart_error_callback_t error_callback;
    void *callback_user_data;
} rampart_config_t;
```

**Or validate in** `rampart_init()`:

```c
/* Normalize boolean values */
pool->strict_thread_mode = (config->strict_thread_mode != 0);
pool->validate_on_free = (config->validate_on_free != 0);
pool->encryption_enabled = (config->encryption_enabled != 0);
```

---

## Implementation Priority

1. **Immediate** (before any release):
   - VULN-002: Integer overflow (simple fix, high impact)
   - VULN-003: Pointer validation (prevents memory disclosure)
   - VULN-001: Document encryption limitation

2. **Short-term** (next minor release):
   - VULN-004: Randomize guard patterns
   - VULN-008: Constant-time guard comparison
   - VULN-009: Wipe block headers
   - VULN-011: Reentrancy protection

3. **Medium-term** (next major release):
   - VULN-006: Safe unlinking
   - VULN-019: Pool validation
   - All medium severity fixes

---

## Testing After Remediation

Each fix should be verified with:

1. **Unit test**: Verify the fix prevents the attack
2. **Regression test**: Ensure existing functionality works
3. **PoC re-run**: Confirm the PoC no longer succeeds

The PoC files in `test/security/` can be modified to verify fixes:
- Change expected behavior from "vulnerable" to "secure"
- Run as part of CI/CD pipeline
