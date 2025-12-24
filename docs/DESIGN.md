# RAMpart Design Document

## Table of Contents

1. [Overview](#overview)
2. [Design Goals](#design-goals)
3. [Architecture](#architecture)
4. [Memory Layout](#memory-layout)
5. [Allocation Strategy](#allocation-strategy)
6. [Security Features](#security-features)
7. [Thread Safety](#thread-safety)
8. [Error Handling](#error-handling)
9. [Performance Considerations](#performance-considerations)

## Overview

RAMpart is a secure memory pool management library designed for applications requiring strict memory safety guarantees. It provides a managed memory pool with built-in protections against common memory-related vulnerabilities and programming errors.

### Key Features

- **Leak Prevention**: All allocations are tracked; orphaned blocks are reported and can be reclaimed
- **Buffer Overflow Detection**: Guard bands detect out-of-bounds writes
- **Thread Ownership**: Memory blocks are bound to their allocating thread
- **Data Protection**: Optional encryption of data at rest
- **Secure Deallocation**: Multi-pass wiping of freed memory
- **Deterministic Allocation**: Worst-fit strategy for predictable fragmentation behavior

## Design Goals

### Primary Goals

1. **Security First**: Every design decision prioritizes memory safety and data protection
2. **Zero Memory Leaks**: The pool tracks all allocations and provides mechanisms to detect and handle leaks
3. **Strict C89 Compliance**: No compiler extensions, no external dependencies beyond POSIX threads
4. **Complete Documentation**: Every function, type, and constant is fully documented

### Non-Goals

- **Maximum Performance**: Security checks add overhead; this library prioritizes safety over raw speed
- **Minimum Memory Overhead**: Metadata and guard bands consume additional memory per allocation
- **Drop-in malloc Replacement**: The API is intentionally different to enforce proper usage patterns

## Architecture

### Module Organization

```
+------------------+
|    rampart.h     |  Public API (user-facing)
+------------------+
        |
        v
+------------------+
|    rampart.c     |  API implementation, pool lifecycle
+------------------+
        |
        +---> pool.c          Pool internals, worst-fit allocator
        |
        +---> block.c         Block metadata, guard band management
        |
        +---> crypto.c        ChaCha20 stream cipher (RFC 8439)
        |
        +---> wipe.c          Secure memory wiping
        |
        +---> thread_guard.c  Thread ID tracking, ownership enforcement
```

### Module Responsibilities

| Module | Responsibility |
|--------|----------------|
| `rampart` | Public API, pool initialization/shutdown, allocation routing |
| `pool` | Free list management, worst-fit search, block splitting/coalescing |
| `block` | Block header management, guard band initialization and validation |
| `crypto` | ChaCha20 stream cipher (RFC 8439), key management, encrypt/decrypt |
| `wipe` | Secure overwrite patterns, multi-pass wiping |
| `thread_guard` | Thread ID capture, ownership validation, cross-thread detection |

## Memory Layout

### Pool Structure

```
+========================================+
|           Pool Header                  |
|  - Total size                          |
|  - Free bytes                          |
|  - Allocation count                    |
|  - Configuration flags                 |
|  - Encryption key (if enabled)         |
|  - Free list head pointer              |
|  - Mutex for thread safety             |
+========================================+
|           Block 1                      |
+----------------------------------------+
|           Block 2                      |
+----------------------------------------+
|           ...                          |
+----------------------------------------+
|           Block N                      |
+========================================+
```

### Block Structure

Each allocated block has the following layout:

```
+----------------------------------------+
|         Block Header (internal)        |
|  - Block size (total, including meta)  |
|  - User data size                      |
|  - Flags (allocated, encrypted, etc.)  |
|  - Owner thread ID                     |
|  - Previous block pointer              |
|  - Next block pointer                  |
|  - Magic number (for validation)       |
+----------------------------------------+
|         Front Guard Band               |
|  - Pattern: 0xDEADBEEF (repeated)      |
|  - Size: RP_GUARD_SIZE bytes           |
+----------------------------------------+
|         User Data Region               |
|  - Initialized to 0x00                 |
|  - Encrypted if encryption enabled     |
|  - Size: as requested by user          |
+----------------------------------------+
|         Rear Guard Band                |
|  - Pattern: 0xFEEDFACE (repeated)      |
|  - Size: RP_GUARD_SIZE bytes           |
+----------------------------------------+
```

### Size Calculations

For a user request of N bytes:

```
Total block size = Header size
                 + Front guard size
                 + User data size (N)
                 + Rear guard size

Actual allocation = ALIGN_UP(Total block size, RP_ALIGNMENT)
```

## Allocation Strategy

### Worst-Fit Algorithm

RAMpart uses worst-fit allocation, which selects the largest available free block for each allocation request.

**Rationale**:
- Leaves the largest possible remainder after splitting
- Reduces fragmentation when allocation sizes vary widely
- Predictable behavior for security-critical applications

**Algorithm**:

```
1. Acquire pool mutex
2. Search free list for block with maximum size >= requested
3. If found:
   a. Remove block from free list
   b. If remainder >= minimum block size:
      - Split block
      - Return remainder to free list
   c. Initialize block metadata
   d. Initialize guard bands
   e. Zero-initialize user data region
   f. Encrypt if encryption enabled
   g. Set thread ownership
   h. Release mutex
   i. Return pointer to user data region
4. If not found:
   a. Release mutex
   b. Return NULL (allocation failed)
```

### Free List Management

The free list is maintained as a doubly-linked list sorted by block address. This ordering:
- Enables efficient coalescing of adjacent free blocks
- Provides deterministic traversal order
- Simplifies debugging and pool inspection

### Block Coalescing

When a block is freed, RAMpart attempts to merge it with adjacent free blocks:

```
1. Check if previous block (by address) is free
2. Check if next block (by address) is free
3. Merge with adjacent free blocks as applicable
4. Update free list pointers
```

## Security Features

### Guard Bands

Guard bands are fixed-size regions at both ends of the user data area filled with known patterns.

**Front Guard Pattern**: `0xDEADBEEF` (repeated)
**Rear Guard Pattern**: `0xFEEDFACE` (repeated)

**Validation Points**:
- On `rampart_free()`: Both guards validated before freeing
- On `rampart_validate()`: Explicit validation on demand
- Optionally on every access (configurable, high overhead)

**On Corruption Detection**:
- Callback function invoked (if registered)
- Error code set
- Operation aborted (block not freed if corrupted)

### Thread Ownership

Each block records the thread ID of its allocating thread. Access from other threads is prohibited.

**Enforcement Points**:
- `rampart_free()`: Only owning thread may free
- `rampart_read()`: Only owning thread may read (if using accessor functions)
- `rampart_write()`: Only owning thread may write (if using accessor functions)

**Implementation**:
- POSIX: `pthread_self()` returns `pthread_t`
- Windows: `GetCurrentThreadId()` returns `DWORD`

**Note**: Direct pointer access bypasses thread checks. Use accessor functions for full enforcement.

### Block Parking (Encryption at Rest)

When enabled, blocks can be "parked" to encrypt their contents in memory
and "unparked" to decrypt them for use.

**Cipher**: ChaCha20 stream cipher (RFC 8439)
- Key size: 32 bytes (256-bit)
- Nonce size: 12 bytes (generated per-park operation)
- No lookup tables (timing-safe)
- No external dependencies

**Key Management**:
- Key provided at pool initialization, or auto-generated from /dev/urandom
- Key stored in pool header
- Same key used for all blocks in pool
- Key generation fails if /dev/urandom is unavailable (no weak fallback)

**Nonce Generation**:
- Each park operation generates a unique nonce from:
  - 8 bytes of fresh randomness from /dev/urandom
  - 4-byte generation counter (increments per-park)
- Nonce reuse is prevented by the random component

**Parking Points**:
- `rampart_park()`: Encrypts block contents, sets parked flag
- `rampart_unpark()`: Decrypts block contents, clears parked flag
- Parked blocks cannot be freed or accessed until unparked

**Security Limitations**:
Block parking protects against casual memory inspection, data in core dumps,
and data leaking to swap (when OS memory protection is used). It does NOT
protect against attackers with memory read access (the key is in pool memory).

**Configuration**:
```c
rampart_config_t config;
config.enable_parking = 1;
config.parking_key = user_provided_key;  /* or NULL for auto-generate */
config.parking_key_len = 32;
```

### Secure Wiping

All freed memory is overwritten to prevent data recovery.

**Wipe Pattern** (3-pass):
1. Pass 1: All zeros (0x00)
2. Pass 2: All ones (0xFF)
3. Pass 3: Random pattern (or 0xAA)

**Timing**:
- Wiping occurs before block is returned to free list
- Wiping includes user data region only (not headers/guards)

## Thread Safety

### Mutex Protection

All pool operations are protected by a mutex:
- `rampart_alloc()`: Acquires mutex during allocation
- `rampart_free()`: Acquires mutex during deallocation
- `rampart_stats()`: Acquires mutex during statistics collection

### Deadlock Prevention

- Single mutex per pool (no nested locking)
- Mutex released before callbacks are invoked
- No mutex held during user code execution

### Multi-Pool Usage

- Each pool has its own mutex
- Cross-pool operations are safe
- No global locks

## Error Handling

### Error Codes

```c
typedef enum {
    RAMPART_OK = 0,              /* Success */
    RAMPART_ERR_NULL_PARAM,      /* NULL parameter passed */
    RAMPART_ERR_INVALID_SIZE,    /* Invalid size (0 or too large) */
    RAMPART_ERR_OUT_OF_MEMORY,   /* Pool exhausted */
    RAMPART_ERR_INVALID_BLOCK,   /* Block validation failed */
    RAMPART_ERR_GUARD_CORRUPTED, /* Guard band corruption detected */
    RAMPART_ERR_WRONG_THREAD,    /* Cross-thread access attempted */
    RAMPART_ERR_DOUBLE_FREE,     /* Block already freed */
    RAMPART_ERR_NOT_INITIALIZED  /* Pool not initialized */
} rampart_error_t;
```

### Error Retrieval

```c
rampart_error_t rampart_get_last_error(rampart_pool_t *pool);
const char *rampart_error_string(rampart_error_t error);
```

### Callbacks

Users can register callbacks for security events:

```c
typedef void (*rampart_error_callback_t)(
    rampart_pool_t *pool,
    rampart_error_t error,
    void *block,
    void *user_data
);

void rampart_set_error_callback(
    rampart_pool_t *pool,
    rampart_error_callback_t callback,
    void *user_data
);
```

## Performance Considerations

### Overhead per Allocation

| Component | Size (bytes, typical) |
|-----------|----------------------|
| Block header | 64 |
| Front guard | 16 |
| Rear guard | 16 |
| **Total overhead** | **96** |

### Time Complexity

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Allocation | O(n) | n = number of free blocks (worst-fit search) |
| Deallocation | O(n) | n = number of free blocks (sorted insert + coalesce) |
| Validation | O(1) | Per-block guard check |

### Optimization Opportunities

For applications requiring better allocation performance:
- Use multiple smaller pools to reduce free list size
- Pre-allocate pools sized for expected workload
- Consider disabling encryption for non-sensitive data pools

### Memory Alignment

All allocations are aligned to `RP_ALIGNMENT` (typically 16 bytes) for:
- CPU cache line efficiency
- SIMD instruction compatibility
- Platform ABI compliance
