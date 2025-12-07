# CLAUDE.md - RAMpart Project

This file provides guidance to Claude Code when working with the RAMpart codebase.

## Project Overview

RAMpart is a secure memory pool management library written in strict ANSI-C (C89). It provides memory allocation with built-in security features including guard bands, thread ownership enforcement, configurable encryption at rest, and secure wiping.

## Build Commands

```bash
make              # Build static library (librampart.a)
make shared       # Build shared library
make test         # Build and run test suite
make coverage     # Build with coverage instrumentation
make clean        # Remove all build artifacts
make install      # Install to PREFIX (default: /usr/local)
```

## Compiler Requirements

- **Standard**: ANSI-C (C89) strict compliance
- **Flags**: `-Wall -Wextra -Werror -std=c89 -pedantic`
- **Additional**: `-Wshadow -Wconversion -Wstrict-prototypes -Wmissing-prototypes`
- **Requirement**: Code must compile with zero warnings

## Directory Structure

```
RAMpart/
├── src/           # Implementation files (.c)
├── h/             # Public headers
│   └── internal/  # Internal headers (not for library users)
├── obj/           # Compiled objects (generated)
├── lib/           # Library output (generated)
├── test/          # Test suite
└── docs/          # Documentation
```

## Code Style

### Indentation and Formatting

- Use **4 spaces** for indentation (no tabs)
- Maximum line length: 100 characters (soft), 120 characters (hard)
- Opening braces on same line as function/control structure
- Single space after keywords (if, while, for, switch)

### Naming Conventions

- Public API functions: `rampart_<action>` (e.g., `rampart_alloc`, `rampart_free`)
- Internal functions: `rp_<module>_<action>` (e.g., `rp_pool_find_block`)
- Types: `rampart_<name>_t` for public, `rp_<name>_t` for internal
- Constants/macros: `RAMPART_<NAME>` for public, `RP_<NAME>` for internal
- Guard band patterns: `RP_GUARD_<type>`

### Documentation Requirements

**Every function must have a documentation block** in the following format:

```c
/**
 * rampart_alloc - Allocate memory from the pool
 *
 * Allocates a block of memory from the managed pool. The returned memory
 * is zero-initialized, protected by guard bands, and owned by the calling
 * thread. If encryption is enabled, data will be encrypted at rest.
 *
 * @param pool   Pointer to an initialized pool handle
 * @param size   Number of bytes to allocate (must be > 0)
 *
 * @return Pointer to allocated memory on success, NULL on failure
 *
 * @note Thread-safe. Only the allocating thread may access this memory.
 * @note Memory is zero-initialized (all bytes set to 0x00).
 *
 * @see rampart_free
 * @see rampart_realloc
 */
void *rampart_alloc(rampart_pool_t *pool, size_t size);
```

Required documentation elements:
- Brief one-line description after function name
- Detailed description paragraph
- All parameters documented with @param
- Return value documented with @return
- Thread safety noted with @note
- Related functions listed with @see

### Memory Initialization

- All user data regions must be initialized to `0x00` before returning to caller
- Guard bands must be initialized to their respective patterns
- Block metadata must be fully initialized before block is usable

## Testing Requirements

- **100% code coverage** required for all library functions
- Tests located in `test/` directory
- Test file naming: `test_<module>.c`
- Each function must have corresponding test cases covering:
  - Normal operation (happy path)
  - Edge cases (zero size, max size, NULL pointers)
  - Error conditions (out of memory, invalid parameters)
  - Thread safety (if applicable)

## Security Features

### Guard Bands
- Front guard: Detects buffer underruns
- Rear guard: Detects buffer overruns
- Validated on free and optionally on access

### Thread Ownership
- Each block tracks its owning thread ID
- Only the owning thread may read/write/free the block
- Cross-thread access attempts are detected and reported

### Encryption at Rest
- Configurable via `rampart_config_t` at pool initialization
- Uses custom Feistel block cipher (no external dependencies)
- Key configurable by user
- Can be enabled/disabled per-pool

### Secure Wiping
- All freed memory is overwritten before returning to pool
- Multi-pass overwrite pattern
- Prevents data recovery from freed blocks

### Worst-Fit Allocation
- Allocator searches for largest available block
- Reduces fragmentation for varied allocation sizes
- Free list maintained in sorted order

## Git Workflow

### Branch Protection
- Direct commits to `main` are prohibited
- All changes require pull requests

### Branch Naming
- `feature/<description>` - New features
- `bugfix/<description>` - Bug fixes
- `refactor/<description>` - Code improvements
- `test/<description>` - Test additions

### Commit Labels
All commits must include a contribution label:
- `[CLASSIC]` - Hand-coded without AI assistance
- `[LLM-ASSISTED]` - Written with LLM pair programming
- `[LLM-ARCH]` - LLM-generated code under human review
- `[LLM-REVIEW]` - LLM code review and fixes
- `[VIBE]` - Experimental coding

### Pre-PR Checklist
- [ ] `make` succeeds with zero warnings
- [ ] `make test` passes all tests
- [ ] `make coverage` shows 100% coverage for changed code
- [ ] All functions have complete documentation
- [ ] Code follows project style guidelines
- [ ] Commits use appropriate contribution labels
