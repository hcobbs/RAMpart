# RAMpart

A secure memory pool management library written in strict ANSI-C (C89).

## Features

- **Guard Bands**: Detect buffer overflows and underflows
- **Thread Ownership**: Enforce thread-based memory access control
- **Encryption at Rest**: Optional Feistel cipher encryption of pool data
- **Secure Wiping**: Multi-pass overwrite of freed memory
- **Worst-Fit Allocation**: Predictable fragmentation behavior
- **Leak Detection**: Track all allocations, report leaks on shutdown
- **Zero-Initialization**: All allocated memory initialized to 0x00

## Building

```bash
make              # Build static library
make shared       # Build shared library
make test         # Build and run tests
make coverage     # Build with coverage
make clean        # Clean build artifacts
```

## Quick Start

```c
#include "rampart.h"

int main(void) {
    rampart_config_t config;
    rampart_pool_t *pool;
    void *ptr;

    rampart_config_default(&config);
    config.pool_size = 1024 * 1024;  /* 1 MB */

    pool = rampart_init(&config);
    ptr = rampart_alloc(pool, 256);

    /* Use memory... */

    rampart_free(pool, ptr);
    rampart_shutdown(pool);
    return 0;
}
```

## Documentation

- [Design Document](docs/DESIGN.md)
- [Usage Guide](docs/USAGE.md)

## Requirements

- GCC or compatible C compiler
- POSIX threads (pthreads) on Linux/macOS
- Windows: MinGW for cross-compilation

## License

TBD
