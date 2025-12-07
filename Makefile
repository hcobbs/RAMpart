# ==============================================================================
# RAMpart - Secure Memory Pool Manager Library
# ==============================================================================
# Build system for librampart static and shared libraries
#
# Targets:
#   make              - Build static library for current platform
#   make shared       - Build shared library for current platform
#   make test         - Build and run test suite
#   make coverage     - Build with coverage instrumentation and run tests
#   make clean        - Remove all build artifacts
#   make install      - Install library and headers (PREFIX=/usr/local)
#
# ==============================================================================

# ------------------------------------------------------------------------------
# Compiler Configuration
# ------------------------------------------------------------------------------
CC = gcc
AR = ar
ARFLAGS = rcs

# Strict C89 compliance with all warnings as errors
CFLAGS = -Wall -Wextra -Werror -std=c89 -pedantic -g
CFLAGS += -I./h

# Additional safety flags
CFLAGS += -Wshadow -Wconversion -Wstrict-prototypes -Wmissing-prototypes

# ------------------------------------------------------------------------------
# Platform Detection
# ------------------------------------------------------------------------------
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    PLATFORM = linux
    SHARED_EXT = .so
    SHARED_FLAGS = -shared -fPIC
    LDFLAGS = -lpthread
endif

ifeq ($(UNAME_S),Darwin)
    PLATFORM = macos
    SHARED_EXT = .dylib
    SHARED_FLAGS = -dynamiclib -fPIC
    LDFLAGS = -lpthread
endif

ifeq ($(OS),Windows_NT)
    PLATFORM = windows
    SHARED_EXT = .dll
    SHARED_FLAGS = -shared
    LDFLAGS = -lws2_32
    CC = x86_64-w64-mingw32-gcc
endif

# ------------------------------------------------------------------------------
# Directory Structure
# ------------------------------------------------------------------------------
SRC_DIR = src
HDR_DIR = h
OBJ_DIR = obj
LIB_DIR = lib
TEST_DIR = test
DOCS_DIR = docs

# Installation directories
PREFIX ?= /usr/local
INSTALL_LIB_DIR = $(PREFIX)/lib
INSTALL_INC_DIR = $(PREFIX)/include/rampart

# ------------------------------------------------------------------------------
# Source Files
# ------------------------------------------------------------------------------
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
OBJS_PIC = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.pic.o,$(SRCS))

TEST_SRCS = $(wildcard $(TEST_DIR)/*.c)
TEST_OBJS = $(patsubst $(TEST_DIR)/%.c,$(OBJ_DIR)/test_%.o,$(TEST_SRCS))

# ------------------------------------------------------------------------------
# Output Files
# ------------------------------------------------------------------------------
STATIC_LIB = $(LIB_DIR)/librampart.a
SHARED_LIB = $(LIB_DIR)/librampart$(SHARED_EXT)
TEST_BIN = $(LIB_DIR)/rampart_test

# ------------------------------------------------------------------------------
# Default Target
# ------------------------------------------------------------------------------
.PHONY: all
all: dirs $(STATIC_LIB)

# ------------------------------------------------------------------------------
# Directory Creation
# ------------------------------------------------------------------------------
.PHONY: dirs
dirs:
	@mkdir -p $(OBJ_DIR) $(LIB_DIR)

# ------------------------------------------------------------------------------
# Static Library
# ------------------------------------------------------------------------------
$(STATIC_LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^
	@echo "Built static library: $@"

# ------------------------------------------------------------------------------
# Shared Library
# ------------------------------------------------------------------------------
.PHONY: shared
shared: CFLAGS += -fPIC
shared: dirs $(SHARED_LIB)

$(SHARED_LIB): $(OBJS_PIC)
	$(CC) $(SHARED_FLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built shared library: $@"

# ------------------------------------------------------------------------------
# Object File Compilation
# ------------------------------------------------------------------------------
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.pic.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

$(OBJ_DIR)/test_%.o: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# ------------------------------------------------------------------------------
# Test Target
# ------------------------------------------------------------------------------
.PHONY: test
test: dirs $(STATIC_LIB) $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $(TEST_BIN) $(TEST_OBJS) -L$(LIB_DIR) -lrampart $(LDFLAGS)
	@echo "Running tests..."
	@$(TEST_BIN)

# ------------------------------------------------------------------------------
# Coverage Target
# ------------------------------------------------------------------------------
.PHONY: coverage
coverage: CFLAGS += --coverage -fprofile-arcs -ftest-coverage
coverage: LDFLAGS += --coverage
coverage: clean test
	@echo "Generating coverage report..."
	@gcov -o $(OBJ_DIR) $(SRCS)
	@echo "Coverage files generated. Use lcov for HTML report."

# ------------------------------------------------------------------------------
# Installation
# ------------------------------------------------------------------------------
.PHONY: install
install: all
	@mkdir -p $(INSTALL_LIB_DIR) $(INSTALL_INC_DIR)
	@cp $(STATIC_LIB) $(INSTALL_LIB_DIR)/
	@cp $(HDR_DIR)/rampart.h $(INSTALL_INC_DIR)/
	@echo "Installed to $(PREFIX)"

.PHONY: uninstall
uninstall:
	@rm -f $(INSTALL_LIB_DIR)/librampart.a
	@rm -rf $(INSTALL_INC_DIR)
	@echo "Uninstalled from $(PREFIX)"

# ------------------------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -rf $(OBJ_DIR) $(LIB_DIR)
	rm -f *.gcov *.gcda *.gcno
	@echo "Cleaned build artifacts"

# ------------------------------------------------------------------------------
# Help
# ------------------------------------------------------------------------------
.PHONY: help
help:
	@echo "RAMpart Build System"
	@echo "===================="
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build static library (default)"
	@echo "  shared    - Build shared library"
	@echo "  test      - Build and run test suite"
	@echo "  coverage  - Build with coverage and run tests"
	@echo "  install   - Install to PREFIX (default: /usr/local)"
	@echo "  uninstall - Remove installed files"
	@echo "  clean     - Remove build artifacts"
	@echo "  help      - Show this message"
	@echo ""
	@echo "Variables:"
	@echo "  CC        - Compiler (default: gcc)"
	@echo "  PREFIX    - Installation prefix (default: /usr/local)"
	@echo ""
	@echo "Platform: $(PLATFORM)"
