# RAMpart Security PoC Suite Makefile
#
# Builds proof-of-concept exploits for identified vulnerabilities.
# Usage: make && make run
#
# WARNING: Some PoCs are destructive and may crash or corrupt memory.
#          Run in a sandboxed environment.

CC = gcc
CFLAGS = -Wall -Wextra -g -std=c89 -pedantic -I../../h
LDFLAGS = -L../../lib -lrampart -lpthread

# Library path for runtime
LIBRARY_PATH = ../../lib

# All PoC targets
POCS = poc_01_fake_encryption \
       poc_02_integer_overflow \
       poc_03_arbitrary_read \
       poc_04_guard_bypass \
       poc_05_thread_bypass \
       poc_06_header_corruption \
       poc_07_coalesce_uaf \
       poc_08_timing_guards \
       poc_09_metadata_leak \
       poc_10_ecb_patterns \
       poc_11_reentrancy \
       poc_12_split_underflow \
       poc_13_validation_bypass \
       poc_14_key_truncation \
       poc_15_barrier_fallback \
       poc_16_sbox_timing \
       poc_17_counter_overflow \
       poc_18_magic_spoof \
       poc_19_pool_validation \
       poc_20_leak_malloc \
       poc_21_wipe_patterns \
       poc_22_guard_residue \
       poc_23_signed_config

.PHONY: all clean run lib

all: lib $(POCS)

# Ensure library is built first
lib:
	@echo "Building RAMpart library..."
	@cd ../.. && $(MAKE) -s

# Build each PoC
poc_%: poc_%.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Run all PoCs (some may crash intentionally)
run: all
	@echo "============================================"
	@echo "Running RAMpart Security PoC Suite"
	@echo "============================================"
	@for poc in $(POCS); do \
		echo ""; \
		echo "--- Running $$poc ---"; \
		LD_LIBRARY_PATH=$(LIBRARY_PATH) DYLD_LIBRARY_PATH=$(LIBRARY_PATH) ./$$poc || true; \
	done
	@echo ""
	@echo "============================================"
	@echo "PoC Suite Complete"
	@echo "============================================"

# Run a single PoC (usage: make run-poc_01_fake_encryption)
run-%: %
	@echo "Running $<..."
	@LD_LIBRARY_PATH=$(LIBRARY_PATH) DYLD_LIBRARY_PATH=$(LIBRARY_PATH) ./$<

clean:
	rm -f $(POCS)
