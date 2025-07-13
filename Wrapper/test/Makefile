# QEMU_RUNNER := qemu-x86_64
QEMU_RUNNER := qemu-riscv64
# CC          := gcc
CC          := riscv64-unknown-linux-gnu-gcc
CFLAGS      := -g -O0 -static

SRC_DIR     := src
BIN_DIR     := bin

EXECUTABLES := $(patsubst test_%.c,%,$(notdir $(wildcard $(SRC_DIR)/test_*.c)))

TARGET_BINS := $(patsubst %,$(BIN_DIR)/test_%,$(EXECUTABLES))

.PHONY: all clean $(EXECUTABLES) fork_bomb

all: $(TARGET_BINS)
	@echo "All C test cases have been compiled successfully."

clean:
	@echo "Cleaning up compiled binaries..."
	@rm -rf $(BIN_DIR)

$(EXECUTABLES): %: $(BIN_DIR)/test_%
	@echo "--- Running test: $@ ---"
	$(QEMU_RUNNER) $(BIN_DIR)/test_$@

$(TARGET_BINS): | $(BIN_DIR)

$(BIN_DIR):
	@echo "Creating binary directory: $(BIN_DIR)"
	@mkdir -p $(BIN_DIR)

$(BIN_DIR)/test_%: $(SRC_DIR)/test_%.c
	@echo "Compiling $< -> $@"
	$(CC) $(CFLAGS) -o $@ $<

$(BIN_DIR)/test_race_condition: $(SRC_DIR)/test_race_condition.c
	@echo "Compiling $< -> $@ (with -pthread)"
	$(CC) $(CFLAGS) -o $@ $< -pthread

