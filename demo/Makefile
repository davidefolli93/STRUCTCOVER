CC ?= gcc
CFLAGS := -g -gdwarf-4 -O0 -fno-eliminate-unused-debug-types -I src

BUILD_DIR := build
ELF := $(BUILD_DIR)/demo.elf

all: $(ELF)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(ELF): $(BUILD_DIR) src/main.c
	$(CC) $(CFLAGS) src/main.c -o $(ELF)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
