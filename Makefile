CC ?= gcc
CFLAGS ?= -std=c11 -O2

INC_DIR := include
SRC_DIR := src
TEST_DIR := tests
BUILD_DIR := build

CIPHER_SRCS := \
	$(SRC_DIR)/aes.c \
	$(SRC_DIR)/des.c \
	$(SRC_DIR)/blowfish.c \
	$(SRC_DIR)/twofish.c \
	$(SRC_DIR)/serpent.c

LIB_SRCS := $(SRC_DIR)/blockcipher.c $(SRC_DIR)/padding.c $(CIPHER_SRCS)

TESTS := \
	test_aes \
	test_des \
	test_blowfish \
	test_twofish \
	test_serpent \
	test_modes \
	test_padding

BINS := $(addprefix $(BUILD_DIR)/,$(TESTS))

.PHONY: all test clean

all: $(BINS)

$(BUILD_DIR):
	mkdir -p $@

# Each test binary is compiled from source in a single command, so there are no
# object files to go stale against header edits and no dependency list to maintain.
# Every test links the whole library; unused ciphers cost nothing and adding a
# cipher here needs no new rule.
$(BUILD_DIR)/%: $(TEST_DIR)/%.c $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) $< $(LIB_SRCS) -o $@

test: all
	@fail=0; \
	for t in $(TESTS); do \
		./$(BUILD_DIR)/$$t || fail=1; \
	done; \
	exit $$fail

clean:
	rm -rf $(BUILD_DIR)
