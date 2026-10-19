# ?= would not work here. Make gives CC a built-in default of "cc", so CC is
# always defined and a conditional assignment never fires: the compiler would
# stay cc while the line looked like it chose gcc. Default to gcc only while CC
# is still that built-in default or unset, which leaves the environment and the
# command line free to pick something else (make CC=clang ...).
CC := $(if $(filter default undefined,$(origin CC)),gcc,$(CC))
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
	test_padding \
	test_cipher \
	test_keys

BINS := $(addprefix $(BUILD_DIR)/,$(TESTS))

.PHONY: all test clean

all: $(BINS)

$(BUILD_DIR):
	mkdir -p $@

# Each test binary is compiled from source in a single command, so there are no
# object files to go stale against header edits and no dependency list to maintain.
# Every test links the whole library; unused ciphers cost nothing and adding a
# cipher here needs no new rule. testutil.h is shared by every test, so it is a
# prerequisite of all of them: editing the harness must rebuild the harness's
# users even when the test itself did not change.
$(BUILD_DIR)/%: $(TEST_DIR)/%.c $(TEST_DIR)/testutil.h $(LIB_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) $< $(LIB_SRCS) -o $@

test: all
	@fail=0; \
	for t in $(TESTS); do \
		./$(BUILD_DIR)/$$t || fail=1; \
	done; \
	exit $$fail

clean:
	rm -rf $(BUILD_DIR)
