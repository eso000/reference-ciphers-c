CC ?= gcc
CFLAGS ?= -std=c11 -O2

TESTS = BlowfishTest TwofishTest padding.test

all: $(TESTS)

BlowfishTest: BlowfishTest.c Blowfish.c Blowfish.h padding.c padding.h
	$(CC) $(CFLAGS) BlowfishTest.c Blowfish.c padding.c -o $@

TwofishTest: TwofishTest.c Twofish.c Twofish.h padding.c padding.h
	$(CC) $(CFLAGS) TwofishTest.c Twofish.c padding.c -o $@

padding.test: padding.test.c padding.c padding.h
	$(CC) $(CFLAGS) padding.test.c padding.c -o $@

test: all
	@fail=0; \
	for t in $(TESTS); do \
		./$$t || fail=1; \
	done; \
	exit $$fail

clean:
	rm -f $(TESTS) a.out
