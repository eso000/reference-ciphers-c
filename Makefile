CC ?= gcc
CFLAGS ?= -std=c11 -O2

TESTS = BlowfishTest TwofishTest ModeTest padding.test

all: $(TESTS)

BlowfishTest: BlowfishTest.c Blowfish.c BlockCipher.c Blowfish.h BlockCipher.h padding.c padding.h
	$(CC) $(CFLAGS) BlowfishTest.c Blowfish.c BlockCipher.c padding.c -o $@

TwofishTest: TwofishTest.c Twofish.c BlockCipher.c Twofish.h BlockCipher.h padding.c padding.h
	$(CC) $(CFLAGS) TwofishTest.c Twofish.c BlockCipher.c padding.c -o $@

ModeTest: ModeTest.c Blowfish.c Twofish.c BlockCipher.c Blowfish.h Twofish.h BlockCipher.h
	$(CC) $(CFLAGS) ModeTest.c Blowfish.c Twofish.c BlockCipher.c -o $@

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
