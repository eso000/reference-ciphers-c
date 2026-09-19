CC ?= gcc
CFLAGS ?= -std=c11 -O2

TESTS = BlowfishTest TwofishTest AESTest DESTest SerpentTest ModeTest padding.test

all: $(TESTS)

BlowfishTest: BlowfishTest.c Blowfish.c BlockCipher.c Blowfish.h BlockCipher.h padding.c padding.h
	$(CC) $(CFLAGS) BlowfishTest.c Blowfish.c BlockCipher.c padding.c -o $@

TwofishTest: TwofishTest.c Twofish.c BlockCipher.c Twofish.h BlockCipher.h padding.c padding.h
	$(CC) $(CFLAGS) TwofishTest.c Twofish.c BlockCipher.c padding.c -o $@

AESTest: AESTest.c AES.c BlockCipher.c AES.h BlockCipher.h padding.c padding.h
	$(CC) $(CFLAGS) AESTest.c AES.c BlockCipher.c padding.c -o $@

DESTest: DESTest.c DES.c BlockCipher.c DES.h BlockCipher.h padding.c padding.h
	$(CC) $(CFLAGS) DESTest.c DES.c BlockCipher.c padding.c -o $@

SerpentTest: SerpentTest.c Serpent.c BlockCipher.c Serpent.h BlockCipher.h padding.c padding.h
	$(CC) $(CFLAGS) SerpentTest.c Serpent.c BlockCipher.c padding.c -o $@

ModeTest: ModeTest.c AES.c DES.c Serpent.c Blowfish.c Twofish.c BlockCipher.c AES.h DES.h Serpent.h Blowfish.h Twofish.h BlockCipher.h
	$(CC) $(CFLAGS) ModeTest.c AES.c DES.c Serpent.c Blowfish.c Twofish.c BlockCipher.c -o $@

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
