/* Key length acceptance across every cipher, through the BlockCipher struct.

   generateKeys returns 1 for a key it accepted and 0 for one it rejected, so
   these cases go through the same function pointer the mode tests use rather
   than calling each cipher's key schedule directly. That is deliberate: the
   struct entry point is what application code reaches.

   Keys are raw bytes, so every length below is a byte count. AES and Twofish
   want 16-, 24- or 32-byte keys and DES wants 8, so any other length has to be
   refused; Blowfish and Serpent accept a range. A NULL key is refused by every
   cipher, whatever the length says.

   Every case here also asserts that the keyOk query agrees with generateKeys:
   accepts() compares the two and aborts on a disagreement, so the matrix below
   is a check of both entry points at once. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block/aes.h"
#include "block/des.h"
#include "block/blowfish.h"
#include "block/serpent.h"
#include "block/twofish.h"
#include "testutil.h"

typedef BlockCipher (*CipherCtor)(void *);

typedef struct {
	const char *name;
	CipherCtor ctor;
	int blockSize;
	size_t stateSize;
	/* A length this cipher accepts, used wherever the test needs "a real
	   key" and must not assume every cipher takes the same one. DES accepts
	   only 8 bytes, so a 32-byte key would be rejected there and the
	   comparison below would compare two zeroed states. */
	size_t validLen;
	/* The cipher's exported validator, which its constructor must install as
	   BlockCipher.keyOk. */
	int (*keyOkFn)(const uint8_t *key, size_t len);
} CipherInfo;

/* stateSize is deliberately generous. Blowfish's struct is about 4 KiB of
   S-boxes, so a tight allocation here would corrupt the heap rather than
   exercise the key check. */
static const CipherInfo CIPHERS[] = {
	{"AES", aes_cipher, 16, 8192, 16, aes_keyOk},
	{"DES", des_cipher, 8, 8192, 8, des_keyOk},
	{"Blowfish", blowfish_cipher, 8, 8192, 16, blowfish_keyOk},
	{"Serpent", serpent_cipher, 16, 8192, 32, serpent_keyOk},
	{"Twofish", twofish_cipher, 16, 8192, 16, twofish_keyOk},
};

/* Blowfish's published set_key vectors: the ciphertext of FEDCBA9876543210
   under each key, every length from 4 to 24 bytes in one-byte steps. The hex
   port could only reach the word-aligned ones (4, 8, 12, 16, 20, 24 bytes)
   because a read of 8 characters would otherwise straddle the terminating
   NUL; with byte keys the schedule cycles with (4 * i) % len and every length
   is representable, so all of them are pinned here. Three of these lengths
   (5, 6, 7 bytes) are exactly the ones the old step-of-8 rule refused. */
static const char *const BF_KATS[][2] = {
	{"F0E1D2C3", "BE1E639408640F05"},
	{"F0E1D2C3B4", "B39E44481BDB1E6E"},
	{"F0E1D2C3B4A5", "9457AA83B1928C0D"},
	{"F0E1D2C3B4A596", "8BB77032F960629D"},
	{"F0E1D2C3B4A59687", "E87A244E2CC85E82"},
	{"F0E1D2C3B4A5968778", "15750E7A4F4EC577"},
	{"F0E1D2C3B4A596877869", "122BA70B3AB64AE0"},
	{"F0E1D2C3B4A5968778695A", "3A833C9AFFC537F6"},
	{"F0E1D2C3B4A5968778695A4B", "9409DA87A90F6BF2"},
	{"F0E1D2C3B4A5968778695A4B3C", "884F80625060B8B4"},
	{"F0E1D2C3B4A5968778695A4B3C2D", "1F85031C19E11968"},
	{"F0E1D2C3B4A5968778695A4B3C2D1E", "79D9373A714CA34F"},
	{"F0E1D2C3B4A5968778695A4B3C2D1E0F", "93142887EE3BE15C"},
	{"F0E1D2C3B4A5968778695A4B3C2D1E0F00", "03429E838CE2D14B"},
	{"F0E1D2C3B4A5968778695A4B3C2D1E0F0011", "A4299E27469FF67B"},
	{"F0E1D2C3B4A5968778695A4B3C2D1E0F001122", "AFD5AED1C1BC96A8"},
	{"F0E1D2C3B4A5968778695A4B3C2D1E0F00112233", "10851C0E3858DA9F"},
	{"F0E1D2C3B4A5968778695A4B3C2D1E0F0011223344", "E6F51ED79B9DB21F"},
	{"F0E1D2C3B4A5968778695A4B3C2D1E0F001122334455", "64A6E14AFD36B46F"},
	{"F0E1D2C3B4A5968778695A4B3C2D1E0F00112233445566", "80C7D7D45A5479AD"},
	{"F0E1D2C3B4A5968778695A4B3C2D1E0F0011223344556677", "05044B62FA52D080"},
};

#define CIPHER_COUNT (sizeof CIPHERS / sizeof CIPHERS[0])

/* Build a key of exactly len bytes. len == 0 gives the empty key, which is the
   case that used to divide by zero in Blowfish. malloc never returns NULL for
   a zero length request here, so the caller is passing a real pointer with no
   bytes, not a NULL the guard would reject for a different reason. */
static uint8_t *makeKey(size_t len)
{
	uint8_t *key = malloc(len ? len : 1);
	for (size_t i = 0; i < len; ++i)
		key[i] = (uint8_t)(i * 7 + 3);
	return key;
}

/* Returns the cipher's 1/0 verdict on the key, allocating and freeing the state.
   Every case in this file runs through here, so the keyOk query is compared
   with generateKeys across the whole accept/reject matrix, not just the cases
   spelled out in testKeyOkQuery. A disagreement is a bug in the port, so it
   aborts rather than counting one more failure. */
static int accepts(const CipherInfo *info, const uint8_t *key, size_t len)
{
	void *state = calloc(1, info->stateSize);
	BlockCipher c = info->ctor(state);
	int ok = c.generateKeys(&c, key, len);
	int queried = c.keyOk(key, len);
	if (ok != queried)
	{
		fprintf(stderr, "%s: keyOk=%d but generateKeys=%d for length %zu\n",
			info->name, queried, ok, len);
		exit(2);
	}
	free(state);
	return ok;
}

/* Encrypt one block under a key, so a caller can observe the resulting state.
   Only called with the cipher's own block size. */
static void encryptBlockWith(const CipherInfo *info, const uint8_t *key, size_t len, uint8_t *out)
{
	void *state = calloc(1, info->stateSize);
	BlockCipher c = info->ctor(state);
	c.generateKeys(&c, key, len);
	memset(out, 0x5A, (size_t)info->blockSize);
	c.encryptBlock(&c, out);
	free(state);
}

static void checkAccepted(const CipherInfo *info, size_t len, const char *label)
{
	uint8_t *key = makeKey(len);
	char name[128];
	snprintf(name, sizeof(name), "%s accepts a %zu byte key (%s)", info->name, len, label);
	CHECK(accepts(info, key, len), name);
	free(key);
}

static void checkRejected(const CipherInfo *info, size_t len, const char *label)
{
	uint8_t *key = makeKey(len);
	char name[128];
	snprintf(name, sizeof(name), "%s rejects a %zu byte key (%s)", info->name, len, label);
	CHECK(!accepts(info, key, len), name);
	free(key);
}

/* Every cipher rejects an empty key and a NULL key. For Blowfish the empty
   case is the regression: the schedule computed (4 * i) % len, so a zero
   length raised SIGFPE and killed the process before anything could report
   the mistake. */
static void testEmptyKeyRejected(void)
{
	printf("== empty and NULL keys ==\n");
	for (size_t i = 0; i < CIPHER_COUNT; ++i)
	{
		char name[128];
		checkRejected(&CIPHERS[i], 0, "empty");
		snprintf(name, sizeof(name), "%s rejects a NULL key", CIPHERS[i].name);
		CHECK(!accepts(&CIPHERS[i], NULL, CIPHERS[i].validLen), name);
	}
}

/* Lengths each cipher must accept, and the neighbours it must refuse. */
static void testLengths(void)
{
	printf("== AES: 16, 24, 32 bytes ==\n");
	checkAccepted(&CIPHERS[0], 16, "AES-128");
	checkAccepted(&CIPHERS[0], 24, "AES-192");
	checkAccepted(&CIPHERS[0], 32, "AES-256");
	checkRejected(&CIPHERS[0], 8, "64-bit key, too short");
	checkRejected(&CIPHERS[0], 15, "one short");
	checkRejected(&CIPHERS[0], 17, "one past AES-128");
	checkRejected(&CIPHERS[0], 20, "between the sizes");
	checkRejected(&CIPHERS[0], 33, "one past AES-256");
	checkRejected(&CIPHERS[0], 64, "twice AES-256");

	printf("== DES: 8 bytes ==\n");
	checkAccepted(&CIPHERS[1], 8, "64-bit key");
	checkRejected(&CIPHERS[1], 4, "32-bit key, too short");
	checkRejected(&CIPHERS[1], 7, "one short");
	checkRejected(&CIPHERS[1], 9, "one over");
	/* strtoull read at most 16 hex digits and stopped at the first non-hex
	   character, so a 12-byte key used to be accepted and silently truncated
	   to its first 8 bytes. */
	checkRejected(&CIPHERS[1], 12, "would have been truncated to 8");
	checkRejected(&CIPHERS[1], 16, "would have been truncated to 8");

	/* Blowfish takes a key of 32 to 448 bits, i.e. 4 to 56 bytes. The
	   schedule cycles key bytes with (4 * i) % len, the algorithm's own rule,
	   so every length in the range works. The hex port could only accept
	   multiples of 8 characters, because a read of 8 characters would have
	   straddled the terminating NUL; raw bytes have no terminator. Python's
	   reference allows the same 4 to 56 bytes, so the two agree here. */
	printf("== Blowfish: 4 to 56 bytes ==\n");
	checkAccepted(&CIPHERS[2], 4, "32-bit key, the minimum");
	checkAccepted(&CIPHERS[2], 5, "off any word boundary, and still valid");
	checkAccepted(&CIPHERS[2], 7, "off any word boundary, and still valid");
	checkAccepted(&CIPHERS[2], 8, "64-bit key");
	checkAccepted(&CIPHERS[2], 56, "448-bit key, the maximum");
	checkRejected(&CIPHERS[2], 3, "below the minimum");
	checkRejected(&CIPHERS[2], 57, "one past the maximum");
	checkRejected(&CIPHERS[2], 120, "far past the maximum");

	printf("== Serpent: 1 to 32 bytes ==\n");
	/* Serpent's specification accepts any key of 1 to 256 bits and defines
	   the padding for shorter ones, so short keys are legal rather than an
	   error. The spec goes down to a single bit; a byte array cannot express
	   a sub-byte key, so 1 byte is the smallest that can be handed over.
	   Python accepts only 16, 24 and 32 bytes, which is a divergence, not
	   the rule. */
	checkAccepted(&CIPHERS[3], 1, "8-bit key, spec padded");
	checkAccepted(&CIPHERS[3], 2, "16-bit key, spec padded");
	checkAccepted(&CIPHERS[3], 4, "32-bit key, spec padded");
	checkAccepted(&CIPHERS[3], 8, "64-bit key, spec padded");
	checkAccepted(&CIPHERS[3], 16, "128-bit key");
	checkAccepted(&CIPHERS[3], 24, "192-bit key");
	checkAccepted(&CIPHERS[3], 32, "256-bit key, the maximum");
	checkRejected(&CIPHERS[3], 33, "one past the maximum");
	checkRejected(&CIPHERS[3], 64, "twice the maximum");

	printf("== Twofish: 16, 24, 32 bytes ==\n");
	checkAccepted(&CIPHERS[4], 16, "128-bit key");
	checkAccepted(&CIPHERS[4], 24, "192-bit key");
	checkAccepted(&CIPHERS[4], 32, "256-bit key");
	checkRejected(&CIPHERS[4], 8, "64-bit key, too short");
	checkRejected(&CIPHERS[4], 10, "not one of the sizes");
	checkRejected(&CIPHERS[4], 15, "one short");
	checkRejected(&CIPHERS[4], 17, "one over");
	checkRejected(&CIPHERS[4], 33, "one past the maximum");
}

/* A rejected key must not leave the caller's state holding something that looks
   usable. Both entry points zero it, so encrypting a block under any two
   rejected keys gives the same answer: the result depends on neither key. */
static void testRejectedKeyLeavesNoUsableState(void)
{
	printf("== rejected keys leave no usable state ==\n");
	for (size_t i = 0; i < CIPHER_COUNT; ++i)
	{
		const CipherInfo *info = &CIPHERS[i];
		uint8_t a[32], b[32];
		uint8_t bad1[80], bad2[80];
		char name[128];

		memset(bad1, 0x00, sizeof bad1);
		memset(bad2, 0x11, sizeof bad2);

		/* Two different rejected keys, both too long. */
		encryptBlockWith(info, bad1, sizeof bad1, a);
		encryptBlockWith(info, bad2, sizeof bad2, b);
		snprintf(name, sizeof(name), "%s state is independent of a rejected key", info->name);
		CHECK(memcmp(a, b, (size_t)info->blockSize) == 0, name);

		/* And a rejected key must not be mistaken for a usable one: the
		   zeroed state has to differ from what any real key produces. */
		uint8_t *good = makeKey(info->validLen);
		encryptBlockWith(info, good, info->validLen, b);
		snprintf(name, sizeof(name), "%s rejected key does not encrypt like a real key", info->name);
		CHECK(memcmp(a, b, (size_t)info->blockSize) != 0, name);
		free(good);
	}
}

/* A rejected key must not disturb a schedule that was already set up: the zeroed
   state is written on failure, so a caller that ignores the return value still
   gets a cipher that is merely useless rather than one running on a stale key. */
static void testRejectedKeyAfterValidKey(void)
{
	printf("== a valid key still works after a rejected one ==\n");
	for (size_t i = 0; i < CIPHER_COUNT; ++i)
	{
		const CipherInfo *info = &CIPHERS[i];
		void *state = calloc(1, info->stateSize);
		BlockCipher c = info->ctor(state);
		uint8_t fresh[32], after[32], iv[32], bad[80];
		char name[128];

		uint8_t *good = makeKey(info->validLen);
		CHECK(accepts(info, good, info->validLen), "the reference key is accepted");

		memset(fresh, 0x11, (size_t)info->blockSize);
		memset(iv, 0x22, (size_t)info->blockSize);
		c.generateKeys(&c, good, info->validLen);
		memcpy(fresh, iv, (size_t)info->blockSize);
		c.encryptBlock(&c, fresh);

		memset(after, 0x11, (size_t)info->blockSize);
		memset(bad, 0xff, sizeof(bad));
		CHECK(c.generateKeys(&c, bad, sizeof bad) == 0, "the over-long key is refused");
		memcpy(after, iv, (size_t)info->blockSize);
		c.generateKeys(&c, good, info->validLen);
		c.encryptBlock(&c, after);

		snprintf(name, sizeof(name), "%s recovers after a rejected key", info->name);
		CHECK(memcmp(fresh, after, (size_t)info->blockSize) == 0, name);

		free(good);
		free(state);
	}
}

/* The by-value entry points are public too, declared in each cipher's header,
   and they carry their own copy of the length guard. Testing only the struct
   leaves that copy uncovered: removing the guard from blowfish_generateKeys
   while leaving blowfish_generateKeysSelf intact still passes every check
   above, and that is the function whose missing guard used to raise SIGFPE.

   A rejected key must come back as an all-zero struct, so a caller holding the
   result by value cannot mistake it for a real schedule either. */
static void testByValueEntryPoints(void)
{
	uint8_t empty[1] = {0};
	uint8_t two[2] = {0x00, 0x01};
	uint8_t eighteen[18];
	printf("== by-value generateKeys rejects and zeroes ==\n");
	memset(eighteen, 0x01, sizeof(eighteen));

	{
		struct AES a = aes_generateKeys(empty, 0);
		struct AES zero;
		memset(&zero, 0, sizeof(zero));
		CHECK(memcmp(&a, &zero, sizeof(a)) == 0, "aes_generateKeys(len 0) returns a zeroed struct");
	}
	{
		struct DES d = des_generateKeys(empty, 0);
		struct DES zero;
		memset(&zero, 0, sizeof(zero));
		CHECK(memcmp(&d, &zero, sizeof(d)) == 0, "des_generateKeys(len 0) returns a zeroed struct");
	}
	{
		/* The regression: this call computes (4 * i) % len, so a zero length
		   raises SIGFPE and the process dies before it can report anything.
		   It passes by not crashing. */
		struct Blowfish bf = blowfish_generateKeys(empty, 0);
		struct Blowfish zero;
		memset(&zero, 0, sizeof(zero));
		CHECK(memcmp(&bf, &zero, sizeof(bf)) == 0, "blowfish_generateKeys(len 0) returns a zeroed struct");
	}
	{
		struct Serpent s = serpent_generateKeys(empty, 0);
		struct Serpent zero;
		memset(&zero, 0, sizeof(zero));
		CHECK(memcmp(&s, &zero, sizeof(s)) == 0, "serpent_generateKeys(len 0) returns a zeroed struct");
	}
	{
		struct Twofish t = twofish_generateKeys(empty, 0);
		struct Twofish zero;
		memset(&zero, 0, sizeof(zero));
		CHECK(memcmp(&t, &zero, sizeof(t)) == 0, "twofish_generateKeys(len 0) returns a zeroed struct");
	}
	{
		struct AES a = aes_generateKeys(NULL, 16);
		struct AES zero;
		memset(&zero, 0, sizeof(zero));
		CHECK(memcmp(&a, &zero, sizeof(a)) == 0, "aes_generateKeys(NULL) returns a zeroed struct");
	}
	{
		struct Blowfish bf = blowfish_generateKeys(NULL, 16);
		struct Blowfish zero;
		memset(&zero, 0, sizeof(zero));
		CHECK(memcmp(&bf, &zero, sizeof(bf)) == 0, "blowfish_generateKeys(NULL) returns a zeroed struct");
	}

	/* One wrong length per cipher, to confirm the by-value guards are real and
	   not just special-casing the empty string. */
	struct AES aesBad = aes_generateKeys(two, 2);
	CHECK(aesBad.nKeys == 0, "aes_generateKeys rejects a 2-byte key");
	struct Twofish tfBad = twofish_generateKeys(eighteen, 18);
	struct Twofish tfZero;
	memset(&tfZero, 0, sizeof(tfZero));
	CHECK(memcmp(&tfBad, &tfZero, sizeof(tfBad)) == 0,
	      "twofish_generateKeys rejects an 18-byte key");
}

/* The accepted Blowfish lengths have to produce the right schedule, not merely
   avoid the length check. These are the published set_key vectors: encrypting
   FEDCBA9876543210 under each key must give the listed ciphertext. Without
   this, relaxing the check to any length would pass while quietly producing
   the wrong key schedule. */
static void testBlowfishSchedules(void)
{
	printf("== Blowfish accepted lengths give the published schedule ==\n");
	for (size_t i = 0; i < sizeof BF_KATS / sizeof BF_KATS[0]; ++i)
	{
		void *state = calloc(1, CIPHERS[2].stateSize);
		BlockCipher c = blowfish_cipher(state);
		uint8_t key[32];
		uint8_t out[8] = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
		char got[17];
		char name[128];

		hexDecode(BF_KATS[i][0], key);
		int ok = c.generateKeys(&c, key, hexLen(BF_KATS[i][0]));
		snprintf(name, sizeof(name), "set_key %zu accepted", i);
		CHECK(ok, name);

		c.encryptBlock(&c, out);
		for (int j = 0; j < 8; ++j)
			snprintf(got + 2 * j, 3, "%02X", out[j]);

		snprintf(name, sizeof(name), "set_key key=%s -> %s", BF_KATS[i][0], BF_KATS[i][1]);
		CHECK(strcmp(got, BF_KATS[i][1]) == 0, name);

		free(state);
	}
}

/* keyOk answers the length question without building a schedule, and it is the
   same predicate generateKeys uses, so the two can never disagree: that is
   asserted for every accept/reject case through accepts(). This section pins
   the query itself, the wiring that installs each cipher's validator on the
   struct, and the exported validators that back the pointer. */
static void testKeyOkQuery(void)
{
	printf("== the keyOk query answers before a schedule is built ==\n");
	for (size_t i = 0; i < CIPHER_COUNT; ++i)
	{
		const CipherInfo *info = &CIPHERS[i];
		void *state = calloc(1, info->stateSize);
		BlockCipher c = info->ctor(state);
		uint8_t *good = makeKey(info->validLen);
		char name[128];

		snprintf(name, sizeof(name), "%s installs its validator as keyOk", info->name);
		CHECK(c.keyOk == info->keyOkFn, name);

		snprintf(name, sizeof(name), "%s keyOk accepts its reference length", info->name);
		CHECK(c.keyOk(good, info->validLen) == 1, name);
		snprintf(name, sizeof(name), "%s keyOk refuses an over-long key", info->name);
		CHECK(c.keyOk(good, 80) == 0, name);
		snprintf(name, sizeof(name), "%s keyOk refuses an empty key", info->name);
		CHECK(c.keyOk(good, 0) == 0, name);
		snprintf(name, sizeof(name), "%s keyOk refuses a NULL key", info->name);
		CHECK(c.keyOk(NULL, info->validLen) == 0, name);

		free(good);
		free(state);
	}

	/* The exported validators are public in each cipher's header; the struct
	   pointer is set to one of these, so checking them directly is checking
	   what the pointer reaches. */
	{
		uint8_t key[32];
		memset(key, 0x5a, sizeof(key));
		CHECK(aes_keyOk(key, 16) && !aes_keyOk(key, 15), "aes_keyOk: 16 bytes in, 15 out");
		CHECK(des_keyOk(key, 8) && !des_keyOk(key, 9), "des_keyOk: 8 bytes in, 9 out");
		CHECK(blowfish_keyOk(key, 56) && !blowfish_keyOk(key, 57), "blowfish_keyOk: 56 bytes in, 57 out");
		CHECK(serpent_keyOk(key, 1) && !serpent_keyOk(key, 33), "serpent_keyOk: 1 byte in, 33 out");
		CHECK(twofish_keyOk(key, 32) && !twofish_keyOk(key, 31), "twofish_keyOk: 32 bytes in, 31 out");
	}
}

int main(void)
{
	testEmptyKeyRejected();
	testKeyOkQuery();
	testLengths();
	testByValueEntryPoints();
	testBlowfishSchedules();
	testRejectedKeyLeavesNoUsableState();
	testRejectedKeyAfterValidKey();

	if (g_fails)
	{
		printf("\n%d test(s) failed\n", g_fails);
		return 1;
	}
	printf("\n0 test(s) failed\n");
	return 0;
}
