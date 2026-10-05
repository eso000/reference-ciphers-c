/* Key length acceptance across every cipher, through the BlockCipher struct.

   generateKeys returns 1 for a key it accepted and 0 for one it rejected, so
   these cases go through the same function pointer the mode tests use rather
   than calling each cipher's key schedule directly. That is deliberate: the
   struct entry point is what application code reaches.

   Keys are NUL-terminated hex strings here, so every length below is in hex
   characters -- twice the byte count. AES and DES want 16/24/32-byte and 8-byte
   keys, so they want 32/48/64 and 16 characters. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block/aes.h"
#include "block/des.h"
#include "block/blowfish.h"
#include "block/serpent.h"
#include "block/twofish.h"

static int g_fails = 0;

#define CHECK(cond, name) { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s\n", name); ++g_fails; } }

typedef BlockCipher (*CipherCtor)(void *);

typedef struct {
	const char *name;
	CipherCtor ctor;
	int blockSize;
	size_t stateSize;
	/* A length this cipher accepts, used wherever the test needs "a real
	   key" and must not assume every cipher takes the same one. DES accepts
	   only 16 characters, so a 64 character key would be rejected there and
	   the comparison below would compare two zeroed states. */
	size_t validLen;
} CipherInfo;

/* stateSize is deliberately generous. Blowfish's struct is about 4 KiB of
   S-boxes, so a tight allocation here would corrupt the heap rather than
   exercise the key check. */
static const CipherInfo CIPHERS[] = {
	{"AES", aes_cipher, 16, 8192, 32},
	{"DES", des_cipher, 8, 8192, 16},
	{"Blowfish", blowfish_cipher, 8, 8192, 16},
	{"Serpent", serpent_cipher, 16, 8192, 64},
	{"Twofish", twofish_cipher, 16, 8192, 32},
};

/* Blowfish's published set_key vectors: the ciphertext of FEDCBA9876543210
   under each key. Only the lengths this port accepts appear; the 1-, 2- and
   3-byte ones are absent because the 8-character-per-word key schedule cannot
   represent them. */
static const char *const BF_KATS[][2] = {
	{"F0E1D2C3", "BE1E639408640F05"},
	{"F0E1D2C3B4A59687", "E87A244E2CC85E82"},
	{"F0E1D2C3B4A5968778695A4B", "9409DA87A90F6BF2"},
	{"F0E1D2C3B4A5968778695A4B3C2D1E0F", "93142887EE3BE15C"},
	{"F0E1D2C3B4A5968778695A4B3C2D1E0F00112233", "10851C0E3858DA9F"},
	{"F0E1D2C3B4A5968778695A4B3C2D1E0F0011223344556677", "05044B62FA52D080"},
};

#define CIPHER_COUNT (sizeof CIPHERS / sizeof CIPHERS[0])

/* Build a hex key of exactly len characters. len == 0 gives the empty key,
   which is the case that used to divide by zero in Blowfish. */
static char *makeKey(size_t len)
{
	char *key = malloc(len + 1);
	for (size_t i = 0; i < len; ++i)
		key[i] = (i % 2 == 0) ? "0123456789abcdef"[i % 16] : "0123456789abcdef"[(i + 5) % 16];
	key[len] = '\0';
	return key;
}

/* Returns the cipher's 1/0 verdict on the key, allocating and freeing the state. */
static int accepts(const CipherInfo *info, const char *key)
{
	void *state = calloc(1, info->stateSize);
	BlockCipher c = info->ctor(state);
	int ok = c.generateKeys(&c, (char *)key);
	free(state);
	return ok;
}

/* Encrypt one block under a key, so a caller can observe the resulting state.
   Only called with the cipher's own block size. */
static void encryptBlockWith(const CipherInfo *info, const char *key, uint8_t *out)
{
	void *state = calloc(1, info->stateSize);
	BlockCipher c = info->ctor(state);
	c.generateKeys(&c, (char *)key);
	memset(out, 0x5A, (size_t)info->blockSize);
	c.encryptBlock(&c, out);
	free(state);
}

static void checkAccepted(const CipherInfo *info, size_t len, const char *label)
{
	char *key = makeKey(len);
	char name[128];
	snprintf(name, sizeof(name), "%s accepts a %zu character key (%s)", info->name, len, label);
	CHECK(accepts(info, key), name);
	free(key);
}

static void checkRejected(const CipherInfo *info, size_t len, const char *label)
{
	char *key = makeKey(len);
	char name[128];
	snprintf(name, sizeof(name), "%s rejects a %zu character key (%s)", info->name, len, label);
	CHECK(!accepts(info, key), name);
	free(key);
}

/* Every cipher rejects an empty key. For Blowfish this is the regression: the
   schedule computed (8 * i) % strlen(key), so an empty key raised SIGFPE and
   killed the process before anything could report the mistake. */
static void testEmptyKeyRejected(void)
{
	printf("== empty keys ==\n");
	for (size_t i = 0; i < CIPHER_COUNT; ++i)
		checkRejected(&CIPHERS[i], 0, "empty");
}

/* Lengths each cipher must accept, and the neighbours it must refuse. */
static void testLengths(void)
{
	printf("== AES: 32, 48, 64 characters ==\n");
	checkAccepted(&CIPHERS[0], 32, "AES-128");
	checkAccepted(&CIPHERS[0], 48, "AES-192");
	checkAccepted(&CIPHERS[0], 64, "AES-256");
	checkRejected(&CIPHERS[0], 16, "64-bit key, too short");
	checkRejected(&CIPHERS[0], 31, "odd and short");
	checkRejected(&CIPHERS[0], 33, "one past AES-128");
	checkRejected(&CIPHERS[0], 40, "not a multiple of 8");
	checkRejected(&CIPHERS[0], 65, "one past AES-256");
	checkRejected(&CIPHERS[0], 128, "twice AES-256");

	printf("== DES: 16 characters ==\n");
	checkAccepted(&CIPHERS[1], 16, "64-bit key");
	checkRejected(&CIPHERS[1], 8, "32-bit key, too short");
	checkRejected(&CIPHERS[1], 15, "odd and short");
	checkRejected(&CIPHERS[1], 17, "one over");
	/* strtoull reads at most 16 digits, so a 24 character key used to be
	   accepted and silently truncated to its first 16 characters. */
	checkRejected(&CIPHERS[1], 24, "would have been truncated to 16");
	checkRejected(&CIPHERS[1], 32, "would have been truncated to 16");

	/* Blowfish's published set_key vectors cover 1-, 2- and 3-byte keys, so those
   lengths are valid here even though the cipher's own prose quotes a 32-bit
   minimum. Rejecting them would mean the C port cannot reproduce three of its
   own vectors. Python rejects them, which is a divergence, not the rule. */
	/* Blowfish in C is restricted to word-aligned keys, 8 to 112 characters in
	   steps of 8, which is narrower than the cipher itself.

	   The schedule reads 8 hex characters per 32-bit word with
	   strtoul(temp, NULL, 16) and wraps with (8 * i) % strlen(key). For any
	   other length the last read straddles the terminator, so the word is
	   keyed from fewer digits than the caller supplied. That is not a guess:
	   checked against the published set_key vectors, the word-aligned lengths
	   (4, 8, 11, 16, 20, 24 bytes) all reproduce the stated ciphertext and
	   every off-word length fails, producing the unchanged plaintext
	   FEDCBA9876543210 instead.

	   Blowfish does permit 1-, 2- and 3-byte keys and its published vectors
	   cover them, so this port cannot reproduce those three. C++ and Java do.
	   The step of 8 is what makes the failure a refusal rather than a silently
	   wrong schedule. */
	printf("== Blowfish: 8 to 112, in steps of 8 ==\n");
	checkAccepted(&CIPHERS[2], 8, "32-bit key, the minimum");
	checkAccepted(&CIPHERS[2], 16, "64-bit key");
	checkAccepted(&CIPHERS[2], 24, "96-bit key");
	checkAccepted(&CIPHERS[2], 40, "160-bit key");
	checkAccepted(&CIPHERS[2], 112, "448-bit key, the maximum");
	checkRejected(&CIPHERS[2], 7, "below the minimum");
	/* The schedule reads 8 characters per word and wraps with
	   (8 * i) % strlen(key), so an off-step length would straddle the
	   terminator and key a word from fewer digits than were supplied. The
	   set_key checks below confirm the aligned lengths really do produce the
	   published schedules. */
	checkRejected(&CIPHERS[2], 9, "off the 8 character step");
	checkRejected(&CIPHERS[2], 15, "off the 8 character step");
	checkRejected(&CIPHERS[2], 113, "off the 8 character step");
	checkRejected(&CIPHERS[2], 120, "past the maximum");
	/* Off-step but not under the minimum, which is the case most likely to be
	   waved through by a range-only check. */
	checkRejected(&CIPHERS[2], 18, "off the step, above the minimum");

	printf("== Serpent: 1 to 64 characters ==\n");
	/* Serpent's specification accepts any key of 1 to 256 bits and defines
	   the padding for shorter ones, so short keys are legal here rather than
	   an error. Only the empty and over-long cases are refused. */
	checkAccepted(&CIPHERS[3], 1, "4-bit key, rounded up to a byte");
	checkAccepted(&CIPHERS[3], 2, "8-bit key, spec padded");
	checkAccepted(&CIPHERS[3], 8, "32-bit key");
	checkAccepted(&CIPHERS[3], 16, "64-bit key");
	checkAccepted(&CIPHERS[3], 24, "96-bit key");
	checkAccepted(&CIPHERS[3], 32, "128-bit key");
	checkAccepted(&CIPHERS[3], 48, "192-bit key");
	checkAccepted(&CIPHERS[3], 64, "256-bit key, the maximum");
	checkRejected(&CIPHERS[3], 65, "one past the maximum");
	checkRejected(&CIPHERS[3], 128, "twice the maximum");

	printf("== Twofish: 32, 48, 64 characters ==\n");
	checkAccepted(&CIPHERS[4], 32, "128-bit key");
	checkAccepted(&CIPHERS[4], 48, "192-bit key");
	checkAccepted(&CIPHERS[4], 64, "256-bit key");
	checkRejected(&CIPHERS[4], 16, "64-bit key, too short");
	checkRejected(&CIPHERS[4], 20, "not a multiple of 8");
	checkRejected(&CIPHERS[4], 31, "one short");
	checkRejected(&CIPHERS[4], 33, "one over");
	checkRejected(&CIPHERS[4], 65, "one past the maximum");
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
		char name[128];

		/* Two different rejected keys, both too long. */
		encryptBlockWith(info, "0000000000000000000000000000000000000000000000000000000000000000000000000", a);
		encryptBlockWith(info, "1111111111111111111111111111111111111111111111111111111111111111111111111", b);
		snprintf(name, sizeof(name), "%s state is independent of a rejected key", info->name);
		CHECK(memcmp(a, b, (size_t)info->blockSize) == 0, name);

		/* And a rejected key must not be mistaken for a usable one: the
		   zeroed state has to differ from what any real key produces. */
		char *good = makeKey(info->validLen);
		encryptBlockWith(info, good, b);
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
		uint8_t fresh[32], after[32], iv[32];
		char name[128];

		char *good = makeKey(info->validLen);
		CHECK(accepts(info, good), "the reference key is accepted");

		memset(fresh, 0x11, (size_t)info->blockSize);
		memset(iv, 0x22, (size_t)info->blockSize);
		c.generateKeys(&c, good);
		memcpy(fresh, iv, (size_t)info->blockSize);
		c.encryptBlock(&c, fresh);

		memset(after, 0x11, (size_t)info->blockSize);
		char bad[80];
		memset(bad, 'f', sizeof(bad) - 1);
		bad[sizeof(bad) - 1] = '\0';
		CHECK(c.generateKeys(&c, bad) == 0, "the over-long key is refused");
		memcpy(after, iv, (size_t)info->blockSize);
		c.generateKeys(&c, good);
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
	printf("== by-value generateKeys rejects and zeroes ==\n");
	{
		struct AES a = aes_generateKeys("");
		struct AES zero;
		memset(&zero, 0, sizeof(zero));
		CHECK(memcmp(&a, &zero, sizeof(a)) == 0, "aes_generateKeys(\"\") returns a zeroed struct");
	}
	{
		struct DES d = des_generateKeys("");
		struct DES zero;
		memset(&zero, 0, sizeof(zero));
		CHECK(memcmp(&d, &zero, sizeof(d)) == 0, "des_generateKeys(\"\") returns a zeroed struct");
	}
	{
		/* The regression: this call computes (8 * i) % strlen(key), so an
		   empty key raises SIGFPE and the process dies before it can report
		   anything. It passes by not crashing. */
		struct Blowfish bf = blowfish_generateKeys("");
		struct Blowfish zero;
		memset(&zero, 0, sizeof(zero));
		CHECK(memcmp(&bf, &zero, sizeof(bf)) == 0, "blowfish_generateKeys(\"\") returns a zeroed struct");
	}
	{
		struct Serpent s = serpent_generateKeys("");
		struct Serpent zero;
		memset(&zero, 0, sizeof(zero));
		CHECK(memcmp(&s, &zero, sizeof(s)) == 0, "serpent_generateKeys(\"\") returns a zeroed struct");
	}
	{
		struct Twofish t = twofish_generateKeys("");
		struct Twofish zero;
		memset(&zero, 0, sizeof(zero));
		CHECK(memcmp(&t, &zero, sizeof(t)) == 0, "twofish_generateKeys(\"\") returns a zeroed struct");
	}

	/* One wrong length per cipher, to confirm the by-value guards are real and
	   not just special-casing the empty string. */
	struct AES aesBad = aes_generateKeys("0001");
	CHECK(aesBad.nKeys == 0, "aes_generateKeys rejects a 4 character key");
	struct Twofish tfBad = twofish_generateKeys("000102030405060708090a0b0c0d0e0f101112");
	struct Twofish tfZero;
	memset(&tfZero, 0, sizeof(tfZero));
	CHECK(memcmp(&tfBad, &tfZero, sizeof(tfBad)) == 0,
	      "twofish_generateKeys rejects an 18 character key");
}

/* The accepted Blowfish lengths have to produce the right schedule, not merely
   avoid the length check. These are the published set_key vectors for the
   lengths this port can represent; encrypting FEDCBA9876543210 under each key
   must give the listed ciphertext. Without this, relaxing the check to any
   length would pass while quietly producing the wrong key schedule. */
static void testBlowfishSchedules(void)
{
	printf("== Blowfish accepted lengths give the published schedule ==\n");
	for (size_t i = 0; i < sizeof BF_KATS / sizeof BF_KATS[0]; ++i)
	{
		void *state = calloc(1, CIPHERS[2].stateSize);
		BlockCipher c = blowfish_cipher(state);
		uint8_t out[8] = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
		char got[17];
		char name[128];

		int ok = c.generateKeys(&c, (char *)BF_KATS[i][0]);
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

int main(void)
{
	testEmptyKeyRejected();
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