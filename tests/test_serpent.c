#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block/serpent.h"
#include "block/padding.h"
#include "testutil.h"

struct Kat
{
	const char *name;
	const char *key;
	const char *plain;
	const char *cipher;
};

/* The published single-block vectors: the NESSIE/verified sets 1-4 for
   128-, 192- and 256-bit keys, exactly the sixteen the Python suite carries
   as SERPENT_KATS and the same little-endian octet order it uses. */
static struct Kat KATS[] = {
	{"128-bit set1 v0", "80000000000000000000000000000000",
		"00000000000000000000000000000000", "264e5481eff42a4606abda06c0bfda3d"},
	{"128-bit set2 v0", "00000000000000000000000000000000",
		"80000000000000000000000000000000", "a3b35de7c358ddd82644678c64b8bcbb"},
	{"128-bit set3 v0", "00000000000000000000000000000000",
		"00000000000000000000000000000000", "3620b17ae6a993d09618b8768266bae9"},
	{"128-bit set4 v0", "000102030405060708090a0b0c0d0e0f",
		"00112233445566778899aabbccddeeff", "563e2cf8740a27c164804560391e9b27"},
	{"128-bit set4 v1", "2bd6459f82c5b300952c49104881ff48",
		"ea024714ad5c4d84ea024714ad5c4d84", "92d7f8ef2c36c53409f275902f06539f"},
	{"192-bit set1 v0", "800000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000", "9e274ead9b737bb21efcfca548602689"},
	{"192-bit set2 v0", "000000000000000000000000000000000000000000000000",
		"80000000000000000000000000000000", "23f5f432ad687e0d4574c16459618abb"},
	{"192-bit set3 v0", "000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000", "a583ef976a292b406bbd5dc8256b0442"},
	{"192-bit set4 v0", "000102030405060708090a0b0c0d0e0f1011121314151617",
		"00112233445566778899aabbccddeeff", "6ab816c82de53b93005008afa2246a02"},
	{"192-bit set4 v1", "2bd6459f82c5b300952c49104881ff482bd6459f82c5b300",
		"ea024714ad5c4d84ea024714ad5c4d84", "827b18c2678a239dfc5512842000e204"},
	{"256-bit set1 v0", "8000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000", "a223aa1288463c0e2be38ebd825616c0"},
	{"256-bit set2 v0", "0000000000000000000000000000000000000000000000000000000000000000",
		"80000000000000000000000000000000", "8314675e8ad5c3ecd83d852bcf7f566e"},
	{"256-bit set3 v0", "0000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000", "49672ba898d98df95019180445491089"},
	{"256-bit set3 v17", "1111111111111111111111111111111111111111111111111111111111111111",
		"11111111111111111111111111111111", "a482eaa5d5771f2fdb2ea1a5f141b9e2"},
	{"256-bit set4 v0", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"00112233445566778899aabbccddeeff", "2868b7a2d28ecd5e4fdefac3c4330074"},
	{"256-bit set4 v1", "2bd6459f82c5b300952c49104881ff482bd6459f82c5b300952c49104881ff48",
		"ea024714ad5c4d84ea024714ad5c4d84", "3e507730776b93fdea661235e1dd99f0"},
};

/* Multi-block vectors. Serpent's published vectors are single-block ECB, so
   nothing published covers the mode wrappers; these were produced by GNU
   nettle and are the only expected values here that are not traceable to a
   numbered table. */
#define TWO_BLOCK_PT "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

struct ModeKat
{
	const char *name;
	const char *key;
	const char *cipher;
};

static struct ModeKat ECB_KATS[] = {
	{"128-bit", "000102030405060708090a0b0c0d0e0f",
		"4c7d8a328072a22c823e4a1f3acda16d1fe31aba9824fb1b33b42582291388db"},
	{"192-bit", "000102030405060708090a0b0c0d0e0f1011121314151617",
		"753d5b42d86672fb29070c4fe4eaaf4c4cc221270d91e743ca7b9d9e4e1ebe65"},
	{"256-bit", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"de269ff833e432b85b2e88d2701ce75ce534b936d9df2fc053bee5ed268fc68c"},
};

#define CBC_KEY   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
#define CBC_IV    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define CBC_CIPHER "2aa5a2ff0c27a0f9590f6167e9e779d861fc6463d2e956091e91677d4f38860c"

int main(void)
{
	char name[96];

	printf("== Serpent known-answer tests (ECB vectors) ==\n");
	for (size_t i = 0; i < sizeof KATS / sizeof KATS[0]; ++i)
	{
		struct Serpent ser;
		BlockCipher c = serpent_cipher(&ser);
		uint8_t key[32], pt[16], ct[16], v[16];

		hexDecode(KATS[i].key, key);
		c.generateKeys(&c, key, hexLen(KATS[i].key));
		hexDecode(KATS[i].plain, pt);
		hexDecode(KATS[i].cipher, ct);

		/* Encrypt: plaintext in, published ciphertext out. */
		memcpy(v, pt, 16);
		cipherEncryptECB(&c, v, 16);
		snprintf(name, sizeof(name), "kat %s encrypt", KATS[i].name);
		CHECK(memcmp(v, ct, 16) == 0, name);

		/* Decrypt: start from the published ciphertext rather than from our own
		   encrypt output, so this cannot pass just by inverting a wrong encrypt. */
		memcpy(v, ct, 16);
		cipherDecryptECB(&c, v, 16);
		snprintf(name, sizeof(name), "kat %s decrypt", KATS[i].name);
		CHECK(memcmp(v, pt, 16) == 0, name);
	}

	printf("== ECB two blocks (nettle) ==\n");
	for (size_t i = 0; i < sizeof ECB_KATS / sizeof ECB_KATS[0]; ++i)
	{
		struct Serpent ser;
		BlockCipher c = serpent_cipher(&ser);
		uint8_t key[32], pt[32], ct[32], v[32];

		hexDecode(ECB_KATS[i].key, key);
		c.generateKeys(&c, key, hexLen(ECB_KATS[i].key));
		hexDecode(TWO_BLOCK_PT, pt);
		hexDecode(ECB_KATS[i].cipher, ct);

		memcpy(v, pt, 32);
		cipherEncryptECB(&c, v, 32);
		snprintf(name, sizeof(name), "ecb two-block %s encrypt", ECB_KATS[i].name);
		CHECK(memcmp(v, ct, 32) == 0, name);

		memcpy(v, ct, 32);
		cipherDecryptECB(&c, v, 32);
		snprintf(name, sizeof(name), "ecb two-block %s decrypt", ECB_KATS[i].name);
		CHECK(memcmp(v, pt, 32) == 0, name);

		/* ECB must not chain: encrypting block 2 alone gives the same bytes. */
		c.generateKeys(&c, key, hexLen(ECB_KATS[i].key));
		memcpy(v, pt + 16, 16);
		cipherEncryptECB(&c, v, 16);
		snprintf(name, sizeof(name), "ecb two-block %s block 2 stands alone", ECB_KATS[i].name);
		CHECK(memcmp(v, ct + 16, 16) == 0, name);
	}

	printf("== CBC two blocks (nettle) ==\n");
	{
		struct Serpent ser;
		BlockCipher c = serpent_cipher(&ser);
		uint8_t key[32], pt[32], ct[32], v[32], iv[16];

		hexDecode(CBC_KEY, key);
		c.generateKeys(&c, key, hexLen(CBC_KEY));
		hexDecode(TWO_BLOCK_PT, pt);
		hexDecode(CBC_CIPHER, ct);

		hexDecode(CBC_IV, iv);
		memcpy(v, pt, 32);
		cipherEncryptCBC(&c, v, 32, iv);
		snprintf(name, sizeof(name), "cbc two-block encrypt (%s)", CBC_KEY);
		CHECK(memcmp(v, ct, 32) == 0, name);

		/* CBC chains, so the two ciphertext blocks must differ. */
		snprintf(name, sizeof(name), "cbc two-block encrypt chains");
		CHECK(memcmp(ct, ct + 16, 16) != 0, name);

		/* cipherDecryptCBC advances the IV it is handed, so start from a fresh copy. */
		hexDecode(CBC_IV, iv);
		memcpy(v, ct, 32);
		cipherDecryptCBC(&c, v, 32, iv);
		snprintf(name, sizeof(name), "cbc two-block decrypt (%s)", CBC_KEY);
		CHECK(memcmp(v, pt, 32) == 0, name);
	}

	printf("== Word order (paper's little-endian bitslice words) ==\n");
	{
		/* Subkey 0 for the all-zero 256-bit key pins the whole convention at
		   once: little-endian loading of block and key words, the un-reversed
		   golden-ratio constant and the un-reversed round counter. A
		   bit-reversed reading of the same schedule gives different words.

		   No published table lists intermediate subkeys, so this is a regression
		   pin: the sixteen official ciphertexts above already constrain this
		   schedule, because any error in it changes the ciphertext. */
		static const uint32_t EXPECTED[4] = {
			0x6f5795d0u, 0xa7e3a3ceu, 0xf2d998edu, 0x8ed77390u,
		};
		uint8_t key[32];
		hexDecode("0000000000000000000000000000000000000000000000000000000000000000", key);
		struct Serpent ser = serpent_generateKeys(key, sizeof key);

		/* Subkeys is a flat array of 33 four-word subkeys, 132 words in all. */
		CHECK(ser.Subkeys[0] == EXPECTED[0] && ser.Subkeys[1] == EXPECTED[1] &&
		      ser.Subkeys[2] == EXPECTED[2] && ser.Subkeys[3] == EXPECTED[3],
		      "subkey 0 for the all-zero key is 0x6f5795d0 0xa7e3a3ce "
		      "0xf2d998ed 0x8ed77390");
	}

	printf("== ECB round trip (two blocks) ==\n");
	{
		struct Serpent ser;
		BlockCipher c = serpent_cipher(&ser);
		uint8_t v[32], w[32];
		uint8_t key[32];
		for (int i = 0; i < 32; ++i)
			v[i] = (uint8_t)(0x10 + i);
		hexDecode("1111111111111111111111111111111111111111111111111111111111111111", key);
		c.generateKeys(&c, key, sizeof key);
		memcpy(w, v, 32);
		cipherEncryptECB(&c, v, 32);
		CHECK(memcmp(v, w, 32) != 0, "ecb ciphertext differs from plaintext");
		cipherDecryptECB(&c, v, 32);
		CHECK(memcmp(v, w, 32) == 0, "ecb encrypt+decrypt restores plaintext");
	}

	printf("== CBC round trip ==\n");
	{
		struct Serpent ser;
		BlockCipher c = serpent_cipher(&ser);
		uint8_t v[32], w[32];
		uint8_t iv[16] = {0}, iv2[16] = {0};
		uint8_t key[32];
		for (int i = 0; i < 32; ++i)
			v[i] = (uint8_t)(0xA0 + i);
		hexDecode("8000000000000000000000000000000000000000000000000000000000000000", key);
		c.generateKeys(&c, key, sizeof key);
		memcpy(w, v, 32);
		cipherEncryptCBC(&c, v, 32, iv);
		CHECK(memcmp(v, w, 32) != 0, "cbc ciphertext differs from plaintext");
		cipherDecryptCBC(&c, v, 32, iv2);
		CHECK(memcmp(v, w, 32) == 0, "cbc encrypt+decrypt restores plaintext");
	}

	printf("== padding to 16-byte blocks ==\n");
	{
		uint8_t *v = malloc(4);
		v[0] = 'A';
		v[1] = 'B';
		v[2] = 'C';
		v[3] = 'D';
		v = padPKCS(v, 4, 12);
		CHECK(v != NULL && v[15] == 12, "4 bytes padded to one block");
		free(v);
	}

	printf("\n%d test(s) failed\n", g_fails);
	return g_fails ? 1 : 0;
}
