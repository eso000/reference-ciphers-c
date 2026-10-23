#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block/aes.h"
#include "block/padding.h"
#include "testutil.h"

/* AES_FIPS is FIPS-197 Appendix C: one block per key size.

   AES_SP800_ECB and AES_SP800_CBC are the four-block ECB and CBC sets from
   NIST SP 800-38A Appendix F (F.1.1-F.1.3 and F.2.1-F.2.3). All three sets
   share the standard's one plaintext; CBC also uses the standard's one IV.
   The Python suite in tests/vectors.py carries the same tables, and provenance
   is listed in the repository README. */

struct Kat
{
	const char *name;
	const char *key;
	const char *plain;
	const char *cipher;
};

static struct Kat AES_FIPS[] = {
	{"AES-128", "000102030405060708090a0b0c0d0e0f",
	 "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"},
	{"AES-192", "000102030405060708090a0b0c0d0e0f1011121314151617",
	 "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"},
	{"AES-256", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	 "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"},
};

/* The four blocks of the SP 800-38A plaintext and the IV used by every CBC
   vector in the standard. */
#define SP800_PT \
	"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" \
	"30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
#define SP800_IV "000102030405060708090a0b0c0d0e0f"

struct ModeKat
{
	const char *name;
	const char *key;
	const char *cipher;
};

static struct ModeKat AES_SP800_ECB[] = {
	{"AES-128", "2b7e151628aed2a6abf7158809cf4f3c",
	 "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
	 "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"},
	{"AES-192", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
	 "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef"
	 "ef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e"},
	{"AES-256", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
	 "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870"
	 "b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7"},
};

static struct ModeKat AES_SP800_CBC[] = {
	{"AES-128", "2b7e151628aed2a6abf7158809cf4f3c",
	 "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
	 "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"},
	{"AES-192", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
	 "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a"
	 "571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd"},
	{"AES-256", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
	 "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
	 "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"},
};

int main(void)
{
	char name[96];

	printf("== AES FIPS-197 known-answer tests ==\n");
	for (size_t i = 0; i < sizeof AES_FIPS / sizeof AES_FIPS[0]; ++i)
	{
		struct AES aes;
		BlockCipher c = aes_cipher(&aes);
		uint8_t key[32], pt[16], ct[16], v[16];

		hexDecode(AES_FIPS[i].key, key);
		c.generateKeys(&c, key, hexLen(AES_FIPS[i].key));
		hexDecode(AES_FIPS[i].plain, pt);
		hexDecode(AES_FIPS[i].cipher, ct);

		memcpy(v, pt, 16);
		cipherEncryptECB(&c, v, 16);
		snprintf(name, sizeof(name), "%s encrypt", AES_FIPS[i].name);
		CHECK(memcmp(v, ct, 16) == 0, name);

		/* Decrypt the published ciphertext, not our own output, so a wrong
		   pair of encrypt and decrypt cannot pass by inverting itself. */
		memcpy(v, ct, 16);
		cipherDecryptECB(&c, v, 16);
		snprintf(name, sizeof(name), "%s decrypt", AES_FIPS[i].name);
		CHECK(memcmp(v, pt, 16) == 0, name);
	}

	printf("== AES ECB four blocks (NIST SP 800-38A F.1) ==\n");
	for (size_t i = 0; i < sizeof AES_SP800_ECB / sizeof AES_SP800_ECB[0]; ++i)
	{
		struct AES aes;
		BlockCipher c = aes_cipher(&aes);
		uint8_t key[32], pt[64], ct[64], v[64];

		hexDecode(AES_SP800_ECB[i].key, key);
		c.generateKeys(&c, key, hexLen(AES_SP800_ECB[i].key));
		hexDecode(SP800_PT, pt);
		hexDecode(AES_SP800_ECB[i].cipher, ct);

		memcpy(v, pt, 64);
		cipherEncryptECB(&c, v, 64);
		snprintf(name, sizeof(name), "%s ecb four-block encrypt", AES_SP800_ECB[i].name);
		CHECK(memcmp(v, ct, 64) == 0, name);

		memcpy(v, ct, 64);
		cipherDecryptECB(&c, v, 64);
		snprintf(name, sizeof(name), "%s ecb four-block decrypt", AES_SP800_ECB[i].name);
		CHECK(memcmp(v, pt, 64) == 0, name);

		/* ECB does not chain. Each block of the standard's ciphertext must
		   come out of encrypting only its own plaintext block. */
		int standalone = 1;
		for (size_t b = 0; b < sizeof ct / 16; ++b)
		{
			memcpy(v, pt + 16 * b, 16);
			cipherEncryptECB(&c, v, 16);
			if (memcmp(v, ct + 16 * b, 16) != 0)
				standalone = 0;
		}
		snprintf(name, sizeof(name), "%s ecb blocks stand alone", AES_SP800_ECB[i].name);
		CHECK(standalone, name);
	}

	printf("== AES CBC four blocks (NIST SP 800-38A F.2) ==\n");
	for (size_t i = 0; i < sizeof AES_SP800_CBC / sizeof AES_SP800_CBC[0]; ++i)
	{
		struct AES aes;
		BlockCipher c = aes_cipher(&aes);
		uint8_t key[32], pt[64], ct[64], v[64], iv[16], iv2[16];

		hexDecode(AES_SP800_CBC[i].key, key);
		c.generateKeys(&c, key, hexLen(AES_SP800_CBC[i].key));
		hexDecode(SP800_PT, pt);
		hexDecode(AES_SP800_CBC[i].cipher, ct);
		hexDecode(SP800_IV, iv);
		memcpy(iv2, iv, 16);

		memcpy(v, pt, 64);
		cipherEncryptCBC(&c, v, 64, iv);
		snprintf(name, sizeof(name), "%s cbc four-block encrypt", AES_SP800_CBC[i].name);
		CHECK(memcmp(v, ct, 64) == 0, name);

		/* cipherDecryptCBC advances the IV it is handed, so it gets the fresh
		   copy; the published ciphertext goes in for the same reason as above. */
		memcpy(v, ct, 64);
		cipherDecryptCBC(&c, v, 64, iv2);
		snprintf(name, sizeof(name), "%s cbc four-block decrypt", AES_SP800_CBC[i].name);
		CHECK(memcmp(v, pt, 64) == 0, name);
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
