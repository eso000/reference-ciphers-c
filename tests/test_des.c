#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block/des.h"
#include "block/padding.h"
#include "testutil.h"

struct Kat
{
	const char *key;
	const char *plain;
	const char *cipher;
};

/* The classic published single-DES values: the FIPS 46-3 walkthrough pair,
   plus the two from the original DES paper's own test set. The Python suite
   carries exactly these three as DES_KATS. The AABB09182736CCDD entry is
   widely reproduced but does not appear in either source, so its provenance
   is unconfirmed -- the same caveat the Python file records for it. */
static struct Kat KATS[] = {
	{"133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"},
	{"0E329232EA6D0D73", "8787878787878787", "0000000000000000"},
	{"AABB09182736CCDD", "123456ABCD132536", "C0B7A8D05F3A829C"},
};

int main(void)
{
	char name[96];

	printf("== DES known-answer tests (both IP/FP implementations) ==\n");
	for (size_t i = 0; i < sizeof KATS / sizeof KATS[0]; ++i)
	{
		struct DES des;
		BlockCipher c = des_cipher(&des);
		uint8_t key[8], pt[8], ct[8], v[8];
		hexDecode(KATS[i].key, key);
		c.generateKeys(&c, key, sizeof key);
		hexDecode(KATS[i].plain, pt);
		hexDecode(KATS[i].cipher, ct);
		for (int ai = 0; ai < 2; ++ai)
		{
			const char *mode = ai ? "alt" : "naive";
			des.use_alt = (uint8_t)ai;
			memcpy(v, pt, 8);
			cipherEncryptECB(&c, v, 8);
			snprintf(name, sizeof(name), "kat ecb %02zu encrypt (%s)", i + 1, mode);
			CHECK(memcmp(v, ct, 8) == 0, name);
			cipherDecryptECB(&c, v, 8);
			snprintf(name, sizeof(name), "kat ecb %02zu decrypt (%s)", i + 1, mode);
			CHECK(memcmp(v, pt, 8) == 0, name);
		}
	}

	printf("== delta-swap networks mutual inverse ==\n");
	{
		uint64_t x = 0x123456789abcdef0ULL;
		int checked = 0;
		for (int i = 0; i < 256; ++i)
		{
			x = x * 6364136223846793005ULL + 1442695040888963407ULL;
			if (des_fp_perm_alt(des_ip_perm_alt(x)) == x)
				++checked;
		}
		CHECK(checked == 256, "fp(ip(x)) == x for 256 random blocks");
	}

	printf("== alt vs naive agree ==\n");
	{
		struct DES des;
		BlockCipher c = des_cipher(&des);
		uint8_t a[8], b[8], orig[8], key[8];
		hexDecode("AABB09182736CCDD", key);
		c.generateKeys(&c, key, sizeof key);
		hexDecode("123456ABCD132536", orig);
		memcpy(a, orig, 8);
		memcpy(b, orig, 8);
		des.use_alt = 1;
		cipherEncryptECB(&c, a, 8);
		des.use_alt = 0;
		cipherEncryptECB(&c, b, 8);
		CHECK(memcmp(a, b, 8) == 0, "alt==naive encrypt");
		des.use_alt = 1;
		cipherDecryptECB(&c, a, 8);
		des.use_alt = 0;
		cipherDecryptECB(&c, b, 8);
		CHECK(memcmp(a, b, 8) == 0 && memcmp(a, orig, 8) == 0, "alt==naive decrypt");
	}

	printf("== ECB round trip (two blocks) ==\n");
	{
		struct DES des;
		BlockCipher c = des_cipher(&des);
		uint8_t v[16] = {0x12, 0x34, 0x56, 0xAB, 0xCD, 0x13, 0x25, 0x36,
				 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		uint8_t w[16];
		uint8_t key[8];
		hexDecode("AABB09182736CCDD", key);
		c.generateKeys(&c, key, sizeof key);
		memcpy(w, v, 16);
		cipherEncryptECB(&c, v, 16);
		CHECK(memcmp(v, w, 16) != 0, "ecb ciphertext differs from plaintext");
		cipherDecryptECB(&c, v, 16);
		CHECK(memcmp(v, w, 16) == 0, "ecb encrypt+decrypt restores plaintext");
	}

	printf("== CBC round trip ==\n");
	{
		struct DES des;
		BlockCipher c = des_cipher(&des);
		uint8_t v[16] = {0x12, 0x34, 0x56, 0xAB, 0xCD, 0x13, 0x25, 0x36,
				 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		uint8_t w[16];
		uint8_t iv[8] = {0}, iv2[8] = {0};
		uint8_t key[8];
		hexDecode("AABB09182736CCDD", key);
		c.generateKeys(&c, key, sizeof key);
		memcpy(w, v, 16);
		cipherEncryptCBC(&c, v, 16, iv);
		CHECK(memcmp(v, w, 16) != 0, "cbc ciphertext differs from plaintext");
		cipherDecryptCBC(&c, v, 16, iv2);
		CHECK(memcmp(v, w, 16) == 0, "cbc encrypt+decrypt restores plaintext");
	}

	printf("== padding to 8-byte blocks ==\n");
	{
		uint8_t *v = malloc(4);
		v[0] = 'A';
		v[1] = 'B';
		v[2] = 'C';
		v[3] = 'D';
		v = padPKCS(v, 4, 4);
		CHECK(v != NULL && v[7] == 4, "4 bytes padded to one block");
		free(v);
	}

	printf("\n%d test(s) failed\n", g_fails);
	return g_fails ? 1 : 0;
}
