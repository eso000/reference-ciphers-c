#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Blowfish.h"
#include "padding.h"

static int g_fails = 0;

#define CHECK(cond, name) { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s\n", name); ++g_fails; } }

static void hexDecode(const char *hex, uint8_t *out)
{
	for (int i = 0; hex[2 * i] && hex[2 * i + 1]; ++i)
	{
		unsigned x;
		sscanf(hex + 2 * i, "%2x", &x);
		out[i] = (uint8_t)x;
	}
}

static void bf_decryptCBC(struct Blowfish *b, uint8_t *data, int len, uint8_t *iv)
{
	uint8_t cur[8], prev[8];
	memcpy(prev, iv, 8);
	for (uint8_t *i = data; i + 8 <= data + len; i = i + 8)
	{
		memcpy(cur, i, 8);
		blowfish_decrypt_block(i, i + 4, *b);
		for (int k = 0; k < 8; ++k)
		{
			i[k] ^= prev[k];
			prev[k] = cur[k];
		}
	}
}

struct Kat
{
	const char *key;
	const char *plain;
	const char *cipher;
};

static struct Kat KATS[] = {
	{"0000000000000000", "0000000000000000", "4EF997456198DD78"},
	{"FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "51866FD5B85ECB8A"},
	{"AABB09182736CCDD", "123456ABCD132536", "C8FDCAEA64FA2C82"},
};

int main()
{
	char name[96];

	printf("== Blowfish known-answer tests (ECB vectors) ==\n");
	for (int i = 0; i < 3; ++i)
	{
		struct Blowfish c = blowfish_generateKeys((char *)KATS[i].key);
		uint8_t pt[8], ct[8], v[8];
		hexDecode(KATS[i].plain, pt);
		hexDecode(KATS[i].cipher, ct);
		memcpy(v, pt, 8);
		blowfish_encryptECB(v, 8, c);
		snprintf(name, sizeof(name), "kat ecb %02d encrypt", i + 1);
		CHECK(memcmp(v, ct, 8) == 0, name);
		blowfish_decryptECB(v, 8, c);
		snprintf(name, sizeof(name), "kat ecb %02d decrypt", i + 1);
		CHECK(memcmp(v, pt, 8) == 0, name);
	}

	printf("== ECB round trip (two blocks) ==\n");
	{
		struct Blowfish c = blowfish_generateKeys("AABB09182736CCDD");
		struct Blowfish d = blowfish_generateKeys("AABB09182736CCDD");
		uint8_t v[16] = {0x12, 0x34, 0x56, 0xAB, 0xCD, 0x13, 0x25, 0x36,
				 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		uint8_t w[16];
		memcpy(w, v, 16);
		blowfish_encryptECB(v, 16, c);
		CHECK(memcmp(v, w, 16) != 0, "ecb ciphertext differs from plaintext");
		blowfish_decryptECB(v, 16, d);
		CHECK(memcmp(v, w, 16) == 0, "ecb encrypt+decrypt restores plaintext");
	}

	printf("== CBC round trip ==\n");
	{
		struct Blowfish c = blowfish_generateKeys("AABB09182736CCDD");
		struct Blowfish d = blowfish_generateKeys("AABB09182736CCDD");
		uint8_t v[16] = {0x12, 0x34, 0x56, 0xAB, 0xCD, 0x13, 0x25, 0x36,
				 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		uint8_t w[16];
		uint8_t iv[8] = {0}, iv2[8] = {0};
		memcpy(w, v, 16);
		blowfish_encryptCBC(v, 16, iv, c);
		CHECK(memcmp(v, w, 16) != 0, "cbc ciphertext differs from plaintext");
		bf_decryptCBC(&d, v, 16, iv2);
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
