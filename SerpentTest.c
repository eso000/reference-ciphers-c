#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Serpent.h"
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

struct Kat
{
	const char *key;
	const char *plain;
	const char *cipher;
};

static struct Kat KATS[] = {
	{"8000000000000000000000000000000000000000000000000000000000000000",
	 "00000000000000000000000000000000", "a223aa1288463c0e2be38ebd825616c0"},
	{"1111111111111111111111111111111111111111111111111111111111111111",
	 "11111111111111111111111111111111", "a482eaa5d5771f2fdb2ea1a5f141b9e2"},
	{"0102030405060708090a0b0c0d0e0f10",
	 "00112233445566778899aabbccddeeff", "98874e1fbed147b9f34420e4118c4465"},
	{"0102030405060708090a0b0c0d0e0f101112131415161718",
	 "00112233445566778899aabbccddeeff", "17141e4724812f8bbe3e0ab978d1521f"},
};

int main()
{
	char name[96];

	printf("== Serpent known-answer tests (ECB vectors) ==\n");
	for (int i = 0; i < 4; ++i)
	{
		struct Serpent ser;
		BlockCipher c = serpent_cipher(&ser);
		uint8_t pt[16], ct[16], v[16];
		c.generateKeys(&c, (char *)KATS[i].key);
		hexDecode(KATS[i].plain, pt);
		hexDecode(KATS[i].cipher, ct);
		memcpy(v, pt, 16);
		cipherEncryptECB(&c, v, 16);
		snprintf(name, sizeof(name), "kat ecb %02d encrypt", i + 1);
		CHECK(memcmp(v, ct, 16) == 0, name);
		cipherDecryptECB(&c, v, 16);
		snprintf(name, sizeof(name), "kat ecb %02d decrypt", i + 1);
		CHECK(memcmp(v, pt, 16) == 0, name);
	}

	printf("== ECB round trip (two blocks) ==\n");
	{
		struct Serpent ser;
		BlockCipher c = serpent_cipher(&ser);
		uint8_t v[32], w[32];
		for (int i = 0; i < 32; ++i)
			v[i] = (uint8_t)(0x10 + i);
		c.generateKeys(&c, "1111111111111111111111111111111111111111111111111111111111111111");
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
		for (int i = 0; i < 32; ++i)
			v[i] = (uint8_t)(0xA0 + i);
		c.generateKeys(&c, "8000000000000000000000000000000000000000000000000000000000000000");
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
