#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block/aes.h"
#include "block/padding.h"
#include "testutil.h"

struct Kat
{
	const char *key;
	const char *plain;
	const char *cipher;
};

static struct Kat KATS[] = {
	{"000102030405060708090a0b0c0d0e0f",
	 "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"},
	{"000102030405060708090a0b0c0d0e0f1011121314151617",
	 "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"},
	{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	 "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"},
	{"2b7e151628aed2a6abf7158809cf4f3c",
	 "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"},
	{"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
	 "6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8"},
};

int main()
{
	char name[96];

	printf("== AES known-answer tests (ECB vectors) ==\n");
	for (size_t i = 0; i < sizeof KATS / sizeof KATS[0]; ++i)
	{
		struct AES aes;
		BlockCipher c = aes_cipher(&aes);
		uint8_t key[32], pt[16], ct[16], v[16];
		hexDecode(KATS[i].key, key);
		c.generateKeys(&c, key, hexLen(KATS[i].key));
		hexDecode(KATS[i].plain, pt);
		hexDecode(KATS[i].cipher, ct);
		memcpy(v, pt, 16);
		cipherEncryptECB(&c, v, 16);
		snprintf(name, sizeof(name), "kat ecb %02zu encrypt", i + 1);
		CHECK(memcmp(v, ct, 16) == 0, name);
		cipherDecryptECB(&c, v, 16);
		snprintf(name, sizeof(name), "kat ecb %02zu decrypt", i + 1);
		CHECK(memcmp(v, pt, 16) == 0, name);
	}

	printf("== ECB round trip (two blocks) ==\n");
	{
		struct AES aes;
		BlockCipher c = aes_cipher(&aes);
		uint8_t v[32], w[32];
		uint8_t pt[32], key[16];
		hexDecode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", pt);
		hexDecode("000102030405060708090a0b0c0d0e0f", key);
		c.generateKeys(&c, key, sizeof key);
		memcpy(v, pt, 32);
		memcpy(w, pt, 32);
		cipherEncryptECB(&c, v, 32);
		CHECK(memcmp(v, w, 32) != 0, "ecb ciphertext differs from plaintext");
		cipherDecryptECB(&c, v, 32);
		CHECK(memcmp(v, w, 32) == 0, "ecb encrypt+decrypt restores plaintext");
	}

	printf("== CBC round trip ==\n");
	{
		struct AES aes;
		BlockCipher c = aes_cipher(&aes);
		uint8_t v[32], w[32], iv[16], iv2[16];
		uint8_t pt[32], key[16];
		hexDecode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", pt);
		hexDecode("000102030405060708090a0b0c0d0e0f", iv);
		hexDecode("2b7e151628aed2a6abf7158809cf4f3c", key);
		memcpy(iv2, iv, 16);
		c.generateKeys(&c, key, sizeof key);
		memcpy(v, pt, 32);
		memcpy(w, pt, 32);
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
