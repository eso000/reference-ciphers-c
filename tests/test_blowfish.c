#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block/blowfish.h"
#include "block/padding.h"
#include "testutil.h"

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
	for (size_t i = 0; i < sizeof KATS / sizeof KATS[0]; ++i)
	{
		struct Blowfish bf;
		BlockCipher c = blowfish_cipher(&bf);
		uint8_t key[8], pt[8], ct[8], v[8];
		hexDecode(KATS[i].key, key);
		c.generateKeys(&c, key, sizeof key);
		hexDecode(KATS[i].plain, pt);
		hexDecode(KATS[i].cipher, ct);
		memcpy(v, pt, 8);
		cipherEncryptECB(&c, v, 8);
		snprintf(name, sizeof(name), "kat ecb %02zu encrypt", i + 1);
		CHECK(memcmp(v, ct, 8) == 0, name);
		cipherDecryptECB(&c, v, 8);
		snprintf(name, sizeof(name), "kat ecb %02zu decrypt", i + 1);
		CHECK(memcmp(v, pt, 8) == 0, name);
	}

	printf("== ECB round trip (two blocks) ==\n");
	{
		struct Blowfish bf;
		BlockCipher c = blowfish_cipher(&bf);
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
		struct Blowfish bf;
		BlockCipher c = blowfish_cipher(&bf);
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
