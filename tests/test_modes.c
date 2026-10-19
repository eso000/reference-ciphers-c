#include <stdio.h>
#include <string.h>

#include "block/blowfish.h"
#include "block/twofish.h"
#include "block/aes.h"
#include "block/des.h"
#include "block/serpent.h"
#include "testutil.h"

typedef void (*ModeFn)(BlockCipher *, uint8_t *, int, uint8_t *);

static void encECB(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv)
{
	(void)iv;
	cipherEncryptECB(c, plt, len);
}

static void decECB(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv)
{
	(void)iv;
	cipherDecryptECB(c, plt, len);
}

static const char *MODE_NAMES[] = {"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR"};

static ModeFn ENC_FNS[] = {encECB, cipherEncryptCBC, cipherEncryptPCBC,
			   cipherEncryptCFB, cipherEncryptOFB, cipherEncryptCTR};

static ModeFn DEC_FNS[] = {decECB, cipherDecryptCBC, cipherDecryptPCBC,
			   cipherDecryptCFB, cipherDecryptOFB, cipherDecryptCTR};

static void fill(uint8_t *p, int n, int seed)
{
	for (int i = 0; i < n; ++i)
		p[i] = (uint8_t)(seed + i * 7 + 3);
}

static void runModes(const char *label, BlockCipher *c, int bs)
{
	int len = bs * 3;
	for (int m = 0; m < 6; ++m)
	{
		uint8_t v[48], w[48];
		uint8_t iv[16], iv2[16];
		char name[96];

		fill(v, len, m + 1);
		memcpy(w, v, len);
		fill(iv, bs, 0x20 + m);
		memcpy(iv2, iv, bs);

		ENC_FNS[m](c, v, len, iv);
		snprintf(name, sizeof(name), "%s %s ciphertext differs", label, MODE_NAMES[m]);
		CHECK(memcmp(v, w, len) != 0, name);

		DEC_FNS[m](c, v, len, iv2);
		snprintf(name, sizeof(name), "%s %s encrypt+decrypt restores plaintext", label, MODE_NAMES[m]);
		CHECK(memcmp(v, w, len) == 0, name);
	}
}

int main()
{
	printf("== BlockCipher modes: Blowfish (8-byte block) ==\n");
	{
		struct Blowfish bf;
		BlockCipher c = blowfish_cipher(&bf);
		uint8_t key[8];
		hexDecode("AABB09182736CCDD", key);
		c.generateKeys(&c, key, sizeof key);
		runModes("blowfish", &c, 8);
	}

	printf("== BlockCipher modes: Twofish (16-byte block) ==\n");
	{
		struct Twofish tf;
		BlockCipher c = twofish_cipher(&tf);
		uint8_t key[16];
		hexDecode("00000000000000000000000000000000", key);
		c.generateKeys(&c, key, sizeof key);
		runModes("twofish", &c, 16);
	}

	printf("== BlockCipher modes: AES (16-byte block) ==\n");
	{
		struct AES aes;
		BlockCipher c = aes_cipher(&aes);
		uint8_t key[16];
		hexDecode("000102030405060708090a0b0c0d0e0f", key);
		c.generateKeys(&c, key, sizeof key);
		runModes("aes", &c, 16);
	}

	printf("== BlockCipher modes: Serpent (16-byte block) ==\n");
	{
		struct Serpent ser;
		BlockCipher c = serpent_cipher(&ser);
		uint8_t key[32];
		hexDecode("1111111111111111111111111111111111111111111111111111111111111111", key);
		c.generateKeys(&c, key, sizeof key);
		runModes("serpent", &c, 16);
	}

	printf("== BlockCipher modes: DES (8-byte block) ==\n");
	{
		struct DES des;
		BlockCipher c = des_cipher(&des);
		uint8_t key[8];
		hexDecode("AABB09182736CCDD", key);
		c.generateKeys(&c, key, sizeof key);
		runModes("des", &c, 8);
	}

	printf("\n%d test(s) failed\n", g_fails);
	return g_fails ? 1 : 0;
}
