#include <stdio.h>
#include <string.h>

#include "Blowfish.h"
#include "Twofish.h"
#include "AES.h"
#include "DES.h"
#include "Serpent.h"

static int g_fails = 0;

#define CHECK(cond, name) { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s\n", name); ++g_fails; } }

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
		c.generateKeys(&c, "AABB09182736CCDD");
		runModes("blowfish", &c, 8);
	}

	printf("== BlockCipher modes: Twofish (16-byte block) ==\n");
	{
		struct Twofish tf;
		BlockCipher c = twofish_cipher(&tf);
		c.generateKeys(&c, "00000000000000000000000000000000");
		runModes("twofish", &c, 16);
	}

	printf("== BlockCipher modes: AES (16-byte block) ==\n");
	{
		struct AES aes;
		BlockCipher c = aes_cipher(&aes);
		c.generateKeys(&c, "000102030405060708090a0b0c0d0e0f");
		runModes("aes", &c, 16);
	}

	printf("== BlockCipher modes: Serpent (16-byte block) ==\n");
	{
		struct Serpent ser;
		BlockCipher c = serpent_cipher(&ser);
		c.generateKeys(&c, "1111111111111111111111111111111111111111111111111111111111111111");
		runModes("serpent", &c, 16);
	}

	printf("== BlockCipher modes: DES (8-byte block) ==\n");
	{
		struct DES des;
		BlockCipher c = des_cipher(&des);
		c.generateKeys(&c, "AABB09182736CCDD");
		runModes("des", &c, 8);
	}

	printf("\n%d test(s) failed\n", g_fails);
	return g_fails ? 1 : 0;
}
