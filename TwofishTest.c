#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Twofish.h"
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
	{"00000000000000000000000000000000",
	 "00000000000000000000000000000000", "9f589f5cf6122c32b6bfec2f2ae8c35a"},
	{"00000000000000000000000000000000",
	 "9f589f5cf6122c32b6bfec2f2ae8c35a", "d491db16e7b1c39e86cb086b789f5419"},
	{"9f589f5cf6122c32b6bfec2f2ae8c35a",
	 "d491db16e7b1c39e86cb086b789f5419", "019f9809de1711858faac3a3ba20fbc3"},
	{"88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44",
	 "39DA69D6BA4997D585B6DC073CA341B2", "182b02d81497ea45f9daacdc29193a65"},
	{"D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F",
	 "90AFE91BB288544F2C32DC239B2635E6", "6cb4561c40bf0a9705931cb6d408e7fa"},
};

int main()
{
	char name[96];

	printf("== Twofish known-answer tests ==\n");
	for (int i = 0; i < 5; ++i)
	{
		char key[128];
		uint8_t pt[16], ct[16], v[16];
		strcpy(key, KATS[i].key);
		struct Twofish c = twofish_generateKeys(key);
		hexDecode(KATS[i].plain, pt);
		hexDecode(KATS[i].cipher, ct);
		memcpy(v, pt, 16);
		twofish_encryptECB(v, 16, c);
		snprintf(name, sizeof(name), "kat %02d encrypt", i + 1);
		CHECK(memcmp(v, ct, 16) == 0, name);
		twofish_decryptECB(v, 16, c);
		snprintf(name, sizeof(name), "kat %02d decrypt", i + 1);
		CHECK(memcmp(v, pt, 16) == 0, name);
	}

	printf("== ECB round trip (two blocks) ==\n");
	{
		char k1[128], k2[128];
		strcpy(k1, "88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44");
		strcpy(k2, "88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44");
		struct Twofish c = twofish_generateKeys(k1);
		struct Twofish d = twofish_generateKeys(k2);
		uint8_t v[32], w[32];
		hexDecode("39DA69D6BA4997D585B6DC073CA341B2"
			  "9F589F5CF6122C32B6BFEC2F2AE8C35A", v);
		memcpy(w, v, 32);
		twofish_encryptECB(v, 32, c);
		CHECK(memcmp(v, w, 32) != 0, "ecb ciphertext differs from plaintext");
		twofish_decryptECB(v, 32, d);
		CHECK(memcmp(v, w, 32) == 0, "ecb encrypt+decrypt restores plaintext");
	}

	printf("== CBC round trip ==\n");
	{
		char k1[128], k2[128];
		strcpy(k1, "00000000000000000000000000000000");
		strcpy(k2, "00000000000000000000000000000000");
		struct Twofish c = twofish_generateKeys(k1);
		struct Twofish d = twofish_generateKeys(k2);
		uint8_t v[32], w[32];
		uint8_t iv[16] = {0}, iv2[16] = {0};
		memset(v, 0, 32);
		memcpy(w, v, 32);
		twofish_encryptCBC(v, 32, iv, c);
		CHECK(memcmp(v, w, 32) != 0, "cbc ciphertext differs from plaintext");
		twofish_decryptCBC(v, 32, iv2, d);
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
