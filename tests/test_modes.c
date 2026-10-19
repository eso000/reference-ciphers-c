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

/* Published mode vectors, plus the ones with no published source.

   CFB128, OFB and CTR are NIST SP 800-38A Appendix F.5 for AES-128: the
   standard's own four-block plaintext, IV, initial counter block and
   ciphertext. AES PCBC and the CBC vectors for DES, Blowfish, Twofish and
   Serpent are not published anywhere as four-block vectors of this shape, so
   they were produced by the Python reference (refciphers) and pasted here;
   AES, DES and Blowfish agree byte for byte with OpenSSL 3.5.9, and the block
   ciphers underneath are themselves pinned by published known-answer tests in
   the other test files, so an error here would have to be in the chaining
   construction that both implementations share. PCBC appears in no standard
   at all -- it survives from Kerberos v4 -- which is why the reference
   implementation is its only source. */

#define SP800_PT \
	"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" \
	"30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"

struct ModeKat
{
	const char *cipher;
	int mode;
	const char *key;
	const char *iv;
	const char *ciphertext;
};

static const struct ModeKat MODE_KATS[] = {
	/* NIST SP 800-38A F.5.3 (CFB128), F.5.4 (OFB), F.5.5 (CTR). */
	{"AES", 3, "2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f",
	 "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
	 "26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6"},
	{"AES", 4, "2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f",
	 "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825"
	 "9740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e"},
	{"AES", 5, "2b7e151628aed2a6abf7158809cf4f3c", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
	 "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
	 "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"},
	/* Everything below has no published source; see the note above. */
	{"AES", 2, "2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f",
	 "7649abac8119b246cee98e9b12e9197d9e8baff12ad5270a0d1eef93d7037994"
	 "5700b39803779fa35a3c600a49a163c033ae199f27379f21be6dd57d295cc87d"},
	{"DES", 1, "133457799BBCDFF1", "0001020304050607",
	 "6a5e353e352bc97e6d7c4bb68aa19d1f79bf99793747c4f7af2484db827079f2"
	 "2db456cf833a3f24b9d1e2a28e537912ce02e80da933e5805cb22379c062eb79"},
	{"Blowfish", 1, "F0E1D2C3B4A5968778695A4B3C2D1E0F", "0001020304050607",
	 "63d2145dcf40bf6ee087f8de4ecbd46d499cc11ebd4c8823f630961a983c9b86"
	 "af024b44c97ac2dac77495f230413e5da154da31d648a9f846684e9072058653"},
	{"Twofish", 1, "000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f",
	 "5b7b3760f13bc88e7552d46a3f418a9571f7ebc3ad64f30d0c3efac19e8886bf"
	 "38c7a6f2f89183ce32c004d2c8c21ab6a2b49be81f1b3f18df9ea5189b180b29"},
	{"Serpent", 1, "000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f",
	 "ad76e539087af6e6b9bcb97f94ecd55289c48f391da6de03951b9c1972f3f074"
	 "a7c8ba35e05e82db025965912d3debddd33847a6669115491ed6655983bad089"},
};

/* Each cipher is a constructor over a differently sized state struct, so the
   runner keeps one union big enough for all of them and picks the
   constructor by name. Choosing by name keeps the table above readable and
   lets a vector list its cipher the way a reader would say it. */
union State
{
	struct AES aes;
	struct DES des;
	struct Blowfish bf;
	struct Serpent ser;
	struct Twofish tf;
};

struct CipherDef
{
	const char *name;
	BlockCipher (*ctor)(void *);
	int blockSize;
};

static const struct CipherDef CIPHER_DEFS[] = {
	{"AES", aes_cipher, 16},
	{"DES", des_cipher, 8},
	{"Blowfish", blowfish_cipher, 8},
	{"Serpent", serpent_cipher, 16},
	{"Twofish", twofish_cipher, 16},
};

/* Run one four-block vector both ways. The published ciphertext is what gets
   decrypted, not our own output, so a matched pair of wrong encrypt and
   decrypt cannot pass. */
static void runModeKat(const struct ModeKat *k)
{
	char name[128];
	union State st;
	const struct CipherDef *def = NULL;

	for (size_t i = 0; i < sizeof CIPHER_DEFS / sizeof CIPHER_DEFS[0]; ++i)
		if (strcmp(CIPHER_DEFS[i].name, k->cipher) == 0)
			def = &CIPHER_DEFS[i];

	if (def == NULL)
	{
		snprintf(name, sizeof(name), "mode kat names a known cipher (%s)", k->cipher);
		CHECK(0, name);
		return;
	}

	uint8_t key[32], pt[64], ct[64], v[64], iv[16], iv2[16];

	hexDecode(k->key, key);
	hexDecode(SP800_PT, pt);
	hexDecode(k->ciphertext, ct);
	hexDecode(k->iv, iv);
	memcpy(iv2, iv, def->blockSize);

	BlockCipher c = def->ctor(&st);
	c.generateKeys(&c, key, hexLen(k->key));

	memcpy(v, pt, 64);
	ENC_FNS[k->mode](&c, v, 64, iv);
	snprintf(name, sizeof(name), "%s %s four-block encrypt", k->cipher, MODE_NAMES[k->mode]);
	CHECK(memcmp(v, ct, 64) == 0, name);

	/* The decrypt functions advance the IV they are handed, so they get the
	   fresh copy. */
	memcpy(v, ct, 64);
	DEC_FNS[k->mode](&c, v, 64, iv2);
	snprintf(name, sizeof(name), "%s %s four-block decrypt", k->cipher, MODE_NAMES[k->mode]);
	CHECK(memcmp(v, pt, 64) == 0, name);
}

static void fill(uint8_t *p, int n, int seed)
{
	for (int i = 0; i < n; ++i)
		p[i] = (uint8_t)(seed + i * 7 + 3);
}

static void runModes(const char *label, BlockCipher *c, int bs)
{
	int len = bs * 3;
	for (size_t m = 0; m < sizeof MODE_NAMES / sizeof MODE_NAMES[0]; ++m)
	{
		uint8_t v[48], w[48];
		uint8_t iv[16], iv2[16];
		char name[96];

		fill(v, len, (int)m + 1);
		memcpy(w, v, len);
		fill(iv, bs, 0x20 + (int)m);
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
	printf("== BlockCipher mode known-answer tests ==\n");
	for (size_t i = 0; i < sizeof MODE_KATS / sizeof MODE_KATS[0]; ++i)
		runModeKat(&MODE_KATS[i]);

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
