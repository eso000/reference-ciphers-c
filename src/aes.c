#include <string.h>

#include "block/aes.h"
#include "aes_data.h"
#include "force_inline.h"


FORCE_INLINE uint8_t byte0(uint32_t x) { return (uint8_t)(x >> 24); }
FORCE_INLINE uint8_t byte1(uint32_t x) { return (uint8_t)(x >> 16); }
FORCE_INLINE uint8_t byte2(uint32_t x) { return (uint8_t)(x >> 8); }
FORCE_INLINE uint8_t byte3(uint32_t x) { return (uint8_t)x; }

FORCE_INLINE uint32_t load32_be(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

FORCE_INLINE void store32_be(uint8_t *p, uint32_t w)
{
	p[0] = byte0(w);
	p[1] = byte1(w);
	p[2] = byte2(w);
	p[3] = byte3(w);
}

/* Loads the block into columns and applies the first round key. */
FORCE_INLINE void aes_firstRound(uint32_t cols[4], const uint8_t *p, const uint32_t *rk)
{
	cols[0] = load32_be(p) ^ rk[0];
	cols[1] = load32_be(p + 4) ^ rk[1];
	cols[2] = load32_be(p + 8) ^ rk[2];
	cols[3] = load32_be(p + 12) ^ rk[3];
}

/* SubBytes, ShiftRows, MixColumns and AddRoundKey through the T-tables. */
FORCE_INLINE void aes_round(const uint32_t in[4], uint32_t out[4], const uint32_t *rk)
{
	out[0] = MixRowCol0[byte0(in[0])] ^ MixRowCol1[byte1(in[1])] ^ MixRowCol2[byte2(in[2])] ^ MixRowCol3[byte3(in[3])] ^ rk[0];
	out[1] = MixRowCol0[byte0(in[1])] ^ MixRowCol1[byte1(in[2])] ^ MixRowCol2[byte2(in[3])] ^ MixRowCol3[byte3(in[0])] ^ rk[1];
	out[2] = MixRowCol0[byte0(in[2])] ^ MixRowCol1[byte1(in[3])] ^ MixRowCol2[byte2(in[0])] ^ MixRowCol3[byte3(in[1])] ^ rk[2];
	out[3] = MixRowCol0[byte0(in[3])] ^ MixRowCol1[byte1(in[0])] ^ MixRowCol2[byte2(in[1])] ^ MixRowCol3[byte3(in[2])] ^ rk[3];
}

/* The final round has no MixColumns: SubBytes, ShiftRows and AddRoundKey,
   written straight to the output bytes. */
FORCE_INLINE void aes_lastRound(const uint32_t c[4], uint8_t *p, const uint32_t *rk)
{
	p[ 0] = SBoxes[byte0(c[0])] ^ byte0(rk[0]);
	p[ 1] = SBoxes[byte1(c[1])] ^ byte1(rk[0]);
	p[ 2] = SBoxes[byte2(c[2])] ^ byte2(rk[0]);
	p[ 3] = SBoxes[byte3(c[3])] ^ byte3(rk[0]);
	p[ 4] = SBoxes[byte0(c[1])] ^ byte0(rk[1]);
	p[ 5] = SBoxes[byte1(c[2])] ^ byte1(rk[1]);
	p[ 6] = SBoxes[byte2(c[3])] ^ byte2(rk[1]);
	p[ 7] = SBoxes[byte3(c[0])] ^ byte3(rk[1]);
	p[ 8] = SBoxes[byte0(c[2])] ^ byte0(rk[2]);
	p[ 9] = SBoxes[byte1(c[3])] ^ byte1(rk[2]);
	p[10] = SBoxes[byte2(c[0])] ^ byte2(rk[2]);
	p[11] = SBoxes[byte3(c[1])] ^ byte3(rk[2]);
	p[12] = SBoxes[byte0(c[3])] ^ byte0(rk[3]);
	p[13] = SBoxes[byte1(c[0])] ^ byte1(rk[3]);
	p[14] = SBoxes[byte2(c[1])] ^ byte2(rk[3]);
	p[15] = SBoxes[byte3(c[2])] ^ byte3(rk[3]);
}

/* The last decryption step: AddRoundKey and store. */
FORCE_INLINE void aes_lastInvRound(const uint32_t c[4], uint8_t *p, const uint32_t *rk)
{
	store32_be(p, c[0] ^ rk[0]);
	store32_be(p + 4, c[1] ^ rk[1]);
	store32_be(p + 8, c[2] ^ rk[2]);
	store32_be(p + 12, c[3] ^ rk[3]);
}

FORCE_INLINE void aes_invMixColumns(const uint32_t in[4], uint32_t out[4])
{
	for (int j = 0; j < 4; ++j)
		out[j] = invMixRowCol0[byte0(in[j])] ^ invMixRowCol1[byte1(in[j])] ^ invMixRowCol2[byte2(in[j])] ^ invMixRowCol3[byte3(in[j])];
}

FORCE_INLINE void aes_invShiftRowsSubBytes(const uint32_t in[4], uint32_t out[4])
{
	out[0] = ((uint32_t)InvSBoxes[byte0(in[0])] << 24) | ((uint32_t)InvSBoxes[byte1(in[3])] << 16) | ((uint32_t)InvSBoxes[byte2(in[2])] << 8) | InvSBoxes[byte3(in[1])];
	out[1] = ((uint32_t)InvSBoxes[byte0(in[1])] << 24) | ((uint32_t)InvSBoxes[byte1(in[0])] << 16) | ((uint32_t)InvSBoxes[byte2(in[3])] << 8) | InvSBoxes[byte3(in[2])];
	out[2] = ((uint32_t)InvSBoxes[byte0(in[2])] << 24) | ((uint32_t)InvSBoxes[byte1(in[1])] << 16) | ((uint32_t)InvSBoxes[byte2(in[0])] << 8) | InvSBoxes[byte3(in[3])];
	out[3] = ((uint32_t)InvSBoxes[byte0(in[3])] << 24) | ((uint32_t)InvSBoxes[byte1(in[2])] << 16) | ((uint32_t)InvSBoxes[byte2(in[1])] << 8) | InvSBoxes[byte3(in[0])];
}

/* One inverse round, in place on cols: AddRoundKey, InvMixColumns, then
   InvShiftRows and InvSubBytes. tmp is scratch. */
FORCE_INLINE void aes_invRound(uint32_t cols[4], uint32_t tmp[4], const uint32_t *rk)
{
	cols[0] ^= rk[0];
	cols[1] ^= rk[1];
	cols[2] ^= rk[2];
	cols[3] ^= rk[3];
	aes_invMixColumns(cols, tmp);
	aes_invShiftRowsSubBytes(tmp, cols);
}

static uint8_t aes_hexNibble(char c)
{
	if (c >= '0' && c <= '9')
		return (uint8_t)(c - '0');
	if (c >= 'a' && c <= 'f')
		return (uint8_t)(c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (uint8_t)(c - 'A' + 10);
	return 0;
}

/* AES accepts a 128, 192 or 256-bit key. The key arrives as a hex string, so
   that is 32, 48 or 64 characters. Anything else used to be silently padded
   with '0' up to the next size, which turned a 33-character key into a valid
   AES-192 key with a '0' the caller never wrote. */
static int aes_key_ok(size_t len)
{
	return len == 32 || len == 48 || len == 64;
}

struct AES aes_generateKeys(char* key)
{
	struct AES a;
	char kbuf[65];
	int klen = (int)strlen(key);
	if (!aes_key_ok((size_t)klen))
	{
		memset(&a, 0, sizeof(a));
		return a;
	}
	memcpy(kbuf, key, (size_t)klen);
	kbuf[klen] = '\0';

	int N = klen / 8;
	int R = 1;
	if (N == 4)
		R = 11;
	if (N == 6)
		R = 13;
	if (N == 8)
		R = 15;

	uint8_t W[60][4];
	for (int i = 0; i < klen; i = i + 8)
		for (int j = 0; j < 4; ++j)
			W[i / 8][j] = (uint8_t)((aes_hexNibble(kbuf[i + 2*j]) << 4) | aes_hexNibble(kbuf[i + 2*j + 1]));

	uint8_t rcon[4] = {1, 0, 0, 0};
	uint8_t temp[4];
	for (int x = N; x < 4 * R; ++x)
	{
		memcpy(temp, W[x - 1], 4);
		if (x % N == 0)
		{
			if (x - N > 0)
			{
				if (rcon[0] < 128)
					rcon[0] = (uint8_t)(2 * rcon[0]);
				else
					rcon[0] = (uint8_t)(((2 * rcon[0]) ^ 0x11B) % 256);
			}
			uint8_t t = temp[0];
			temp[0] = temp[1];
			temp[1] = temp[2];
			temp[2] = temp[3];
			temp[3] = t;
			for (int j = 0; j < 4; ++j)
				temp[j] = SBoxes[temp[j]];
			for (int j = 0; j < 4; ++j)
				temp[j] ^= rcon[j];
			for (int j = 0; j < 4; ++j)
				temp[j] ^= W[x - N][j];
			memcpy(W[x], temp, 4);
		}
		else if (N > 6 && x % N == 4)
		{
			for (int j = 0; j < 4; ++j)
				temp[j] = SBoxes[temp[j]];
			for (int j = 0; j < 4; ++j)
				temp[j] ^= W[x - N][j];
			memcpy(W[x], temp, 4);
		}
		else
		{
			for (int j = 0; j < 4; ++j)
				temp[j] ^= W[x - N][j];
			memcpy(W[x], temp, 4);
		}
	}
	for (int i = 0; i < 4 * R; ++i)
		a.Subkeys[i] = ((uint32_t)W[i][0] << 24) | ((uint32_t)W[i][1] << 16) | ((uint32_t)W[i][2] << 8) | W[i][3];
	a.nKeys = 4 * R;
	return a;
}

static void aes_encrypt_block128(uint8_t *p, const struct AES *a)
{
	uint32_t columnA[4];
	uint32_t columnB[4];

	aes_firstRound(columnA, p, &a->Subkeys[0]);
	aes_round(columnA, columnB, &a->Subkeys[4]);
	aes_round(columnB, columnA, &a->Subkeys[8]);
	aes_round(columnA, columnB, &a->Subkeys[12]);
	aes_round(columnB, columnA, &a->Subkeys[16]);
	aes_round(columnA, columnB, &a->Subkeys[20]);
	aes_round(columnB, columnA, &a->Subkeys[24]);
	aes_round(columnA, columnB, &a->Subkeys[28]);
	aes_round(columnB, columnA, &a->Subkeys[32]);
	aes_round(columnA, columnB, &a->Subkeys[36]);

	aes_lastRound(columnB, p, &a->Subkeys[40]);
}

static void aes_encrypt_block192(uint8_t *p, const struct AES *a)
{
	uint32_t columnA[4];
	uint32_t columnB[4];

	aes_firstRound(columnA, p, &a->Subkeys[0]);
	aes_round(columnA, columnB, &a->Subkeys[4]);
	aes_round(columnB, columnA, &a->Subkeys[8]);
	aes_round(columnA, columnB, &a->Subkeys[12]);
	aes_round(columnB, columnA, &a->Subkeys[16]);
	aes_round(columnA, columnB, &a->Subkeys[20]);
	aes_round(columnB, columnA, &a->Subkeys[24]);
	aes_round(columnA, columnB, &a->Subkeys[28]);
	aes_round(columnB, columnA, &a->Subkeys[32]);
	aes_round(columnA, columnB, &a->Subkeys[36]);
	aes_round(columnB, columnA, &a->Subkeys[40]);
	aes_round(columnA, columnB, &a->Subkeys[44]);

	aes_lastRound(columnB, p, &a->Subkeys[48]);
}

static void aes_encrypt_block256(uint8_t *p, const struct AES *a)
{
	uint32_t columnA[4];
	uint32_t columnB[4];

	aes_firstRound(columnA, p, &a->Subkeys[0]);
	aes_round(columnA, columnB, &a->Subkeys[4]);
	aes_round(columnB, columnA, &a->Subkeys[8]);
	aes_round(columnA, columnB, &a->Subkeys[12]);
	aes_round(columnB, columnA, &a->Subkeys[16]);
	aes_round(columnA, columnB, &a->Subkeys[20]);
	aes_round(columnB, columnA, &a->Subkeys[24]);
	aes_round(columnA, columnB, &a->Subkeys[28]);
	aes_round(columnB, columnA, &a->Subkeys[32]);
	aes_round(columnA, columnB, &a->Subkeys[36]);
	aes_round(columnB, columnA, &a->Subkeys[40]);
	aes_round(columnA, columnB, &a->Subkeys[44]);
	aes_round(columnB, columnA, &a->Subkeys[48]);
	aes_round(columnA, columnB, &a->Subkeys[52]);

	aes_lastRound(columnB, p, &a->Subkeys[56]);
}

static void aes_decrypt_block128(uint8_t *p, const struct AES *a)
{
	uint32_t columnA[4];
	uint32_t columnB[4];

	aes_firstRound(columnB, p, &a->Subkeys[40]);
	aes_invShiftRowsSubBytes(columnB, columnA);

	aes_invRound(columnA, columnB, &a->Subkeys[36]);
	aes_invRound(columnA, columnB, &a->Subkeys[32]);
	aes_invRound(columnA, columnB, &a->Subkeys[28]);
	aes_invRound(columnA, columnB, &a->Subkeys[24]);
	aes_invRound(columnA, columnB, &a->Subkeys[20]);
	aes_invRound(columnA, columnB, &a->Subkeys[16]);
	aes_invRound(columnA, columnB, &a->Subkeys[12]);
	aes_invRound(columnA, columnB, &a->Subkeys[8]);
	aes_invRound(columnA, columnB, &a->Subkeys[4]);

	aes_lastInvRound(columnA, p, &a->Subkeys[0]);
}

static void aes_decrypt_block192(uint8_t *p, const struct AES *a)
{
	uint32_t columnA[4];
	uint32_t columnB[4];

	aes_firstRound(columnB, p, &a->Subkeys[48]);
	aes_invShiftRowsSubBytes(columnB, columnA);

	aes_invRound(columnA, columnB, &a->Subkeys[44]);
	aes_invRound(columnA, columnB, &a->Subkeys[40]);
	aes_invRound(columnA, columnB, &a->Subkeys[36]);
	aes_invRound(columnA, columnB, &a->Subkeys[32]);
	aes_invRound(columnA, columnB, &a->Subkeys[28]);
	aes_invRound(columnA, columnB, &a->Subkeys[24]);
	aes_invRound(columnA, columnB, &a->Subkeys[20]);
	aes_invRound(columnA, columnB, &a->Subkeys[16]);
	aes_invRound(columnA, columnB, &a->Subkeys[12]);
	aes_invRound(columnA, columnB, &a->Subkeys[8]);
	aes_invRound(columnA, columnB, &a->Subkeys[4]);

	aes_lastInvRound(columnA, p, &a->Subkeys[0]);
}

static void aes_decrypt_block256(uint8_t *p, const struct AES *a)
{
	uint32_t columnA[4];
	uint32_t columnB[4];

	aes_firstRound(columnB, p, &a->Subkeys[56]);
	aes_invShiftRowsSubBytes(columnB, columnA);

	aes_invRound(columnA, columnB, &a->Subkeys[52]);
	aes_invRound(columnA, columnB, &a->Subkeys[48]);
	aes_invRound(columnA, columnB, &a->Subkeys[44]);
	aes_invRound(columnA, columnB, &a->Subkeys[40]);
	aes_invRound(columnA, columnB, &a->Subkeys[36]);
	aes_invRound(columnA, columnB, &a->Subkeys[32]);
	aes_invRound(columnA, columnB, &a->Subkeys[28]);
	aes_invRound(columnA, columnB, &a->Subkeys[24]);
	aes_invRound(columnA, columnB, &a->Subkeys[20]);
	aes_invRound(columnA, columnB, &a->Subkeys[16]);
	aes_invRound(columnA, columnB, &a->Subkeys[12]);
	aes_invRound(columnA, columnB, &a->Subkeys[8]);
	aes_invRound(columnA, columnB, &a->Subkeys[4]);

	aes_lastInvRound(columnA, p, &a->Subkeys[0]);
}

void aes_encrypt_block(uint8_t *p, const struct AES *a)
{
	switch (a->nKeys)
	{
		case 60: aes_encrypt_block256(p, a); break;
		case 52: aes_encrypt_block192(p, a); break;
		case 44: aes_encrypt_block128(p, a); break;
	}
}

void aes_decrypt_block(uint8_t *p, const struct AES *a)
{
	switch (a->nKeys)
	{
		case 60: aes_decrypt_block256(p, a); break;
		case 52: aes_decrypt_block192(p, a); break;
		case 44: aes_decrypt_block128(p, a); break;
	}
}

int aes_generateKeysSelf(BlockCipher *self, char *key)
{
	struct AES *a = self->cipherState;
	if (!aes_key_ok(strlen(key)))
	{
		memset(a, 0, sizeof(*a));
		return 0;
	}
	*a = aes_generateKeys(key);
	return 1;
}

void aes_encryptBlock(BlockCipher *self, uint8_t *block)
{
	aes_encrypt_block(block, self->cipherState);
}

void aes_decryptBlock(BlockCipher *self, uint8_t *block)
{
	aes_decrypt_block(block, self->cipherState);
}

BlockCipher aes_cipher(void *state)
{
	BlockCipher c;
	c.blockSize = 16;
	c.cipherState = state;
	c.generateKeys = aes_generateKeysSelf;
	c.encryptBlock = aes_encryptBlock;
	c.decryptBlock = aes_decryptBlock;
	return c;
}
