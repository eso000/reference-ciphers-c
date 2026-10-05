#include <string.h>

#include "block/aes.h"
#include "aes_data.h"


#define byte0(x) ((uint8_t)((x) >> 24))
#define byte1(x) ((uint8_t)((x) >> 16))
#define byte2(x) ((uint8_t)((x) >> 8))
#define byte3(x) ((uint8_t)(x))

#define SB(id) SBoxes[(id)]

#define firstround(cols, p1, k) cols[0] = (((uint32_t)*(p1)<<24)|((uint32_t)*(p1+1)<<16)|((uint32_t)*(p1+2)<<8)|(uint32_t)*(p1+3)) ^ a->Subkeys[k + 0];\
			cols[1] = (((uint32_t)*(p1+4)<<24)|((uint32_t)*(p1+5)<<16)|((uint32_t)*(p1+6)<<8)|(uint32_t)*(p1+7)) ^ a->Subkeys[k + 1];\
			cols[2] = (((uint32_t)*(p1+8)<<24)|((uint32_t)*(p1+9)<<16)|((uint32_t)*(p1+10)<<8)|(uint32_t)*(p1+11)) ^ a->Subkeys[k + 2];\
			cols[3] = (((uint32_t)*(p1+12)<<24)|((uint32_t)*(p1+13)<<16)|((uint32_t)*(p1+14)<<8)|(uint32_t)*(p1+15)) ^ a->Subkeys[k + 3];

#define lastround(cols, p1, i) *(p1) = SB(byte0(cols[0])) ^ (uint8_t)(a->Subkeys[i]>>24);\
		*(p1+ 1) = SB(byte1(cols[1])) ^ (uint8_t)(a->Subkeys[i]>>16);\
		*(p1+ 2) = SB(byte2(cols[2])) ^ (uint8_t)(a->Subkeys[i]>>8);\
		*(p1+ 3) = SB(byte3(cols[3])) ^ (uint8_t)a->Subkeys[i];\
		*(p1+ 4) = SB(byte0(cols[1])) ^ (uint8_t)(a->Subkeys[i+1]>>24);\
		*(p1+ 5) = SB(byte1(cols[2])) ^ (uint8_t)(a->Subkeys[i+1]>>16);\
		*(p1+ 6) = SB(byte2(cols[3])) ^ (uint8_t)(a->Subkeys[i+1]>>8);\
		*(p1+ 7) = SB(byte3(cols[0])) ^ (uint8_t)a->Subkeys[i+1];\
		*(p1+ 8) = SB(byte0(cols[2])) ^ (uint8_t)(a->Subkeys[i+2]>>24);\
		*(p1+ 9) = SB(byte1(cols[3])) ^ (uint8_t)(a->Subkeys[i+2]>>16);\
		*(p1+10) = SB(byte2(cols[0])) ^ (uint8_t)(a->Subkeys[i+2]>>8);\
		*(p1+11) = SB(byte3(cols[1])) ^ (uint8_t)a->Subkeys[i+2];\
		*(p1+12) = SB(byte0(cols[3])) ^ (uint8_t)(a->Subkeys[i+3]>>24);\
		*(p1+13) = SB(byte1(cols[0])) ^ (uint8_t)(a->Subkeys[i+3]>>16);\
		*(p1+14) = SB(byte2(cols[1])) ^ (uint8_t)(a->Subkeys[i+3]>>8);\
		*(p1+15) = SB(byte3(cols[2])) ^ (uint8_t)a->Subkeys[i+3];

#define lastInvround(cols, p1, i) *(p1) = (byte0(cols[0])) ^ (uint8_t)(a->Subkeys[i]>>24);\
		*(p1+ 1) = (byte1(cols[0])) ^ (uint8_t)(a->Subkeys[i]>>16);\
		*(p1+ 2) = (byte2(cols[0])) ^ (uint8_t)(a->Subkeys[i]>>8);\
		*(p1+ 3) = (byte3(cols[0])) ^ (uint8_t)a->Subkeys[i];\
		*(p1+ 4) = (byte0(cols[1])) ^ (uint8_t)(a->Subkeys[i+1]>>24);\
		*(p1+ 5) = (byte1(cols[1])) ^ (uint8_t)(a->Subkeys[i+1]>>16);\
		*(p1+ 6) = (byte2(cols[1])) ^ (uint8_t)(a->Subkeys[i+1]>>8);\
		*(p1+ 7) = (byte3(cols[1])) ^ (uint8_t)a->Subkeys[i+1];\
		*(p1+ 8) = (byte0(cols[2])) ^ (uint8_t)(a->Subkeys[i+2]>>24);\
		*(p1+ 9) = (byte1(cols[2])) ^ (uint8_t)(a->Subkeys[i+2]>>16);\
		*(p1+10) = (byte2(cols[2])) ^ (uint8_t)(a->Subkeys[i+2]>>8);\
		*(p1+11) = (byte3(cols[2])) ^ (uint8_t)a->Subkeys[i+2];\
		*(p1+12) = (byte0(cols[3])) ^ (uint8_t)(a->Subkeys[i+3]>>24);\
		*(p1+13) = (byte1(cols[3])) ^ (uint8_t)(a->Subkeys[i+3]>>16);\
		*(p1+14) = (byte2(cols[3])) ^ (uint8_t)(a->Subkeys[i+3]>>8);\
		*(p1+15) = (byte3(cols[3])) ^ (uint8_t)a->Subkeys[i+3];

#define invMixRows(coln1, coln2) coln2[0] = invMixRowCol0[byte0(coln1[0])]^invMixRowCol1[byte1(coln1[0])]^invMixRowCol2[byte2(coln1[0])]^invMixRowCol3[byte3(coln1[0])];\
			coln2[1] = invMixRowCol0[byte0(coln1[1])]^invMixRowCol1[byte1(coln1[1])]^invMixRowCol2[byte2(coln1[1])]^invMixRowCol3[byte3(coln1[1])];\
			coln2[2] = invMixRowCol0[byte0(coln1[2])]^invMixRowCol1[byte1(coln1[2])]^invMixRowCol2[byte2(coln1[2])]^invMixRowCol3[byte3(coln1[2])];\
			coln2[3] = invMixRowCol0[byte0(coln1[3])]^invMixRowCol1[byte1(coln1[3])]^invMixRowCol2[byte2(coln1[3])]^invMixRowCol3[byte3(coln1[3])];

#define invShiftRowsSB(cols1, cols2) cols2[0] = ((uint32_t)InvSBoxes[byte0(cols1[0])]<<24)|((uint32_t)InvSBoxes[byte1(cols1[3])]<<16)|((uint32_t)InvSBoxes[byte2(cols1[2])]<<8)|InvSBoxes[byte3(cols1[1])];\
			cols2[1] = ((uint32_t)InvSBoxes[byte0(cols1[1])]<<24)|((uint32_t)InvSBoxes[byte1(cols1[0])]<<16)|((uint32_t)InvSBoxes[byte2(cols1[3])]<<8)|InvSBoxes[byte3(cols1[2])];\
			cols2[2] = ((uint32_t)InvSBoxes[byte0(cols1[2])]<<24)|((uint32_t)InvSBoxes[byte1(cols1[1])]<<16)|((uint32_t)InvSBoxes[byte2(cols1[0])]<<8)|InvSBoxes[byte3(cols1[3])];\
			cols2[3] = ((uint32_t)InvSBoxes[byte0(cols1[3])]<<24)|((uint32_t)InvSBoxes[byte1(cols1[2])]<<16)|((uint32_t)InvSBoxes[byte2(cols1[1])]<<8)|InvSBoxes[byte3(cols1[0])];

#define round(col1, col2, i) col2[0] = MixRowCol0[byte0(col1[0])]^MixRowCol1[byte1(col1[1])]^MixRowCol2[byte2(col1[2])]^MixRowCol3[byte3(col1[3])]^a->Subkeys[4*i];\
			col2[1] = MixRowCol0[byte0(col1[1])]^MixRowCol1[byte1(col1[2])]^MixRowCol2[byte2(col1[3])]^MixRowCol3[byte3(col1[0])]^a->Subkeys[4*i+1];\
			col2[2] = MixRowCol0[byte0(col1[2])]^MixRowCol1[byte1(col1[3])]^MixRowCol2[byte2(col1[0])]^MixRowCol3[byte3(col1[1])]^a->Subkeys[4*i+2];\
			col2[3] = MixRowCol0[byte0(col1[3])]^MixRowCol1[byte1(col1[0])]^MixRowCol2[byte2(col1[1])]^MixRowCol3[byte3(col1[2])]^a->Subkeys[4*i+3];

#define invround(col1, col2, i) col1[0] ^= a->Subkeys[4*i]; col1[1] ^= a->Subkeys[4*i+1];\
			col1[2] ^= a->Subkeys[4*i+2]; col1[3] ^= a->Subkeys[4*i+3];\
			invMixRows(col1, col2)\
			invShiftRowsSB(col2, col1)

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

	firstround(columnA, p, 0)
	round(columnA,columnB,1)
	round(columnB,columnA,2)
	round(columnA,columnB,3)
	round(columnB,columnA,4)
	round(columnA,columnB,5)
	round(columnB,columnA,6)
	round(columnA,columnB,7)
	round(columnB,columnA,8)
	round(columnA,columnB,9)

	lastround(columnB, p, 40)
}

static void aes_encrypt_block192(uint8_t *p, const struct AES *a)
{
	uint32_t columnA[4];
	uint32_t columnB[4];

	firstround(columnA, p, 0)
	round(columnA,columnB, 1)
	round(columnB,columnA, 2)
	round(columnA,columnB, 3)
	round(columnB,columnA, 4)
	round(columnA,columnB, 5)
	round(columnB,columnA, 6)
	round(columnA,columnB, 7)
	round(columnB,columnA, 8)
	round(columnA,columnB, 9)
	round(columnB,columnA,10)
	round(columnA,columnB,11)

	lastround(columnB, p, 48)
}

static void aes_encrypt_block256(uint8_t *p, const struct AES *a)
{
	uint32_t columnA[4];
	uint32_t columnB[4];

	firstround(columnA, p, 0)
	round(columnA,columnB, 1)
	round(columnB,columnA, 2)
	round(columnA,columnB, 3)
	round(columnB,columnA, 4)
	round(columnA,columnB, 5)
	round(columnB,columnA, 6)
	round(columnA,columnB, 7)
	round(columnB,columnA, 8)
	round(columnA,columnB, 9)
	round(columnB,columnA,10)
	round(columnA,columnB,11)
	round(columnB,columnA,12)
	round(columnA,columnB,13)

	lastround(columnB, p, 56)
}

static void aes_decrypt_block128(uint8_t *p, const struct AES *a)
{
	uint32_t columnA[4];
	uint32_t columnB[4];

	firstround(columnB, p, 40)
	invShiftRowsSB(columnB, columnA)

	invround(columnA,columnB, 9)
	invround(columnA,columnB, 8)
	invround(columnA,columnB, 7)
	invround(columnA,columnB, 6)
	invround(columnA,columnB, 5)
	invround(columnA,columnB, 4)
	invround(columnA,columnB, 3)
	invround(columnA,columnB, 2)
	invround(columnA,columnB, 1)

	lastInvround(columnA, p, 0)
}

static void aes_decrypt_block192(uint8_t *p, const struct AES *a)
{
	uint32_t columnA[4];
	uint32_t columnB[4];

	firstround(columnB, p, 48)
	invShiftRowsSB(columnB, columnA)

	invround(columnA,columnB,11)
	invround(columnA,columnB,10)
	invround(columnA,columnB, 9)
	invround(columnA,columnB, 8)
	invround(columnA,columnB, 7)
	invround(columnA,columnB, 6)
	invround(columnA,columnB, 5)
	invround(columnA,columnB, 4)
	invround(columnA,columnB, 3)
	invround(columnA,columnB, 2)
	invround(columnA,columnB, 1)

	lastInvround(columnA, p, 0)
}

static void aes_decrypt_block256(uint8_t *p, const struct AES *a)
{
	uint32_t columnA[4];
	uint32_t columnB[4];

	firstround(columnB, p, 56)
	invShiftRowsSB(columnB, columnA)

	invround(columnA,columnB,13)
	invround(columnA,columnB,12)
	invround(columnA,columnB,11)
	invround(columnA,columnB,10)
	invround(columnA,columnB, 9)
	invround(columnA,columnB, 8)
	invround(columnA,columnB, 7)
	invround(columnA,columnB, 6)
	invround(columnA,columnB, 5)
	invround(columnA,columnB, 4)
	invround(columnA,columnB, 3)
	invround(columnA,columnB, 2)
	invround(columnA,columnB, 1)

	lastInvround(columnA, p, 0)
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
