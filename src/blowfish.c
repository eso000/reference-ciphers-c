#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "block/blowfish.h"
#include "blowfish_data.h"
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

FORCE_INLINE uint32_t blowfish_F(const struct Blowfish *bf, uint32_t x)
{
	return ((bf->SBoxes0[byte0(x)] + bf->SBoxes1[byte1(x)]) ^ bf->SBoxes2[byte2(x)]) + bf->SBoxes3[byte3(x)];
}

FORCE_INLINE void blowfish_round(uint32_t *l, uint32_t *r, int i, const struct Blowfish *bf)
{
	*l ^= bf->Subkeys[i];
	*r ^= blowfish_F(bf, *l);
}

void blowfish_encrypt_block(uint8_t *lb, uint8_t *rb, const struct Blowfish *bf)
{
	uint32_t left = load32_be(lb);
	uint32_t right = load32_be(rb);

	blowfish_round(&left, &right, 0, bf);  blowfish_round(&right, &left, 1, bf);
	blowfish_round(&left, &right, 2, bf);  blowfish_round(&right, &left, 3, bf);
	blowfish_round(&left, &right, 4, bf);  blowfish_round(&right, &left, 5, bf);
	blowfish_round(&left, &right, 6, bf);  blowfish_round(&right, &left, 7, bf);
	blowfish_round(&left, &right, 8, bf);  blowfish_round(&right, &left, 9, bf);
	blowfish_round(&left, &right, 10, bf); blowfish_round(&right, &left, 11, bf);
	blowfish_round(&left, &right, 12, bf); blowfish_round(&right, &left, 13, bf);
	blowfish_round(&left, &right, 14, bf); blowfish_round(&right, &left, 15, bf);
	left ^= bf->Subkeys[16];
	right ^= bf->Subkeys[17];

	store32_be(rb, left);
	store32_be(lb, right);
}

void blowfish_decrypt_block(uint8_t *lb, uint8_t *rb, const struct Blowfish *bf)
{
	uint32_t left = load32_be(lb);
	uint32_t right = load32_be(rb);

	blowfish_round(&left, &right, 17, bf); blowfish_round(&right, &left, 16, bf);
	blowfish_round(&left, &right, 15, bf); blowfish_round(&right, &left, 14, bf);
	blowfish_round(&left, &right, 13, bf); blowfish_round(&right, &left, 12, bf);
	blowfish_round(&left, &right, 11, bf); blowfish_round(&right, &left, 10, bf);
	blowfish_round(&left, &right, 9, bf);  blowfish_round(&right, &left, 8, bf);
	blowfish_round(&left, &right, 7, bf);  blowfish_round(&right, &left, 6, bf);
	blowfish_round(&left, &right, 5, bf);  blowfish_round(&right, &left, 4, bf);
	blowfish_round(&left, &right, 3, bf);  blowfish_round(&right, &left, 2, bf);
	left ^= bf->Subkeys[1];
	right ^= bf->Subkeys[0];

	store32_be(rb, left);
	store32_be(lb, right);
}

/* Blowfish takes a key of 32 to 448 bits, i.e. 4 to 56 bytes, which is
   8 to 112 hex characters. The schedule consumes 8 hex characters (one
   32-bit word) at a time and wraps with (8 * i) % strlen(key), so a
   length that is not a multiple of 8 would straddle the terminator and
   silently key a word from fewer digits than the caller supplied. Hence
   the step of 8.

   The length guard is what keeps (8 * i) % strlen(key) from dividing by
   zero: an empty key used to raise SIGFPE. */
static int blowfish_key_ok(size_t len)
{
	return len >= 8 && len <= 112 && len % 8 == 0;
}

struct Blowfish blowfish_generateKeys(char* key)
{
	if (!blowfish_key_ok(strlen(key)))
	{
		struct Blowfish bad;
		memset(&bad, 0, sizeof(bad));
		return bad;
	}

	size_t t;
	uint32_t keys[18];
	for (int i = 0; i < 18; i++)
	{
		t = (8 * (size_t)i) % strlen(key);
		char temp[9];
		strncpy(temp, key + t, 8);
		temp[8] = '\0';
		keys[i] = (uint32_t)strtoul(temp, NULL, 16) ^ PBox[i];
	}
	struct Blowfish blowfish;
	memcpy(blowfish.SBoxes0, SBox[0], sizeof(SBox[0]));
	memcpy(blowfish.SBoxes1, SBox[1], sizeof(SBox[1]));
	memcpy(blowfish.SBoxes2, SBox[2], sizeof(SBox[2]));
	memcpy(blowfish.SBoxes3, SBox[3], sizeof(SBox[3]));
	memcpy(blowfish.Subkeys, keys, sizeof(keys));

	uint8_t P[8] = {0, 0, 0, 0, 0, 0, 0, 0};

	for (int i = 0; i < 18; i = i + 2)
	{
		blowfish_encrypt_block(&P[0], &P[4], &blowfish);
		blowfish.Subkeys[i] = load32_be(&P[0]);
		blowfish.Subkeys[i+1] = load32_be(&P[4]);
	}
	for (int i = 0; i < 256; i = i + 2)
	{
		blowfish_encrypt_block(&P[0], &P[4], &blowfish);
		blowfish.SBoxes0[i] = load32_be(&P[0]);
		blowfish.SBoxes0[i+1] = load32_be(&P[4]);
	}
	for (int i = 0; i < 256; i = i + 2)
	{
		blowfish_encrypt_block(&P[0], &P[4], &blowfish);
		blowfish.SBoxes1[i] = load32_be(&P[0]);
		blowfish.SBoxes1[i+1] = load32_be(&P[4]);
	}
	for (int i = 0; i < 256; i = i + 2)
	{
		blowfish_encrypt_block(&P[0], &P[4], &blowfish);
		blowfish.SBoxes2[i] = load32_be(&P[0]);
		blowfish.SBoxes2[i+1] = load32_be(&P[4]);
	}
	for (int i = 0; i < 256; i = i + 2)
	{
		blowfish_encrypt_block(&P[0], &P[4], &blowfish);
		blowfish.SBoxes3[i] = load32_be(&P[0]);
		blowfish.SBoxes3[i+1] = load32_be(&P[4]);
	}

	return blowfish;
}

int blowfish_generateKeysSelf(BlockCipher *self, char *key)
{
	struct Blowfish *bf = self->cipherState;
	if (!blowfish_key_ok(strlen(key)))
	{
		memset(bf, 0, sizeof(*bf));
		return 0;
	}
	*bf = blowfish_generateKeys(key);
	return 1;
}

void blowfish_encryptBlock(BlockCipher *self, uint8_t *block)
{
	blowfish_encrypt_block(block, block + 4, (const struct Blowfish *)self->cipherState);
}

void blowfish_decryptBlock(BlockCipher *self, uint8_t *block)
{
	blowfish_decrypt_block(block, block + 4, (const struct Blowfish *)self->cipherState);
}

BlockCipher blowfish_cipher(void *state)
{
	BlockCipher c = {8, state, blowfish_generateKeysSelf, blowfish_encryptBlock, blowfish_decryptBlock};
	return c;
}
