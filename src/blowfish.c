#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "block/blowfish.h"
#include "blowfish_data.h"
#include "bytes.h"
#include "force_inline.h"

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

/* Returns 1 when key is a usable Blowfish key: 32 to 448 bits, i.e. 4 to 56
   bytes. The schedule consumes four key bytes (one 32-bit word) at a time and
   wraps with (4 * i) % len, which is the algorithm's own key-cycling rule, so
   every length in the range is usable.

   The length check is also what keeps (4 * i) % len from dividing by zero: an
   empty key used to raise SIGFPE. With hex strings this function also required
   a multiple of 8 characters, because a read of 8 would otherwise straddle the
   terminating NUL; raw bytes have no terminator to straddle, so that
   restriction is gone. Both entry points and BlockCipher.keyOk route through
   this one answer. */
int blowfish_keyOk(const uint8_t *key, size_t len)
{
	return key != NULL && len >= 4 && len <= 56;
}

struct Blowfish blowfish_generateKeys(const uint8_t *key, size_t len)
{
	if (!blowfish_keyOk(key, len))
	{
		struct Blowfish bad;
		memset(&bad, 0, sizeof(bad));
		return bad;
	}

	uint32_t keys[18];
	uint8_t word[4];
	for (int i = 0; i < 18; i++)
	{
		for (int j = 0; j < 4; ++j)
			word[j] = key[(4 * (size_t)i + (size_t)j) % len];
		keys[i] = load32_be(word) ^ PBox[i];
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

int blowfish_generateKeysSelf(BlockCipher *self, const uint8_t *key, size_t len)
{
	struct Blowfish *bf = self->cipherState;
	if (!blowfish_keyOk(key, len))
	{
		memset(bf, 0, sizeof(*bf));
		return 0;
	}
	*bf = blowfish_generateKeys(key, len);
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
	BlockCipher c;
	c.blockSize = 8;
	c.cipherState = state;
	c.generateKeys = blowfish_generateKeysSelf;
	c.keyOk = blowfish_keyOk;
	c.encryptBlock = blowfish_encryptBlock;
	c.decryptBlock = blowfish_decryptBlock;
	return c;
}
