#include <stdlib.h>
#include <string.h>

#include "block/des.h"
#include "des_data.h"

union word{
	uint32_t w;
	uint8_t b[4];
};

static inline uint32_t rol32(uint32_t x, int n)
{
	n &= 31;
	if (!n)
		return x;
	return (x << n) | (x >> (32 - n));
}

static inline uint32_t ror32(uint32_t x, int n)
{
	n &= 31;
	if (!n)
		return x;
	return (x >> n) | (x << (32 - n));
}

uint64_t des_ip_perm_alt(uint64_t block)
{
	uint32_t left = block >> 32;
	uint32_t right = block & 0xffffffff;
	uint32_t work;

	right = rol32(right, 4);
	work = (left ^ right) & 0xf0f0f0f0;
	left ^= work;
	right = ror32(right ^ work, 20);
	work = (left ^ right) & 0xffff0000;
	left ^= work;
	right = ror32(right ^ work, 18);
	work = (left ^ right) & 0x33333333;
	left ^= work;
	right = ror32(right ^ work, 6);
	work = (left ^ right) & 0x00ff00ff;
	left ^= work;
	right = rol32(right ^ work, 9);
	work = (left ^ right) & 0xaaaaaaaa;
	left = rol32(left ^ work, 1);
	right ^= work;
	return ((uint64_t)rol32(left, 31) << 32) | rol32(right, 31);
}

uint64_t des_fp_perm_alt(uint64_t block)
{
	uint32_t left = block >> 32;
	uint32_t right = block & 0xffffffff;
	uint32_t work;

	left = rol32(left, 1);
	right = rol32(right, 1);
	work = (ror32(left, 1) ^ right) & 0xaaaaaaaa;
	left = ror32(left, 1) ^ work;
	right ^= work;
	work = (left ^ ror32(right, 9)) & 0x00ff00ff;
	left ^= work;
	right = ror32(right, 9) ^ work;
	work = (left ^ rol32(right, 6)) & 0x33333333;
	left ^= work;
	right = rol32(right, 6) ^ work;
	work = (left ^ rol32(right, 18)) & 0xffff0000;
	left ^= work;
	right = rol32(right, 18) ^ work;
	work = (left ^ rol32(right, 20)) & 0xf0f0f0f0;
	left ^= work;
	right = rol32(right, 20) ^ work;
	right = ror32(right, 4);
	return ((uint64_t)left << 32) | right;
}


static uint64_t des_permutate(uint64_t x, const uint8_t *P, int n, int base_size)
{
	uint64_t result = 0;
	for (int i = 0; i < n; ++i)
	{
		result <<= 1;
		result |= (x >> (base_size - P[i]) & 1);
	}
	return result;
}

#define rotr28(xr, times) ((((xr) << (times)) | ((xr) >> (28 - (times)))) & 0xFFFFFFF)

/* DES takes a 64-bit key, i.e. 16 hex characters. strtoull below reads at most
   16 digits and stops at the first non-hex character, so a longer key used to
   be accepted and quietly truncated to its first 16 characters. */
static int des_key_ok(size_t len)
{
	return len == 16;
}

struct DES des_generateKeys(char* key)
{
	struct DES d;
	d.use_alt = 1;
	if (!des_key_ok(strlen(key)))
	{
		memset(&d, 0, sizeof(d));
		return d;
	}
	uint64_t leftKey = strtoull(key, NULL, 16);
	leftKey = des_permutate(leftKey, keyperm1, 56, 64);
	uint64_t rightKey = leftKey & 0xFFFFFFF;
	leftKey >>= 28;
	int shift;
	for (int i = 0; i < 16; i++)
	{
		shift = 2;
		if ((i + 1 == 1) || (i + 1 == 2) || (i + 1 == 9) || (i + 1 == 16))
			shift = 1;
		leftKey = rotr28(leftKey, shift);
		rightKey = rotr28(rightKey, shift);
		d.Subkeys[i] = des_permutate((leftKey << 28) | rightKey, keyperm2, 48, 56);
	}
	return d;
}

#define F(x, i) temp = des_permutate((x).w, ExpentionPerm, 48, 32) ^ d->Subkeys[i];\
				if (d->use_alt)\
				temp = SPBox[0][(temp >> 42) & 0x3f] ^ SPBox[1][(temp >> 36) & 0x3f] ^ SPBox[2][(temp >> 30) & 0x3f] ^ SPBox[3][(temp >> 24) & 0x3f]\
				^ SPBox[4][(temp >> 18) & 0x3f] ^ SPBox[5][(temp >> 12) & 0x3f] ^ SPBox[6][(temp >> 6) & 0x3f] ^ SPBox[7][temp & 0x3f];\
				else {\
				temp = ((uint32_t)SBoxes0[(temp >> 42) & 0x3f] << 28) | ((uint32_t)SBoxes1[(temp >> 36) & 0x3f] << 24)\
				| ((uint32_t)SBoxes2[(temp >> 30) & 0x3f] << 20) | ((uint32_t)SBoxes3[(temp >> 24) & 0x3f] << 16)\
				| ((uint32_t)SBoxes4[(temp >> 18) & 0x3f] << 12) | ((uint32_t)SBoxes5[(temp >> 12) & 0x3f] << 8)\
				| ((uint32_t)SBoxes6[(temp >> 6) & 0x3f] << 4) | (uint32_t)SBoxes7[temp & 0x3f];\
				temp = des_permutate(temp, PBox, 32, 32);\
				}
#define round(l, r, i) F(r, i); (l).w ^= temp;

void des_encrypt_block(uint8_t *lb, uint8_t *rb, const struct DES *d)
{
	union word left, right;
	left.b[3] = *lb; left.b[2] = *(lb+1); left.b[1] = *(lb+2); left.b[0] = *(lb+3);
	right.b[3] = *rb; right.b[2] = *(rb+1); right.b[1] = *(rb+2); right.b[0] = *(rb+3);

	uint64_t temp;
	if (d->use_alt)
		temp = des_ip_perm_alt((uint64_t)left.w << 32 | right.w);
	else
			temp = des_permutate((uint64_t)left.w << 32 | right.w, initialperm, 64, 64);
	left.w = temp >> 32;
	right.w = temp & 0xffffffff;

	round (left, right, 0) ;  round (right, left, 1) ;
	round (left, right, 2) ;  round (right, left, 3) ;
	round (left, right, 4) ;  round (right, left, 5) ;
	round (left, right, 6) ;  round (right, left, 7) ;
	round (left, right, 8) ;  round (right, left, 9) ;
	round (left, right, 10) ; round (right, left, 11) ;
	round (left, right, 12) ; round (right, left, 13) ;
	round (left, right, 14) ; round (right, left, 15) ;

	if (d->use_alt)
		temp = des_fp_perm_alt((uint64_t)right.w << 32 | left.w);
	else
			temp = des_permutate((uint64_t)right.w << 32 | left.w, inverseperm, 64, 64);

	right.w = temp & 0xffffffff;
	left.w = temp >> 32;
	*lb = left.b[3]; *(lb+1) = left.b[2]; *(lb+2) = left.b[1]; *(lb+3) = left.b[0];
	*rb = right.b[3]; *(rb+1) = right.b[2]; *(rb+2) = right.b[1]; *(rb+3) = right.b[0];
}

void des_decrypt_block(uint8_t *lb, uint8_t *rb, const struct DES *d)
{
	union word left, right;
	left.b[3] = *lb; left.b[2] = *(lb+1); left.b[1] = *(lb+2); left.b[0] = *(lb+3);
	right.b[3] = *rb; right.b[2] = *(rb+1); right.b[1] = *(rb+2); right.b[0] = *(rb+3);

	uint64_t temp;
	if (d->use_alt)
		temp = des_ip_perm_alt((uint64_t)left.w << 32 | right.w);
	else
			temp = des_permutate((uint64_t)left.w << 32 | right.w, initialperm, 64, 64);
	left.w = temp >> 32;
	right.w = temp & 0xffffffff;

	round (left, right, 15) ;  round (right, left, 14) ;
	round (left, right, 13) ;  round (right, left, 12) ;
	round (left, right, 11) ;  round (right, left, 10) ;
	round (left, right,  9) ;  round (right, left,  8) ;
	round (left, right,  7) ;  round (right, left,  6) ;
	round (left, right,  5) ;  round (right, left,  4) ;
	round (left, right,  3) ;  round (right, left,  2) ;
	round (left, right,  1) ;  round (right, left,  0) ;

	if (d->use_alt)
		temp = des_fp_perm_alt((uint64_t)right.w << 32 | left.w);
	else
			temp = des_permutate((uint64_t)right.w << 32 | left.w, inverseperm, 64, 64);

	right.w = temp & 0xffffffff;
	left.w = temp >> 32;
	*lb = left.b[3]; *(lb+1) = left.b[2]; *(lb+2) = left.b[1]; *(lb+3) = left.b[0];
	*rb = right.b[3]; *(rb+1) = right.b[2]; *(rb+2) = right.b[1]; *(rb+3) = right.b[0];
}

int des_generateKeysSelf(BlockCipher *self, char *key)
{
	struct DES *d = self->cipherState;
	if (!des_key_ok(strlen(key)))
	{
		memset(d, 0, sizeof(*d));
		return 0;
	}
	*d = des_generateKeys(key);
	return 1;
}

void des_encryptBlock(BlockCipher *self, uint8_t *block)
{
	des_encrypt_block(block, block + 4, self->cipherState);
}

void des_decryptBlock(BlockCipher *self, uint8_t *block)
{
	des_decrypt_block(block, block + 4, self->cipherState);
}

BlockCipher des_cipher(void *state)
{
	BlockCipher c;
	c.blockSize = 8;
	c.cipherState = state;
	c.generateKeys = des_generateKeysSelf;
	c.encryptBlock = des_encryptBlock;
	c.decryptBlock = des_decryptBlock;
	return c;
}
