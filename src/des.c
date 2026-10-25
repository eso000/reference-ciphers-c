#include <stdlib.h>
#include <string.h>

#include "block/des.h"
#include "bytes.h"
#include "des_data.h"
#include "force_inline.h"

FORCE_INLINE uint32_t rol32(uint32_t x, int n)
{
	n &= 31;
	if (!n)
		return x;
	return (x << n) | (x >> (32 - n));
}

FORCE_INLINE uint32_t ror32(uint32_t x, int n)
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

FORCE_INLINE uint64_t des_rotl28(uint64_t x, int n)
{
	return ((x << n) | (x >> (28 - n))) & 0xFFFFFFF;
}

/* Returns 1 when key is a usable DES key: 64 bits, i.e. 8 bytes. A longer hex
   string used to be accepted and quietly truncated: strtoull read at most 16
   digits and stopped at the first non-hex character, so only the leading
   characters ever reached the schedule. Both entry points and
   BlockCipher.keyOk route through this one answer. */
int des_keyOk(const uint8_t *key, size_t len)
{
	return key != NULL && len == 8;
}

struct DES des_generateKeys(const uint8_t *key, size_t len)
{
	struct DES d;
	d.use_alt = 1;
	if (!des_keyOk(key, len))
	{
		memset(&d, 0, sizeof(d));
		return d;
	}
	uint64_t leftKey = 0;
	for (int i = 0; i < 8; ++i)
		leftKey = (leftKey << 8) | key[i];
	leftKey = des_permutate(leftKey, keyperm1, 56, 64);
	uint64_t rightKey = leftKey & 0xFFFFFFF;
	leftKey >>= 28;
	int shift;
	for (int i = 0; i < 16; i++)
	{
		shift = 2;
		if ((i + 1 == 1) || (i + 1 == 2) || (i + 1 == 9) || (i + 1 == 16))
			shift = 1;
		leftKey = des_rotl28(leftKey, shift);
		rightKey = des_rotl28(rightKey, shift);
		d.Subkeys[i] = des_permutate((leftKey << 28) | rightKey, keyperm2, 48, 56);
	}
	return d;
}

/* The round function f(R, K): expansion, key mixing, the S-boxes and P. The
   alternative path uses SPBox, which fuses each S-box with its share of P. */
FORCE_INLINE uint32_t des_f(uint32_t r, uint64_t k, const struct DES *d)
{
	uint64_t t = des_permutate(r, ExpentionPerm, 48, 32) ^ k;
	if (d->use_alt)
		return SPBox[0][(t >> 42) & 0x3f] ^ SPBox[1][(t >> 36) & 0x3f] ^ SPBox[2][(t >> 30) & 0x3f] ^ SPBox[3][(t >> 24) & 0x3f]
			^ SPBox[4][(t >> 18) & 0x3f] ^ SPBox[5][(t >> 12) & 0x3f] ^ SPBox[6][(t >> 6) & 0x3f] ^ SPBox[7][t & 0x3f];

	uint32_t s = ((uint32_t)SBoxes0[(t >> 42) & 0x3f] << 28) | ((uint32_t)SBoxes1[(t >> 36) & 0x3f] << 24)
		| ((uint32_t)SBoxes2[(t >> 30) & 0x3f] << 20) | ((uint32_t)SBoxes3[(t >> 24) & 0x3f] << 16)
		| ((uint32_t)SBoxes4[(t >> 18) & 0x3f] << 12) | ((uint32_t)SBoxes5[(t >> 12) & 0x3f] << 8)
		| ((uint32_t)SBoxes6[(t >> 6) & 0x3f] << 4) | (uint32_t)SBoxes7[t & 0x3f];
	return (uint32_t)des_permutate(s, PBox, 32, 32);
}

FORCE_INLINE void des_round(uint32_t *l, const uint32_t *r, int i, const struct DES *d)
{
	*l ^= des_f(*r, d->Subkeys[i], d);
}

void des_encrypt_block(uint8_t *block, const struct DES *d)
{
	uint8_t *lb = block;
	uint8_t *rb = block + 4;
	uint32_t left = load32_be(lb);
	uint32_t right = load32_be(rb);

	uint64_t temp;
	if (d->use_alt)
		temp = des_ip_perm_alt((uint64_t)left << 32 | right);
	else
			temp = des_permutate((uint64_t)left << 32 | right, initialperm, 64, 64);
	left = (uint32_t)(temp >> 32);
	right = (uint32_t)(temp & 0xffffffff);

	des_round(&left, &right, 0, d);  des_round(&right, &left, 1, d);
	des_round(&left, &right, 2, d);  des_round(&right, &left, 3, d);
	des_round(&left, &right, 4, d);  des_round(&right, &left, 5, d);
	des_round(&left, &right, 6, d);  des_round(&right, &left, 7, d);
	des_round(&left, &right, 8, d);  des_round(&right, &left, 9, d);
	des_round(&left, &right, 10, d); des_round(&right, &left, 11, d);
	des_round(&left, &right, 12, d); des_round(&right, &left, 13, d);
	des_round(&left, &right, 14, d); des_round(&right, &left, 15, d);

	if (d->use_alt)
		temp = des_fp_perm_alt((uint64_t)right << 32 | left);
	else
			temp = des_permutate((uint64_t)right << 32 | left, inverseperm, 64, 64);

	right = (uint32_t)(temp & 0xffffffff);
	left = (uint32_t)(temp >> 32);
	store32_be(lb, left);
	store32_be(rb, right);
}

void des_decrypt_block(uint8_t *block, const struct DES *d)
{
	uint8_t *lb = block;
	uint8_t *rb = block + 4;
	uint32_t left = load32_be(lb);
	uint32_t right = load32_be(rb);

	uint64_t temp;
	if (d->use_alt)
		temp = des_ip_perm_alt((uint64_t)left << 32 | right);
	else
			temp = des_permutate((uint64_t)left << 32 | right, initialperm, 64, 64);
	left = (uint32_t)(temp >> 32);
	right = (uint32_t)(temp & 0xffffffff);

	des_round(&left, &right, 15, d);  des_round(&right, &left, 14, d);
	des_round(&left, &right, 13, d);  des_round(&right, &left, 12, d);
	des_round(&left, &right, 11, d);  des_round(&right, &left, 10, d);
	des_round(&left, &right, 9, d);  des_round(&right, &left, 8, d);
	des_round(&left, &right, 7, d);  des_round(&right, &left, 6, d);
	des_round(&left, &right, 5, d);  des_round(&right, &left, 4, d);
	des_round(&left, &right, 3, d);  des_round(&right, &left, 2, d);
	des_round(&left, &right, 1, d);  des_round(&right, &left, 0, d);

	if (d->use_alt)
		temp = des_fp_perm_alt((uint64_t)right << 32 | left);
	else
			temp = des_permutate((uint64_t)right << 32 | left, inverseperm, 64, 64);

	right = (uint32_t)(temp & 0xffffffff);
	left = (uint32_t)(temp >> 32);
	store32_be(lb, left);
	store32_be(rb, right);
}

int des_generateKeysSelf(BlockCipher *self, const uint8_t *key, size_t len)
{
	struct DES *d = self->cipherState;
	if (!des_keyOk(key, len))
	{
		memset(d, 0, sizeof(*d));
		return 0;
	}
	*d = des_generateKeys(key, len);
	return 1;
}

void des_encryptBlock(BlockCipher *self, uint8_t *block)
{
	des_encrypt_block(block, self->cipherState);
}

void des_decryptBlock(BlockCipher *self, uint8_t *block)
{
	des_decrypt_block(block, self->cipherState);
}

BlockCipher des_cipher(void *state)
{
	BlockCipher c;
	c.blockSize = 8;
	c.cipherState = state;
	c.generateKeys = des_generateKeysSelf;
	c.keyOk = des_keyOk;
	c.encryptBlock = des_encryptBlock;
	c.decryptBlock = des_decryptBlock;
	return c;
}
