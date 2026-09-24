#include <stdlib.h>

#include "DES.h"
/* Data tables physically live at the end of this file (see the appendix below). */
static const uint8_t initialperm[64];
static const uint8_t inverseperm[64];
static const uint8_t ExpentionPerm[48];
static const uint8_t SBoxes0[64];
static const uint8_t SBoxes1[64];
static const uint8_t SBoxes2[64];
static const uint8_t SBoxes3[64];
static const uint8_t SBoxes4[64];
static const uint8_t SBoxes5[64];
static const uint8_t SBoxes6[64];
static const uint8_t SBoxes7[64];
static const uint8_t keyperm1[56];
static const uint8_t keyperm2[48];
static const uint8_t PBox[32];
static const uint32_t SPBox[8][64];









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

struct DES des_generateKeys(char* key)
{
	struct DES d;
	d.use_alt = 1;
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

void des_generateKeysSelf(BlockCipher *self, char *key)
{
	*(struct DES *)self->cipherState = des_generateKeys(key);
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

/* ---------------------------------------------------------------------- */
/* DES data tables (appendix)                                          */
/* These constants physically live at the end of this file; the           */
/* declarations are forward-declared near the top.                        */
/* ---------------------------------------------------------------------- */

static const uint8_t initialperm [64] = {
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};

static const uint8_t inverseperm [64] = {
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25
};

static const uint8_t ExpentionPerm [48] = {
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1
};

static const uint8_t SBoxes0 [64] = {14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1, 3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8, 4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7, 15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13};

static const uint8_t SBoxes1 [64] = {15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14, 9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5, 0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2, 5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9};

static const uint8_t SBoxes2 [64] = {10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10, 1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1, 13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7, 11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12};

static const uint8_t SBoxes3 [64] = {7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3, 1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9, 10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8, 15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14};

static const uint8_t SBoxes4 [64] = {2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1, 8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6, 4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13, 15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3};

static const uint8_t SBoxes5 [64] = {12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5, 0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8, 9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10, 7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13};

static const uint8_t SBoxes6 [64] = {4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10, 3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6, 1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7, 10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12};

static const uint8_t SBoxes7 [64] = {13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4, 10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2, 7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13, 0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11};

static const uint8_t keyperm1 [56] = {
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4
};

static const uint8_t keyperm2 [48] = {
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

static const uint8_t PBox [32] = {
	16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25
};

static const uint32_t SPBox[8][64] = {
	{0x00808200, 0x00000000, 0x00008000, 0x00808202, 0x00808002, 0x00008202, 0x00000002, 0x00008000, 0x00000200, 0x00808200, 0x00808202, 0x00000200, 0x00800202, 0x00808002, 0x00800000, 0x00000002, 0x00000202, 0x00800200, 0x00800200, 0x00008200, 0x00008200, 0x00808000, 0x00808000, 0x00800202, 0x00008002, 0x00800002, 0x00800002, 0x00008002, 0x00000000, 0x00000202, 0x00008202, 0x00800000, 0x00008000, 0x00808202, 0x00000002, 0x00808000, 0x00808200, 0x00800000, 0x00800000, 0x00000200, 0x00808002, 0x00008000, 0x00008200, 0x00800002, 0x00000200, 0x00000002, 0x00800202, 0x00008202, 0x00808202, 0x00008002, 0x00808000, 0x00800202, 0x00800002, 0x00000202, 0x00008202, 0x00808200, 0x00000202, 0x00800200, 0x00800200, 0x00000000, 0x00008002, 0x00008200, 0x00000000, 0x00808002},
	{0x40084010, 0x40004000, 0x00004000, 0x00084010, 0x00080000, 0x00000010, 0x40080010, 0x40004010, 0x40000010, 0x40084010, 0x40084000, 0x40000000, 0x40004000, 0x00080000, 0x00000010, 0x40080010, 0x00084000, 0x00080010, 0x40004010, 0x00000000, 0x40000000, 0x00004000, 0x00084010, 0x40080000, 0x00080010, 0x40000010, 0x00000000, 0x00084000, 0x00004010, 0x40084000, 0x40080000, 0x00004010, 0x00000000, 0x00084010, 0x40080010, 0x00080000, 0x40004010, 0x40080000, 0x40084000, 0x00004000, 0x40080000, 0x40004000, 0x00000010, 0x40084010, 0x00084010, 0x00000010, 0x00004000, 0x40000000, 0x00004010, 0x40084000, 0x00080000, 0x40000010, 0x00080010, 0x40004010, 0x40000010, 0x00080010, 0x00084000, 0x00000000, 0x40004000, 0x00004010, 0x40000000, 0x40080010, 0x40084010, 0x00084000},
	{0x00000104, 0x04010100, 0x00000000, 0x04010004, 0x04000100, 0x00000000, 0x00010104, 0x04000100, 0x00010004, 0x04000004, 0x04000004, 0x00010000, 0x04010104, 0x00010004, 0x04010000, 0x00000104, 0x04000000, 0x00000004, 0x04010100, 0x00000100, 0x00010100, 0x04010000, 0x04010004, 0x00010104, 0x04000104, 0x00010100, 0x00010000, 0x04000104, 0x00000004, 0x04010104, 0x00000100, 0x04000000, 0x04010100, 0x04000000, 0x00010004, 0x00000104, 0x00010000, 0x04010100, 0x04000100, 0x00000000, 0x00000100, 0x00010004, 0x04010104, 0x04000100, 0x04000004, 0x00000100, 0x00000000, 0x04010004, 0x04000104, 0x00010000, 0x04000000, 0x04010104, 0x00000004, 0x00010104, 0x00010100, 0x04000004, 0x04010000, 0x04000104, 0x00000104, 0x04010000, 0x00010104, 0x00000004, 0x04010004, 0x00010100},
	{0x80401000, 0x80001040, 0x80001040, 0x00000040, 0x00401040, 0x80400040, 0x80400000, 0x80001000, 0x00000000, 0x00401000, 0x00401000, 0x80401040, 0x80000040, 0x00000000, 0x00400040, 0x80400000, 0x80000000, 0x00001000, 0x00400000, 0x80401000, 0x00000040, 0x00400000, 0x80001000, 0x00001040, 0x80400040, 0x80000000, 0x00001040, 0x00400040, 0x00001000, 0x00401040, 0x80401040, 0x80000040, 0x00400040, 0x80400000, 0x00401000, 0x80401040, 0x80000040, 0x00000000, 0x00000000, 0x00401000, 0x00001040, 0x00400040, 0x80400040, 0x80000000, 0x80401000, 0x80001040, 0x80001040, 0x00000040, 0x80401040, 0x80000040, 0x80000000, 0x00001000, 0x80400000, 0x80001000, 0x00401040, 0x80400040, 0x80001000, 0x00001040, 0x00400000, 0x80401000, 0x00000040, 0x00400000, 0x00001000, 0x00401040},
	{0x00000080, 0x01040080, 0x01040000, 0x21000080, 0x00040000, 0x00000080, 0x20000000, 0x01040000, 0x20040080, 0x00040000, 0x01000080, 0x20040080, 0x21000080, 0x21040000, 0x00040080, 0x20000000, 0x01000000, 0x20040000, 0x20040000, 0x00000000, 0x20000080, 0x21040080, 0x21040080, 0x01000080, 0x21040000, 0x20000080, 0x00000000, 0x21000000, 0x01040080, 0x01000000, 0x21000000, 0x00040080, 0x00040000, 0x21000080, 0x00000080, 0x01000000, 0x20000000, 0x01040000, 0x21000080, 0x20040080, 0x01000080, 0x20000000, 0x21040000, 0x01040080, 0x20040080, 0x00000080, 0x01000000, 0x21040000, 0x21040080, 0x00040080, 0x21000000, 0x21040080, 0x01040000, 0x00000000, 0x20040000, 0x21000000, 0x00040080, 0x01000080, 0x20000080, 0x00040000, 0x00000000, 0x20040000, 0x01040080, 0x20000080},
	{0x10000008, 0x10200000, 0x00002000, 0x10202008, 0x10200000, 0x00000008, 0x10202008, 0x00200000, 0x10002000, 0x00202008, 0x00200000, 0x10000008, 0x00200008, 0x10002000, 0x10000000, 0x00002008, 0x00000000, 0x00200008, 0x10002008, 0x00002000, 0x00202000, 0x10002008, 0x00000008, 0x10200008, 0x10200008, 0x00000000, 0x00202008, 0x10202000, 0x00002008, 0x00202000, 0x10202000, 0x10000000, 0x10002000, 0x00000008, 0x10200008, 0x00202000, 0x10202008, 0x00200000, 0x00002008, 0x10000008, 0x00200000, 0x10002000, 0x10000000, 0x00002008, 0x10000008, 0x10202008, 0x00202000, 0x10200000, 0x00202008, 0x10202000, 0x00000000, 0x10200008, 0x00000008, 0x00002000, 0x10200000, 0x00202008, 0x00002000, 0x00200008, 0x10002008, 0x00000000, 0x10202000, 0x10000000, 0x00200008, 0x10002008},
	{0x00100000, 0x02100001, 0x02000401, 0x00000000, 0x00000400, 0x02000401, 0x00100401, 0x02100400, 0x02100401, 0x00100000, 0x00000000, 0x02000001, 0x00000001, 0x02000000, 0x02100001, 0x00000401, 0x02000400, 0x00100401, 0x00100001, 0x02000400, 0x02000001, 0x02100000, 0x02100400, 0x00100001, 0x02100000, 0x00000400, 0x00000401, 0x02100401, 0x00100400, 0x00000001, 0x02000000, 0x00100400, 0x02000000, 0x00100400, 0x00100000, 0x02000401, 0x02000401, 0x02100001, 0x02100001, 0x00000001, 0x00100001, 0x02000000, 0x02000400, 0x00100000, 0x02100400, 0x00000401, 0x00100401, 0x02100400, 0x00000401, 0x02000001, 0x02100401, 0x02100000, 0x00100400, 0x00000000, 0x00000001, 0x02100401, 0x00000000, 0x00100401, 0x02100000, 0x00000400, 0x02000001, 0x02000400, 0x00000400, 0x00100001},
	{0x08000820, 0x00000800, 0x00020000, 0x08020820, 0x08000000, 0x08000820, 0x00000020, 0x08000000, 0x00020020, 0x08020000, 0x08020820, 0x00020800, 0x08020800, 0x00020820, 0x00000800, 0x00000020, 0x08020000, 0x08000020, 0x08000800, 0x00000820, 0x00020800, 0x00020020, 0x08020020, 0x08020800, 0x00000820, 0x00000000, 0x00000000, 0x08020020, 0x08000020, 0x08000800, 0x00020820, 0x00020000, 0x00020820, 0x00020000, 0x08020800, 0x00000800, 0x00000020, 0x08020020, 0x00000800, 0x00020820, 0x08000800, 0x00000020, 0x08000020, 0x08020000, 0x08020020, 0x08000000, 0x00020000, 0x08000820, 0x00000000, 0x08020820, 0x00020020, 0x08000020, 0x08020000, 0x08000800, 0x08000820, 0x00000000, 0x08020820, 0x00020800, 0x00020800, 0x00000820, 0x00000820, 0x00020020, 0x08000000, 0x08020800},
};
