#include <string.h>

#include "block/serpent.h"
#include "serpent_data.h"
#include "force_inline.h"



/* The block is held as four 32-bit words in little-endian bit order, so the
   paper's "<<<" and "<<" (Serpent proposal, Section 3) are plain rotl and
   masked left shifts on those words. */
FORCE_INLINE uint32_t rotl(uint32_t x, int n)
{
	return (x << n) | (x >> (32 - n));
}

FORCE_INLINE uint32_t rotr(uint32_t x, int n)
{
	return (x >> n) | (x << (32 - n));
}

/* The ten steps of the paper's linear transformation, in its order. */
FORCE_INLINE void serpent_LT(uint32_t *x0, uint32_t *x1, uint32_t *x2, uint32_t *x3)
{
	*x0 = rotl(*x0, 13);
	*x2 = rotl(*x2, 3);
	*x1 = *x1 ^ *x0 ^ *x2;
	*x3 = *x3 ^ *x2 ^ (*x0 << 3);
	*x1 = rotl(*x1, 1);
	*x3 = rotl(*x3, 7);
	*x0 = *x0 ^ *x1 ^ *x3;
	*x2 = *x2 ^ *x3 ^ (*x1 << 7);
	*x0 = rotl(*x0, 5);
	*x2 = rotl(*x2, 22);
}

/* The same ten steps in reverse order, with every rotation turned around. */
FORCE_INLINE void serpent_invLT(uint32_t *x0, uint32_t *x1, uint32_t *x2, uint32_t *x3)
{
	*x2 = rotr(*x2, 22);
	*x0 = rotr(*x0, 5);
	*x2 = *x2 ^ *x3 ^ (*x1 << 7);
	*x0 = *x0 ^ *x1 ^ *x3;
	*x3 = rotr(*x3, 7);
	*x1 = rotr(*x1, 1);
	*x3 = *x3 ^ *x2 ^ (*x0 << 3);
	*x1 = *x1 ^ *x0 ^ *x2;
	*x2 = rotr(*x2, 3);
	*x0 = rotr(*x0, 13);
}

/* Word and byte conversion follow Serpent's bit order (Section 3.3): the first
   bit of the block is the least significant bit of word 0, so the four bytes
   of a word are read and written little-endian and left unreversed. */
static uint32_t serpent_load32(const uint8_t *p)
{
	return (uint32_t)p[0]
		| ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16)
		| ((uint32_t)p[3] << 24);
}

static void serpent_store32(uint8_t *p, uint32_t w)
{
	p[0] = (uint8_t)(w);
	p[1] = (uint8_t)(w >> 8);
	p[2] = (uint8_t)(w >> 16);
	p[3] = (uint8_t)(w >> 24);
}

FORCE_INLINE void applySBox(uint32_t *x0, uint32_t *x1, uint32_t *x2, uint32_t *x3, int n)
{
	uint32_t r0 = *x0;
	uint32_t r1 = *x1;
	uint32_t r2 = *x2;
	uint32_t r3 = *x3;
	uint32_t r4 = 0;
	switch (n) {
		case 0:
			r3 ^= r0;
			r4 = r1;
			r1 &= r3;
			r4 ^= r2;
			r1 ^= r0;
			r0 |= r3;
			r0 ^= r4;
			r4 ^= r3;
			r3 ^= r2;
			r2 |= r1;
			r2 ^= r4;
			r4 ^= 0xffffffff;
			r4 |= r1;
			r1 ^= r3;
			r1 ^= r4;
			r3 |= r0;
			r1 ^= r3;
			r4 ^= r3;

			*x0 = r1;
			*x1 = r4;
			*x2 = r2;
			*x3 = r0;
			return;

		case 1:
			r0 ^= 0xffffffff;
			r2 ^= 0xffffffff;
			r4 = r0;
			r0 &= r1;
			r2 ^= r0;
			r0 |= r3;
			r3 ^= r2;
			r1 ^= r0;
			r0 ^= r4;
			r4 |= r1;
			r1 ^= r3;
			r2 |= r0;
			r2 &= r4;
			r0 ^= r1;
			r1 &= r2;
			r1 ^= r0;
			r0 &= r2;
			r0 ^= r4;

			*x0 = r2;
			*x1 = r0;
			*x2 = r3;
			*x3 = r1;
			return;

		case 2:
			r4 = r0;
			r0 &= r2;
			r0 ^= r3;
			r2 ^= r1;
			r2 ^= r0;
			r3 |= r4;
			r3 ^= r1;
			r4 ^= r2;
			r1 = r3;
			r3 |= r4;
			r3 ^= r0;
			r0 &= r1;
			r4 ^= r0;
			r1 ^= r3;
			r1 ^= r4;
			r4 ^= 0xffffffff;

			*x0 = r2;
			*x1 = r3;
			*x2 = r1;
			*x3 = r4;
			return;

		case 3:
			r4 = r0;
			r0 |= r3;
			r3 ^= r1;
			r1 &= r4;
			r4 ^= r2;
			r2 ^= r3;
			r3 &= r0;
			r4 |= r1;
			r3 ^= r4;
			r0 ^= r1;
			r4 &= r0;
			r1 ^= r3;
			r4 ^= r2;
			r1 |= r0;
			r1 ^= r2;
			r0 ^= r3;
			r2 = r1;
			r1 |= r3;
			r1 ^= r0;

			*x0 = r1;
			*x1 = r2;
			*x2 = r3;
			*x3 = r4;
			return;

		case 4:
			r1 ^= r3;
			r3 ^= 0xffffffff;
			r2 ^= r3;
			r3 ^= r0;
			r4 = r1;
			r1 &= r3;
			r1 ^= r2;
			r4 ^= r3;
			r0 ^= r4;
			r2 &= r4;
			r2 ^= r0;
			r0 &= r1;
			r3 ^= r0;
			r4 |= r1;
			r4 ^= r0;
			r0 |= r3;
			r0 ^= r2;
			r2 &= r3;
			r0 ^= 0xffffffff;
			r4 ^= r2;

			*x0 = r1;
			*x1 = r4;
			*x2 = r0;
			*x3 = r3;
			return;

		case 5:
			r0 ^= r1;
			r1 ^= r3;
			r3 ^= 0xffffffff;
			r4 = r1;
			r1 &= r0;
			r2 ^= r3;
			r1 ^= r2;
			r2 |= r4;
			r4 ^= r3;
			r3 &= r1;
			r3 ^= r0;
			r4 ^= r1;
			r4 ^= r2;
			r2 ^= r0;
			r0 &= r3;
			r2 ^= 0xffffffff;
			r0 ^= r4;
			r4 |= r3;
			r2 ^= r4;

			*x0 = r1;
			*x1 = r3;
			*x2 = r0;
			*x3 = r2;
			return;

		case 6:
			r2 ^= 0xffffffff;
			r4 = r3;
			r3 &= r0;
			r0 ^= r4;
			r3 ^= r2;
			r2 |= r4;
			r1 ^= r3;
			r2 ^= r0;
			r0 |= r1;
			r2 ^= r1;
			r4 ^= r0;
			r0 |= r3;
			r0 ^= r2;
			r4 ^= r3;
			r4 ^= r0;
			r3 ^= 0xffffffff;
			r2 &= r4;
			r2 ^= r3;

			*x0 = r0;
			*x1 = r1;
			*x2 = r4;
			*x3 = r2;
			return;

		case 7:
			r4 = r1;
			r1 |= r2;
			r1 ^= r3;
			r4 ^= r2;
			r2 ^= r1;
			r3 |= r4;
			r3 &= r0;
			r4 ^= r2;
			r3 ^= r1;
			r1 |= r4;
			r1 ^= r0;
			r0 |= r4;
			r0 ^= r2;
			r1 ^= r4;
			r2 ^= r1;
			r1 &= r0;
			r1 ^= r4;
			r2 ^= 0xffffffff;
			r2 |= r0;
			r4 ^= r2;

			*x0 = r4;
			*x1 = r3;
			*x2 = r1;
			*x3 = r0;
			return;
	}
}

/* Applies inverse S-box n bit-slice by bit-slice: bit x of the four words
   forms one 4-bit S-box input, and its output bits go back to bit x. */
static void applyInvSBox(uint32_t *x0, uint32_t *x1, uint32_t *x2, uint32_t *x3, int n)
{
	uint32_t nx0 = 0;
	uint32_t nx1 = 0;
	uint32_t nx2 = 0;
	uint32_t nx3 = 0;

	for (int x = 0; x < 32; ++x)
	{
		uint8_t newbits = invSBox[n][((*x0 >> x) & 1) << 0 |
					     ((*x1 >> x) & 1) << 1 |
					     ((*x2 >> x) & 1) << 2 |
					     ((*x3 >> x) & 1) << 3];
		nx0 |= (uint32_t)((newbits >> 0) & 1) << x;
		nx1 |= (uint32_t)((newbits >> 1) & 1) << x;
		nx2 |= (uint32_t)((newbits >> 2) & 1) << x;
		nx3 |= (uint32_t)((newbits >> 3) & 1) << x;
	}

	*x0 = nx0;
	*x1 = nx1;
	*x2 = nx2;
	*x3 = nx3;
}

FORCE_INLINE void serpent_addRoundKey(uint32_t *x0, uint32_t *x1, uint32_t *x2, uint32_t *x3, int i, const struct Serpent *s)
{
	*x0 ^= s->Subkeys[4*i];
	*x1 ^= s->Subkeys[4*i+1];
	*x2 ^= s->Subkeys[4*i+2];
	*x3 ^= s->Subkeys[4*i+3];
}

/* Rounds 0 to 30: key mixing, S-box i mod 8, linear transformation. */
FORCE_INLINE void serpent_round(uint32_t *x0, uint32_t *x1, uint32_t *x2, uint32_t *x3, int i, const struct Serpent *s)
{
	serpent_addRoundKey(x0, x1, x2, x3, i, s);
	applySBox(x0, x1, x2, x3, i % 8);
	serpent_LT(x0, x1, x2, x3);
}

FORCE_INLINE void serpent_invRound(uint32_t *x0, uint32_t *x1, uint32_t *x2, uint32_t *x3, int i, const struct Serpent *s)
{
	serpent_invLT(x0, x1, x2, x3);
	applyInvSBox(x0, x1, x2, x3, i % 8);
	serpent_addRoundKey(x0, x1, x2, x3, i, s);
}

/* Returns 1 when key is a usable Serpent key: 1 to 256 bits, i.e. 1 to 32
   bytes. Only a NULL, empty or over-long key is refused: the Section 3
   padding would otherwise turn an empty key into the all-zero key and
   truncate past 32 bytes without telling the caller. Both entry points and
   BlockCipher.keyOk route through this one answer. */
int serpent_keyOk(const uint8_t *key, size_t len)
{
	return key != NULL && len >= 1 && len <= 32;
}

struct Serpent serpent_generateKeys(const uint8_t *key, size_t len)
{
	struct Serpent s;
	if (!serpent_keyOk(key, len))
	{
		memset(&s, 0, sizeof(s));
		return s;
	}

	/* Section 3 padding, which a byte API makes direct: a key shorter than
	   256 bits gets a 1 bit appended, i.e. a 0x01 byte after the key bytes,
	   then zero bytes up to 32. Serpent's words are little-endian, so the
	   same serpent_load32 used on blocks reads these key bytes. */
	uint8_t k[32];
	memset(k, 0, sizeof(k));
	memcpy(k, key, len);
	if (len < 32)
		k[len] = 0x01;

	uint32_t wi;
	uint32_t w[140];

	for (int i = 0; i < 32; i = i + 4)
	{
		w[i / 4] = serpent_load32(k + i);
	}

	/* Prekey recurrence (Section 4):
	     w_i := (w_i-8 ^ w_i-5 ^ w_i-3 ^ w_i-1 ^ PHI ^ i) <<< 11
	   with PHI the fractional part of the golden ratio, 0x9E3779B9. The eight
	   key words are w_-8 .. w_-1, so w[8] holds w_0. */
	for (int i = 8; i < 140; ++i)
	{
		wi = w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ 0x9E3779B9u ^ (uint32_t)(i - 8);
		wi = rotl(wi, 11);
		w[i] = wi;
	}
	/* Subkey i is prekeys 4i .. 4i+3 through S-box (3 - i) mod 8, which is the
	   S3, S2, S1, S0, S7, S6, S5, S4 order listed in Section 4. C's % keeps the
	   sign of the dividend, so the double modulo keeps the index in 0..7. */
	for (int i = 0; i < 33; ++i)
	{
		applySBox(&w[4*i+8], &w[4*i+1+8], &w[4*i+2+8], &w[4*i+3+8], ((3 - i) % 8 + 8) % 8);
	}
	for (int i = 0; i < 132; ++i)
		s.Subkeys[i] = w[i + 8];

	return s;
}

void serpent_encrypt_block(uint8_t *x0, uint8_t *x1, uint8_t *x2, uint8_t *x3, const struct Serpent *s)
{
	uint32_t w0 = serpent_load32(x0);
	uint32_t w1 = serpent_load32(x1);
	uint32_t w2 = serpent_load32(x2);
	uint32_t w3 = serpent_load32(x3);

	serpent_round(&w0, &w1, &w2, &w3, 0, s);
	serpent_round(&w0, &w1, &w2, &w3, 1, s);
	serpent_round(&w0, &w1, &w2, &w3, 2, s);
	serpent_round(&w0, &w1, &w2, &w3, 3, s);
	serpent_round(&w0, &w1, &w2, &w3, 4, s);
	serpent_round(&w0, &w1, &w2, &w3, 5, s);
	serpent_round(&w0, &w1, &w2, &w3, 6, s);
	serpent_round(&w0, &w1, &w2, &w3, 7, s);
	serpent_round(&w0, &w1, &w2, &w3, 8, s);
	serpent_round(&w0, &w1, &w2, &w3, 9, s);
	serpent_round(&w0, &w1, &w2, &w3, 10, s);
	serpent_round(&w0, &w1, &w2, &w3, 11, s);
	serpent_round(&w0, &w1, &w2, &w3, 12, s);
	serpent_round(&w0, &w1, &w2, &w3, 13, s);
	serpent_round(&w0, &w1, &w2, &w3, 14, s);
	serpent_round(&w0, &w1, &w2, &w3, 15, s);
	serpent_round(&w0, &w1, &w2, &w3, 16, s);
	serpent_round(&w0, &w1, &w2, &w3, 17, s);
	serpent_round(&w0, &w1, &w2, &w3, 18, s);
	serpent_round(&w0, &w1, &w2, &w3, 19, s);
	serpent_round(&w0, &w1, &w2, &w3, 20, s);
	serpent_round(&w0, &w1, &w2, &w3, 21, s);
	serpent_round(&w0, &w1, &w2, &w3, 22, s);
	serpent_round(&w0, &w1, &w2, &w3, 23, s);
	serpent_round(&w0, &w1, &w2, &w3, 24, s);
	serpent_round(&w0, &w1, &w2, &w3, 25, s);
	serpent_round(&w0, &w1, &w2, &w3, 26, s);
	serpent_round(&w0, &w1, &w2, &w3, 27, s);
	serpent_round(&w0, &w1, &w2, &w3, 28, s);
	serpent_round(&w0, &w1, &w2, &w3, 29, s);
	serpent_round(&w0, &w1, &w2, &w3, 30, s);

	serpent_addRoundKey(&w0, &w1, &w2, &w3, 31, s);
	applySBox(&w0, &w1, &w2, &w3, 7);	/* the last round used S7 */
	serpent_addRoundKey(&w0, &w1, &w2, &w3, 32, s);

	serpent_store32(x0, w0);

	serpent_store32(x1, w1);

	serpent_store32(x2, w2);

	serpent_store32(x3, w3);
}

void serpent_decrypt_block(uint8_t *x0, uint8_t *x1, uint8_t *x2, uint8_t *x3, const struct Serpent *s)
{
	uint32_t w0 = serpent_load32(x0);
	uint32_t w1 = serpent_load32(x1);
	uint32_t w2 = serpent_load32(x2);
	uint32_t w3 = serpent_load32(x3);

	serpent_addRoundKey(&w0, &w1, &w2, &w3, 32, s);
	applyInvSBox(&w0, &w1, &w2, &w3, 7);	/* the last round used S7 */
	serpent_addRoundKey(&w0, &w1, &w2, &w3, 31, s);

	for (int i = 30; i >= 0; --i)
	{
		serpent_invRound(&w0, &w1, &w2, &w3, i, s);
	}

	serpent_store32(x0, w0);

	serpent_store32(x1, w1);

	serpent_store32(x2, w2);

	serpent_store32(x3, w3);
}

int serpent_generateKeysSelf(BlockCipher *self, const uint8_t *key, size_t len)
{
	struct Serpent *s = self->cipherState;
	if (!serpent_keyOk(key, len))
	{
		memset(s, 0, sizeof(*s));
		return 0;
	}
	*s = serpent_generateKeys(key, len);
	return 1;
}

void serpent_encryptBlock(BlockCipher *self, uint8_t *block)
{
	serpent_encrypt_block(block, block + 4, block + 8, block + 12, self->cipherState);
}

void serpent_decryptBlock(BlockCipher *self, uint8_t *block)
{
	serpent_decrypt_block(block, block + 4, block + 8, block + 12, self->cipherState);
}

BlockCipher serpent_cipher(void *state)
{
	BlockCipher c;
	c.blockSize = 16;
	c.cipherState = state;
	c.generateKeys = serpent_generateKeysSelf;
	c.keyOk = serpent_keyOk;
	c.encryptBlock = serpent_encryptBlock;
	c.decryptBlock = serpent_decryptBlock;
	return c;
}
