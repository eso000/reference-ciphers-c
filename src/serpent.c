#include <string.h>

#include "block/serpent.h"
#include "serpent_data.h"



/* The block is held as four 32-bit words in little-endian bit order, so the
   paper's "<<<" and "<<" (Serpent proposal, Section 3) are plain rotl and
   masked left shifts on those words. */
#define rotl(xr, times) (((xr) << (times)) | ((xr) >> (32 - (times))))

#define rotr(xr, times) (((xr) >> (times)) | ((xr) << (32 - (times))))

/* The ten steps of the paper's linear transformation, in its order. */
#define LT(x0, x1, x2, x3){\
		x0 = rotl(x0, 13);\
		x2 = rotl(x2, 3);\
		x1 = x1^x0^x2;\
		x3 = x3^x2^(x0<<3);\
		x1 = rotl(x1, 1);\
		x3 = rotl(x3, 7);\
		x0 = x0^x1^x3;\
		x2 = x2^x3^(x1<<7);\
		x0 = rotl(x0, 5);\
		x2 = rotl(x2, 22);}

/* The same ten steps in reverse order, with every rotation turned around. */
#define invLT(x0, x1, x2, x3){\
		x2 = rotr(x2, 22);\
		x0 = rotr(x0, 5);\
		x2 = x2^x3^(x1<<7);\
		x0 = x0^x1^x3;\
		x3 = rotr(x3, 7);\
		x1 = rotr(x1, 1);\
		x3 = x3^x2^(x0<<3);\
		x1 = x1^x0^x2;\
		x2 = rotr(x2, 3);\
		x0 = rotr(x0, 13);}

#define SboxstepInv(x) newbits = invSBox[n][(((*x0>>x)&1) <<0 |\
												 ((*x1>>x)&1) <<1 |\
												 ((*x2>>x)&1) <<2 |\
												 ((*x3>>x)&1) <<3 )];\
			nx0 |= ((newbits >> 0)&1) << x;\
			nx1 |= ((newbits >> 1)&1) << x;\
			nx2 |= ((newbits >> 2)&1) << x;\
			nx3 |= ((newbits >> 3)&1) << x;

#define round(i, p0,p1,p2,p3) p0 ^= s->Subkeys[(i<<2)];\
											p1 ^= s->Subkeys[(i<<2)+1];\
											p2 ^= s->Subkeys[(i<<2)+2];\
											p3 ^= s->Subkeys[(i<<2)+3];\
											applySBox(&p0, &p1, &p2, &p3, (i)%8);\
											LT(p0, p1, p2, p3)

#define roundInv(i, p0,p1,p2,p3) invLT(p0, p1, p2, p3);\
											applyInvSBox(&p0, &p1, &p2, &p3, (i)%8);\
											p0 ^= s->Subkeys[(i<<2)];\
											p1 ^= s->Subkeys[(i<<2)+1];\
											p2 ^= s->Subkeys[(i<<2)+2];\
											p3 ^= s->Subkeys[(i<<2)+3];

static uint8_t hexNibble(char c)
{
	if (c >= '0' && c <= '9')
		return (uint8_t)(c - '0');
	if (c >= 'a' && c <= 'f')
		return (uint8_t)(c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (uint8_t)(c - 'A' + 10);
	return 0;
}

static void padKeyBit(const char *key, char out[65])
{
	char k[66];
	if (key[0] == '\0')
	{
		k[0] = '0'; k[1] = '0'; k[2] = '\0';
	}
	else
	{
		strncpy(k, key, 65);
		k[65] = '\0';
		int len = (int)strlen(k);
		if (len % 2 == 1)
		{
			k[len] = '0';
			k[len + 1] = '\0';
		}
	}
	int len = (int)strlen(k);
	if (len >= 64)
	{
		memcpy(out, k, 64);
		out[64] = '\0';
		return;
	}

	char bin[257];
	int n = 0;
	for (int i = 0; i < len; ++i)
	{
		uint8_t v = hexNibble(k[i]);
		for (int b = 3; b >= 0; --b)
			bin[n++] = ((v >> b) & 1) ? '1' : '0';
	}
	/* The spec pads short keys by appending a '1' bit, i.e. a byte of
	   0x01 right after the key bytes. */
	{
		uint8_t pad = 0x01;
		for (int b = 7; b >= 0; --b)
			bin[n++] = ((pad >> b) & 1) ? '1' : '0';
	}
	while (n < 256)
		bin[n++] = '0';

	static const char hexchars[] = "0123456789abcdef";
	for (int i = 0; i < 255; i += 4)
	{
		int v = ((bin[i] - '0') << 3) | ((bin[i+1] - '0') << 2) | ((bin[i+2] - '0') << 1) | (bin[i+3] - '0');
		out[i / 4] = hexchars[v];
	}
	out[64] = '\0';
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

/* The same little-endian word, read from eight hex characters. */
static uint32_t serpent_word_from_hex(const char *s)
{
	uint32_t result = 0;
	for (int i = 0; i < 4; ++i)
	{
		uint32_t byte = ((uint32_t)hexNibble(s[2 * i]) << 4) | hexNibble(s[2 * i + 1]);
		result |= byte << (8 * i);
	}
	return result;
}

static void applySBox(uint32_t *x0, uint32_t *x1, uint32_t *x2, uint32_t *x3, int n)
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

static void applyInvSBox(uint32_t *x0, uint32_t *x1, uint32_t *x2, uint32_t *x3, int n)
{
	uint32_t nx0 = 0;
	uint32_t nx1 = 0;
	uint32_t nx2 = 0;
	uint32_t nx3 = 0;
	uint8_t newbits = 0;

	for (int x = 0; x < 32; ++x)
	{
		SboxstepInv(x)
	}

	*x0 = nx0;
	*x1 = nx1;
	*x2 = nx2;
	*x3 = nx3;
}

/* Serpent accepts any key from 1 to 256 bits. The key arrives as a hex string,
   so 2 to 64 characters, and padKeyBit applies the spec's Section 3 padding to
   anything shorter than 256 bits. Only an empty key and an over-long one are
   rejected: padKeyBit would otherwise turn "" into the "00" key and truncate
   past 64 characters without telling the caller. */
static int serpent_key_ok(size_t len)
{
	return len >= 1 && len <= 64;
}

struct Serpent serpent_generateKeys(char* key)
{
	struct Serpent s;
	char pk[65];
	if (!serpent_key_ok(strlen(key)))
	{
		memset(&s, 0, sizeof(s));
		return s;
	}
	padKeyBit(key, pk);
	uint32_t wi;
	uint32_t w[140];

	for (int i = 0; i < 64; i = i + 8)
	{
		w[i / 8] = serpent_word_from_hex(pk + i);
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

	round( 0,w0,w1,w2,w3)
	round( 1,w0,w1,w2,w3)
	round( 2,w0,w1,w2,w3)
	round( 3,w0,w1,w2,w3)
	round( 4,w0,w1,w2,w3)
	round( 5,w0,w1,w2,w3)
	round( 6,w0,w1,w2,w3)
	round( 7,w0,w1,w2,w3)
	round( 8,w0,w1,w2,w3)
	round( 9,w0,w1,w2,w3)
	round(10,w0,w1,w2,w3)
	round(11,w0,w1,w2,w3)
	round(12,w0,w1,w2,w3)
	round(13,w0,w1,w2,w3)
	round(14,w0,w1,w2,w3)
	round(15,w0,w1,w2,w3)
	round(16,w0,w1,w2,w3)
	round(17,w0,w1,w2,w3)
	round(18,w0,w1,w2,w3)
	round(19,w0,w1,w2,w3)
	round(20,w0,w1,w2,w3)
	round(21,w0,w1,w2,w3)
	round(22,w0,w1,w2,w3)
	round(23,w0,w1,w2,w3)
	round(24,w0,w1,w2,w3)
	round(25,w0,w1,w2,w3)
	round(26,w0,w1,w2,w3)
	round(27,w0,w1,w2,w3)
	round(28,w0,w1,w2,w3)
	round(29,w0,w1,w2,w3)
	round(30,w0,w1,w2,w3)

	w0 ^= s->Subkeys[31<<2];
	w1 ^= s->Subkeys[(31<<2)+1];
	w2 ^= s->Subkeys[(31<<2)+2];
	w3 ^= s->Subkeys[(31<<2)+3];
	applySBox(&w0, &w1, &w2, &w3, 7);	/* the last round used S7 */
	w0 ^= s->Subkeys[32<<2];
	w1 ^= s->Subkeys[(32<<2)+1];
	w2 ^= s->Subkeys[(32<<2)+2];
	w3 ^= s->Subkeys[(32<<2)+3];

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

	w0 ^= s->Subkeys[32<<2];
	w1 ^= s->Subkeys[(32<<2)+1];
	w2 ^= s->Subkeys[(32<<2)+2];
	w3 ^= s->Subkeys[(32<<2)+3];
	applyInvSBox(&w0, &w1, &w2, &w3, 7);	/* the last round used S7 */
	w0 ^= s->Subkeys[31<<2];
	w1 ^= s->Subkeys[(31<<2)+1];
	w2 ^= s->Subkeys[(31<<2)+2];
	w3 ^= s->Subkeys[(31<<2)+3];

	for (int i = 30; i >= 0; --i)
	{
		roundInv(i, w0,w1,w2,w3)
	}

	serpent_store32(x0, w0);

	serpent_store32(x1, w1);

	serpent_store32(x2, w2);

	serpent_store32(x3, w3);
}

int serpent_generateKeysSelf(BlockCipher *self, char *key)
{
	struct Serpent *s = self->cipherState;
	if (!serpent_key_ok(strlen(key)))
	{
		memset(s, 0, sizeof(*s));
		return 0;
	}
	*s = serpent_generateKeys(key);
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
	c.encryptBlock = serpent_encryptBlock;
	c.decryptBlock = serpent_decryptBlock;
	return c;
}
