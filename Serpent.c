#include <string.h>

#include "Serpent.h"

static const uint8_t invSBox [8][16] = {
	{13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 },
	{ 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 },
	{12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 },
	{ 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 },
	{ 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 },
	{ 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 },
	{15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 },
	{ 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 }
};

#define rotl(xr, times) (((xr) >> (times)) | ((xr) << (32 - (times))))

#define rotr(xr, times) (((xr) << (times)) | ((xr) >> (32 - (times))))

#define LT(x0, x1, x2, x3){\
		x0 = rotl(x0, 13);\
		x2 = rotl(x2, 3);\
		x1 = x1^x0^x2;\
		x3 = x3^x2^(x0>>3);\
		x1 = rotl(x1, 1);\
		x3 = rotl(x3, 7);\
		x0 = x0^x1^x3;\
		x2 = x2^x3^(x1>>7);\
		x0 = rotl(x0, 5);\
		x2 = rotl(x2, 22);}

#define invLT(x0, x1, x2, x3){\
		x2 = rotr(x2, 22);\
		x0 = rotr(x0, 5);\
		x2 = x2^x3^(x1>>7);\
		x0 = x0^x1^x3;\
		x3 = rotr(x3, 7);\
		x1 = rotr(x1, 1);\
		x3 = x3^x2^(x0>>3);\
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

static uint8_t serpent_ltb(uint8_t v)
{
	uint8_t result = 0;
	for (int i = 0; i < 8; ++i)
	{
		result += (v >> i) & 1;
		if (i != 7)
			result <<= 1;
	}
	return result;
}

static uint32_t serpent_ltb_str(const char *s)
{
	uint32_t result = 0;
	for (int i = 0; i < 8; i = i + 2)
	{
		uint32_t v = ((uint32_t)hexNibble(s[i]) << 4) | hexNibble(s[i+1]);
		result += serpent_ltb((uint8_t)v);
		if (i != 6)
			result <<= 8;
	}
	return result;
}

static uint32_t serpent_ltb32(int v)
{
	uint32_t result = 0;
	for (int i = 0; i < 32; ++i)
	{
		result += (v >> i) & 1;
		if (i != 31)
			result <<= 1;
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

struct Serpent serpent_generateKeys(char* key)
{
	struct Serpent s;
	char pk[65];
	padKeyBit(key, pk);
	uint32_t wi;
	uint32_t w[140];

	for (int i = 0; i < 64; i = i + 8)
	{
		w[i / 8] = serpent_ltb_str(pk + i);
	}

	for (int i = 8; i < 140; ++i)
	{
		wi = w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ 2644438137u ^ serpent_ltb32(i - 8);
		wi = rotl(wi, 11);
		w[i] = wi;
	}
	for (int i = 0; i < 33; ++i)
	{
		applySBox(&w[4*i+8], &w[4*i+1+8], &w[4*i+2+8], &w[4*i+3+8], (((32 + 3 - i) % 32) % 8));
	}
	for (int i = 0; i < 132; ++i)
		s.Subkeys[i] = w[i + 8];

	return s;
}

void serpent_encrypt_block(uint8_t *x0, uint8_t *x1, uint8_t *x2, uint8_t *x3, const struct Serpent *s)
{
	uint32_t w0 = (serpent_ltb(*x0) << 24) + (serpent_ltb(*(x0+1)) << 16) + (serpent_ltb(*(x0+2)) << 8) + serpent_ltb(*(x0+3));
	uint32_t w1 = (serpent_ltb(*x1) << 24) + (serpent_ltb(*(x1+1)) << 16) + (serpent_ltb(*(x1+2)) << 8) + serpent_ltb(*(x1+3));
	uint32_t w2 = (serpent_ltb(*x2) << 24) + (serpent_ltb(*(x2+1)) << 16) + (serpent_ltb(*(x2+2)) << 8) + serpent_ltb(*(x2+3));
	uint32_t w3 = (serpent_ltb(*x3) << 24) + (serpent_ltb(*(x3+1)) << 16) + (serpent_ltb(*(x3+2)) << 8) + serpent_ltb(*(x3+3));

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
	applySBox(&w0, &w1, &w2, &w3, 31%8);
	w0 ^= s->Subkeys[32<<2];
	w1 ^= s->Subkeys[(32<<2)+1];
	w2 ^= s->Subkeys[(32<<2)+2];
	w3 ^= s->Subkeys[(32<<2)+3];

	*x0 = serpent_ltb(w0>>24 & 0xff); *(x0+1) = serpent_ltb((w0>>16) & 0xff);
	*(x0+2) = serpent_ltb((w0>>8) & 0xff); *(x0+3) = serpent_ltb(w0 & 0xff);

	*x1 = serpent_ltb(w1>>24 & 0xff); *(x1+1) = serpent_ltb((w1>>16) & 0xff);
	*(x1+2) = serpent_ltb((w1>>8) & 0xff); *(x1+3) = serpent_ltb(w1 & 0xff);

	*x2 = serpent_ltb(w2>>24 & 0xff); *(x2+1) = serpent_ltb((w2>>16) & 0xff);
	*(x2+2) = serpent_ltb((w2>>8) & 0xff); *(x2+3) = serpent_ltb(w2 & 0xff);

	*x3 = serpent_ltb(w3>>24 & 0xff); *(x3+1) = serpent_ltb((w3>>16) & 0xff);
	*(x3+2) = serpent_ltb((w3>>8) & 0xff); *(x3+3) = serpent_ltb(w3 & 0xff);
}

void serpent_decrypt_block(uint8_t *x0, uint8_t *x1, uint8_t *x2, uint8_t *x3, const struct Serpent *s)
{
	uint32_t w0 = (serpent_ltb(*x0) << 24) + (serpent_ltb(*(x0+1)) << 16) + (serpent_ltb(*(x0+2)) << 8) + serpent_ltb(*(x0+3));
	uint32_t w1 = (serpent_ltb(*x1) << 24) + (serpent_ltb(*(x1+1)) << 16) + (serpent_ltb(*(x1+2)) << 8) + serpent_ltb(*(x1+3));
	uint32_t w2 = (serpent_ltb(*x2) << 24) + (serpent_ltb(*(x2+1)) << 16) + (serpent_ltb(*(x2+2)) << 8) + serpent_ltb(*(x2+3));
	uint32_t w3 = (serpent_ltb(*x3) << 24) + (serpent_ltb(*(x3+1)) << 16) + (serpent_ltb(*(x3+2)) << 8) + serpent_ltb(*(x3+3));

	w0 ^= s->Subkeys[32<<2];
	w1 ^= s->Subkeys[(32<<2)+1];
	w2 ^= s->Subkeys[(32<<2)+2];
	w3 ^= s->Subkeys[(32<<2)+3];
	applyInvSBox(&w0, &w1, &w2, &w3, 31%8);
	w0 ^= s->Subkeys[31<<2];
	w1 ^= s->Subkeys[(31<<2)+1];
	w2 ^= s->Subkeys[(31<<2)+2];
	w3 ^= s->Subkeys[(31<<2)+3];

	for (int i = 30; i >= 0; --i)
	{
		roundInv(i, w0,w1,w2,w3)
	}

	*x0 = serpent_ltb(w0>>24 & 0xff); *(x0+1) = serpent_ltb((w0>>16) & 0xff);
	*(x0+2) = serpent_ltb((w0>>8) & 0xff); *(x0+3) = serpent_ltb(w0 & 0xff);

	*x1 = serpent_ltb(w1>>24 & 0xff); *(x1+1) = serpent_ltb((w1>>16) & 0xff);
	*(x1+2) = serpent_ltb((w1>>8) & 0xff); *(x1+3) = serpent_ltb(w1 & 0xff);

	*x2 = serpent_ltb(w2>>24 & 0xff); *(x2+1) = serpent_ltb((w2>>16) & 0xff);
	*(x2+2) = serpent_ltb((w2>>8) & 0xff); *(x2+3) = serpent_ltb(w2 & 0xff);

	*x3 = serpent_ltb(w3>>24 & 0xff); *(x3+1) = serpent_ltb((w3>>16) & 0xff);
	*(x3+2) = serpent_ltb((w3>>8) & 0xff); *(x3+3) = serpent_ltb(w3 & 0xff);
}

void serpent_generateKeysSelf(BlockCipher *self, char *key)
{
	*(struct Serpent *)self->cipherState = serpent_generateKeys(key);
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
