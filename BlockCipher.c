#include <string.h>

#include "BlockCipher.h"

static void xorBlock(uint8_t *dst, const uint8_t *src, int n)
{
	for (int i = 0; i < n; ++i)
		dst[i] ^= src[i];
}

static void incrementCounter(uint8_t *ctr, int n)
{
	for (int i = n - 1; i >= 0; --i)
		if (++ctr[i] != 0)
			break;
}

void cipherEncryptECB(BlockCipher *c, uint8_t *plt, int len)
{
	int bs = c->blockSize;
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
		c->encryptBlock(c, i);
}

void cipherDecryptECB(BlockCipher *c, uint8_t *plt, int len)
{
	int bs = c->blockSize;
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
		c->decryptBlock(c, i);
}

void cipherEncryptCBC(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv)
{
	int bs = c->blockSize;
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
	{
		xorBlock(i, iv, bs);
		c->encryptBlock(c, i);
		iv = i;
	}
}

void cipherDecryptCBC(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv)
{
	int bs = c->blockSize;
	uint8_t t[16];
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
	{
		memcpy(t, i, bs);
		c->decryptBlock(c, i);
		xorBlock(i, iv, bs);
		memcpy(iv, t, bs);
	}
}

void cipherEncryptPCBC(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv)
{
	int bs = c->blockSize;
	uint8_t t[16];
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
	{
		memcpy(t, i, bs);
		xorBlock(i, iv, bs);
		c->encryptBlock(c, i);
		xorBlock(t, i, bs);
		memcpy(iv, t, bs);
	}
}

void cipherDecryptPCBC(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv)
{
	int bs = c->blockSize;
	uint8_t t[16];
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
	{
		memcpy(t, i, bs);
		c->decryptBlock(c, i);
		xorBlock(i, iv, bs);
		xorBlock(t, i, bs);
		memcpy(iv, t, bs);
	}
}

void cipherEncryptCFB(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv)
{
	int bs = c->blockSize;
	uint8_t reg[16];
	memcpy(reg, iv, bs);
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
	{
		c->encryptBlock(c, reg);
		xorBlock(i, reg, bs);
		memcpy(reg, i, bs);
	}
}

void cipherDecryptCFB(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv)
{
	int bs = c->blockSize;
	uint8_t reg[16];
	uint8_t t[16];
	memcpy(reg, iv, bs);
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
	{
		c->encryptBlock(c, reg);
		memcpy(t, i, bs);
		xorBlock(i, reg, bs);
		memcpy(reg, t, bs);
	}
}

void cipherEncryptOFB(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv)
{
	int bs = c->blockSize;
	uint8_t reg[16];
	memcpy(reg, iv, bs);
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
	{
		c->encryptBlock(c, reg);
		xorBlock(i, reg, bs);
	}
}

void cipherDecryptOFB(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv)
{
	cipherEncryptOFB(c, plt, len, iv);
}

void cipherEncryptCTR(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv)
{
	int bs = c->blockSize;
	uint8_t ctr[16];
	uint8_t ks[16];
	memcpy(ctr, iv, bs);
	for (uint8_t *i = plt; i + bs <= plt + len; i += bs)
	{
		memcpy(ks, ctr, bs);
		c->encryptBlock(c, ks);
		xorBlock(i, ks, bs);
		incrementCounter(ctr, bs);
	}
}

void cipherDecryptCTR(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv)
{
	cipherEncryptCTR(c, plt, len, iv);
}
