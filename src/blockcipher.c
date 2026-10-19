#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "block/blockcipher.h"
#include "block/padding.h"

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
	uint8_t *i = plt;
	uint8_t *end = plt + len;

	memcpy(reg, iv, bs);
	for (; i + bs <= end; i += bs)
	{
		c->encryptBlock(c, reg);
		xorBlock(i, reg, bs);
		memcpy(reg, i, bs);
	}
	/* A short final block is XORed against the leading bytes of one more
	   keystream block. The feedback value that would follow it is never used
	   again, so the truncated ciphertext does not have to be padded. */
	if (i < end)
	{
		c->encryptBlock(c, reg);
		xorBlock(i, reg, (int)(end - i));
	}
}

void cipherDecryptCFB(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv)
{
	int bs = c->blockSize;
	uint8_t reg[16];
	uint8_t t[16];
	uint8_t *i = plt;
	uint8_t *end = plt + len;

	memcpy(reg, iv, bs);
	for (; i + bs <= end; i += bs)
	{
		c->encryptBlock(c, reg);
		memcpy(t, i, bs);
		xorBlock(i, reg, bs);
		memcpy(reg, t, bs);
	}
	if (i < end)
	{
		c->encryptBlock(c, reg);
		xorBlock(i, reg, (int)(end - i));
	}
}

void cipherEncryptOFB(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv)
{
	int bs = c->blockSize;
	uint8_t reg[16];
	uint8_t *i = plt;
	uint8_t *end = plt + len;

	memcpy(reg, iv, bs);
	for (; i + bs <= end; i += bs)
	{
		c->encryptBlock(c, reg);
		xorBlock(i, reg, bs);
	}
	if (i < end)
	{
		c->encryptBlock(c, reg);
		xorBlock(i, reg, (int)(end - i));
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
	uint8_t *i = plt;
	uint8_t *end = plt + len;

	memcpy(ctr, iv, bs);
	for (; i + bs <= end; i += bs)
	{
		memcpy(ks, ctr, bs);
		c->encryptBlock(c, ks);
		xorBlock(i, ks, bs);
		incrementCounter(ctr, bs);
	}
	if (i < end)
	{
		memcpy(ks, ctr, bs);
		c->encryptBlock(c, ks);
		xorBlock(i, ks, (int)(end - i));
	}
}

void cipherDecryptCTR(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv)
{
	cipherEncryptCTR(c, plt, len, iv);
}

/* The sign of CipherMode encodes whether the mode needs padding, so this is the
   whole test. */
static int needsPadding(CipherMode mode)
{
	return mode < 0;
}

static int modeKnown(CipherMode mode)
{
	switch (mode)
	{
	case CIPHER_ECB:
	case CIPHER_CBC:
	case CIPHER_PCBC:
	case CIPHER_CFB:
	case CIPHER_OFB:
	case CIPHER_CTR:
		return 1;
	default:
		return 0;
	}
}

/* A switch rather than a range check: PaddingScheme's enumerators are all
   non-negative, so the compiler is free to make the type unsigned, and "pad <
   PAD_NONE" would then be a comparison that is always false. */
static int padKnown(PaddingScheme pad)
{
	switch (pad)
	{
	case PAD_NONE:
	case PAD_ZERO:
	case PAD_PKCS:
	case PAD_ANSIX923:
	case PAD_ISO78164:
	case PAD_TBC:
		return 1;
	default:
		return 0;
	}
}

/* ECB takes no IV; every chained mode takes exactly one block. */
static int ivOk(CipherMode mode, const uint8_t *iv, size_t ivLen, int blockSize)
{
	if (mode == CIPHER_ECB)
		return ivLen == 0;
	return ivLen == (size_t)blockSize && iv != NULL;
}

/* Pick the padding routine by scheme. Only the strict schemes can fail (on
   allocation); PAD_NONE and PAD_ZERO are handled before this is called, and
   PAD_NONE is never passed here. */
static uint8_t *padByScheme(uint8_t *buf, int size, int missing, PaddingScheme pad)
{
	switch (pad)
	{
	case PAD_PKCS:
		return padPKCS(buf, size, missing);
	case PAD_ZERO:
		return padZeros(buf, size, missing);
	case PAD_ANSIX923:
		return padANSIX923(buf, size, missing);
	case PAD_ISO78164:
		return padISO78164(buf, size, missing);
	case PAD_TBC:
		return padTBC(buf, size, missing);
	default:
		return buf;
	}
}

/* Depadding returns the remaining length, or -1 when the padding is malformed.
   PAD_NONE and PAD_ZERO remove nothing, which is Python's unpad_for_mode. */
static int unpadByScheme(const uint8_t *buf, int size, int blockSize, PaddingScheme pad)
{
	switch (pad)
	{
	case PAD_PKCS:
		return unpadPKCS(buf, size, blockSize);
	case PAD_ANSIX923:
		return unpadANSIX923(buf, size, blockSize);
	case PAD_ISO78164:
		return unpadISO78164(buf, size, blockSize);
	case PAD_TBC:
		return unpadTBC(buf, size, blockSize);
	default:
		return size;
	}
}

int cipherEncrypt(BlockCipher *c, CipherMode mode,
		  const uint8_t *iv, size_t ivLen,
		  const uint8_t *in, size_t inLen,
		  PaddingScheme pad, uint8_t **out, size_t *outLen)
{
	int bs = c->blockSize;

	if (!modeKnown(mode) || !ivOk(mode, iv, ivLen, bs))
		return -1;
	if (inLen > (size_t)INT_MAX || inLen > SIZE_MAX - (size_t)bs)
		return -1;
	if (!padKnown(pad))
		return -1;

	/* The strict schemes add a whole extra block when the message is already
	   aligned, so always reserve blockSize bytes beyond the input. */
	uint8_t *buf = malloc(inLen + (size_t)bs);

	if (buf == NULL)
		return -1;

	if (inLen)
		memcpy(buf, in, inLen);

	size_t n = inLen;

	if (needsPadding(mode))
	{
		int missing;

		if (pad == PAD_NONE)
		{
			if (inLen % (size_t)bs != 0)
			{
				free(buf);
				return -1;
			}
			missing = 0;
		}
		else if (pad == PAD_ZERO)
		{
			/* Fills to the boundary only: no extra block when aligned. */
			missing = (int)(((size_t)bs - inLen % (size_t)bs) % (size_t)bs);
		}
		else
		{
			missing = bs - (int)(inLen % (size_t)bs);
		}

		if (missing > 0)
		{
			uint8_t *padded = padByScheme(buf, (int)inLen, missing, pad);

			if (padded == NULL)
			{
				free(buf);
				return -1;
			}
			buf = padded;
		}
		n = inLen + (size_t)missing;
	}

	/* cipherDecryptCBC/PCBC advance the IV they are handed, and the caller's
	   IV must survive, so the engine always gets a private copy. */
	uint8_t ivcopy[16];

	if (mode != CIPHER_ECB)
		memcpy(ivcopy, iv, (size_t)bs);

	switch (mode)
	{
	case CIPHER_ECB:
		cipherEncryptECB(c, buf, (int)n);
		break;
	case CIPHER_CBC:
		cipherEncryptCBC(c, buf, (int)n, ivcopy);
		break;
	case CIPHER_PCBC:
		cipherEncryptPCBC(c, buf, (int)n, ivcopy);
		break;
	case CIPHER_CFB:
		cipherEncryptCFB(c, buf, (int)n, ivcopy);
		break;
	case CIPHER_OFB:
		cipherEncryptOFB(c, buf, (int)n, ivcopy);
		break;
	case CIPHER_CTR:
		cipherEncryptCTR(c, buf, (int)n, ivcopy);
		break;
	default:
		free(buf);
		return -1;
	}

	*out = buf;
	*outLen = n;
	return 0;
}

int cipherDecrypt(BlockCipher *c, CipherMode mode,
		  const uint8_t *iv, size_t ivLen,
		  const uint8_t *in, size_t inLen,
		  PaddingScheme pad, uint8_t **out, size_t *outLen)
{
	int bs = c->blockSize;

	if (!modeKnown(mode) || !ivOk(mode, iv, ivLen, bs))
		return -1;
	if (!padKnown(pad))
		return -1;
	/* A block-mode ciphertext has to be whole blocks before anything runs;
	   unpad reads the final block. */
	if (needsPadding(mode) && inLen % (size_t)bs != 0)
		return -1;
	if (inLen > (size_t)INT_MAX)
		return -1;

	uint8_t *buf = malloc(inLen ? inLen : 1);

	if (buf == NULL)
		return -1;

	if (inLen)
		memcpy(buf, in, inLen);

	uint8_t ivcopy[16];

	if (mode != CIPHER_ECB)
		memcpy(ivcopy, iv, (size_t)bs);

	switch (mode)
	{
	case CIPHER_ECB:
		cipherDecryptECB(c, buf, (int)inLen);
		break;
	case CIPHER_CBC:
		cipherDecryptCBC(c, buf, (int)inLen, ivcopy);
		break;
	case CIPHER_PCBC:
		cipherDecryptPCBC(c, buf, (int)inLen, ivcopy);
		break;
	case CIPHER_CFB:
		cipherDecryptCFB(c, buf, (int)inLen, ivcopy);
		break;
	case CIPHER_OFB:
		cipherDecryptOFB(c, buf, (int)inLen, ivcopy);
		break;
	case CIPHER_CTR:
		cipherDecryptCTR(c, buf, (int)inLen, ivcopy);
		break;
	default:
		free(buf);
		return -1;
	}

	size_t n = inLen;

	if (needsPadding(mode))
	{
		int back = unpadByScheme(buf, (int)inLen, bs, pad);

		if (back < 0)
		{
			free(buf);
			return -1;
		}
		n = (size_t)back;
	}

	*out = buf;
	*outLen = n;
	return 0;
}
