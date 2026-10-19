#ifndef BLOCKCIPHER_HEADER
#define BLOCKCIPHER_HEADER

#include <stddef.h>
#include <stdint.h>

typedef struct BlockCipher BlockCipher;

struct BlockCipher {
	int blockSize;
	void *cipherState;
	/* Expands key into cipherState, returning 1 on success. If key is not a
	   valid length for this cipher the return is 0 and cipherState is zeroed,
	   so a rejected key can never be mistaken for a usable schedule.

	   Keys are raw bytes: len is the key length in bytes, not characters, and
	   a NULL key is rejected outright. Each cipher's accepted lengths are
	   documented on its own generateKeys. */
	int (*generateKeys)(BlockCipher *self, const uint8_t *key, size_t len);
	/* Returns 1 if this cipher accepts key, without reading or writing any
	   state. generateKeys routes through the same check, so a caller can ask
	   the question up front and the two answers cannot disagree. */
	int (*keyOk)(const uint8_t *key, size_t len);
	void (*encryptBlock)(BlockCipher *self, uint8_t *block);
	void (*decryptBlock)(BlockCipher *self, uint8_t *block);
};

/* Mode wrappers. plt is len bytes, enciphered in place.

   ECB, CBC and PCBC are block modes: they need len to be a whole number of
   blocks. A trailing partial block is left untouched and is not reported --
   the functions return void, so callers must pad to blockSize first (padding.h
   has the schemes). Pass a length that is not a multiple of blockSize and the
   tail simply comes back unchanged.

   CFB, OFB and CTR are keystream modes and take any length. When len is not a
   multiple of blockSize the final partial block is XORed against the leading
   bytes of one more keystream block, which is what the Python reference does;
   nothing is written past the len bytes.

   iv is one block for every mode except ECB. The keystream modes and
   cipherEncryptCBC read it and leave the caller's copy alone.
   cipherDecryptCBC and cipherDecryptPCBC advance it, so a caller that wants
   the original back must keep its own copy. */

void cipherEncryptECB(BlockCipher *c, uint8_t *plt, int len);

void cipherDecryptECB(BlockCipher *c, uint8_t *plt, int len);

void cipherEncryptCBC(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherDecryptCBC(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherEncryptPCBC(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherDecryptPCBC(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherEncryptCFB(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherDecryptCFB(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherEncryptOFB(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherDecryptOFB(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherEncryptCTR(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherDecryptCTR(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

#endif
