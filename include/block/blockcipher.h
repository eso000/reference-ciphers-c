#ifndef BLOCKCIPHER_HEADER
#define BLOCKCIPHER_HEADER

#include <stdint.h>

typedef struct BlockCipher BlockCipher;

struct BlockCipher {
	int blockSize;
	void *cipherState;
	/* Expands key into cipherState, returning 1 on success. If key is not a
	   valid length for this cipher the return is 0 and cipherState is zeroed,
	   so a rejected key can never be mistaken for a usable schedule.

	   Keys are NUL-terminated hex strings, so a length here is in hex
	   characters: a 16-byte key is 32 characters, not 16. Each cipher's
	   accepted lengths are documented on its own generateKeysSelf. */
	int (*generateKeys)(BlockCipher *self, char *key);
	void (*encryptBlock)(BlockCipher *self, uint8_t *block);
	void (*decryptBlock)(BlockCipher *self, uint8_t *block);
};

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
