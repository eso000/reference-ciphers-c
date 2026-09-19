#ifndef BLOCKCIPHER_HEADER
#define BLOCKCIPHER_HEADER

#include <stdint.h>

typedef struct BlockCipher BlockCipher;

struct BlockCipher {
	int blockSize;
	void *cipherState;
	void (*generateKeys)(BlockCipher *self, char *key);
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
