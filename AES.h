#ifndef AES_HEADER
#define AES_HEADER

#include <stdint.h>

#include "BlockCipher.h"

struct AES{
	uint32_t Subkeys [60];
	int nKeys;
};

struct AES aes_generateKeys(char* key);

void aes_encrypt_block(uint8_t *p, const struct AES *a);

void aes_decrypt_block(uint8_t *p, const struct AES *a);

void aes_generateKeysSelf(BlockCipher *self, char *key);

void aes_encryptBlock(BlockCipher *self, uint8_t *block);

void aes_decryptBlock(BlockCipher *self, uint8_t *block);

BlockCipher aes_cipher(void *state);

#endif
