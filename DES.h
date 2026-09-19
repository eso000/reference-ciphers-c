#ifndef DES_HEADER
#define DES_HEADER

#include <stdint.h>

#include "BlockCipher.h"

struct DES{
	uint64_t Subkeys [16];
};

struct DES des_generateKeys(char* key);

void des_encrypt_block(uint8_t *lb, uint8_t *rb, const struct DES *d);

void des_decrypt_block(uint8_t *lb, uint8_t *rb, const struct DES *d);

void des_generateKeysSelf(BlockCipher *self, char *key);

void des_encryptBlock(BlockCipher *self, uint8_t *block);

void des_decryptBlock(BlockCipher *self, uint8_t *block);

BlockCipher des_cipher(void *state);

#endif
