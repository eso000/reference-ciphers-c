#ifndef SERPENT_HEADER
#define SERPENT_HEADER

#include <stdint.h>

#include "block/blockcipher.h"

struct Serpent{
	uint32_t Subkeys [132];
};

struct Serpent serpent_generateKeys(char* key);

void serpent_encrypt_block(uint8_t *x0, uint8_t *x1, uint8_t *x2, uint8_t *x3, const struct Serpent *s);

void serpent_decrypt_block(uint8_t *x0, uint8_t *x1, uint8_t *x2, uint8_t *x3, const struct Serpent *s);

void serpent_generateKeysSelf(BlockCipher *self, char *key);

void serpent_encryptBlock(BlockCipher *self, uint8_t *block);

void serpent_decryptBlock(BlockCipher *self, uint8_t *block);

BlockCipher serpent_cipher(void *state);

#endif
