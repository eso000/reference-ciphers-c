#ifndef BLOWFISH_HEADER
#define BLOWFISH_HEADER

#include <stdint.h>

#include "block/blockcipher.h"

struct Blowfish{
	uint32_t SBoxes0 [256];
	uint32_t SBoxes1 [256];
	uint32_t SBoxes2 [256];
	uint32_t SBoxes3 [256];
	uint32_t Subkeys [18];
};

struct Blowfish blowfish_generateKeys(char* key);

void blowfish_encrypt_block(uint8_t *lb, uint8_t *rb, const struct Blowfish *bf);

void blowfish_decrypt_block(uint8_t *lb, uint8_t *rb, const struct Blowfish *bf);

void blowfish_generateKeysSelf(BlockCipher *self, char *key);

void blowfish_encryptBlock(BlockCipher *self, uint8_t *block);

void blowfish_decryptBlock(BlockCipher *self, uint8_t *block);

BlockCipher blowfish_cipher(void *state);

#endif
