#ifndef AES_HEADER
#define AES_HEADER

#include <stdint.h>

#include "block/blockcipher.h"

struct AES{
	uint32_t Subkeys [60];
	int nKeys;
};

/* aes_generateKeys returns a zeroed struct if key is not 32, 48 or 64 hex
   characters, i.e. a 128, 192 or 256-bit key. */
struct AES aes_generateKeys(char* key);

void aes_encrypt_block(uint8_t *p, const struct AES *a);

void aes_decrypt_block(uint8_t *p, const struct AES *a);

/* Returns 1 on success, 0 if key is not a valid AES key length. */
int aes_generateKeysSelf(BlockCipher *self, char *key);

void aes_encryptBlock(BlockCipher *self, uint8_t *block);

void aes_decryptBlock(BlockCipher *self, uint8_t *block);

BlockCipher aes_cipher(void *state);

#endif
