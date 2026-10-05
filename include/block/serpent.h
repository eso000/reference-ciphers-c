#ifndef SERPENT_HEADER
#define SERPENT_HEADER

#include <stdint.h>

#include "block/blockcipher.h"

struct Serpent{
	uint32_t Subkeys [132];
};

/* serpent_generateKeys returns a zeroed struct if key is empty or longer than
   64 hex characters. Shorter keys are accepted and padded as the spec's
   Section 3 requires, so 2 to 64 hex characters all give a usable schedule. */
struct Serpent serpent_generateKeys(char* key);

void serpent_encrypt_block(uint8_t *x0, uint8_t *x1, uint8_t *x2, uint8_t *x3, const struct Serpent *s);

void serpent_decrypt_block(uint8_t *x0, uint8_t *x1, uint8_t *x2, uint8_t *x3, const struct Serpent *s);

/* Returns 1 on success, 0 if key is empty or over-long. */
int serpent_generateKeysSelf(BlockCipher *self, char *key);

void serpent_encryptBlock(BlockCipher *self, uint8_t *block);

void serpent_decryptBlock(BlockCipher *self, uint8_t *block);

BlockCipher serpent_cipher(void *state);

#endif
