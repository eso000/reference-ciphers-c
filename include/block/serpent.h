#ifndef SERPENT_HEADER
#define SERPENT_HEADER

#include <stdint.h>

#include "block/blockcipher.h"

struct Serpent {
    uint32_t Subkeys[132];
};

/* serpent_generateKeys returns a zeroed struct if key is NULL, empty or
   longer than 32 bytes. Shorter keys are accepted and padded as the spec's
   Section 3 requires, so 1 to 32 bytes all give a usable schedule. The spec
   allows keys down to a single bit; a byte array cannot express a sub-byte
   key, so a full byte is the smallest here. */
struct Serpent serpent_generateKeys(const uint8_t *key, size_t len);

/* Returns 1 if key is a length Serpent accepts. generateKeys uses the same
   check, so a caller can ask before building a schedule. */
int serpent_keyOk(const uint8_t *key, size_t len);

void serpent_encrypt_block(uint8_t *x0, uint8_t *x1, uint8_t *x2, uint8_t *x3,
                           const struct Serpent *s);

void serpent_decrypt_block(uint8_t *x0, uint8_t *x1, uint8_t *x2, uint8_t *x3,
                           const struct Serpent *s);

/* Returns 1 on success, 0 if key is NULL, empty or over-long. */
int serpent_generateKeysSelf(BlockCipher *self, const uint8_t *key, size_t len);

void serpent_encryptBlock(BlockCipher *self, uint8_t *block);

void serpent_decryptBlock(BlockCipher *self, uint8_t *block);

BlockCipher serpent_cipher(void *state);

#endif
