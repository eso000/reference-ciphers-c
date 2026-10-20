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

/* blowfish_generateKeys returns a zeroed struct if key is NULL or not 4 to
   56 bytes, i.e. a 32- to 448-bit key. Every length in the range is usable:
   the schedule cycles key bytes with (4 * i) % len, which is the algorithm's
   own rule and needs no alignment. */
struct Blowfish blowfish_generateKeys(const uint8_t *key, size_t len);

/* Returns 1 if key is a length Blowfish accepts. generateKeys uses the same
   check, so a caller can ask before building a schedule. */
int blowfish_keyOk(const uint8_t *key, size_t len);

void blowfish_encrypt_block(uint8_t *block, const struct Blowfish *bf);

void blowfish_decrypt_block(uint8_t *block, const struct Blowfish *bf);

/* Returns 1 on success, 0 if key is NULL or not a valid Blowfish key length. */
int blowfish_generateKeysSelf(BlockCipher *self, const uint8_t *key, size_t len);

void blowfish_encryptBlock(BlockCipher *self, uint8_t *block);

void blowfish_decryptBlock(BlockCipher *self, uint8_t *block);

BlockCipher blowfish_cipher(void *state);

#endif
