#ifndef DES_HEADER
#define DES_HEADER

#include <stdint.h>

#include "block/blockcipher.h"

struct DES{
	uint64_t Subkeys [16];
	uint8_t use_alt;
};

/* des_generateKeys returns a zeroed struct if key is NULL or not 8 bytes,
   i.e. a 64-bit key. */
struct DES des_generateKeys(const uint8_t *key, size_t len);

/* Returns 1 if key is a length DES accepts. generateKeys uses the same check,
   so a caller can ask before building a schedule. */
int des_keyOk(const uint8_t *key, size_t len);

uint64_t des_ip_perm_alt(uint64_t block);

uint64_t des_fp_perm_alt(uint64_t block);

void des_encrypt_block(uint8_t *block, const struct DES *d);

void des_decrypt_block(uint8_t *block, const struct DES *d);

/* Returns 1 on success, 0 if key is NULL or not a valid DES key length. */
int des_generateKeysSelf(BlockCipher *self, const uint8_t *key, size_t len);

void des_encryptBlock(BlockCipher *self, uint8_t *block);

void des_decryptBlock(BlockCipher *self, uint8_t *block);

BlockCipher des_cipher(void *state);

#endif
