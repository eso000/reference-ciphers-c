#ifndef DES_HEADER
#define DES_HEADER

#include <stdint.h>

#include "BlockCipher.h"

struct DES{
	uint64_t Subkeys [16];
	uint8_t use_alt;
};

struct DES des_generateKeys(char* key);

uint64_t des_ip_perm_alt(uint64_t block);

uint64_t des_fp_perm_alt(uint64_t block);

void des_encrypt_block(uint8_t *lb, uint8_t *rb, const struct DES *d);

void des_decrypt_block(uint8_t *lb, uint8_t *rb, const struct DES *d);

void des_generateKeysSelf(BlockCipher *self, char *key);

void des_encryptBlock(BlockCipher *self, uint8_t *block);

void des_decryptBlock(BlockCipher *self, uint8_t *block);

BlockCipher des_cipher(void *state);

#endif
