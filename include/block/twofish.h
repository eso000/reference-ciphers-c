#ifndef TWIFISH_HEADER
#define TWIFISH_HEADER

#include <stdint.h>

#include "block/blockcipher.h"

struct Twofish {
    uint32_t Subkeys[40];

    uint32_t Sbox0[256];
    uint32_t Sbox1[256];
    uint32_t Sbox2[256];
    uint32_t Sbox3[256];
};

/* twofish_generateKeys returns a zeroed struct if key is NULL or not 16, 24
   or 32 bytes, i.e. a 128, 192 or 256-bit key. */
struct Twofish twofish_generateKeys(const uint8_t *mkey, size_t ksize);

/* Returns 1 if key is a length Twofish accepts. generateKeys uses the same
   check, so a caller can ask before building a schedule. */
int twofish_keyOk(const uint8_t *key, size_t len);

void twofish_encrypt_block(uint8_t *block, const struct Twofish *tf);

void twofish_decrypt_block(uint8_t *block, const struct Twofish *tf);

/* Returns 1 on success, 0 if key is NULL or not a valid Twofish key length. */
int twofish_generateKeysSelf(BlockCipher *self, const uint8_t *key, size_t len);

void twofish_encryptBlock(BlockCipher *self, uint8_t *block);

void twofish_decryptBlock(BlockCipher *self, uint8_t *block);

BlockCipher twofish_cipher(void *state);

#endif
