#ifndef TWIFISH_HEADER
#define TWIFISH_HEADER

#include <stdint.h>

#include "block/blockcipher.h"

struct Twofish{
    uint32_t Subkeys [40];

    uint32_t Sbox0 [256];
    uint32_t Sbox1 [256];
    uint32_t Sbox2 [256];
    uint32_t Sbox3 [256];
};



struct Twofish twofish_generateKeys(char *mkey);

void twofish_encrypt_block(uint8_t *lb0, uint8_t *lb1, uint8_t *rb0, uint8_t *rb1, const struct Twofish *tf);

void twofish_decrypt_block(uint8_t *lb0, uint8_t *lb1, uint8_t *rb0, uint8_t *rb1, const struct Twofish *tf);

void twofish_generateKeysSelf(BlockCipher *self, char *key);

void twofish_encryptBlock(BlockCipher *self, uint8_t *block);

void twofish_decryptBlock(BlockCipher *self, uint8_t *block);

BlockCipher twofish_cipher(void *state);

#endif
