#ifndef BLOWFISH_HEADER
#define BLOWFISH_HEADER

#include <stdint.h>

struct Blowfish{
	uint32_t SBoxes0 [256];
	uint32_t SBoxes1 [256];
	uint32_t SBoxes2 [256];
	uint32_t SBoxes3 [256];
	uint32_t Subkeys [18];
};

struct Blowfish blowfish_generateKeys(char* key);

void blowfish_encrypt_block(uint8_t *lb, uint8_t *rb, struct Blowfish bf);

void blowfish_decrypt_block(uint8_t *lb, uint8_t *rb, struct Blowfish bf);

void blowfish_encryptECB(uint8_t *plt, int len, struct Blowfish bf);

void blowfish_decryptECB(uint8_t *plt, int len, struct Blowfish bf);

void blowfish_encryptCBC(uint8_t *plt, int len, uint8_t *iv, struct Blowfish bf);

void blowfish_encryptPCBC(uint8_t *plt, int len, uint8_t *iv, struct Blowfish bf);

void blowfish_encryptCFB(uint8_t *plt, int len, uint8_t *iv, struct Blowfish bf);

uint8_t *blowfish_encrypt(uint8_t *plt, uint8_t *iv, struct Blowfish bf);

#endif
