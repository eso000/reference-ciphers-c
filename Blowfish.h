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





//void encrypt_block(uint8_t *lb,uint8_t *rb);
//
//void decrypt_block(uint8_t *lb,uint8_t *rb);
//
struct Blowfish generateKeys(char* key);
//
//void encryptECB(uint8_t *plt, int len);
//
//void decryptECB(uint8_t *plt, int len);
//
//void encryptCBC(uint8_t *plt, int len, uint8_t *iv);
//
//void encryptPCBC(uint8_t *plt, int len, uint8_t *iv);
//
//void encryptCFB(uint8_t *plt, int len, uint8_t *iv);
//
//uint8_t* blowfish_encrypt(uint8_t* plt, uint8_t* iv)

//void encrypt_File(char* path);

//void decrypt_File(char* path);


#endif
