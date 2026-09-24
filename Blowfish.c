#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "Blowfish.h"
#include "Blowfish_data.h"



#define byte0(x) (uint8_t)(x>>24)
#define byte1(x) (uint8_t)(x>>16)
#define byte2(x) (uint8_t)(x>>8)
#define byte3(x) (uint8_t)x

#define S(i,n) bf->SBoxes##i[byte##i(n)]
#define F(x) (( ( S(0,x)+ S(1,x))^S(2,x)) + S(3,x))
#define round(l,r,i) l ^= bf->Subkeys[i]; r ^= F(l);

    
void blowfish_encrypt_block(uint8_t *lb,uint8_t *rb, const struct Blowfish *bf)
    {
        uint32_t left, right;
        left = (*lb<<24)| (*(lb+1)<<16)|(*(lb+2)<<8)|*(lb+3);
        right = (*rb<<24)| (*(rb+1)<<16)|(*(rb+2)<<8)|*(rb+3);

        round (left, right, 0) ; round (right, left, 1) ;
        round (left, right, 2) ;  round (right, left, 3) ;
        round (left, right, 4) ;  round (right, left, 5) ;
        round (left, right, 6) ;  round (right, left, 7) ;
        round (left, right, 8) ;  round (right, left, 9) ;
        round (left, right, 10) ; round (right, left, 11) ;
        round (left, right, 12) ; round (right, left, 13) ;
        round (left, right, 14) ; round (right, left, 15) ;
        left ^= bf->Subkeys[16];
        right ^= bf->Subkeys[17];

        *rb = byte0(left); *(rb+1) = byte1(left); *(rb+2) = byte2(left); *(rb+3) = byte3(left);
        *lb = byte0(right); *(lb+1) = byte1(right); *(lb+2) = byte2(right); *(lb+3) = byte3(right);
    }


    void blowfish_decrypt_block(uint8_t *lb,uint8_t *rb, const struct Blowfish *bf)
    {
        uint32_t left, right;
        left = (*lb<<24)| (*(lb+1)<<16)|(*(lb+2)<<8)|*(lb+3);
        right = (*rb<<24)| (*(rb+1)<<16)|(*(rb+2)<<8)|*(rb+3);

        
        round (left, right, 17); round (right, left, 16);
        round (left, right, 15); round (right, left, 14);
        round (left, right, 13); round (right, left, 12);
        round (left, right, 11); round (right, left, 10);
        round (left, right, 9) ; round (right, left, 8) ;
        round (left, right, 7) ; round (right, left, 6) ;
        round (left, right, 5) ; round (right, left, 4) ;
        round (left, right, 3) ; round (right, left, 2) ;
        left ^= bf->Subkeys[1];
        right ^= bf->Subkeys[0];

        *rb = byte0(left); *(rb+1) = byte1(left); *(rb+2) = byte2(left); *(rb+3) = byte3(left);
        *lb = byte0(right); *(lb+1) = byte1(right); *(lb+2) = byte2(right); *(lb+3) = byte3(right);
    }


    
    struct Blowfish blowfish_generateKeys(char* key){



        int t;
        uint32_t keys[18];
        for(int i = 0;i <18;i++){
            t = (8 * i) % strlen(key);
            char temp[9];
            strncpy(temp, key + t, 8);
            temp[8] = '\0';
            keys[i] = strtoul(temp, NULL, 16) ^ PBox[i];
        }
        struct Blowfish blowfish;
        memcpy(blowfish.SBoxes0, SBox[0], sizeof(SBox[0]));
        memcpy(blowfish.SBoxes1, SBox[1], sizeof(SBox[1]));
        memcpy(blowfish.SBoxes2, SBox[2], sizeof(SBox[2]));
        memcpy(blowfish.SBoxes3, SBox[3], sizeof(SBox[3]));
        memcpy(blowfish.Subkeys, keys, sizeof(keys));

        uint8_t P[8] = {(uint8_t)0, (uint8_t)0, (uint8_t)0, (uint8_t)0,(uint8_t)0,(uint8_t)0,(uint8_t)0,(uint8_t)0};

        for(int i=0;i <18; i=i+2){
            blowfish_encrypt_block(&P[0], &P[4], &blowfish);
            blowfish.Subkeys[i] = (P[0]<<24) + (P[1]<<16) + (P[2]<<8) + P[3];
            blowfish.Subkeys[i+1] = (P[4]<<24) + (P[5]<<16) + (P[6]<<8) + P[7];
        }
        for(int i = 0 ;i<256;i=i+2){
            blowfish_encrypt_block(&P[0], &P[4], &blowfish);
            blowfish.SBoxes0[i] = (P[0]<<24) + (P[1]<<16) + (P[2]<<8) + P[3];
            blowfish.SBoxes0[i+1] = (P[4]<<24) + (P[5]<<16) + (P[6]<<8) + P[7];
        }
        for(int i = 0 ;i<256;i=i+2){
            blowfish_encrypt_block(&P[0], &P[4], &blowfish);
            blowfish.SBoxes1[i] = (P[0]<<24) + (P[1]<<16) + (P[2]<<8) + P[3];
            blowfish.SBoxes1[i+1] = (P[4]<<24) + (P[5]<<16) + (P[6]<<8) + P[7];
        }
        for(int i = 0 ;i<256;i=i+2){
            blowfish_encrypt_block(&P[0], &P[4], &blowfish);
            blowfish.SBoxes2[i] = (P[0]<<24) + (P[1]<<16) + (P[2]<<8) + P[3];
            blowfish.SBoxes2[i+1] = (P[4]<<24) + (P[5]<<16) + (P[6]<<8) + P[7];
        }
        for(int i = 0 ;i<256;i=i+2){
            blowfish_encrypt_block(&P[0], &P[4], &blowfish);
            blowfish.SBoxes3[i] = (P[0]<<24) + (P[1]<<16) + (P[2]<<8) + P[3];
            blowfish.SBoxes3[i+1] = (P[4]<<24) + (P[5]<<16) + (P[6]<<8) + P[7];
        }

        return blowfish;
    }   
    
void blowfish_generateKeysSelf(BlockCipher *self, char *key)
{
    *(struct Blowfish *)self->cipherState = blowfish_generateKeys(key);
}

void blowfish_encryptBlock(BlockCipher *self, uint8_t *block)
{
    blowfish_encrypt_block(block, block + 4, (const struct Blowfish *)self->cipherState);
}

void blowfish_decryptBlock(BlockCipher *self, uint8_t *block)
{
    blowfish_decrypt_block(block, block + 4, (const struct Blowfish *)self->cipherState);
}

BlockCipher blowfish_cipher(void *state)
{
    BlockCipher c = {8, state, blowfish_generateKeysSelf, blowfish_encryptBlock, blowfish_decryptBlock};
    return c;
}
