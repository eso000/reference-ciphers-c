#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "block/twofish.h"
#include "twofish_data.h"


#define byte0(x) (uint8_t)(x>>24)
#define byte1(x) (uint8_t)(x>>16)
#define byte2(x) (uint8_t)(x>>8)
#define byte3(x) (uint8_t)x


#define PHT(ax, bx) aph = ax; ax =(ax+bx); bx=(aph+(bx<<1));

#define rotl4(xr) (((xr>>1)|(xr<< 3))&0xf)

#define rotr(xr,times) (((xr << times)|(xr >> 32-times)))

#define rotl(xr,times) (((xr >> times)|(xr << 32-times)))



#define MDSmult(hword) hword = ((byte3(temp)^MDSEF[byte2(temp)]^MDS5B[byte1(temp)]^MDS5B[byte0(temp)]))|\
                                      ((MDS5B[byte3(temp)]^MDSEF[byte2(temp)]^MDSEF[byte1(temp)]^byte0(temp))<<8)|\
                                     ((MDSEF[byte3(temp)]^MDS5B[byte2(temp)]^byte1(temp)^MDSEF[byte0(temp)])<<16)|\
                                     ((MDSEF[byte3(temp)]^byte2(temp)^MDSEF[byte1(temp)]^MDS5B[byte0(temp)])<<24);

#define h128(hword, hkey)  temp = ( q1[q0[q0[byte0(hword)]^*(hkey)]^*(hkey+4)])|\
                                    ((q0[q0[q1[byte1(hword)]^*(hkey+1)]^*(hkey+5)])<<8)|\
                                    ((q1[q1[q0[byte2(hword)]^*(hkey+2)]^*(hkey+6)])<<16)|\
                                    ((q0[q1[q1[byte3(hword)]^*(hkey+3)]^*(hkey+7)])<<24);\
                                    MDSmult(hword)


#define h196(hword, hkey) temp =  ( q1[q0[q0[q1[byte0(hword)]^*(hkey)]^*(hkey+4)]^*(hkey+8)])|\
                                    ((q0[q0[q1[q1[byte1(hword)]^*(hkey+1)]^*(hkey+5)]^*(hkey+9)])<<8)|\
                                    ((q1[q1[q0[q0[byte2(hword)]^*(hkey+2)]^*(hkey+6)]^*(hkey+10)])<<16)|\
                                    ((q0[q1[q1[q0[byte3(hword)]^*(hkey+3)]^*(hkey+7)]^*(hkey+11)])<<24);\
                                    MDSmult(hword)


#define h256(hword, hkey) temp =  ( q1[q0[q0[q1[q1[byte0(hword)]^*(hkey)]^*(hkey+4)]^*(hkey+8)]^*(hkey+12)])|\
                                    ((q0[q0[q1[q1[q0[byte1(hword)]^*(hkey+1)]^*(hkey+5)]^*(hkey+9)]^*(hkey+13)])<<8)|\
                                    ((q1[q1[q0[q0[q0[byte2(hword)]^*(hkey+2)]^*(hkey+6)]^*(hkey+10)]^*(hkey+14)])<<16)|\
                                    ((q0[q1[q1[q0[q1[byte3(hword)]^*(hkey+3)]^*(hkey+7)]^*(hkey+11)]^*(hkey+15)])<<24);\
                                    MDSmult(hword)


#define g(hword, _tf) hword = _tf->Sbox0[byte0(hword)]^ _tf->Sbox1[byte1(hword)]^_tf->Sbox2[byte2(hword)]^ _tf->Sbox3[byte3(hword)];
                             

#define round(i, l0,l1,r0,r1, nl0,nl1, _tf) nl0 = l0; nl1 = rotr(l1,8);\
                                          g(nl0, _tf)\
                                            g(nl1, _tf)\
                                            PHT(nl0,nl1)\
                                            nl0 += _tf->Subkeys[2*i+8];\
                                            nl1 += _tf->Subkeys[2*i+9];\
                                            nl0 = rotl((nl0^r0),1);\
                                            nl1 ^= rotr(r1,1);

#define invround(i, l0,l1,r0,r1, nl0,nl1, _tf) nl0 = l0; nl1 = rotr(l1,8);\
                                          g(nl0, _tf)\
                                            g(nl1, _tf)\
                                            PHT(nl0,nl1)\
                                            nl0 += _tf->Subkeys[2*i+8];\
                                            nl1 += _tf->Subkeys[2*i+9];\
                                            nl0 ^= rotr(r0,1);\
                                            nl1 = rotl((nl1^r1),1);



    uint32_t twofish_multgf(uint32_t a,uint32_t b,uint32_t pol){
        if (b == 0 )
            return 0L;
        uint32_t p = 0;
        while (b != 0){
            if (b%2L == 1)
                p = p^a;
            b = b>>1;
            a = a<<1;
            if (a > 255)
                a = a^pol;            
        }
        return p;
    }

    uint8_t multgf(uint16_t a,uint16_t b){
        if (b == 0 )
            return (uint8_t)0;
        uint16_t p = 0;
        while (b != 0){
            if (b&1)
                p = p^a;
            b = b>>1;
            a = a<<1;
            if (a > 255)
                a = a^333;            
        }
        return (uint8_t)p;
    }

    uint8_t RSAmul(int i, uint8_t *p)
    {
        uint8_t result = 0;
        for (int t = 0; t < 8; ++t)
            result ^= multgf((uint16_t)*(p+t),(uint16_t)RS[i][t]);
        return result;
    }

    struct Twofish twofish_generateKeys(char * mkey)
    {
        size_t ksize = strlen(mkey);

        if (ksize != 32 && ksize != 48 && ksize != 64){
            struct Twofish bad;
            memset(&bad, 0, sizeof(bad));
            return bad;
        }

        int n = (int)ksize/2;

        uint8_t m[32];

        for (int i = 0 ;i < (int)ksize ;i= i+2 ) {
            char temp[3];
            strncpy(temp, mkey + i, 2);
            temp[2] = '\0';
            m[i/2] = (uint8_t)strtoul(temp, NULL, 16);
        }
    
        uint8_t S[n/2];
        for (int i = 0; i< n/8; i = ++i)
        {
            S[4*i]   = RSAmul(0,&m[8*i]);
            S[4*i+1] = RSAmul(1,&m[8*i]);
            S[4*i+2] = RSAmul(2,&m[8*i]);
            S[4*i+3] = RSAmul(3,&m[8*i]);
        }



        uint8_t s0 = 0;
        uint8_t s1 = 0;
        uint8_t s2 = 0;
        uint8_t s3 = 0;

        struct Twofish tf;
        for (int i = 0; i < 256; ++i)
        {
            if(n/2 == 16){
                s0 = q1[q0[q0[q1[q1[i]^S[0]]^S[4]]^S[8]]^S[12]];
                s1 = q0[q0[q1[q1[q0[i]^S[1]]^S[5]]^S[9]]^S[13]];
                s2 = q1[q1[q0[q0[q0[i]^S[2]]^S[6]]^S[10]]^S[14]];
                s3 = q0[q1[q1[q0[q1[i]^S[3]]^S[7]]^S[11]]^S[15]];
            }else if(n/2 == 12){
                s0 = q1[q0[q0[q1[i]^S[0]]^S[4]]^S[8]];
                s1 = q0[q0[q1[q1[i]^S[1]]^S[5]]^S[9]];
                s2 = q1[q1[q0[q0[i]^S[2]]^S[6]]^S[10]];
                s3 = q0[q1[q1[q0[i]^S[3]]^S[7]]^S[11]];
            }else if(n/2 == 8){
                s0 = q1[q0[q0[i]^S[0]]^S[4]];
                s1 = q0[q0[q1[i]^S[1]]^S[5]];
                s2 = q1[q1[q0[i]^S[2]]^S[6]];
                s3 = q0[q1[q1[i]^S[3]]^S[7]];
            }

            tf.Sbox3[i] =((uint32_t)s0 |((uint32_t)MDS5B[s0]<<8)|((uint32_t)MDSEF[s0]<<16)|((uint32_t)MDSEF[s0]<<24));
            tf.Sbox2[i] =((uint32_t)MDSEF[s1]|((uint32_t)MDSEF[s1]<<8)|((uint32_t)MDS5B[s1]<<16)|((uint32_t)s1<<24));
            tf.Sbox1[i] =((uint32_t)MDS5B[s2]|((uint32_t)MDSEF[s2]<<8)|((uint32_t)s2<<16)|((uint32_t)MDSEF[s2]<<24));
            tf.Sbox0[i] =((uint32_t)MDS5B[s3]|((uint32_t)s3<<8)|((uint32_t)MDSEF[s3]<<16)|((uint32_t)MDS5B[s3]<<24));                    
        }

        uint8_t M_odd[n/2];
        uint8_t M_even[n/2];
        int i_even = 0;
        int i_odd = 0;
        for (int i = 0;i < n; i = i+4){
            if ((i/4)%2 == 1){
                M_odd[n/2-i_odd-4] = m[i];
                M_odd[n/2-i_odd-3] = m[i+1];
                M_odd[n/2-i_odd-2] = m[i+2];
                M_odd[n/2-i_odd-1] = m[i+3];
                i_odd += 4;
            }else{
                M_even[n/2-i_even-4] = m[i];
                M_even[n/2-i_even-3] = m[i+1];
                M_even[n/2-i_even-2] = m[i+2];
                M_even[n/2-i_even-1] = m[i+3];
                i_even += 4;
            }
        }

        
                
        uint32_t rho = 16843009;//2**24+2**16+2**8+1
        uint32_t a0, b0, a1, b1, temp, aph;
        for (int i = 0 ; i < 20; ++i){
            a0 = 2*i*rho;
            b0 = (2*i+1)*rho;
            switch (n/8){
                case 4:
                    h256(a0,&M_even[0]);
                    h256(b0,&M_odd[0]);
                    break;
                case 3:
                    h196(a0,&M_even[0]);
                    h196(b0,&M_odd[0]);
                    break;
                case 2:
                    h128(a0,&M_even[0]);
                    h128(b0,&M_odd[0]);
                    break;
            }
            b0 = rotr(b0,8);
            PHT(a0,b0)    
            tf.Subkeys[2*i] = a0;
            b0 = rotr(b0,9);
            tf.Subkeys[2*i+1] = b0;     
        }

        return tf;
    }

    void twofish_encrypt_block(uint8_t *lb0,uint8_t *lb1,uint8_t *rb0,uint8_t *rb1, const struct Twofish *tf)
    {
        uint32_t left0, left1, right0, right1,newl0, newl1, temp, aph;
        
        left0 = (*lb0)| (*(lb0+1)<<8)|(*(lb0+2)<<16)| (*(lb0+3)<<24);
        left1 = (*lb1)| (*(lb1+1)<<8)|(*(lb1+2)<<16)| (*(lb1+3)<<24);
        right0 = (*rb0)| (*(rb0+1)<<8)|(*(rb0+2)<<16)| (*(rb0+3)<<24);
        right1 = (*rb1)| (*(rb1+1)<<8)|(*(rb1+2)<<16)| (*(rb1+3)<<24);
        

        left0 ^= tf->Subkeys[0]; left1 ^= tf->Subkeys[1];
        right0 ^= tf->Subkeys[2]; right1 ^= tf->Subkeys[3];

        round( 0, left0, left1, right0, right1, newl0, newl1, tf)
        round( 1, newl0, newl1, left0, left1, right0, right1, tf)
        round( 2, right0, right1, newl0, newl1, left0, left1, tf)
        round( 3, left0, left1, right0, right1, newl0, newl1, tf)
        round( 4, newl0, newl1, left0, left1, right0, right1, tf)
        round( 5, right0, right1, newl0, newl1, left0, left1, tf)
        round( 6, left0, left1, right0, right1, newl0, newl1, tf)
        round( 7, newl0, newl1, left0, left1, right0, right1, tf)
        round( 8, right0, right1, newl0, newl1, left0, left1, tf)
        round( 9, left0, left1, right0, right1, newl0, newl1, tf)
        round(10, newl0, newl1, left0, left1, right0, right1, tf)
        round(11, right0, right1, newl0, newl1, left0, left1, tf)
        round(12, left0, left1, right0, right1, newl0, newl1, tf)
        round(13, newl0, newl1, left0, left1, right0, right1, tf)
        round(14, right0, right1, newl0, newl1, left0, left1, tf)
        round(15, left0, left1, right0, right1, newl0, newl1, tf)

        left0 ^= tf->Subkeys[4]; left1 ^= tf->Subkeys[5];
        newl0 ^= tf->Subkeys[6]; newl1 ^= tf->Subkeys[7];
        
        *lb0 = byte3(left0); *(lb0+1) = byte2(left0);*(lb0+2) = byte1(left0); *(lb0+3) = byte0(left0);
        *lb1 = byte3(left1); *(lb1+1) = byte2(left1);*(lb1+2) = byte1(left1); *(lb1+3) = byte0(left1);
        *rb0 = byte3(newl0); *(rb0+1) = byte2(newl0);*(rb0+2) = byte1(newl0); *(rb0+3) = byte0(newl0);
        *rb1 = byte3(newl1); *(rb1+1) = byte2(newl1);*(rb1+2) = byte1(newl1); *(rb1+3) = byte0(newl1);
    }

    void twofish_decrypt_block(uint8_t *lb0,uint8_t *lb1,uint8_t *rb0,uint8_t *rb1, const struct Twofish *tf)
    {
        uint32_t left0, left1, right0, right1,newl0, newl1, temp, aph;
        
        left0 = (*lb0)| (*(lb0+1)<<8)|(*(lb0+2)<<16)| (*(lb0+3)<<24);
        left1 = (*lb1)| (*(lb1+1)<<8)|(*(lb1+2)<<16)| (*(lb1+3)<<24);
        right0 = (*rb0)| (*(rb0+1)<<8)|(*(rb0+2)<<16)| (*(rb0+3)<<24);
        right1 = (*rb1)| (*(rb1+1)<<8)|(*(rb1+2)<<16)| (*(rb1+3)<<24);
        
        left0 ^= tf->Subkeys[4]; left1 ^= tf->Subkeys[5];
        right0 ^= tf->Subkeys[6]; right1 ^= tf->Subkeys[7];
        
        invround(15, left0, left1, right0, right1, newl0, newl1, tf)
        invround(14, newl0, newl1, left0, left1, right0, right1, tf)
        invround(13, right0, right1, newl0, newl1, left0, left1, tf)
        invround(12, left0, left1, right0, right1, newl0, newl1, tf)
        invround(11, newl0, newl1, left0, left1, right0, right1, tf)
        invround(10, right0, right1, newl0, newl1, left0, left1, tf)
        invround( 9, left0, left1, right0, right1, newl0, newl1, tf)
        invround( 8, newl0, newl1, left0, left1, right0, right1, tf)
        invround( 7, right0, right1, newl0, newl1, left0, left1, tf)
        invround( 6, left0, left1, right0, right1, newl0, newl1, tf)
        invround( 5, newl0, newl1, left0, left1, right0, right1, tf)
        invround( 4, right0, right1, newl0, newl1, left0, left1, tf)
        invround( 3, left0, left1, right0, right1, newl0, newl1, tf)
        invround( 2, newl0, newl1, left0, left1, right0, right1, tf)
        invround( 1, right0, right1, newl0, newl1, left0, left1, tf)
        invround( 0, left0, left1, right0, right1, newl0, newl1, tf)
    
		left0 ^= tf->Subkeys[0]; left1 ^= tf->Subkeys[1];
		newl0 ^= tf->Subkeys[2]; newl1 ^= tf->Subkeys[3];
		
		*lb0 = byte3(left0); *(lb0+1) = byte2(left0);*(lb0+2) = byte1(left0); *(lb0+3) = byte0(left0);
		*lb1 = byte3(left1); *(lb1+1) = byte2(left1);*(lb1+2) = byte1(left1); *(lb1+3) = byte0(left1);
		*rb0 = byte3(newl0); *(rb0+1) = byte2(newl0);*(rb0+2) = byte1(newl0); *(rb0+3) = byte0(newl0);
		*rb1 = byte3(newl1); *(rb1+1) = byte2(newl1);*(rb1+2) = byte1(newl1); *(rb1+3) = byte0(newl1);
	}


void twofish_generateKeysSelf(BlockCipher *self, char *key)
{
    *(struct Twofish *)self->cipherState = twofish_generateKeys(key);
}

void twofish_encryptBlock(BlockCipher *self, uint8_t *block)
{
    twofish_encrypt_block(block, block + 4, block + 8, block + 12, (const struct Twofish *)self->cipherState);
}

void twofish_decryptBlock(BlockCipher *self, uint8_t *block)
{
    twofish_decrypt_block(block, block + 4, block + 8, block + 12, (const struct Twofish *)self->cipherState);
}

BlockCipher twofish_cipher(void *state)
{
    BlockCipher c = {16, state, twofish_generateKeysSelf, twofish_encryptBlock, twofish_decryptBlock};
    return c;
}

