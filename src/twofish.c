#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "block/twofish.h"
#include "twofish_data.h"
#include "force_inline.h"

FORCE_INLINE uint8_t byte0(uint32_t x) { return (uint8_t)(x >> 24); }
FORCE_INLINE uint8_t byte1(uint32_t x) { return (uint8_t)(x >> 16); }
FORCE_INLINE uint8_t byte2(uint32_t x) { return (uint8_t)(x >> 8); }
FORCE_INLINE uint8_t byte3(uint32_t x) { return (uint8_t)x; }

FORCE_INLINE uint32_t rotl(uint32_t x, int n)
{
	return (x << n) | (x >> (32 - n));
}

FORCE_INLINE uint32_t rotr(uint32_t x, int n)
{
	return (x >> n) | (x << (32 - n));
}

FORCE_INLINE uint32_t load32_le(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

FORCE_INLINE void store32_le(uint8_t *p, uint32_t w)
{
	p[0] = byte3(w);
	p[1] = byte2(w);
	p[2] = byte1(w);
	p[3] = byte0(w);
}

/* Pseudo-Hadamard transform: a' = a + b, b' = a + 2b. */
FORCE_INLINE void twofish_pht(uint32_t *a, uint32_t *b)
{
	uint32_t t = *a;
	*a = *a + *b;
	*b = t + (*b << 1);
}

/* Multiplies the four bytes of t by the MDS matrix. */
FORCE_INLINE uint32_t twofish_mds(uint32_t t)
{
	return (uint32_t)(byte3(t) ^ MDSEF[byte2(t)] ^ MDS5B[byte1(t)] ^ MDS5B[byte0(t)])
		| (uint32_t)(MDS5B[byte3(t)] ^ MDSEF[byte2(t)] ^ MDSEF[byte1(t)] ^ byte0(t)) << 8
		| (uint32_t)(MDSEF[byte3(t)] ^ MDS5B[byte2(t)] ^ byte1(t) ^ MDSEF[byte0(t)]) << 16
		| (uint32_t)(MDSEF[byte3(t)] ^ byte2(t) ^ MDSEF[byte1(t)] ^ MDS5B[byte0(t)]) << 24;
}

/* The h function for 128, 192 and 256-bit keys: the q-permutation chain for
   that key length, followed by the MDS multiply. Only the key schedule uses
   it; encryption goes through the precomputed Sbox0..3 tables instead. */
static uint32_t twofish_h128(uint32_t x, const uint8_t *k)
{
	uint32_t t = (uint32_t)q1[q0[q0[byte0(x)] ^ k[0]] ^ k[4]]
		| (uint32_t)q0[q0[q1[byte1(x)] ^ k[1]] ^ k[5]] << 8
		| (uint32_t)q1[q1[q0[byte2(x)] ^ k[2]] ^ k[6]] << 16
		| (uint32_t)q0[q1[q1[byte3(x)] ^ k[3]] ^ k[7]] << 24;
	return twofish_mds(t);
}

static uint32_t twofish_h192(uint32_t x, const uint8_t *k)
{
	uint32_t t = (uint32_t)q1[q0[q0[q1[byte0(x)] ^ k[0]] ^ k[4]] ^ k[8]]
		| (uint32_t)q0[q0[q1[q1[byte1(x)] ^ k[1]] ^ k[5]] ^ k[9]] << 8
		| (uint32_t)q1[q1[q0[q0[byte2(x)] ^ k[2]] ^ k[6]] ^ k[10]] << 16
		| (uint32_t)q0[q1[q1[q0[byte3(x)] ^ k[3]] ^ k[7]] ^ k[11]] << 24;
	return twofish_mds(t);
}

static uint32_t twofish_h256(uint32_t x, const uint8_t *k)
{
	uint32_t t = (uint32_t)q1[q0[q0[q1[q1[byte0(x)] ^ k[0]] ^ k[4]] ^ k[8]] ^ k[12]]
		| (uint32_t)q0[q0[q1[q1[q0[byte1(x)] ^ k[1]] ^ k[5]] ^ k[9]] ^ k[13]] << 8
		| (uint32_t)q1[q1[q0[q0[q0[byte2(x)] ^ k[2]] ^ k[6]] ^ k[10]] ^ k[14]] << 16
		| (uint32_t)q0[q1[q1[q0[q1[byte3(x)] ^ k[3]] ^ k[7]] ^ k[11]] ^ k[15]] << 24;
	return twofish_mds(t);
}

/* The g function, through the key-dependent S-boxes built by the schedule. */
FORCE_INLINE uint32_t twofish_g(const struct Twofish *tf, uint32_t x)
{
	return tf->Sbox0[byte0(x)] ^ tf->Sbox1[byte1(x)] ^ tf->Sbox2[byte2(x)] ^ tf->Sbox3[byte3(x)];
}

/* One encryption round: F of the half (l0, l1) is mixed into (*r0, *r1) in
   place. Calling it with the halves swapped on alternate rounds gives the
   Feistel swap without moving any data. */
FORCE_INLINE void twofish_round(int i, uint32_t l0, uint32_t l1, uint32_t *r0, uint32_t *r1, const struct Twofish *tf)
{
	uint32_t t0 = twofish_g(tf, l0);
	uint32_t t1 = twofish_g(tf, rotl(l1, 8));
	twofish_pht(&t0, &t1);
	t0 += tf->Subkeys[2*i+8];
	t1 += tf->Subkeys[2*i+9];
	*r0 = rotr(t0 ^ *r0, 1);
	*r1 = rotl(*r1, 1) ^ t1;
}

/* The inverse round: the same F, with the rotations of the mixing step undone. */
FORCE_INLINE void twofish_invRound(int i, uint32_t l0, uint32_t l1, uint32_t *r0, uint32_t *r1, const struct Twofish *tf)
{
	uint32_t t0 = twofish_g(tf, l0);
	uint32_t t1 = twofish_g(tf, rotl(l1, 8));
	twofish_pht(&t0, &t1);
	t0 += tf->Subkeys[2*i+8];
	t1 += tf->Subkeys[2*i+9];
	*r0 = rotl(*r0, 1) ^ t0;
	*r1 = rotr(t1 ^ *r1, 1);
}

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

/* Twofish accepts a 128, 192 or 256-bit key, i.e. 32, 48 or 64 hex
   characters. */
static int twofish_key_ok(size_t len)
{
	return len == 32 || len == 48 || len == 64;
}

struct Twofish twofish_generateKeys(char * mkey)
{
	size_t ksize = strlen(mkey);

	if (!twofish_key_ok(ksize)){
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
	for (int i = 0; i< n/8; i++)
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
	uint32_t a0, b0;
	for (int i = 0 ; i < 20; ++i){
		a0 = (uint32_t)(2*i) * rho;
		b0 = (uint32_t)(2*i+1) * rho;
		switch (n/8){
			case 4:
				a0 = twofish_h256(a0, &M_even[0]);
				b0 = twofish_h256(b0, &M_odd[0]);
				break;
			case 3:
				a0 = twofish_h192(a0, &M_even[0]);
				b0 = twofish_h192(b0, &M_odd[0]);
				break;
			case 2:
				a0 = twofish_h128(a0, &M_even[0]);
				b0 = twofish_h128(b0, &M_odd[0]);
				break;
		}
		b0 = rotl(b0, 8);
		twofish_pht(&a0, &b0);
		tf.Subkeys[2*i] = a0;
		b0 = rotl(b0, 9);
		tf.Subkeys[2*i+1] = b0;
	}

	return tf;
}

void twofish_encrypt_block(uint8_t *lb0, uint8_t *lb1, uint8_t *rb0, uint8_t *rb1, const struct Twofish *tf)
{
	uint32_t left0 = load32_le(lb0) ^ tf->Subkeys[0];
	uint32_t left1 = load32_le(lb1) ^ tf->Subkeys[1];
	uint32_t right0 = load32_le(rb0) ^ tf->Subkeys[2];
	uint32_t right1 = load32_le(rb1) ^ tf->Subkeys[3];

	twofish_round( 0, left0, left1, &right0, &right1, tf);
	twofish_round( 1, right0, right1, &left0, &left1, tf);
	twofish_round( 2, left0, left1, &right0, &right1, tf);
	twofish_round( 3, right0, right1, &left0, &left1, tf);
	twofish_round( 4, left0, left1, &right0, &right1, tf);
	twofish_round( 5, right0, right1, &left0, &left1, tf);
	twofish_round( 6, left0, left1, &right0, &right1, tf);
	twofish_round( 7, right0, right1, &left0, &left1, tf);
	twofish_round( 8, left0, left1, &right0, &right1, tf);
	twofish_round( 9, right0, right1, &left0, &left1, tf);
	twofish_round(10, left0, left1, &right0, &right1, tf);
	twofish_round(11, right0, right1, &left0, &left1, tf);
	twofish_round(12, left0, left1, &right0, &right1, tf);
	twofish_round(13, right0, right1, &left0, &left1, tf);
	twofish_round(14, left0, left1, &right0, &right1, tf);
	twofish_round(15, right0, right1, &left0, &left1, tf);

	/* The last round's swap is undone, so the halves leave in swapped order. */
	store32_le(lb0, right0 ^ tf->Subkeys[4]);
	store32_le(lb1, right1 ^ tf->Subkeys[5]);
	store32_le(rb0, left0 ^ tf->Subkeys[6]);
	store32_le(rb1, left1 ^ tf->Subkeys[7]);
}

void twofish_decrypt_block(uint8_t *lb0, uint8_t *lb1, uint8_t *rb0, uint8_t *rb1, const struct Twofish *tf)
{
	uint32_t left0 = load32_le(lb0) ^ tf->Subkeys[4];
	uint32_t left1 = load32_le(lb1) ^ tf->Subkeys[5];
	uint32_t right0 = load32_le(rb0) ^ tf->Subkeys[6];
	uint32_t right1 = load32_le(rb1) ^ tf->Subkeys[7];

	twofish_invRound(15, left0, left1, &right0, &right1, tf);
	twofish_invRound(14, right0, right1, &left0, &left1, tf);
	twofish_invRound(13, left0, left1, &right0, &right1, tf);
	twofish_invRound(12, right0, right1, &left0, &left1, tf);
	twofish_invRound(11, left0, left1, &right0, &right1, tf);
	twofish_invRound(10, right0, right1, &left0, &left1, tf);
	twofish_invRound( 9, left0, left1, &right0, &right1, tf);
	twofish_invRound( 8, right0, right1, &left0, &left1, tf);
	twofish_invRound( 7, left0, left1, &right0, &right1, tf);
	twofish_invRound( 6, right0, right1, &left0, &left1, tf);
	twofish_invRound( 5, left0, left1, &right0, &right1, tf);
	twofish_invRound( 4, right0, right1, &left0, &left1, tf);
	twofish_invRound( 3, left0, left1, &right0, &right1, tf);
	twofish_invRound( 2, right0, right1, &left0, &left1, tf);
	twofish_invRound( 1, left0, left1, &right0, &right1, tf);
	twofish_invRound( 0, right0, right1, &left0, &left1, tf);

	store32_le(lb0, right0 ^ tf->Subkeys[0]);
	store32_le(lb1, right1 ^ tf->Subkeys[1]);
	store32_le(rb0, left0 ^ tf->Subkeys[2]);
	store32_le(rb1, left1 ^ tf->Subkeys[3]);
}

int twofish_generateKeysSelf(BlockCipher *self, char *key)
{
	struct Twofish *tf = self->cipherState;
	if (!twofish_key_ok(strlen(key)))
	{
		memset(tf, 0, sizeof(*tf));
		return 0;
	}
	*tf = twofish_generateKeys(key);
	return 1;
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
