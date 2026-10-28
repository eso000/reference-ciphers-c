#ifndef BLOCKCIPHER_HEADER
#define BLOCKCIPHER_HEADER

#include <stddef.h>
#include <stdint.h>

typedef struct BlockCipher BlockCipher;

struct BlockCipher {
    int blockSize;
    void *cipherState;
    /* Expands key into cipherState, returning 1 on success. If key is not a
       valid length for this cipher the return is 0 and cipherState is zeroed,
       so a rejected key can never be mistaken for a usable schedule.

       Keys are raw bytes: len is the key length in bytes, not characters, and
       a NULL key is rejected outright. Each cipher's accepted lengths are
       documented on its own generateKeys. */
    int (*generateKeys)(BlockCipher *self, const uint8_t *key, size_t len);
    /* Returns 1 if this cipher accepts key, without reading or writing any
       state. generateKeys routes through the same check, so a caller can ask
       the question up front and the two answers cannot disagree. */
    int (*keyOk)(const uint8_t *key, size_t len);
    void (*encryptBlock)(BlockCipher *self, uint8_t *block);
    void (*decryptBlock)(BlockCipher *self, uint8_t *block);
};

/* Mode wrappers. plt is len bytes, enciphered in place.

   ECB, CBC and PCBC are block modes: they need len to be a whole number of
   blocks. A trailing partial block is left untouched and is not reported --
   the functions return void, so callers must pad to blockSize first (padding.h
   has the schemes). Pass a length that is not a multiple of blockSize and the
   tail simply comes back unchanged. cipherEncrypt and cipherDecrypt below do
   that padding and unpadding for a whole message; these wrappers stay the
   block-only engine they call.

   CFB, OFB and CTR are keystream modes and take any length. When len is not a
   multiple of blockSize the final partial block is XORed against the leading
   bytes of one more keystream block, which is what the Python reference does;
   nothing is written past the len bytes.

   iv is one block for every mode except ECB. The keystream modes and
   cipherEncryptCBC read it and leave the caller's copy alone.
   cipherDecryptCBC and cipherDecryptPCBC advance it, so a caller that wants
   the original back must keep its own copy. */

void cipherEncryptECB(BlockCipher *c, uint8_t *plt, int len);

void cipherDecryptECB(BlockCipher *c, uint8_t *plt, int len);

void cipherEncryptCBC(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherDecryptCBC(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherEncryptPCBC(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherDecryptPCBC(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherEncryptCFB(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherDecryptCFB(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherEncryptOFB(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherDecryptOFB(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherEncryptCTR(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

void cipherDecryptCTR(BlockCipher *c, uint8_t *plt, int len, uint8_t *iv);

/* Whole-message encryption and decryption: the mode dispatch plus the padding
   stage the mode wrappers above leave to the caller. This is the C equivalent
   of the Python reference's encrypt/decrypt.

   The mode wrappers take a raw mode; these two take CipherMode. The block
   modes (ECB, CBC, PCBC) are negative and need padding, the keystream modes
   (CFB, OFB, CTR) are positive and ignore padding entirely, so "does this mode
   need padding?" is exactly mode < 0. The enum's values are load-bearing and
   are documented so, not incidental. */
typedef enum CipherMode {
    CIPHER_ECB = -3,
    CIPHER_CBC = -2,
    CIPHER_PCBC = -1,
    CIPHER_CFB = 1,
    CIPHER_OFB = 2,
    CIPHER_CTR = 3
} CipherMode;

/* Padding schemes, mirroring the Python reference's names. Every scheme except
   PAD_NONE and PAD_ZERO pads by blockSize - inLen % blockSize bytes, i.e. a
   whole extra block when inLen is already aligned, so depadding always has a
   count to read. */
typedef enum PaddingScheme {
    PAD_NONE,     /* no padding: inLen must already be a multiple of blockSize */
    PAD_ZERO,     /* fill to the block boundary; cannot be removed again */
    PAD_PKCS,     /* count byte, 1..blockSize */
    PAD_ANSIX923, /* zeros then the count byte */
    PAD_ISO78164, /* 0x80 then zeros */
    PAD_TBC       /* complement of the final data bit */
} PaddingScheme;

/* Encrypt in bytes of plaintext under mode, applying pad for the block modes.

   iv is one block for every mode except ECB. Pass NULL and ivLen 0 for ECB,
   which takes no IV; pass a pointer to blockSize bytes and ivLen == blockSize
   for every other mode. Any other ivLen is rejected before any work, as is an
   unknown mode or padding scheme.

   For a block mode PAD_NONE returns -1 unless inLen is already a multiple of
   blockSize. PAD_ZERO fills only to the boundary and cannot be reversed, so
   cipherDecrypt returns that fill still attached, exactly as Python's
   unpad_for_mode does.

   On success *out is a freshly malloc'd buffer of *outLen bytes that the caller
   frees, and 0 is returned. On failure -1 is returned and *out is untouched. */
int cipherEncrypt(BlockCipher *c, CipherMode mode, const uint8_t *iv, size_t ivLen,
                  const uint8_t *in, size_t inLen, PaddingScheme pad, uint8_t **out,
                  size_t *outLen);

/* Decrypt in bytes of ciphertext under mode, removing pad for the block modes.

   A block-mode ciphertext must be a whole number of blocks; malformed padding
   is rejected with -1 and nothing is returned. Keystream modes take any length
   and ignore pad. IV rules are the same as cipherEncrypt. The caller's iv is
   never modified, unlike the raw cipherDecryptCBC/PCBC wrappers. */
int cipherDecrypt(BlockCipher *c, CipherMode mode, const uint8_t *iv, size_t ivLen,
                  const uint8_t *in, size_t inLen, PaddingScheme pad, uint8_t **out,
                  size_t *outLen);

#endif
