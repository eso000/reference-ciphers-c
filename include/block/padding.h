#ifndef __PADDING_
#define __PADDING_

#include <stddef.h>
#include <stdint.h>

uint8_t *padPKCS(uint8_t *pvec, int size, int missing);

uint8_t *padZeros(uint8_t *pvec, int size, int missing);

uint8_t *padANSIX923(uint8_t *pvec, int size, int missing);

uint8_t *padISO78164(uint8_t *pvec, int size, int missing);

/* Trailing-bit-complement padding: fill with 0x00 when the last data byte
   ends in a 1 bit and with 0xFF otherwise (including the empty message), so
   the byte before the padding always differs from the padding itself. */
uint8_t *padTBC(uint8_t *pvec, int size, int missing);

/* Depadding. Each returns the length of the data that remains, in place, or
   -1 when the padding is malformed; the buffer itself is never modified.
   blockSize is the cipher's block size in bytes, and only the last
   min(blockSize, size) bytes are examined.

   The checks mirror the Python reference exactly
   (refciphers.encryption_base.unpad_for_mode), so a buffer Python accepts is
   accepted here and one it rejects is rejected here: the count byte must be
   between 1 and min(blockSize, size) and the filler bytes must match, ISO
   7816-4 must find its 0x80 marker after stripping the zero fill, and TBC's
   final byte must be 0x00 or 0xFF.

   There is deliberately no unpadZeros. Zero padding is indistinguishable from
   a message that happens to end in zero bytes, so removing it would be a
   guess; Python returns such data unchanged for the same reason. Use PKCS or
   ISO 7816-4 when the padding has to come back off. */
int unpadPKCS(const uint8_t *pvec, int size, int blockSize);

int unpadANSIX923(const uint8_t *pvec, int size, int blockSize);

int unpadISO78164(const uint8_t *pvec, int size, int blockSize);

int unpadTBC(const uint8_t *pvec, int size, int blockSize);

#endif
