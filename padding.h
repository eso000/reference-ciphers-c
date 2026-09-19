#ifndef __PADDING_
#define __PADDING_

#include <stdint.h>

uint8_t *padPKCS(uint8_t *pvec, int size, int missing);

uint8_t *padZeros(uint8_t *pvec, int size, int missing);

uint8_t *padANSIX923(uint8_t *pvec, int size, int missing);

uint8_t *padISO78164(uint8_t *pvec, int size, int missing);

#endif
