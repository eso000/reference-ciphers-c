#ifndef __PADDING_
#define __PADDING_

#include <stdint.h>


int padPKCS(uint8_t *pvec, int size, int missing);

int padZeros(uint8_t *pvec, int size, int missing);

int padANSIX923(uint8_t *pvec, int size, int missing);

int padISO78164(uint8_t *pvec, int size, int missing);

#endif
