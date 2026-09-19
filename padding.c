#include "padding.h"

#include <stdlib.h>
#include <string.h>

#define realc {\
    uint8_t *temp = realloc(pvec, size+missing);\
\
    if(temp == NULL)\
        return -1;\
    pvec = temp;\
}\

int  padPKCS(uint8_t *pvec, int size, int missing)
{
    realc
    memset(pvec + size, (uint8_t)missing, missing);
    return 0;
}

int  padZeros(uint8_t *pvec, int size, int missing)
{
    realc
    memset(pvec + size, 0, missing);
    return 0;
}

int padANSIX923(uint8_t *pvec, int size, int missing)
{
    realc
    memset(pvec + size, 0, missing - 1);
    pvec[size + missing -1] = (uint8_t)missing;
    return 0;
}

int padISO78164(uint8_t *pvec, int size, int missing)
{
    realc
    pvec[size] = (uint8_t)0x80;
    memset(pvec + size + 1, 0, missing - 1);
    return 0;
}
