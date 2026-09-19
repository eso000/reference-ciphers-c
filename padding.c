#include "padding.h"

#include <stdlib.h>
#include <string.h>

uint8_t *padPKCS(uint8_t *pvec, int size, int missing)
{
    if (missing <= 0)
        return pvec;

    uint8_t *temp = realloc(pvec, size + missing);

    if (temp == NULL)
        return NULL;

    memset(temp + size, (uint8_t)missing, missing);

    return temp;
}

uint8_t *padZeros(uint8_t *pvec, int size, int missing)
{
    if (missing <= 0)
        return pvec;

    uint8_t *temp = realloc(pvec, size + missing);

    if (temp == NULL)
        return NULL;

    memset(temp + size, 0, missing);

    return temp;
}

uint8_t *padANSIX923(uint8_t *pvec, int size, int missing)
{
    if (missing <= 0)
        return pvec;

    uint8_t *temp = realloc(pvec, size + missing);

    if (temp == NULL)
        return NULL;

    memset(temp + size, 0, missing - 1);
    temp[size + missing - 1] = (uint8_t)missing;

    return temp;
}

uint8_t *padISO78164(uint8_t *pvec, int size, int missing)
{
    if (missing <= 0)
        return pvec;

    uint8_t *temp = realloc(pvec, size + missing);

    if (temp == NULL)
        return NULL;

    temp[size] = (uint8_t)0x80;
    memset(temp + size + 1, 0, missing - 1);

    return temp;
}
