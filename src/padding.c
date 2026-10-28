#include "block/padding.h"

#include <stdlib.h>
#include <string.h>

uint8_t *padPKCS(uint8_t *pvec, int size, int missing) {
    if (missing <= 0)
        return pvec;

    uint8_t *temp = realloc(pvec, size + missing);

    if (temp == NULL)
        return NULL;

    memset(temp + size, (uint8_t)missing, missing);

    return temp;
}

uint8_t *padZeros(uint8_t *pvec, int size, int missing) {
    if (missing <= 0)
        return pvec;

    uint8_t *temp = realloc(pvec, size + missing);

    if (temp == NULL)
        return NULL;

    memset(temp + size, 0, missing);

    return temp;
}

uint8_t *padANSIX923(uint8_t *pvec, int size, int missing) {
    if (missing <= 0)
        return pvec;

    uint8_t *temp = realloc(pvec, size + missing);

    if (temp == NULL)
        return NULL;

    memset(temp + size, 0, missing - 1);
    temp[size + missing - 1] = (uint8_t)missing;

    return temp;
}

uint8_t *padISO78164(uint8_t *pvec, int size, int missing) {
    if (missing <= 0)
        return pvec;

    uint8_t *temp = realloc(pvec, size + missing);

    if (temp == NULL)
        return NULL;

    temp[size] = (uint8_t)0x80;
    memset(temp + size + 1, 0, missing - 1);

    return temp;
}

uint8_t *padTBC(uint8_t *pvec, int size, int missing) {
    if (missing <= 0)
        return pvec;

    /* Trailing bit complement: the filler byte is the complement of the last
       bit of the data, so the boundary byte is always visible. An empty
       message has no last bit and uses 0xFF, as Python does. */
    uint8_t fill = (size > 0 && (pvec[size - 1] & 1)) ? 0x00 : 0xFF;

    uint8_t *temp = realloc(pvec, size + missing);

    if (temp == NULL)
        return NULL;

    memset(temp + size, fill, missing);

    return temp;
}

/* Shared by the two count-byte schemes: the final byte is the length of the
   padding, and it has to be between 1 and the smaller of the block size and
   the data length. Anything else cannot be a padding this cipher produced. */
static int unpadCount(const uint8_t *pvec, int size, int blockSize) {
    if (pvec == NULL || blockSize < 1 || size < 1)
        return -1;

    int max = size < blockSize ? size : blockSize;
    int count = pvec[size - 1];

    if (count < 1 || count > max)
        return -1;

    return count;
}

int unpadPKCS(const uint8_t *pvec, int size, int blockSize) {
    int count = unpadCount(pvec, size, blockSize);

    if (count < 0)
        return -1;

    for (int i = 0; i < count; ++i)
        if (pvec[size - 1 - i] != (uint8_t)count)
            return -1;

    return size - count;
}

int unpadANSIX923(const uint8_t *pvec, int size, int blockSize) {
    int count = unpadCount(pvec, size, blockSize);

    if (count < 0)
        return -1;

    /* Everything before the count byte must be zero. */
    for (int i = 1; i < count; ++i)
        if (pvec[size - 1 - i] != 0)
            return -1;

    return size - count;
}

int unpadISO78164(const uint8_t *pvec, int size, int blockSize) {
    if (pvec == NULL || blockSize < 1 || size < 1)
        return -1;

    int tail = size < blockSize ? size : blockSize;
    const uint8_t *t = pvec + size - tail;

    /* Strip the zero fill, then require the 0x80 marker that precedes it. */
    int end = tail;
    while (end > 0 && t[end - 1] == 0x00)
        --end;

    if (end == 0 || t[end - 1] != 0x80)
        return -1;

    return size - tail + end - 1;
}

int unpadTBC(const uint8_t *pvec, int size, int blockSize) {
    if (pvec == NULL || blockSize < 1 || size < 1)
        return -1;

    int tail = size < blockSize ? size : blockSize;
    const uint8_t *t = pvec + size - tail;

    uint8_t last = t[tail - 1];

    if (last != 0x00 && last != 0xFF)
        return -1;

    int count = 0;
    while (count < tail && t[tail - 1 - count] == last)
        ++count;

    return size - count;
}
