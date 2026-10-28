#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block/padding.h"
#include "testutil.h"

static uint8_t *make(int n, uint8_t fill) {
    uint8_t *v = malloc(n ? (size_t)n : 1);
    memset(v, fill, (size_t)n);
    return v;
}

/* Bytes a strict scheme adds: blockSize - size % blockSize, so a full block
   when the data is already aligned. None of these schemes can produce a zero
   count, because a zero count is indistinguishable from "no padding". */
static int missingFor(int size, int blockSize) { return blockSize - size % blockSize; }

/* Pad a fresh copy of a patterned buffer, unpad it again, and require the
   original length and bytes back. Sizes that are not multiples of blockSize
   are the interesting ones: they are what an unaligned message leaves. */
static void checkRoundTrip(const char *scheme, uint8_t *(*pad)(uint8_t *, int, int),
                           int (*unpad)(const uint8_t *, int, int), int blockSize, int size) {
    uint8_t orig[64];
    char name[128];

    uint8_t *v = make(size, 0x00);
    for (int i = 0; i < size; ++i) {
        orig[i] = (uint8_t)(0x30 + i);
        v[i] = orig[i];
    }

    int missing = missingFor(size, blockSize);
    v = pad(v, size, missing);
    int back = unpad(v, size + missing, blockSize);

    snprintf(name, sizeof(name), "%s block %d size %d round trip", scheme, blockSize, size);
    CHECK(v != NULL && back == size && memcmp(v, orig, (size_t)size) == 0, name);
    free(v);
}

static void checkRejected(const char *name, int (*unpad)(const uint8_t *, int, int),
                          const uint8_t *buf, int size, int blockSize) {
    CHECK(unpad(buf, size, blockSize) == -1, name);
}

int main(void) {
    printf("== padding ==\n");
    {
        uint8_t *v = make(4, 0xAA);
        v = padPKCS(v, 4, 4);
        CHECK(v != NULL && v[0] == 0xAA && v[4] == 4 && v[5] == 4 && v[6] == 4 && v[7] == 4,
              "padPKCS fills with length");
        free(v);
    }
    {
        uint8_t *v = make(4, 0xAA);
        v = padZeros(v, 4, 4);
        CHECK(v != NULL && v[0] == 0xAA && v[4] == 0 && v[5] == 0 && v[6] == 0 && v[7] == 0,
              "padZeros fills with zero");
        free(v);
    }
    {
        uint8_t *v = make(4, 0xAA);
        v = padANSIX923(v, 4, 4);
        CHECK(v != NULL && v[0] == 0xAA && v[4] == 0 && v[5] == 0 && v[6] == 0 && v[7] == 4,
              "padANSIX923 zeros then length");
        free(v);
    }
    {
        uint8_t *v = make(4, 0xAA);
        v = padISO78164(v, 4, 4);
        CHECK(v != NULL && v[0] == 0xAA && v[4] == 0x80 && v[5] == 0 && v[6] == 0 && v[7] == 0,
              "padISO78164 0x80 then zeros");
        free(v);
    }
    {
        uint8_t *v = make(4, 0xAA);
        uint8_t *same = padPKCS(v, 4, 0);
        CHECK(same == v && v[0] == 0xAA, "padPKCS missing==0 leaves buffer");
        free(v);
    }

    printf("== trailing-bit-complement padding ==\n");
    {
        /* 0xAA ends in a 0 bit, so the filler complements it with 0xFF. */
        uint8_t *v = make(4, 0xAA);
        v = padTBC(v, 4, 4);
        CHECK(v != NULL && v[0] == 0xAA && v[4] == 0xFF && v[7] == 0xFF,
              "padTBC fills with 0xFF when the last data bit is clear");
        free(v);
    }
    {
        /* 0xAB ends in a 1 bit, so the filler is 0x00. */
        uint8_t *v = make(4, 0xAA);
        v[3] = 0xAB;
        v = padTBC(v, 4, 4);
        CHECK(v != NULL && v[3] == 0xAB && v[4] == 0x00 && v[7] == 0x00,
              "padTBC fills with 0x00 when the last data bit is set");
        free(v);
    }
    {
        /* An empty message has no last bit; Python uses 0xFF there too. */
        uint8_t *v = make(0, 0);
        v = padTBC(v, 0, 4);
        CHECK(v != NULL && v[0] == 0xFF && v[3] == 0xFF,
              "padTBC on an empty message fills with 0xFF");
        free(v);
    }

    printf("== pad/unpad round trips ==\n");
    {
        const int BLOCKS[] = {8, 16};
        for (size_t b = 0; b < sizeof BLOCKS / sizeof BLOCKS[0]; ++b) {
            int bs = BLOCKS[b];
            for (int size = 0; size <= 2 * bs + 1; ++size) {
                checkRoundTrip("PKCS", padPKCS, unpadPKCS, bs, size);
                checkRoundTrip("ANSIX923", padANSIX923, unpadANSIX923, bs, size);
                checkRoundTrip("ISO78164", padISO78164, unpadISO78164, bs, size);
                checkRoundTrip("TBC", padTBC, unpadTBC, bs, size);
            }
        }
    }

    printf("== depadding rejects malformed padding ==\n");
    {
        uint8_t v[16];
        memset(v, 0xAA, sizeof v);

        v[15] = 0x00;
        checkRejected("unpadPKCS rejects a zero count", unpadPKCS, v, 16, 16);

        v[15] = 0x11;
        checkRejected("unpadPKCS rejects a count over the block size", unpadPKCS, v, 16, 16);

        v[15] = 0x04;
        checkRejected("unpadPKCS rejects inconsistent filler", unpadPKCS, v, 16, 16);

        v[14] = 0x04;
        v[13] = 0x04;
        v[12] = 0x04;
        CHECK(unpadPKCS(v, 16, 16) == 12, "unpadPKCS accepts four 0x04 bytes");
    }
    {
        uint8_t v[4] = {0xAA, 0xAA, 0xAA, 0x05};
        checkRejected("unpadPKCS rejects a count longer than the data", unpadPKCS, v, 4, 16);
    }
    {
        uint8_t v[16];
        memset(v, 0x00, sizeof v);
        v[15] = 0x04;
        v[12] = 0x01;
        checkRejected("unpadANSIX923 rejects a nonzero filler", unpadANSIX923, v, 16, 16);

        v[12] = 0x00;
        CHECK(unpadANSIX923(v, 16, 16) == 12, "unpadANSIX923 accepts zeros then the count");

        v[15] = 0x00;
        checkRejected("unpadANSIX923 rejects a zero count", unpadANSIX923, v, 16, 16);
    }
    {
        uint8_t v[16];
        memset(v, 0x00, sizeof v);
        checkRejected("unpadISO78164 rejects an all-zero tail", unpadISO78164, v, 16, 16);

        v[15] = 0x01;
        checkRejected("unpadISO78164 rejects a tail with no 0x80 marker", unpadISO78164, v, 16, 16);

        memset(v, 0x00, sizeof v);
        v[15] = 0x01;
        v[14] = 0x80;
        checkRejected("unpadISO78164 rejects a nonzero byte after the marker", unpadISO78164, v, 16,
                      16);

        memset(v, 0x00, sizeof v);
        v[14] = 0x80;
        CHECK(unpadISO78164(v, 16, 16) == 14, "unpadISO78164 finds 0x80 before the zeros");
    }
    {
        uint8_t v[16];
        memset(v, 0xAA, sizeof v);
        v[15] = 0x7F;
        checkRejected("unpadTBC rejects a final byte that is neither 0x00 nor 0xFF", unpadTBC, v,
                      16, 16);

        memset(v, 0xFF, sizeof v);
        CHECK(unpadTBC(v, 16, 16) == 0, "unpadTBC accepts an all-0xFF tail as an empty message");

        memset(v, 0xAA, sizeof v);
        v[15] = 0x00;
        v[14] = 0x00;
        CHECK(unpadTBC(v, 16, 16) == 14, "unpadTBC strips a run of trailing zeros");
    }

    printf("== depadding on a short final block ==\n");
    {
        /* size < blockSize: the tail examined is the whole buffer, which is
           what Python does with data[-block_size:]. */
        const uint8_t iso[3] = {0x41, 0x80, 0x00};
        CHECK(unpadISO78164(iso, 3, 16) == 1, "unpadISO78164 short block with a marker");

        const uint8_t tbc[2] = {0x41, 0xFF};
        CHECK(unpadTBC(tbc, 2, 16) == 1, "unpadTBC short block with one filler byte");

        const uint8_t pkcs[3] = {0x41, 0x02, 0x02};
        CHECK(unpadPKCS(pkcs, 3, 16) == 1, "unpadPKCS short block with a two-byte count");
    }

    printf("== depadding guards ==\n");
    {
        uint8_t v[4] = {0xAA, 0xAA, 0xAA, 0x01};
        checkRejected("unpadPKCS rejects a NULL buffer", unpadPKCS, NULL, 4, 16);
        checkRejected("unpadPKCS rejects an empty buffer", unpadPKCS, v, 0, 16);
        checkRejected("unpadPKCS rejects a zero block size", unpadPKCS, v, 4, 0);
        checkRejected("unpadANSIX923 rejects an empty buffer", unpadANSIX923, v, 0, 16);
        checkRejected("unpadANSIX923 rejects a zero block size", unpadANSIX923, v, 4, 0);
        checkRejected("unpadISO78164 rejects an empty buffer", unpadISO78164, v, 0, 16);
        checkRejected("unpadISO78164 rejects a zero block size", unpadISO78164, v, 4, 0);
        checkRejected("unpadTBC rejects an empty buffer", unpadTBC, v, 0, 16);
        checkRejected("unpadTBC rejects a zero block size", unpadTBC, v, 4, 0);
    }

    printf("\n%d test(s) failed\n", g_fails);
    return g_fails ? 1 : 0;
}
