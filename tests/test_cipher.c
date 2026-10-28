/* Tests for the whole-message path, cipherEncrypt/cipherDecrypt: the mode
   dispatch plus the padding stage the raw mode wrappers leave to the caller.

   The exact ciphertexts come from the Python reference (refciphers), which is
   the source of the padding and mode semantics here. Padding decisions that
   the raw layer already pins -- what padPKCS writes, what unpadTBC rejects --
   are tested in test_padding.c; this file is about the funnel around them:
   which modes pad, how much, what the lengths come out as, and what the IV
   rules are. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block/aes.h"
#include "block/des.h"
#include "block/blowfish.h"
#include "block/twofish.h"
#include "block/serpent.h"
#include "block/blockcipher.h"
#include "testutil.h"

union State {
    struct AES aes;
    struct DES des;
    struct Blowfish bf;
    struct Twofish tf;
    struct Serpent ser;
};

struct CipherDef {
    const char *name;
    BlockCipher (*ctor)(void *);
    int keyLen;
};

static const struct CipherDef CIPHER_DEFS[] = {
    {"AES", aes_cipher, 16},           {"DES", des_cipher, 8},
    {"Blowfish", blowfish_cipher, 16}, {"Serpent", serpent_cipher, 16},
    {"Twofish", twofish_cipher, 16},
};

static const struct CipherDef *findCipher(const char *name) {
    for (size_t i = 0; i < sizeof CIPHER_DEFS / sizeof CIPHER_DEFS[0]; ++i)
        if (strcmp(CIPHER_DEFS[i].name, name) == 0)
            return &CIPHER_DEFS[i];
    return NULL;
}

static const char *modeName(CipherMode m) {
    switch (m) {
    case CIPHER_ECB:
        return "ECB";
    case CIPHER_CBC:
        return "CBC";
    case CIPHER_PCBC:
        return "PCBC";
    case CIPHER_CFB:
        return "CFB";
    case CIPHER_OFB:
        return "OFB";
    case CIPHER_CTR:
        return "CTR";
    default:
        return "?";
    }
}

static const char *padName(PaddingScheme p) {
    switch (p) {
    case PAD_NONE:
        return "NONE";
    case PAD_ZERO:
        return "ZERO";
    case PAD_PKCS:
        return "PKCS";
    case PAD_ANSIX923:
        return "ANSIX923";
    case PAD_ISO78164:
        return "ISO78164";
    case PAD_TBC:
        return "TBC";
    default:
        return "?";
    }
}

/* The schemes cipherDecrypt can take all the way back off. PAD_NONE can too,
   but only when the message is already aligned; PAD_ZERO cannot, so it has its
   own check. */
static const PaddingScheme REMOVABLE[] = {PAD_PKCS, PAD_ANSIX923, PAD_ISO78164, PAD_TBC};

static void makePlaintext(uint8_t *p, int len, int seed) {
    for (int i = 0; i < len; ++i)
        p[i] = (uint8_t)(seed + i * 7 + 1);
}

static void makeIv(uint8_t *iv, int bs, int seed) {
    for (int i = 0; i < bs; ++i)
        iv[i] = (uint8_t)(seed + i * 5);
}

/* Encrypt then decrypt a fresh message and require the plaintext back. Uses
   the caller's IV twice: the funnel must not consume it. */
static void checkRoundTrip(const char *label, BlockCipher *c, CipherMode mode, PaddingScheme pad,
                           int len, int bs) {
    char name[160];
    uint8_t pt[80], iv[16], ivBefore[16];
    uint8_t *ct = NULL, *back = NULL;
    size_t ctLen = 0, backLen = 0;
    int hasIv = mode != CIPHER_ECB;

    makePlaintext(pt, len, (int)mode * 31 + len);
    makeIv(iv, bs, 3);
    memcpy(ivBefore, iv, (size_t)bs);

    int e = cipherEncrypt(c, mode, hasIv ? iv : NULL, hasIv ? (size_t)bs : 0, pt, (size_t)len, pad,
                          &ct, &ctLen);
    int d = -1;
    if (e == 0)
        d = cipherDecrypt(c, mode, hasIv ? iv : NULL, hasIv ? (size_t)bs : 0, ct, ctLen, pad, &back,
                          &backLen);

    snprintf(name, sizeof(name), "%s %s %s len %d round trip", label, modeName(mode), padName(pad),
             len);
    CHECK(e == 0 && d == 0 && backLen == (size_t)len &&
              (len == 0 || memcmp(back, pt, (size_t)len) == 0),
          name);

    if (hasIv) {
        snprintf(name, sizeof(name), "%s %s %s len %d leaves the caller IV alone", label,
                 modeName(mode), padName(pad), len);
        CHECK(memcmp(iv, ivBefore, (size_t)bs) == 0, name);
    }

    free(ct);
    free(back);
}

/* Zero padding only fills to the boundary, so it cannot be removed: decrypt
   returns the fill still attached, exactly as the Python reference does. */
static void checkZeroPad(const char *label, BlockCipher *c, CipherMode mode, int len, int bs) {
    char name[160];
    uint8_t pt[80], iv[16];
    uint8_t *ct = NULL, *back = NULL;
    size_t ctLen = 0, backLen = 0;
    int hasIv = mode != CIPHER_ECB;

    makePlaintext(pt, len, 0x5A + len);
    makeIv(iv, bs, 9);

    int e = cipherEncrypt(c, mode, hasIv ? iv : NULL, hasIv ? (size_t)bs : 0, pt, (size_t)len,
                          PAD_ZERO, &ct, &ctLen);
    int d = -1;
    if (e == 0)
        d = cipherDecrypt(c, mode, hasIv ? iv : NULL, hasIv ? (size_t)bs : 0, ct, ctLen, PAD_ZERO,
                          &back, &backLen);

    /* Fills to the next boundary only: an aligned message grows by nothing. */
    int wantFill = (bs - len % bs) % bs;
    int zeros = 1;
    for (int i = 0; back != NULL && i < wantFill; ++i)
        if (back[len + i] != 0x00)
            zeros = 0;

    snprintf(name, sizeof(name), "%s %s ZERO len %d keeps the fill attached", label, modeName(mode),
             len);
    CHECK(e == 0 && d == 0 && ctLen == (size_t)(len + wantFill) &&
              backLen == (size_t)(len + wantFill) &&
              (len == 0 || memcmp(back, pt, (size_t)len) == 0) && zeros,
          name);

    free(ct);
    free(back);
}

/* The keystream modes ignore the padding argument completely: the same bytes
   come out for every scheme, and the length is the input length. */
static void checkKeystreamIgnoresPad(const char *label, BlockCipher *c, CipherMode mode, int len,
                                     int bs) {
    char name[160];
    uint8_t pt[80], iv[16];
    uint8_t *first = NULL;
    size_t firstLen = 0;
    int same = 1;

    makePlaintext(pt, len, 0x71 + len);
    makeIv(iv, bs, 0x2A);

    const PaddingScheme PADS[] = {PAD_NONE,     PAD_ZERO,     PAD_PKCS,
                                  PAD_ANSIX923, PAD_ISO78164, PAD_TBC};
    for (size_t i = 0; i < sizeof PADS / sizeof PADS[0]; ++i) {
        uint8_t *ct = NULL;
        size_t ctLen = 0;
        int rc = cipherEncrypt(c, mode, iv, (size_t)bs, pt, (size_t)len, PADS[i], &ct, &ctLen);
        if (rc != 0)
            same = 0;
        else if (i == 0) {
            first = ct;
            firstLen = ctLen;
            ct = NULL;
        } else if (ctLen != firstLen || memcmp(ct, first, firstLen) != 0)
            same = 0;
        free(ct);
    }

    snprintf(name, sizeof(name), "%s %s ignores padding, len %d", label, modeName(mode), len);
    CHECK(same && firstLen == (size_t)len, name);
    free(first);
}

/* The block modes must be a whole number of blocks: PAD_NONE passes an aligned
   message through and rejects an unaligned one rather than quietly dropping a
   partial tail the way the raw wrapper would. */
static void checkNoneAlignment(const char *label, BlockCipher *c, CipherMode mode, int bs) {
    char name[160];
    uint8_t pt[80], iv[16];
    uint8_t *out = NULL;
    size_t outLen = 0;
    int hasIv = mode != CIPHER_ECB;

    makePlaintext(pt, bs * 2, 0x33);
    makeIv(iv, bs, 1);

    int aligned = cipherEncrypt(c, mode, hasIv ? iv : NULL, hasIv ? (size_t)bs : 0, pt,
                                (size_t)(bs * 2), PAD_NONE, &out, &outLen);
    snprintf(name, sizeof(name), "%s %s NONE accepts an aligned message", label, modeName(mode));
    CHECK(aligned == 0 && outLen == (size_t)(bs * 2), name);
    free(out);
    out = NULL;

    int partial = cipherEncrypt(c, mode, hasIv ? iv : NULL, hasIv ? (size_t)bs : 0, pt,
                                (size_t)(bs + 1), PAD_NONE, &out, &outLen);
    snprintf(name, sizeof(name), "%s %s NONE rejects an unaligned message", label, modeName(mode));
    CHECK(partial == -1 && out == NULL, name);
    free(out);
}

/* A block-mode ciphertext with a strict scheme grows to a whole number of
   blocks, and by a full extra block when the message is already aligned. */
static void checkPaddedLength(const char *label, BlockCipher *c, CipherMode mode, PaddingScheme pad,
                              int len, int bs) {
    char name[160];
    uint8_t pt[80], iv[16];
    uint8_t *ct = NULL;
    size_t ctLen = 0;
    int hasIv = mode != CIPHER_ECB;

    makePlaintext(pt, len, 0x11 + len);
    makeIv(iv, bs, 6);

    int rc = cipherEncrypt(c, mode, hasIv ? iv : NULL, hasIv ? (size_t)bs : 0, pt, (size_t)len, pad,
                           &ct, &ctLen);
    size_t want = (size_t)len + (size_t)(bs - len % bs);

    snprintf(name, sizeof(name), "%s %s %s len %d grows to %d bytes", label, modeName(mode),
             padName(pad), len, (int)want);
    CHECK(rc == 0 && ctLen == want, name);
    free(ct);
}

static void sweepCipher(const struct CipherDef *def) {
    union State st;
    BlockCipher c = def->ctor(&st);
    int bs = c.blockSize;
    uint8_t key[32];

    for (int i = 0; i < def->keyLen; ++i)
        key[i] = (uint8_t)(0x10 + 7 * i);
    c.generateKeys(&c, key, (size_t)def->keyLen);

    const int LENS[] = {0, 1, bs / 2, bs - 1, bs, bs + 1, 2 * bs + 1};

    for (int mode = -3; mode <= 3; ++mode) {
        if (mode == 0)
            continue;
        CipherMode m = (CipherMode)mode;

        if (m == CIPHER_ECB || m == CIPHER_CBC || m == CIPHER_PCBC) {
            for (size_t p = 0; p < sizeof REMOVABLE / sizeof REMOVABLE[0]; ++p)
                for (size_t l = 0; l < sizeof LENS / sizeof LENS[0]; ++l) {
                    checkRoundTrip(def->name, &c, m, REMOVABLE[p], LENS[l], bs);
                    checkPaddedLength(def->name, &c, m, REMOVABLE[p], LENS[l], bs);
                }
            checkNoneAlignment(def->name, &c, m, bs);
            for (size_t l = 0; l < sizeof LENS / sizeof LENS[0]; ++l)
                checkZeroPad(def->name, &c, m, LENS[l], bs);
            checkRoundTrip(def->name, &c, m, PAD_NONE, bs * 2, bs);
        } else {
            for (size_t l = 0; l < sizeof LENS / sizeof LENS[0]; ++l) {
                checkRoundTrip(def->name, &c, m, PAD_NONE, LENS[l], bs);
                checkKeystreamIgnoresPad(def->name, &c, m, LENS[l], bs);
            }
        }
    }
}

/* A fresh reference vector, produced by the Python implementation, pinning the
   whole funnel: mode dispatch, the padding applied before it and removed
   after, and the IV handling. */
struct CipherKat {
    const char *cipher;
    CipherMode mode;
    PaddingScheme pad;
    const char *key;
    const char *iv; /* "-" for ECB */
    const char *plaintext;
    const char *ciphertext;
};

static const struct CipherKat CIPHER_KATS[] = {
    {"AES", CIPHER_CBC, PAD_PKCS, "2b7e151628aed2a6abf7158809cf4f3c",
     "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff00",
     "b577ed00e35432951e2f6e82cbe27177c698c2ec2085bfc9644026dddd5f3e95"},
    {"AES", CIPHER_ECB, PAD_ISO78164, "2b7e151628aed2a6abf7158809cf4f3c", "-",
     "00112233445566778899aabbccddeeff",
     "8df4e9aac5c7573a27d8d055d6e4d64bf6c71eedc3d99bb183cb5b8d1568e606"},
    {"AES", CIPHER_OFB, PAD_TBC, "2b7e151628aed2a6abf7158809cf4f3c",
     "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff0011",
     "50ef45ffdd3854c152909d525772029fd9b5"},
    {"DES", CIPHER_CBC, PAD_ANSIX923, "133457799BBCDFF1", "0102030405060708", "414243444546474849",
     "7955c49a084f5f0c8c1897ee1cfc1770"},
    {"Blowfish", CIPHER_CTR, PAD_NONE, "F0E1D2C3B4A5968778695A4B3C2D1E0F", "0102030405060708",
     "de61646f6e6c79", "f79b709d7ca737"},
    {"Twofish", CIPHER_PCBC, PAD_TBC, "000102030405060708090a0b0c0d0e0f",
     "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff00",
     "457df6e9ff10a0716383285b48628619d6afc523abd2e6772c68964329e00271"},
    {"Serpent", CIPHER_CFB, PAD_PKCS, "000102030405060708090a0b0c0d0e0f",
     "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff0011",
     "4c6ca801c427c45b0aa7e0a4f6104f926940"},
};

static void runCipherKat(const struct CipherKat *k) {
    char name[160];
    union State st;
    const struct CipherDef *def = findCipher(k->cipher);
    uint8_t key[32], iv[16], pt[64], ct[64];
    size_t klen = hexLen(k->key);
    size_t ivlen = (strcmp(k->iv, "-") == 0) ? 0 : hexLen(k->iv);

    if (def == NULL) {
        snprintf(name, sizeof(name), "cipher kat names a known cipher (%s)", k->cipher);
        CHECK(0, name);
        return;
    }

    hexDecode(k->key, key);
    hexDecode(k->plaintext, pt);
    hexDecode(k->ciphertext, ct);
    if (ivlen)
        hexDecode(k->iv, iv);

    BlockCipher c = def->ctor(&st);
    c.generateKeys(&c, key, klen);

    uint8_t *out = NULL;
    size_t outLen = 0;
    int e = cipherEncrypt(&c, k->mode, ivlen ? iv : NULL, ivlen, pt, hexLen(k->plaintext), k->pad,
                          &out, &outLen);
    snprintf(name, sizeof(name), "%s %s %s encrypts to the reference ciphertext", k->cipher,
             modeName(k->mode), padName(k->pad));
    CHECK(e == 0 && outLen == hexLen(k->ciphertext) && memcmp(out, ct, outLen) == 0, name);
    free(out);
    out = NULL;

    int d = cipherDecrypt(&c, k->mode, ivlen ? iv : NULL, ivlen, ct, hexLen(k->ciphertext), k->pad,
                          &out, &outLen);
    snprintf(name, sizeof(name), "%s %s %s decrypts the reference ciphertext", k->cipher,
             modeName(k->mode), padName(k->pad));
    CHECK(d == 0 && outLen == hexLen(k->plaintext) && memcmp(out, pt, outLen) == 0, name);
    free(out);
}

/* Whatever the cipher says its IV rules are, the funnel must agree before it
   touches the data. */
static void checkIvRules(const struct CipherDef *def) {
    char name[160];
    union State st;
    BlockCipher c = def->ctor(&st);
    int bs = c.blockSize;
    uint8_t key[32], pt[32], iv[16];
    uint8_t *out = NULL;
    size_t outLen = 0;

    for (int i = 0; i < def->keyLen; ++i)
        key[i] = (uint8_t)(0x20 + i);
    c.generateKeys(&c, key, (size_t)def->keyLen);
    makePlaintext(pt, bs, 0x44);
    makeIv(iv, bs, 2);

    snprintf(name, sizeof(name), "%s ECB accepts no IV", def->name);
    CHECK(cipherEncrypt(&c, CIPHER_ECB, NULL, 0, pt, (size_t)bs, PAD_PKCS, &out, &outLen) == 0,
          name);
    free(out);
    out = NULL;

    snprintf(name, sizeof(name), "%s ECB rejects an IV", def->name);
    CHECK(cipherEncrypt(&c, CIPHER_ECB, iv, (size_t)bs, pt, (size_t)bs, PAD_PKCS, &out, &outLen) ==
                  -1 &&
              out == NULL,
          name);
    free(out);
    out = NULL;

    snprintf(name, sizeof(name), "%s CBC needs a full-block IV", def->name);
    CHECK(cipherEncrypt(&c, CIPHER_CBC, iv, (size_t)bs, pt, (size_t)bs, PAD_PKCS, &out, &outLen) ==
              0,
          name);
    free(out);
    out = NULL;

    snprintf(name, sizeof(name), "%s CBC rejects a short IV", def->name);
    CHECK(cipherEncrypt(&c, CIPHER_CBC, iv, (size_t)(bs - 1), pt, (size_t)bs, PAD_PKCS, &out,
                        &outLen) == -1,
          name);
    free(out);
    out = NULL;

    snprintf(name, sizeof(name), "%s CTR rejects a missing IV", def->name);
    CHECK(cipherEncrypt(&c, CIPHER_CTR, NULL, 0, pt, (size_t)bs, PAD_NONE, &out, &outLen) == -1,
          name);
    free(out);
    out = NULL;
}

/* A block-mode ciphertext whose last block is not valid padding must be
   rejected, not silently returned short. */
static void checkMalformedPadding(const struct CipherDef *def) {
    char name[160];
    union State st;
    BlockCipher c = def->ctor(&st);
    int bs = c.blockSize;
    uint8_t key[32], pt[32], iv[16];
    uint8_t *ct = NULL;
    size_t ctLen = 0;

    for (int i = 0; i < def->keyLen; ++i)
        key[i] = (uint8_t)(0x30 + i);
    c.generateKeys(&c, key, (size_t)def->keyLen);
    makePlaintext(pt, bs, 0x66);
    makeIv(iv, bs, 4);

    if (cipherEncrypt(&c, CIPHER_CBC, iv, (size_t)bs, pt, (size_t)bs, PAD_PKCS, &ct, &ctLen) != 0) {
        snprintf(name, sizeof(name), "%s malformed-padding setup", def->name);
        CHECK(0, name);
        free(ct);
        return;
    }

    const uint8_t TAMPER[] = {0x00, 0x11, 0xFF};
    for (size_t i = 0; i < sizeof TAMPER / sizeof TAMPER[0]; ++i) {
        uint8_t *out = NULL;
        size_t outLen = 0;
        ct[ctLen - 1] = TAMPER[i];
        int rc = cipherDecrypt(&c, CIPHER_CBC, iv, (size_t)bs, ct, ctLen, PAD_PKCS, &out, &outLen);
        snprintf(name, sizeof(name), "%s CBC rejects padding ending 0x%02X", def->name, TAMPER[i]);
        CHECK(rc == -1 && out == NULL, name);
        free(out);
    }

    /* A count longer than the trailing run of identical bytes. */
    ct[ctLen - 1] = 0x05;
    ct[ctLen - 2] = 0x00;
    uint8_t *out = NULL;
    size_t outLen = 0;
    snprintf(name, sizeof(name), "%s CBC rejects an inconsistent PKCS count", def->name);
    CHECK(cipherDecrypt(&c, CIPHER_CBC, iv, (size_t)bs, ct, ctLen, PAD_PKCS, &out, &outLen) == -1,
          name);
    free(out);
    free(ct);
}

int main(void) {
    printf("== whole-message path: reference vectors ==\n");
    for (size_t i = 0; i < sizeof CIPHER_KATS / sizeof CIPHER_KATS[0]; ++i)
        runCipherKat(&CIPHER_KATS[i]);

    printf("== whole-message path: sweeps ==\n");
    for (size_t i = 0; i < sizeof CIPHER_DEFS / sizeof CIPHER_DEFS[0]; ++i)
        sweepCipher(&CIPHER_DEFS[i]);

    printf("== whole-message path: IV rules ==\n");
    for (size_t i = 0; i < sizeof CIPHER_DEFS / sizeof CIPHER_DEFS[0]; ++i)
        checkIvRules(&CIPHER_DEFS[i]);

    printf("== whole-message path: malformed padding ==\n");
    for (size_t i = 0; i < sizeof CIPHER_DEFS / sizeof CIPHER_DEFS[0]; ++i)
        checkMalformedPadding(&CIPHER_DEFS[i]);

    printf("\n%d test(s) failed\n", g_fails);
    return g_fails ? 1 : 0;
}
