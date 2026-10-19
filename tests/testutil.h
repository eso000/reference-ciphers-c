#ifndef TESTUTIL_HEADER
#define TESTUTIL_HEADER

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Shared test harness: every test binary includes this file, so the failure
   tally, the CHECK macro and the hex decoder exist once instead of once per
   test. */

static int g_fails = 0;

#define CHECK(cond, name) { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s\n", name); ++g_fails; } }

static inline int hexNibble(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* Decode a hex string into out, writing strlen(hex)/2 bytes. An odd length or
   a non-hex character aborts the test loudly: a vector that cannot be decoded
   is a broken test, and the old per-file sscanf copies silently wrote zeroes
   for such input, which could turn a broken vector into a silent pass. */
static inline void hexDecode(const char *hex, uint8_t *out)
{
	size_t n = strlen(hex);
	if (n % 2 != 0)
	{
		fprintf(stderr, "hexDecode: odd-length string \"%s\"\n", hex);
		exit(2);
	}
	for (size_t i = 0; i < n / 2; ++i)
	{
		int hi = hexNibble(hex[2 * i]);
		int lo = hexNibble(hex[2 * i + 1]);
		if (hi < 0 || lo < 0)
		{
			fprintf(stderr, "hexDecode: non-hex character in \"%s\"\n", hex);
			exit(2);
		}
		out[i] = (uint8_t)((hi << 4) | lo);
	}
}

/* Byte length a hex string decodes to, for the generateKeys call sites that
   pass it straight through. */
static inline size_t hexLen(const char *hex)
{
	return strlen(hex) / 2;
}

#endif
