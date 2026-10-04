#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block/padding.h"

static int g_fails = 0;

#define CHECK(cond, name) { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s\n", name); ++g_fails; } }

static uint8_t *make(int n, uint8_t fill)
{
	uint8_t *v = malloc(n);
	memset(v, fill, n);
	return v;
}

int main()
{
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

	printf("\n%d test(s) failed\n", g_fails);
	return g_fails ? 1 : 0;
}
