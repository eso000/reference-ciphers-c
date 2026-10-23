/*
 * AES-128-CBC + ISO 7816-4 padding round trip.
 *
 * Demo only: the key and IV are fixed so the output is reproducible. Real code
 * needs a random, unpredictable IV for every message and a proper key
 * derivation function.
 *
 * Build and run with:
 *     make examples
 *     ./build/roundtrip
 */

#include <stdio.h>
#include <stdlib.h>

#include "block/aes.h"
#include "block/blockcipher.h"

int main(void)
{
	struct AES aes;
	BlockCipher c = aes_cipher(&aes);

	uint8_t key[16];
	for (int i = 0; i < 16; ++i)
		key[i] = (uint8_t)i;

	if (!c.generateKeys(&c, key, sizeof key))
	{
		fprintf(stderr, "AES rejected the key\n");
		return EXIT_FAILURE;
	}

	uint8_t iv[16] = {0}; /* demo only; fresh and unpredictable in real use */
	uint8_t msg[] = "attack at dawn";
	uint8_t *ct = NULL;
	uint8_t *pt = NULL;
	size_t ctLen = 0;
	size_t ptLen = 0;

	if (cipherEncrypt(&c, CIPHER_CBC, iv, sizeof iv, msg, sizeof msg - 1,
			  PAD_ISO78164, &ct, &ctLen) != 0)
	{
		fprintf(stderr, "encryption failed\n");
		return EXIT_FAILURE;
	}

	if (cipherDecrypt(&c, CIPHER_CBC, iv, sizeof iv, ct, ctLen,
			  PAD_ISO78164, &pt, &ptLen) != 0)
	{
		fprintf(stderr, "decryption failed\n");
		free(ct);
		return EXIT_FAILURE;
	}

	printf("recovered: %.*s\n", (int)ptLen, pt);

	free(ct);
	free(pt);
	return EXIT_SUCCESS;
}
