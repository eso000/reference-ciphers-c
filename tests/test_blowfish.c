#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "block/blowfish.h"
#include "block/padding.h"
#include "testutil.h"

/* Schneier's 34-entry official ECB set, the same table the Python suite
   carries as BLOWFISH_OFFICIAL. Every one of these uses an 8-byte key.

   The final entry, AABB09182736CCDD, is not in that set: it is the widely
   reproduced vector from the SSLeay test data, and its published source is
   unconfirmed in the same way the DES provenance note says of its own
   AABB09182736CCDD pair. It is kept because it was here before and nothing
   else covers that key.

   The 4- to 24-byte set_key vectors live in test_keys, where they are what
   pins the 4-to-56-byte length rule; these all fit in eight bytes. */
struct Kat
{
	const char *key;
	const char *plain;
	const char *cipher;
};

static struct Kat KATS[] = {
	{"0000000000000000", "0000000000000000", "4EF997456198DD78"},
	{"FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "51866FD5B85ECB8A"},
	{"3000000000000000", "1000000000000001", "7D856F9A613063F2"},
	{"1111111111111111", "1111111111111111", "2466DD878B963C9D"},
	{"0123456789ABCDEF", "1111111111111111", "61F9C3802281B096"},
	{"1111111111111111", "0123456789ABCDEF", "7D0CC630AFDA1EC7"},
	{"0000000000000000", "0000000000000000", "4EF997456198DD78"},
	{"FEDCBA9876543210", "0123456789ABCDEF", "0ACEAB0FC6A0A28D"},
	{"7CA110454A1A6E57", "01A1D6D039776742", "59C68245EB05282B"},
	{"0131D9619DC1376E", "5CD54CA83DEF57DA", "B1B8CC0B250F09A0"},
	{"07A1133E4A0B2686", "0248D43806F67172", "1730E5778BEA1DA4"},
	{"3849674C2602319E", "51454B582DDF440A", "A25E7856CF2651EB"},
	{"04B915BA43FEB5B6", "42FD443059577FA2", "353882B109CE8F1A"},
	{"0113B970FD34F2CE", "059B5E0851CF143A", "48F4D0884C379918"},
	{"0170F175468FB5E6", "0756D8E0774761D2", "432193B78951FC98"},
	{"43297FAD38E373FE", "762514B829BF486A", "13F04154D69D1AE5"},
	{"07A7137045DA2A16", "3BDD119049372802", "2EEDDA93FFD39C79"},
	{"04689104C2FD3B2F", "26955F6835AF609A", "D887E0393C2DA6E3"},
	{"37D06BB516CB7546", "164D5E404F275232", "5F99D04F5B163969"},
	{"1F08260D1AC2465E", "6B056E18759F5CCA", "4A057A3B24D3977B"},
	{"584023641ABA6176", "004BD6EF09176062", "452031C1E4FADA8E"},
	{"025816164629B007", "480D39006EE762F2", "7555AE39F59B87BD"},
	{"49793EBC79B3258F", "437540C8698F3CFA", "53C55F9CB49FC019"},
	{"4FB05E1515AB73A7", "072D43A077075292", "7A8E7BFA937E89A3"},
	{"49E95D6D4CA229BF", "02FE55778117F12A", "CF9C5D7A4986ADB5"},
	{"018310DC409B26D6", "1D9D5C5018F728C2", "D1ABB290658BC778"},
	{"1C587F1C13924FEF", "305532286D6F295A", "55CB3774D13EF201"},
	{"0101010101010101", "0123456789ABCDEF", "FA34EC4847B268B2"},
	{"1F1F1F1F0E0E0E0E", "0123456789ABCDEF", "A790795108EA3CAE"},
	{"E0FEE0FEF1FEF1FE", "0123456789ABCDEF", "C39E072D9FAC631D"},
	{"0000000000000000", "FFFFFFFFFFFFFFFF", "014933E0CDAFF6E4"},
	{"FFFFFFFFFFFFFFFF", "0000000000000000", "F21E9A77B71C49BC"},
	{"0123456789ABCDEF", "0000000000000000", "245946885754369A"},
	{"FEDCBA9876543210", "FFFFFFFFFFFFFFFF", "6B5C5A9C5D9E0A5A"},
	{"AABB09182736CCDD", "123456ABCD132536", "C8FDCAEA64FA2C82"},
};

int main(void)
{
	char name[96];

	printf("== Blowfish known-answer tests (ECB vectors) ==\n");
	for (size_t i = 0; i < sizeof KATS / sizeof KATS[0]; ++i)
	{
		struct Blowfish bf;
		BlockCipher c = blowfish_cipher(&bf);
		uint8_t key[8], pt[8], ct[8], v[8];
		hexDecode(KATS[i].key, key);
		c.generateKeys(&c, key, hexLen(KATS[i].key));
		hexDecode(KATS[i].plain, pt);
		hexDecode(KATS[i].cipher, ct);
		memcpy(v, pt, 8);
		cipherEncryptECB(&c, v, 8);
		snprintf(name, sizeof(name), "ecb %02zu key=%s encrypt", i + 1, KATS[i].key);
		CHECK(memcmp(v, ct, 8) == 0, name);
		/* Decrypt the published ciphertext, not our own output, so a wrong
		   pair of encrypt and decrypt cannot cancel out. */
		memcpy(v, ct, 8);
		cipherDecryptECB(&c, v, 8);
		snprintf(name, sizeof(name), "ecb %02zu key=%s decrypt", i + 1, KATS[i].key);
		CHECK(memcmp(v, pt, 8) == 0, name);
	}

	printf("== ECB round trip (two blocks) ==\n");
	{
		struct Blowfish bf;
		BlockCipher c = blowfish_cipher(&bf);
		uint8_t v[16] = {0x12, 0x34, 0x56, 0xAB, 0xCD, 0x13, 0x25, 0x36,
				 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		uint8_t w[16];
		uint8_t key[8];
		hexDecode("AABB09182736CCDD", key);
		c.generateKeys(&c, key, sizeof key);
		memcpy(w, v, 16);
		cipherEncryptECB(&c, v, 16);
		CHECK(memcmp(v, w, 16) != 0, "ecb ciphertext differs from plaintext");
		cipherDecryptECB(&c, v, 16);
		CHECK(memcmp(v, w, 16) == 0, "ecb encrypt+decrypt restores plaintext");
	}

	printf("== CBC round trip ==\n");
	{
		struct Blowfish bf;
		BlockCipher c = blowfish_cipher(&bf);
		uint8_t v[16] = {0x12, 0x34, 0x56, 0xAB, 0xCD, 0x13, 0x25, 0x36,
				 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		uint8_t w[16];
		uint8_t iv[8] = {0}, iv2[8] = {0};
		uint8_t key[8];
		hexDecode("AABB09182736CCDD", key);
		c.generateKeys(&c, key, sizeof key);
		memcpy(w, v, 16);
		cipherEncryptCBC(&c, v, 16, iv);
		CHECK(memcmp(v, w, 16) != 0, "cbc ciphertext differs from plaintext");
		cipherDecryptCBC(&c, v, 16, iv2);
		CHECK(memcmp(v, w, 16) == 0, "cbc encrypt+decrypt restores plaintext");
	}

	printf("== padding to 8-byte blocks ==\n");
	{
		uint8_t *v = malloc(4);
		v[0] = 'A';
		v[1] = 'B';
		v[2] = 'C';
		v[3] = 'D';
		v = padPKCS(v, 4, 4);
		CHECK(v != NULL && v[7] == 4, "4 bytes padded to one block");
		free(v);
	}

	printf("\n%d test(s) failed\n", g_fails);
	return g_fails ? 1 : 0;
}
