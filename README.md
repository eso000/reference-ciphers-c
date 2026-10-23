# reference-ciphers-c

[![CI](https://github.com/eso000/reference-ciphers-c/actions/workflows/ci.yml/badge.svg)](https://github.com/eso000/reference-ciphers-c/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/eso000/reference-ciphers-c/branch/main/graph/badge.svg)](https://codecov.io/gh/eso000/reference-ciphers-c)
![C11](https://img.shields.io/badge/C-C11-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen)

From-scratch, dependency-free reference implementations of five classic block
ciphers in C11 — AES, DES, Blowfish, Twofish and Serpent — together with the six
classic modes of operation and the usual padding schemes. Every cipher is checked
against its official published test vectors.

This is the C sibling of
[`refciphers`](https://github.com/eso000/reference-ciphers-python). The two
implementations were developed against each other and agree byte for byte: the
mode, padding and whole-message layers were differentially tested across every
cipher × mode × scheme × length, including the error cases (see
[Testing and verification](#testing-and-verification)).

Written to be read, and written to be checked.

## Security notice

**This is an educational, from-scratch implementation. Do not use it to protect
real secrets.**

- It is **not constant-time** and makes **no side-channel claims**. The cipher
  implementations use table lookups and branches that leak through timing and
  cache behaviour.
- It provides **no authenticated encryption** — no MAC and no AEAD. Ciphertexts
  are malleable.
- It has **no key derivation** and no protection against misuse, and it has
  **not been audited**.

Use a vetted, maintained library such as OpenSSL or libsodium for anything that
matters.

## Ciphers

| Cipher   | Block size      | Key sizes        | Standard / source                  |
|----------|-----------------|------------------|------------------------------------|
| AES      | 16 bytes (128 b)| 16 / 24 / 32     | FIPS-197                           |
| DES      | 8 bytes (64 b)  | 8 (56 b + parity)| FIPS 46-3                          |
| Blowfish | 8 bytes (64 b)  | 4–56 (32–448 b)  | Bruce Schneier, FSE 1993           |
| Twofish  | 16 bytes (128 b)| 16 / 24 / 32     | AES submission (Schneier et al.)   |
| Serpent  | 16 bytes (128 b)| 1–32 \*          | NESSIE finalist (Anderson et al.)  |

\* Serpent follows the specification's key range (keys shorter than 16 bytes are
padded internally as §3 requires). The Python sibling restricts itself to
16/24/32; see [Divergences from the Python reference](#divergences-from-the-python-reference).

There is no Triple DES here; the Python sibling provides it, this port does not.

## Modes and padding

Six modes of operation are shared by every cipher:

- **ECB, CBC and PCBC** operate on whole blocks. The whole-message API always
  pads — even a block-aligned message receives a full extra block, so unpadding
  is unambiguous. Schemes: `PKCS`, `ANSI X9.23`, `ISO 7816-4`, `TBC`, and zero
  padding (`PAD_ZERO`), which only fills to the block boundary and therefore
  cannot be removed again. `PAD_NONE` means no padding and requires block-aligned
  input.
- **CFB, OFB and CTR** are keystream modes: no padding, and the ciphertext is
  exactly as long as the plaintext, including a short final block.

Malformed padding, a ciphertext that is not block-aligned, or a key/IV of the
wrong length are all reported as errors (see [API](#api)).

## Requirements

- A C11 compiler (tested with gcc and clang). No third-party libraries, no
  runtime dependencies.
- `make` to build; nothing else.

## Build and test

```bash
make          # build the tests and the example into build/
make test     # build, then run the tests
make examples # build just the example
make clean    # remove build/
```

`make` respects `CC` from the environment or command line and otherwise defaults
to `gcc`. Test and example binaries are each compiled from source in one command,
so there are no stale objects to maintain.

Because the project is warning-clean and sanitizer-clean, the strict build is
worth running locally:

```bash
# warnings as errors, both compilers
make CC=gcc   CFLAGS="-std=c11 -O2 -Wall -Wextra -Wpedantic -Werror" test
make CC=clang CFLAGS="-std=c11 -O2 -Wall -Wextra -Wpedantic -Werror" test

# address and undefined-behaviour sanitizers
make CC=clang CFLAGS="-std=c11 -O1 -g -Wall -Wextra -Wpedantic -Werror \
     -fsanitize=address,undefined" test

# line coverage with gcovr
make CC=gcc CFLAGS="-std=c11 -O0 -g -Wall -Wextra -Wpedantic --coverage" test
gcovr --root . --txt --print-summary
```

## Example

The complete program is [`examples/roundtrip.c`](examples/roundtrip.c). It
encrypts and decrypts a short message with AES-128-CBC and ISO 7816-4 padding,
checks every return value, and frees both buffers.

```bash
make examples
./build/roundtrip
# recovered: attack at dawn
```

The key and IV are fixed so the output is reproducible. Real code needs a
random, unpredictable IV for every message and a proper key-derivation function.
CI builds and runs the example in each compiler and sanitizer configuration of
the test matrix, so it cannot drift from the public API.

## API

There are two layers. For whole messages, use the first.

### Whole-message path (recommended)

`cipherEncrypt` / `cipherDecrypt` take a `CipherMode` and a `PaddingScheme`,
apply padding for the block modes, run the mode, and return a freshly `malloc`'d
buffer that the caller frees. This mirrors the Python reference's
`encrypt` / `decrypt`.

The core calls are below; the complete, compiling version is
[`examples/roundtrip.c`](examples/roundtrip.c).

```c
struct AES aes;
BlockCipher c = aes_cipher(&aes);

uint8_t key[16] = {0}; /* demo only; use a real key in production */
uint8_t iv[16] = {0};  /* demo only; fresh and unpredictable in real use */
uint8_t msg[] = "attack at dawn";
uint8_t *ct = NULL, *pt = NULL;
size_t ctLen = 0, ptLen = 0;

if (!c.generateKeys(&c, key, sizeof key))
	return 1;
if (cipherEncrypt(&c, CIPHER_CBC, iv, sizeof iv, msg, sizeof msg - 1,
		  PAD_ISO78164, &ct, &ctLen) != 0)
	return 1;
if (cipherDecrypt(&c, CIPHER_CBC, iv, sizeof iv, ct, ctLen,
		  PAD_ISO78164, &pt, &ptLen) != 0)
{
	free(ct);
	return 1;
}

printf("recovered: %.*s\n", (int)ptLen, pt); /* recovered: attack at dawn */
free(ct);
free(pt);
```

`CipherMode` is `CIPHER_ECB`, `CIPHER_CBC`, `CIPHER_PCBC` (negative) or
`CIPHER_CFB`, `CIPHER_OFB`, `CIPHER_CTR` (positive); the sign records whether
the mode needs padding, so "does this mode pad?" is `mode < 0`. `PaddingScheme`
is one of `PAD_NONE`, `PAD_ZERO`, `PAD_PKCS`, `PAD_ANSIX923`, `PAD_ISO78164`,
`PAD_TBC`.

### Block-level path

`cipherEncryptECB` / `cipherDecryptCBC` / … are the in-place, block-only
engines that the whole-message path calls. They take a plain buffer and a length
and return `void`; the block modes (ECB, CBC, PCBC) require the length to be a
whole number of blocks, and a trailing partial block is left untouched. Use them
only when you are managing padding yourself.

## API contract

- **Keys are raw bytes.** Every `generateKeys` takes `const uint8_t *key,
  size_t len`; there is no hex parsing anywhere in the library. (`X_keyOk`
  answers "is this length acceptable?" without touching any state, and
  `generateKeys` routes through the same check, so the two can never disagree.)
- **Blocks** are exactly `blockSize` bytes for the block functions.
- **IVs** are one block for every mode except ECB. The whole-message path
  rejects an IV on ECB and rejects an IV that is not exactly one block on every
  other mode. The caller's IV is never modified.
- **Error handling.** C has no exceptions, so the whole-message path returns `0`
  on success and `-1` on any failure (bad mode, bad scheme, wrong IV length,
  unaligned block-mode input, malformed padding, allocation failure), leaving
  `*out` untouched. Nothing is ever silently truncated.

## Architecture

Every cipher is a `BlockCipher` value: a `blockSize`, an opaque state pointer,
and function pointers for the key schedule and the single-block encrypt/decrypt.
A cipher constructor (`aes_cipher`, `des_cipher`, …) fills that in over a
caller-provided state struct, so there is no hidden allocation.

```
include/block/   public headers: one per cipher, plus blockcipher.h and padding.h
src/             implementations and the constant tables (*_data.h)
tests/           one binary per cipher, plus modes, padding, whole-message and keys
examples/        runnable end-to-end example (binary goes to build/)
build/           test and example binaries, coverage artifacts (make output; ignored)
```

The mode layer (`src/blockcipher.c`) is written once against the `BlockCipher`
vtable and shared by every cipher. Padding (`src/padding.c`) is a set of
standalone primitives; the whole-message path selects between them by scheme.

The cipher cores follow the specifications. Where an implementation uses a
speed-oriented path, it is documented rather than hidden:

- **AES** — FIPS 197 key expansion and round structure. The round function uses
  the standard 32-bit Rijndael T-table layout for SubBytes, ShiftRows,
  MixColumns and AddRoundKey; the S-box and inverse S-box are from FIPS 197
  §5.1, and the T-table entries are determined by those S-boxes and the
  MixColumns / inverse MixColumns matrices.
- **DES** — two implementations of the same Feistel cipher. The default
  (`use_alt = 1`) uses delta-swap IP/FP networks and SP-boxes that fuse each
  S-box with its share of P. `use_alt = 0` uses the literal bit-permutation and
  S-box tables. The test suite requires both paths to agree.
- **Blowfish** — the on-spec P-array and S-boxes, 16-round Feistel.
- **Twofish** — GF polynomial multiplication, MDS matrices, PHT and q-boxes.
- **Serpent** — bit-sliced S-box circuits and the linear transform.

## Testing and verification

`make test` runs every test binary; the suite records **2363 assertions**. Each
test file links the whole library, so one run covers all five ciphers, the mode
layer, the padding helpers and the whole-message path.

| Test | Covers |
|---|---|
| `tests/test_aes.c` | FIPS-197 C.1–C.3, NIST SP 800-38A ECB and CBC |
| `tests/test_des.c` | the classic single-DES vectors, plus agreement between the delta-swap and table paths |
| `tests/test_blowfish.c` | Schneier's official 34-vector set and the `set_key` set |
| `tests/test_twofish.c` | the official submission KATs |
| `tests/test_serpent.c` | the NESSIE/verified sets |
| `tests/test_modes.c` | all six modes; NIST CFB128/OFB/CTR; short final blocks |
| `tests/test_padding.c` | every scheme, round trips and malformed input |
| `tests/test_cipher.c` | the whole-message path: reference vectors and sweeps |
| `tests/test_keys.c` | per-cipher key-length rules |

Coverage is measured with `gcovr` in the CI coverage job and is currently ~97%
of lines (96.8% over the whole tree, 99.3% of functions).

Beyond the committed vectors, two independent checks were run during
development:

- **Cross-language differential.** The mode layer (1566 cases) and the
  depadding layer (13,240 cases) were diffed against the Python sibling across
  every cipher × mode × scheme × length, and the whole-message path was diffed
  over 6,696 encrypt/decrypt cases plus 45 error cases. No mismatches.
- **OpenSSL oracle.** The AES, DES and Blowfish mode and padding output was
  compared against OpenSSL 3.5.9 and agrees byte for byte.

The committed known-answer tests are the regression guard; the differentials
above were a one-time verification against an independent implementation.

## Divergences from the Python reference

The two implementations are intended to agree; these are the deliberate
differences. They are listed so that the intent is explicit rather than
surprising.

| Area | Python (`refciphers`) | This C port |
|---|---|---|
| Serpent keys | 16 / 24 / 32 bytes | 1–32 bytes (the spec's full range) |
| Triple DES | provided | not ported |
| Command-line tool | `refciphers` CLI | none |
| Raw mode wrappers | private methods | public, block-only |
| Error signalling | raises `ValueError` | returns `-1` |
| Key input | `bytes` | `const uint8_t *` + length |

## Known limitations

- The raw `cipherDecryptCBC` / `cipherDecryptPCBC` wrappers advance the IV they
  are handed. The whole-message `cipherDecrypt` copies the IV, so it does not;
  callers of the raw wrappers must keep their own copy.
- The CBC/PCBC/CFB/OFB/CTR wrappers use fixed `uint8_t[16]` scratch, which
  assumes `blockSize <= 16`. That holds for all five ciphers here, all of which
  are 8- or 16-byte block ciphers.
- No authentication, no key derivation, not constant-time, not audited (see
  [Security notice](#security-notice)).
- No fuzzing target yet.

## References and attribution

Every cipher follows a published specification. The source of each table and
each non-obvious algorithm is listed below.

| Cipher   | Specification | Constants and tables |
|----------|---------------|----------------------|
| AES      | FIPS 197 | S-box and inverse S-box (FIPS 197 §5.1); standard Rijndael T-tables derived from them and MixColumns |
| DES      | FIPS 46-3 | IP, FP, E, P, S-boxes, PC-1/PC-2; delta-swap IP/FP after Wei Dai/Outerbridge; SP-boxes derived from S-boxes + P |
| Blowfish | Schneier, FSE 1993 | P-array and S-boxes (the hexadecimal digits of π, *Applied Cryptography* 2nd ed., appendix A.1) |
| Twofish  | Schneier, Kelsey, Whiting, Wagner, Hall and Ferguson (AES submission, 1998) | MDS and RS matrices, q0/q1 permutations |
| Serpent  | Anderson, Biham and Knudsen (1998) | S-boxes and the bit-slice gate networks (§3) |

The block modes (ECB, CBC, CFB, OFB, CTR) are from NIST SP 800-38A; PCBC is a
legacy construction (ANSI X9.52 / Kerberos). Padding schemes are PKCS#7
(RFC 2315), ANSI X9.23, ISO/IEC 7816-4, trailing bit complement, and zero
padding.

### Borrowed code

The DES initial and final permutations in `src/des.c` use a delta-swap bit
network — Wei Dai's variant of Richard Outerbridge's IP/FP algorithm — instead
of the per-bit table loop. The table-driven path it replaces is kept behind
`use_alt = 0`, and `tests/test_des.c` checks that the two agree.

Further reading:

- NIST, *Advanced Encryption Standard (AES)*, FIPS 197 — <https://csrc.nist.gov/pubs/fips/197/final>
- NIST, *Data Encryption Standard (DES)*, FIPS 46-3 — <https://csrc.nist.gov/pubs/fips/46-3/final>
- NIST, *Recommendation for Block Cipher Modes of Operation: Methods and Techniques*, SP 800-38A — <https://csrc.nist.gov/pubs/sp/800/38/a/final>
- B. Schneier, *Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish)*, FSE 1993 — <https://www.schneier.com/academic/blowfish/>
- B. Schneier, J. Kelsey, D. Whiting, D. Wagner, C. Hall and N. Ferguson, *Twofish: A 128-Bit Block Cipher*, AES submission (1998) — <https://www.schneier.com/academic/twofish/>
- R. Anderson, E. Biham and L. Knudsen, *Serpent: A Proposal for the Advanced Encryption Standard* (1998) — <https://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf>
- B. Kaliski, *PKCS #7: Cryptographic Message Syntax Version 1.5*, RFC 2315 — <https://www.rfc-editor.org/rfc/rfc2315>

## License

MIT — see [LICENSE](LICENSE).
