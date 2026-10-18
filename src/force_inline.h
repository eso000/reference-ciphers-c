#ifndef FORCE_INLINE_HEADER
#define FORCE_INLINE_HEADER

/* `inline` is only a hint. At -O2 gcc declines it for the larger round
   helpers, which cost AES and Serpent about 30% of their speed against the
   macros these functions replaced. always_inline makes it binding on gcc and
   clang; other compilers fall back to the plain hint. */
#if defined(__GNUC__)
#define FORCE_INLINE static inline __attribute__((always_inline))
#else
#define FORCE_INLINE static inline
#endif

#endif
