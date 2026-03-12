/*
 * SHA-1 implementation using x86 SHA-NI intrinsics.
 *
 * Maps directly to the four dedicated hardware instructions:
 *   SHA1RNDS4  (_mm_sha1rnds4_epu32)  – 4 rounds of compression
 *   SHA1NEXTE  (_mm_sha1nexte_epu32)  – compute next-group E value
 *   SHA1MSG1   (_mm_sha1msg1_epu32)   – message schedule step 1
 *   SHA1MSG2   (_mm_sha1msg2_epu32)   – message schedule step 2
 *
 * Requires ISA: SHA + SSE4.1 (Intel Goldmont / AMD Zen or later).
 *
 * Compiler portability:
 *   GCC/Clang: sha1_compress is tagged with __attribute__((target("sha,sse4.1")))
 *              so the rest of the TU does not require -msha/-msse4.1.
 *   MSVC:      no per-function target attribute exists; the intrinsics map
 *              directly to the hardware instructions assuming the target CPU
 *              supports SHA-NI (pass /arch:AVX or rely on runtime dispatch).
 *
 * Exposed API:
 *   int  sha1_get_plugin_name(char *name, int max_length);
 *   void sha1_init(void);
 *   void sha1_update(const uint8_t *data, uint32_t size);
 *   int  sha1_get(uint8_t *sha1_buffer);
 */

#include <stdint.h>
#include <string.h>
#include <immintrin.h>

/* ------------------------------------------------------------------ */
/*  Compiler portability macros                                         */
/* ------------------------------------------------------------------ */

/*
 * SHA1_TARGET_ATTR: enable SHA + SSE4.1 code generation for a single
 * function on GCC/Clang.  MSVC compiles intrinsics unconditionally.
 */
#if defined(_MSC_VER)
#  define SHA1_TARGET_ATTR
#elif defined(__GNUC__) || defined(__clang__)
#  define SHA1_TARGET_ATTR __attribute__((target("sha,sse4.1")))
#else
#  define SHA1_TARGET_ATTR
#endif

/*
 * SHA1_EXPORT: mark public symbols for export from a shared library.
 * Required by MSVC DLLs; a no-op on ELF targets where all non-static
 * symbols are exported by default.
 */
#if defined(_MSC_VER)
#  define SHA1_EXPORT __declspec(dllexport)
#else
#  define SHA1_EXPORT
#endif

/* ------------------------------------------------------------------ */
/*  Internal context                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t h[5];        /* Hash state (A..E)                       */
    uint64_t bit_count;   /* Total message bits processed            */
    uint8_t  buf[64];     /* Partial input block                     */
    uint32_t buf_len;     /* Bytes currently in buf                  */
    int      finished;    /* Non-zero after sha1_get() finalisation  */
} sha1_ctx_t;

static sha1_ctx_t ctx;

/* ------------------------------------------------------------------ */
/*  Big-endian helpers (used only in padding / digest output)          */
/* ------------------------------------------------------------------ */

static inline void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v      );
}

static inline void store_be64(uint8_t *p, uint64_t v)
{
    store_be32(p,     (uint32_t)(v >> 32));
    store_be32(p + 4, (uint32_t)(v      ));
}

/* ------------------------------------------------------------------ */
/*  SHA-1 block compression – hardware path                            */
/*                                                                     */
/*  State layout inside __m128i ABCD:                                  */
/*    bits [127:96] = A,  [95:64] = B,  [63:32] = C,  [31:0] = D     */
/*  E is kept in bits [127:96] of a separate __m128i (E0 / E1).       */
/*                                                                     */
/*  The 64-byte block is split into four MSG0..MSG3 registers, each   */
/*  holding four consecutive big-endian message words after a byte     */
/*  swap.  The interleaved SHA1MSG1/SHA1MSG2/XOR sequence expands the  */
/*  16 initial words to the full 80-word schedule on the fly.          */
/* ------------------------------------------------------------------ */

SHA1_TARGET_ATTR
static void sha1_compress(uint32_t h[5], const uint8_t block[64])
{
    /*
     * Mask that byte-reverses each 32-bit lane, converting big-endian
     * message bytes to the word format expected by the SHA-NI instructions.
     */
    const __m128i BSWAP = _mm_set_epi64x(
        0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL);

    /*
     * Load state.  _mm_loadu_si128 reads h[0..3] so that:
     *   [127:96]=h[3]=D  [95:64]=h[2]=C  [63:32]=h[1]=B  [31:0]=h[0]=A
     * Shuffle 0x1B reverses the four dwords:
     *   [127:96]=A  [95:64]=B  [63:32]=C  [31:0]=D
     */
    __m128i ABCD = _mm_shuffle_epi32(
        _mm_loadu_si128((const __m128i *)h), 0x1B);

    /* E is held in [127:96]; lower lanes are don't-care for SHA1NEXTE. */
    __m128i E0 = _mm_set_epi32((int)h[4], 0, 0, 0);

    /* Save initial state for the Davies-Meyer feed-forward. */
    const __m128i ABCD_SAVE = ABCD;
    const __m128i E0_SAVE   = E0;

    __m128i E1;
    __m128i MSG0, MSG1, MSG2, MSG3;

    /* ----------------------------------------------------------------
     * Rounds 0-3
     * For the very first group E is folded into W[0] with a plain add
     * (there is no prior ABCD from which SHA1NEXTE could derive it).
     * ---------------------------------------------------------------- */
    MSG0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(block +  0)), BSWAP);
    E0   = _mm_add_epi32(E0, MSG0);   /* b[127:96] = E + W[0], rest = W[1..3] */
    E1   = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);

    /* ----------------------------------------------------------------
     * Rounds 4-7
     * From here on SHA1NEXTE computes the E for the next 4-round group:
     *   E_next[127:96] = W[i] + ROL30(A_saved)
     * where A_saved is the A that was INPUT to the preceding rnds4 call,
     * matching the SHA-1 identity: E_after_4_rounds = ROL30(A_initial).
     * ---------------------------------------------------------------- */
    MSG1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(block + 16)), BSWAP);
    E1   = _mm_sha1nexte_epu32(E1, MSG1);
    E0   = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);

    /* Rounds 8-11 */
    MSG2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(block + 32)), BSWAP);
    E0   = _mm_sha1nexte_epu32(E0, MSG2);
    E1   = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    /* Rounds 12-15 */
    MSG3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(block + 48)), BSWAP);
    E1   = _mm_sha1nexte_epu32(E1, MSG3);
    E0   = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    /* Rounds 16-19 */
    E0   = _mm_sha1nexte_epu32(E0, MSG0);
    E1   = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    /* Rounds 20-23 */
    E1   = _mm_sha1nexte_epu32(E1, MSG1);
    E0   = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    /* Rounds 24-27 */
    E0   = _mm_sha1nexte_epu32(E0, MSG2);
    E1   = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    /* Rounds 28-31 */
    E1   = _mm_sha1nexte_epu32(E1, MSG3);
    E0   = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    /* Rounds 32-35 */
    E0   = _mm_sha1nexte_epu32(E0, MSG0);
    E1   = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    /* Rounds 36-39 */
    E1   = _mm_sha1nexte_epu32(E1, MSG1);
    E0   = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    /* Rounds 40-43 */
    E0   = _mm_sha1nexte_epu32(E0, MSG2);
    E1   = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    /* Rounds 44-47 */
    E1   = _mm_sha1nexte_epu32(E1, MSG3);
    E0   = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    /* Rounds 48-51 */
    E0   = _mm_sha1nexte_epu32(E0, MSG0);
    E1   = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    /* Rounds 52-55 */
    E1   = _mm_sha1nexte_epu32(E1, MSG1);
    E0   = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
    MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
    MSG3 = _mm_xor_si128(MSG3, MSG1);

    /* Rounds 56-59 */
    E0   = _mm_sha1nexte_epu32(E0, MSG2);
    E1   = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
    MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
    MSG0 = _mm_xor_si128(MSG0, MSG2);

    /* Rounds 60-63 */
    E1   = _mm_sha1nexte_epu32(E1, MSG3);
    E0   = ABCD;
    MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
    MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
    MSG1 = _mm_xor_si128(MSG1, MSG3);

    /* Rounds 64-67 */
    E0   = _mm_sha1nexte_epu32(E0, MSG0);
    E1   = ABCD;
    MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
    MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
    MSG2 = _mm_xor_si128(MSG2, MSG0);

    /* Rounds 68-71 */
    E1   = _mm_sha1nexte_epu32(E1, MSG1);
    E0   = ABCD;
    MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
    MSG3 = _mm_xor_si128(MSG3, MSG1);       /* no sha1msg1 needed here */

    /* Rounds 72-75 */
    E0   = _mm_sha1nexte_epu32(E0, MSG2);
    E1   = ABCD;
    MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
    ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);

    /* Rounds 76-79 */
    E1   = _mm_sha1nexte_epu32(E1, MSG3);
    E0   = ABCD;
    ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);

    /* ----------------------------------------------------------------
     * Davies-Meyer feed-forward:
     *   ABCD_new = ABCD_computed + ABCD_initial
     *   E_new    = ROL30(A_pre_last_rnds4) + E_initial
     *            = sha1nexte(E0, E0_SAVE)[127:96]
     * ---------------------------------------------------------------- */
    E0   = _mm_sha1nexte_epu32(E0, E0_SAVE);
    ABCD = _mm_add_epi32(ABCD, ABCD_SAVE);

    /* Reverse word order back and store {A,B,C,D} → h[0..3]. */
    _mm_storeu_si128((__m128i *)h, _mm_shuffle_epi32(ABCD, 0x1B));
    /* E result sits in [127:96] of E0 after sha1nexte. */
    h[4] = (uint32_t)_mm_extract_epi32(E0, 3);
}

/* ------------------------------------------------------------------ */
/*  Public API                                                          */
/* ------------------------------------------------------------------ */

SHA1_EXPORT int sha1_get_plugin_name(char *name, int max_length)
{
    if (!name || max_length <= 0)
        return -1;
#if defined(_MSC_VER)
    strncpy_s(name, (size_t)max_length, "sha1intrinsics-x86", _TRUNCATE);
#else
    strncpy(name, "sha1intrinsics-x86", (size_t)max_length - 1);
    name[max_length - 1] = '\0';
#endif
    return 0;
}

SHA1_EXPORT void sha1_init(void)
{
    ctx.h[0]      = 0x67452301u;
    ctx.h[1]      = 0xEFCDAB89u;
    ctx.h[2]      = 0x98BADCFEu;
    ctx.h[3]      = 0x10325476u;
    ctx.h[4]      = 0xC3D2E1F0u;
    ctx.bit_count = 0;
    ctx.buf_len   = 0;
    ctx.finished  = 0;
}

SHA1_EXPORT void sha1_update(const uint8_t *data, uint32_t size)
{
    if (ctx.finished || !data || size == 0)
        return;

    ctx.bit_count += (uint64_t)size * 8;

    uint32_t        remaining = size;
    const uint8_t  *src       = data;

    /* Drain partial block first. */
    if (ctx.buf_len > 0) {
        uint32_t space = 64 - ctx.buf_len;
        uint32_t copy  = (remaining < space) ? remaining : space;
        memcpy(ctx.buf + ctx.buf_len, src, copy);
        ctx.buf_len += copy;
        src         += copy;
        remaining   -= copy;

        if (ctx.buf_len == 64) {
            sha1_compress(ctx.h, ctx.buf);
            ctx.buf_len = 0;
        }
    }

    /* Process full blocks directly from the caller's buffer. */
    while (remaining >= 64) {
        sha1_compress(ctx.h, src);
        src       += 64;
        remaining -= 64;
    }

    /* Buffer any leftover bytes. */
    if (remaining > 0) {
        memcpy(ctx.buf, src, remaining);
        ctx.buf_len = remaining;
    }
}

SHA1_EXPORT int sha1_get(uint8_t *sha1_buffer)
{
    if (!sha1_buffer)
        return -1;

    if (ctx.finished) {
        for (int i = 0; i < 5; i++)
            store_be32(sha1_buffer + i * 4, ctx.h[i]);
        return 0;
    }

    /* -- Padding -- */
    uint8_t  pad[128];
    uint32_t pad_len = 0;

    memcpy(pad, ctx.buf, ctx.buf_len);
    pad_len = ctx.buf_len;

    pad[pad_len++] = 0x80;

    if (pad_len <= 56) {
        memset(pad + pad_len, 0, 56 - pad_len);
        pad_len = 56;
    } else {
        memset(pad + pad_len, 0, 120 - pad_len);
        pad_len = 120;
    }

    store_be64(pad + pad_len, ctx.bit_count);
    pad_len += 8;

    sha1_compress(ctx.h, pad);
    if (pad_len == 128)
        sha1_compress(ctx.h, pad + 64);

    ctx.finished = 1;

    for (int i = 0; i < 5; i++)
        store_be32(sha1_buffer + i * 4, ctx.h[i]);

    return 0;
}
