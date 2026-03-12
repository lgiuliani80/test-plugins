/*
 * SHA-1 implementation as a plugin module.
 *
 * Exposed API:
 *   void sha1_init(void);
 *   void sha1_update(const uint8_t *data, uint32_t size);
 *   int  sha1_get(uint8_t *sha1_buffer);
 */

#include <stdint.h>
#include <string.h>

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
/*  Internal state                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t h[5];          /* Hash state                             */
    uint64_t bit_count;     /* Total bits processed                   */
    uint8_t  buf[64];       /* Partial input block                    */
    uint32_t buf_len;       /* Bytes currently held in buf            */
    int      finished;      /* sha1_get() has been called             */
} sha1_ctx_t;

static sha1_ctx_t ctx;

/* ------------------------------------------------------------------ */
/*  Helpers                                                             */
/* ------------------------------------------------------------------ */

static inline uint32_t rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

/* Load a big-endian 32-bit word from an unaligned byte pointer */
static inline uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |
            (uint32_t)p[3];
}

/* Store a big-endian 32-bit word into a byte pointer */
static inline void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v      );
}

/* Store a big-endian 64-bit integer into a byte pointer */
static inline void store_be64(uint8_t *p, uint64_t v)
{
    store_be32(p,     (uint32_t)(v >> 32));
    store_be32(p + 4, (uint32_t)(v      ));
}

/* ------------------------------------------------------------------ */
/*  Core SHA-1 block compression (operates on one 64-byte block)       */
/* ------------------------------------------------------------------ */

static void sha1_compress(uint32_t h[5], const uint8_t block[64])
{
    uint32_t w[80];
    int i;

    /* Prepare message schedule */
    for (i = 0; i < 16; i++)
        w[i] = load_be32(block + i * 4);
    for (i = 16; i < 80; i++)
        w[i] = rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    uint32_t f, k, temp;

    for (i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }

        temp = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = temp;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                          */
/* ------------------------------------------------------------------ */

SHA1_EXPORT int sha1_get_plugin_name(char *name, int max_length)
{
    static const char * const plugin_name = "sha1basic";
    const int plugin_name_len = strlen(plugin_name);

    if (!name || max_length <= 0)
        return -1;
    strncpy(name, plugin_name, (size_t)max_length - 1);
    name[max_length - 1] = '\0';
    
    return plugin_name_len;
}

SHA1_EXPORT int sha1_init(void)
{
    ctx.h[0]     = 0x67452301u;
    ctx.h[1]     = 0xEFCDAB89u;
    ctx.h[2]     = 0x98BADCFEu;
    ctx.h[3]     = 0x10325476u;
    ctx.h[4]     = 0xC3D2E1F0u;
    ctx.bit_count = 0;
    ctx.buf_len   = 0;
    ctx.finished  = 0;

    return 0;
}

SHA1_EXPORT void sha1_update(const uint8_t *data, uint32_t size)
{
    if (ctx.finished || !data || size == 0)
        return;

    ctx.bit_count += (uint64_t)size * 8;

    uint32_t remaining = size;
    const uint8_t *src = data;

    /* Fill the partial block first */
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

    /* Process full 64-byte blocks directly from the input */
    while (remaining >= 64) {
        sha1_compress(ctx.h, src);
        src       += 64;
        remaining -= 64;
    }

    /* Buffer the leftover bytes */
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
        /* Allow repeated calls to sha1_get() after finalisation */
        for (int i = 0; i < 5; i++)
            store_be32(sha1_buffer + i * 4, ctx.h[i]);
        return 0;
    }

    /* --- Padding --- */
    uint8_t pad_block[128];
    uint32_t pad_len = 0;

    /* Copy buffered bytes */
    memcpy(pad_block, ctx.buf, ctx.buf_len);
    pad_len = ctx.buf_len;

    /* Append 0x80 */
    pad_block[pad_len++] = 0x80;

    /* Zero-fill to position 56 (mod 64); if we're past 56 we need an extra block */
    if (pad_len <= 56) {
        memset(pad_block + pad_len, 0, 56 - pad_len);
        pad_len = 56;
    } else {
        memset(pad_block + pad_len, 0, 120 - pad_len);
        pad_len = 120;
    }

    /* Append 64-bit big-endian bit count */
    store_be64(pad_block + pad_len, ctx.bit_count);
    pad_len += 8;

    /* Compress remaining padding block(s) */
    sha1_compress(ctx.h, pad_block);
    if (pad_len == 128)
        sha1_compress(ctx.h, pad_block + 64);

    ctx.finished = 1;

    /* Produce the 20-byte digest */
    for (int i = 0; i < 5; i++)
        store_be32(sha1_buffer + i * 4, ctx.h[i]);

    return 0;
}
