#include "sha1.h"
#include <endian.h>
#include <stdint.h>
#include <string.h>

#define LEFT_ROTATE(value, shift) (((value) << (shift)) | ((value) >> (32 - (shift))))
#define getBlock(blk, off) ((blk[off] << 24) | (blk[off + 1] << 16) | (blk[off + 2] << 8) | (blk[off + 3]))

void SHA1_init(SHA1_ctx *ctx) {
    ctx->h[0] = 0x67452301;
    ctx->h[1] = 0xEFCDAB89;
    ctx->h[2] = 0x98BADCFE;
    ctx->h[3] = 0x10325476;
    ctx->h[4] = 0xC3D2E1F0;
    ctx->buf_len = 0;
    ctx->total_len = 0;
}

static void SHA1_round(SHA1_ctx *ctx, uint8_t blk[static 64]) {
    uint32_t blocks[80];
    for (int i = 0; i < 16; i++) {
        blocks[i] = getBlock(blk, i * 4);
    }

    for (int i = 16; i < 80; i++) {
        blocks[i] = LEFT_ROTATE(blocks[i - 3] ^ blocks[i - 8] ^ blocks[i - 14] ^ blocks[i - 16], 1);
    }

    uint32_t a, b, c, d, e;
    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];

    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        uint32_t temp = LEFT_ROTATE(a, 5) + f + e + k + blocks[i];
        e = d;
        d = c;
        c = LEFT_ROTATE(b, 30);
        b = a;
        a = temp;
    }

    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
}


void SHA1_update(SHA1_ctx *ctx, uint8_t *b, size_t b_len) {
    ctx->total_len += b_len;
    size_t i = b_len > 64 - ctx->buf_len ? 64 - ctx->buf_len : b_len;
    memcpy(ctx->buf + ctx->buf_len, b, i);

    ctx->buf_len += i;
    b += i;
    b_len -= i;

    if (ctx->buf_len == 64) {
        SHA1_round(ctx, ctx->buf);

        while (b_len >= 64) {
            SHA1_round(ctx, b);
            b += 64;
            b_len -= 64;
        }

        memcpy(ctx->buf, b, b_len);
        ctx->buf_len = b_len;
    }
}

void SHA1_final(SHA1_ctx *ctx, uint8_t *out) {
    memset(ctx->buf + ctx->buf_len, 0, 64 - ctx->buf_len);
    ctx->buf[ctx->buf_len] = 0x80;
    ctx->buf_len += 1;
    if (64 - ctx->buf_len < 8) {
        SHA1_round(ctx, ctx->buf);
        ctx->buf_len = 0;
        memset(ctx->buf, 0, 64);
    }

    uint64_t len = ctx->total_len * 8;
#if BYTE_ORDER == LITTLE_ENDIAN
    len = __builtin_bswap64(len);
#endif

    memcpy(ctx->buf + 56, &len, sizeof(len));

    SHA1_round(ctx, ctx->buf);

    for (size_t i = 0; i < 5; ++i) {
        out[i * 4] = (ctx->h[i] >> 24) & 0xFF;
        out[i * 4 + 1] = (ctx->h[i] >> 16) & 0xFF;
        out[i * 4 + 2] = (ctx->h[i] >> 8) & 0xFF;
        out[i * 4 + 3] = ctx->h[i] & 0xFF;
    }
}

void SHA1_hash(const uint8_t *message, size_t len, uint8_t *hash) {
    SHA1_ctx ctx;
    SHA1_init(&ctx);
    SHA1_update(&ctx, (uint8_t*)message, len);
    SHA1_final(&ctx, hash);
}
