#ifndef SHA1
#define SHA1

#include <stddef.h>
#include <stdint.h>
typedef struct SHA1_ctx {
    uint32_t h[5];
    uint8_t buf[64];
    size_t buf_len;
    uint64_t total_len;
} SHA1_ctx;

#define SHA1_DIGEST_LENGTH 20
void SHA1_init(SHA1_ctx *ctx);
void SHA1_update(SHA1_ctx *ctx, uint8_t* b, size_t b_len);
void SHA1_final(SHA1_ctx *ctx, uint8_t out[static SHA1_DIGEST_LENGTH]);
void SHA1_hash(const uint8_t *message, size_t len, uint8_t *hash);
#endif