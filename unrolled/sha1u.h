#ifndef SHA1U_H
#define SHA1U_H

/*
   SHA-1 in C
   By Steve Reid <steve@edmweb.com>
   100% Public Domain
 */

#include "stdint.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1U_CTX;

void SHA1UTransform(
    uint32_t state[5],
    const unsigned char buffer[64]
    );

void SHA1UInit(
    SHA1U_CTX * context
    );

void SHA1UUpdate(
    SHA1U_CTX * context,
    const unsigned char *data,
    uint32_t len
    );

void SHA1UFinal(
    unsigned char digest[20],
    SHA1U_CTX * context
    );

void SHA1U(
    char *hash_out,
    const char *str,
    uint32_t len);

#if defined(__cplusplus)
}
#endif

#endif /* SHA1U_H */