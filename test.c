#include "sha1.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void printHash(const uint8_t *hash) {
    for (int i = 0; i < SHA1_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}


void testSHA1() {
    const char *messages[] = {
        "abc",
        "The quick brown fox jumps over the lazy dog",
        "The quick brown fox jumps over the lazy cog",
        "",
    };

    const char *expectedHashes[] = {
        "a9993e364706816aba3e25717850c26c9cd0d89d",
        "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    };

    for (size_t i = 0; i < sizeof(messages) / sizeof(messages[0]); ++i) {
        uint8_t hash[SHA1_DIGEST_LENGTH];
        SHA1_hash((const uint8_t *)messages[i], strlen(messages[i]), hash);

        printf("Test %zu:\n", i + 1);
        printf("Message: %s\n", messages[i]);
        printf("Expected Hash: %s\n", expectedHashes[i]);
        printf("Computed Hash: ");
        printHash(hash);
        printf("\n");
    }
}

int main() {
    testSHA1();

    return 0;
}
