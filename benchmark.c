#include "sha1.h"
#include "unrolled/sha1u.h"
#include <bits/time.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>

#define BUF_LEN 1024*1024
#define ITER 1024


double diff_timespec(const struct timespec *time1, const struct timespec *time0) {
  return (time1->tv_sec - time0->tv_sec)
      + (time1->tv_nsec - time0->tv_nsec) / 1000000000.0;
}

double test_this() {
    uint8_t buf[BUF_LEN];

    struct timespec start;
    SHA1_ctx ctx;
    SHA1_init(&ctx);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i=0;i<ITER;i++) {
        SHA1_update(&ctx, buf, BUF_LEN);
    }
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    double spent_seconds = diff_timespec(&end, &start);
    double bytes_per_sec = (BUF_LEN * ITER) / spent_seconds;
    double mb_per_sec = bytes_per_sec / (1024 * 1024);
    return mb_per_sec;
}

double test_unrolled() {
    uint8_t buf[BUF_LEN];

    struct timespec start;
    SHA1U_CTX ctx;
    SHA1UInit(&ctx);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i=0;i<ITER;i++) {
        SHA1UUpdate(&ctx, buf, BUF_LEN);
    }
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    double spent_seconds = diff_timespec(&end, &start);
    double bytes_per_sec = (BUF_LEN * ITER) / spent_seconds;
    double mb_per_sec = bytes_per_sec / (1024 * 1024);
    return mb_per_sec;
}

int main() {
    double this = test_this();
    double unrolled = test_unrolled();
    printf("This gives %f mb/sec \n", this);
    printf("Unrolled gives %f mb/sec \n", unrolled);
}