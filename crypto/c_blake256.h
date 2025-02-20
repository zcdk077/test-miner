#pragma once
#ifndef __BLAKE256_H__
#define __BLAKE256_H__

#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER) || defined(__x86_64__) || defined(__x86__)
#define NATIVE_LITTLE_ENDIAN
#endif

typedef struct {
  uint32_t h[8], s[4], t[2];
  int buflen, nullt;
  uint8_t buf[64];
} blake256_ctx;

typedef struct {
  blake256_ctx inner;
  blake256_ctx outer;
} hmac_ctx;

#if defined(__cplusplus)
extern "C" {
#endif

void blake256_init(blake256_ctx *ctx);
void blake256_update(blake256_ctx *ctx, const uint8_t *data, uint64_t datalen);
void blake256_final(blake256_ctx *ctx, uint8_t *digest);

#if defined(__cplusplus)
}
#endif

#endif /* _BLAKE256_H_ */
