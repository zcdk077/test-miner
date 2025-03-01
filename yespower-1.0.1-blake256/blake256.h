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

void blake2561_init(blake256_ctx *ctx);
void blake2561_update(blake256_ctx *ctx, const uint8_t *data, uint64_t datalen);
void blake2561_final(blake256_ctx *ctx, uint8_t *digest);
void blake2561_hash(uint8_t *out, const uint8_t *in, uint64_t inlen);

/* HMAC functions: */

void hmac_blake2561_init(hmac_ctx *ctx, const uint8_t *_key, uint64_t keylen);
void hmac_blake2561_update(hmac_ctx *ctx, const uint8_t *data, uint64_t datalen);
void hmac_blake2561_final(hmac_ctx *ctx, uint8_t *digest);
void hmac_blake2561_hash(uint8_t *out, const uint8_t *key, uint64_t keylen, const uint8_t *in, uint64_t inlen);

void pbkdf2_blake256(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
  size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen);

#if defined(__cplusplus)
}
#endif

#endif /* _BLAKE256_H_ */
