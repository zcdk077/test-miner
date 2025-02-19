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
} state;

typedef struct {
  state inner;
  state outer;
} hmac_state;

#if defined(__cplusplus)
extern "C" {
#endif

void blake256_init(state *);
void blake256_update(state *, const uint8_t *in, uint64_t inlen);
void blake256_final(state *, uint8_t *out);
void blake256_hash(uint8_t *, const uint8_t *in, uint64_t inlen);

/* HMAC functions: */

void hmac_blake256_init(hmac_state *S, const uint8_t *_key, uint64_t keylen);
void hmac_blake256_update(hmac_state *S, const uint8_t *in, uint64_t inlen);
void hmac_blake256_final(hmac_state *S, uint8_t *out);
void hmac_blake256_hash(uint8_t *out, const uint8_t *key, uint64_t keylen, const uint8_t *in, uint64_t inlen);

void pbkdf2_blake256(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
  size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen);

#if defined(__cplusplus)
}
#endif

#endif /* _BLAKE256_H_ */
