#pragma once
#ifndef _BLAKE256_H_
#define _BLAKE256_H_

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
void blake256_update(state *, const uint8_t *, uint64_t);
void blake256_final(state *, uint8_t *);
void blake256_hash(uint8_t *, const uint8_t *, uint64_t);
void hmac_blake256_init(hmac_state *, const uint8_t *, uint64_t);
void hmac_blake256_update(hmac_state *, const uint8_t *, uint64_t);
void hmac_blake256_final(hmac_state *, uint8_t *);
void hmac_blake256_hash(uint8_t *, const uint8_t *, uint64_t, const uint8_t *, uint64_t);
void pbkdf2_blake256(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
  size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen);

#if defined(__cplusplus)
}
#endif

#endif /* _BLAKE256_H_ */
