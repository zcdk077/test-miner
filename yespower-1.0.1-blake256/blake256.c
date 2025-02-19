/*
 * The blake256_* and blake224_* functions are largely copied from
 * blake256_light.c and blake224_light.c from the BLAKE website:
 *
 *     http://131002.net/blake/
 *
 * The hmac_* functions implement HMAC-BLAKE-256 and HMAC-BLAKE-224.
 * HMAC is specified by RFC 2104.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "sph_types.h"
#include "sysendian-b256.h"
#include "blake256.h"

#define U8TO32(p) \
    (((uint32_t)((p)[0]) << 24) | ((uint32_t)((p)[1]) << 16) |  \
   ((uint32_t)((p)[2]) <<  8) | ((uint32_t)((p)[3])      ))
#define U32TO8(p, v) \
    (p)[0] = (uint8_t)((v) >> 24); (p)[1] = (uint8_t)((v) >> 16); \
    (p)[2] = (uint8_t)((v) >>  8); (p)[3] = (uint8_t)((v)      );

const uint8_t sigma[][16] =
{
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
  {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
  { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
  { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
  {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
  {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
  { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
  {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13 , 0 },
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
  {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
  { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
  { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 }
};

const uint32_t cst[16] = {
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
    0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
    0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
    0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
};

static const uint8_t padding[129] =
{
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


void blake256_compress(state *S, const uint8_t *block) {
    uint32_t v[16], m[16], i;

#define ROT(x,n) (((x)<<(32-n))|((x)>>(n)))
#define G(a,b,c,d,e)                                      \
    v[a] += (m[sigma[i][e]] ^ cst[sigma[i][e+1]]) + v[b]; \
    v[d] = ROT(v[d] ^ v[a],16);                           \
    v[c] += v[d];                                         \
    v[b] = ROT(v[b] ^ v[c],12);                           \
    v[a] += (m[sigma[i][e+1]] ^ cst[sigma[i][e]])+v[b];   \
    v[d] = ROT(v[d] ^ v[a], 8);                           \
    v[c] += v[d];                                         \
    v[b] = ROT(v[b] ^ v[c], 7);

    for (i = 0; i < 16; ++i) m[i] = U8TO32(block + i * 4);
    for (i = 0; i < 8;  ++i) v[i] = S->h[i];
    v[ 8] = S->s[0] ^ cst[0];
    v[ 9] = S->s[1] ^ cst[1];
    v[10] = S->s[2] ^ cst[2];
    v[11] = S->s[3] ^ cst[3];
    v[12] = cst[4];
    v[13] = cst[5];
    v[14] = cst[6];
    v[15] = cst[7];

    if ( !S->nullt) {
        v[12] ^= S->t[0];
        v[13] ^= S->t[0];
        v[14] ^= S->t[1];
        v[15] ^= S->t[1];
    }

    for (i = 0; i < 14; ++i) {
        G(0, 4,  8, 12,  0);
        G(1, 5,  9, 13,  2);
        G(2, 6, 10, 14,  4);
        G(3, 7, 11, 15,  6);
        G( 0,  5, 10, 15,  8 );
        G( 1,  6, 11, 12, 10 );
        G( 2,  7,  8, 13, 12 );
        G( 3,  4,  9, 14, 14 );
    }

    for (i = 0; i < 16; ++i) S->h[i % 8] ^= v[i];
    for (i = 0; i < 8;  ++i) S->h[i] ^= S->s[i % 4];
}

void blake256_init(state *S) {
    S->h[0] = 0x6a09e667;
    S->h[1] = 0xbb67ae85;
    S->h[2] = 0x3c6ef372;
    S->h[3] = 0xa54ff53a;
    S->h[4] = 0x510e527f;
    S->h[5] = 0x9b05688c;
    S->h[6] = 0x1f83d9ab;
    S->h[7] = 0x5be0cd19;
    S->t[0] = S->t[1] = S->buflen = S->nullt = 0;
    S->s[0] = S->s[1] = S->s[2] = S->s[3] = 0;
}

// datalen = number of bits
void blake256_update(state *S, const uint8_t *in, uint64_t inlen) {
    int left = S->buflen;
    int fill = 64 - left;

    if( left && ( inlen >= fill ) )
    {
      memcpy( ( void * ) ( S->buf + left ), ( void * ) in, fill );
      S->t[0] += 512;
      if ( S->t[0] == 0 ) S->t[1]++;
        blake256_compress( S, S->buf );
        in += fill;
        inlen  -= fill;
        left = 0;
    }

    while (inlen >= 64) {
        S->t[0] += 512;
        if (S->t[0] == 0) S->t[1]++;
        blake256_compress(S, in);
        in += 64;
        inlen -= 64;
    }

    if (inlen > 0) {
        memcpy((void *) (S->buf + left), (void *) in, inlen);
        S->buflen = left + (int)inlen;
    } else {
        S->buflen = 0;
    }
}

void blake256_final(state *S, uint8_t *out) {
    uint8_t msglen[8], zo = 0x01, oo = 0x81;
    uint32_t lo = S->t[0] + S->buflen, hi = S->t[1];

    if ( lo < ( S->buflen << 3 ) ) hi++;
    U32TO8(msglen + 0, hi);
    U32TO8(msglen + 4, lo);

    if ( S->buflen == 55 )   /* one padding byte */
    {
      S->t[0] -= 8;
      blake256_update( S, &oo, 1 );
    }
    else
    {
        if ( S->buflen < 55 )   /* enough space to fill the block  */
        {
          if ( !S->buflen ) S->nullt = 1;
          S->t[0] -= 440 - ( S->buflen << 3 );
          blake256_update( S, padding, 55 - S->buflen );
        }
        else   /* need 2 compressions */
        {
            S->t[0] -= 512 - ( S->buflen << 3 );
            blake256_update( S, padding, 64 - S->buflen );
            S->t[0] -= 440;
            blake256_update( S, padding + 1, 55 );
            S->nullt = 1;
        }
        blake256_update( S, &zo, 1 );
        S->t[0] -= 8;
    }
    S->t[0] -= 64;
    blake256_update(S, msglen, 8);

    U32TO8(out +  0, S->h[0]);
    U32TO8(out +  4, S->h[1]);
    U32TO8(out +  8, S->h[2]);
    U32TO8(out + 12, S->h[3]);
    U32TO8(out + 16, S->h[4]);
    U32TO8(out + 20, S->h[5]);
    U32TO8(out + 24, S->h[6]);
    U32TO8(out + 28, S->h[7]);
}

// inlen = number of bytes
void blake256_hash(uint8_t *out, const uint8_t *in, uint64_t inlen) {
    state S;
    blake256_init(&S);
    blake256_update(&S, in, inlen);
    blake256_final(&S, out);
}

// keylen = number of bytes
void hmac_blake256_init(hmac_state *S, const uint8_t *_key, uint64_t keylen) {
    const uint8_t *key = _key;
    uint8_t keyhash[32];
    uint8_t pad[64];
    uint64_t i;

    if (keylen > 64) {
        blake256_hash(keyhash, key, keylen);
        key = keyhash;
        keylen = 32;
    }

    blake256_init(&S->inner);
    memset(pad, 0x36, 64);
    for (i = 0; i < keylen; ++i) {
        pad[i] ^= key[i];
    }
    blake256_update(&S->inner, pad, 512);

    blake256_init(&S->outer);
    memset(pad, 0x5c, 64);
    for (i = 0; i < keylen; ++i) {
        pad[i] ^= key[i];
    }
    blake256_update(&S->outer, pad, 512);

    memset(keyhash, 0, 32);
}

// datalen = number of bits
void hmac_blake256_update(hmac_state *S, const uint8_t *in, uint64_t inlen) {
  // update the inner state
  blake256_update(&S->inner, in, inlen);
}

void hmac_blake256_final(hmac_state *S, uint8_t *out) {
    uint8_t ihash[32];
    blake256_final(&S->inner, ihash);
    blake256_update(&S->outer, ihash, 256);
    blake256_final(&S->outer, out);
    memset(ihash, 0, 32);
}

// keylen = number of bytes; inlen = number of bytes
void hmac_blake256_hash(uint8_t *out, const uint8_t *key, uint64_t keylen, const uint8_t *in, uint64_t inlen) {
    hmac_state S;
    hmac_blake256_init(&S, key, keylen);
    hmac_blake256_update(&S, in, inlen);
    hmac_blake256_final(&S, out);
}

void pbkdf2_blake256(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
  size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen)
{
  hmac_state PShctx, hctx;
  size_t i;
  uint8_t ivec[4];
  uint8_t U[32];
  uint8_t T[32];
  uint64_t j;
  int k;
  size_t clen;

  /* Compute HMAC state after processing P and S. */
  hmac_blake256_init(&PShctx, passwd, passwdlen);
  hmac_blake256_update(&PShctx, salt, saltlen);

  /* Iterate through the blocks. */
  for (i = 0; i * 32 < dkLen; i++) {
    /* Generate INT(i + 1). */
    be32enc(ivec, (uint32_t)(i + 1));

    /* Compute U_1 = PRF(P, S || INT(i)). */
    memcpy(&hctx, &PShctx, sizeof(hmac_state));
    hmac_blake256_update(&hctx, ivec, 4);
    hmac_blake256_final(&hctx, U);

    /* T_i = U_1 ... */
    memcpy(T, U, 32);

    for (j = 2; j <= c; j++) {
      /* Compute U_j. */
      hmac_blake256_init(&hctx, passwd, passwdlen);
      hmac_blake256_update(&hctx, U, 32);
      hmac_blake256_final(&hctx, U);

      /* ... xor U_j ... */
      for (k = 0; k < 32; k++) {
        T[k] ^= U[k];
      }
    }

    /* Copy as many bytes as necessary into buf. */
    clen = dkLen - i * 32;
    if (clen > 32) {
      clen = 32;
    }

    memcpy(&buf[i * 32], T, clen);
  }

  /* Clean PShctx, since we never called _Final on it. */
  memset(&PShctx, 0, sizeof(hmac_state));
}
