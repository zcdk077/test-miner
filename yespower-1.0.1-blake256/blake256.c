/*
 * The blake256_* and blake224_* functions are largely copied from
 * blake256_light.c and blake224_light.c from the BLAKE website:
 *
 *     http://131002.net/blake/
 *
 * The hmac_* functions implement HMAC-BLAKE-256 and HMAC-BLAKE-224.
 * HMAC is specified by RFC 2104.
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sph_types.h"
#include "sysendian-b256.h"
#include "blake256.h"

#define U8TO32(p) \
    (((uint32_t)((p)[0]) << 24) | ((uint32_t)((p)[1]) << 16) |  \
    ((uint32_t)((p)[2]) <<  8) | ((uint32_t)((p)[3])))
#define U32TO8(p, v) \
    (p)[0] = (uint8_t)((v) >> 24); (p)[1] = (uint8_t)((v) >> 16); \
    (p)[2] = (uint8_t)((v) >>  8); (p)[3] = (uint8_t)((v)      );

static const uint8_t sigma[][16] =
{
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13 ,0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 }
};

static const uint32_t cst[16] =
{
    0x243F6A88,0x85A308D3,0x13198A2E,0x03707344,
    0xA4093822,0x299F31D0,0x082EFA98,0xEC4E6C89,
    0x452821E6,0x38D01377,0xBE5466CF,0x34E90C6C,
    0xC0AC29B7,0xC97C50DD,0x3F84D5B5,0xB5470917
};

static const uint8_t padding [] =
{
    0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

static void blake256_compress(blake256_ctx *ctx, const uint8_t *block)
{
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

    for(i=0; i<16;++i)  m[i] = U8TO32(block + i*4);
    for(i=0; i< 8;++i)  v[i] = ctx->h[i];
    v[ 8] = ctx->s[0] ^ 0x243F6A88;
    v[ 9] = ctx->s[1] ^ 0x85A308D3;
    v[10] = ctx->s[2] ^ 0x13198A2E;
    v[11] = ctx->s[3] ^ 0x03707344;
    v[12] = 0xA4093822;
    v[13] = 0x299F31D0;
    v[14] = 0x082EFA98;
    v[15] = 0xEC4E6C89;
    if (ctx->nullt == 0)
    {
        v[12] ^= ctx->t[0];
        v[13] ^= ctx->t[0];
        v[14] ^= ctx->t[1];
        v[15] ^= ctx->t[1];
    }

    for(i=0; i<14; ++i)
    {
        G( 0, 4, 8,12, 0);
        G( 1, 5, 9,13, 2);
        G( 2, 6,10,14, 4);
        G( 3, 7,11,15, 6);
        G( 3, 4, 9,14,14);
        G( 2, 7, 8,13,12);
        G( 0, 5,10,15, 8);
        G( 1, 6,11,12,10);
    }
    for(i=0; i<16;++i)  ctx->h[i%8] ^= v[i];
    for(i=0; i<8 ;++i)  ctx->h[i] ^= ctx->s[i%4];
}

void blake2561_init(blake256_ctx *ctx)
{
    ctx->h[0] = 0x6A09E667;
    ctx->h[1] = 0xBB67AE85;
    ctx->h[2] = 0x3C6EF372;
    ctx->h[3] = 0xA54FF53A;
    ctx->h[4] = 0x510E527F;
    ctx->h[5] = 0x9B05688C;
    ctx->h[6] = 0x1F83D9AB;
    ctx->h[7] = 0x5BE0CD19;
    ctx->t[0] = ctx->t[1] = ctx->buflen = ctx->nullt = 0;
    ctx->s[0] = ctx->s[1] = ctx->s[2] = ctx->s[3] = 0;
}

void blake2561_update(blake256_ctx *ctx, const uint8_t *data, uint64_t datalen)
{
    int left = ctx->buflen >> 3;
    int fill = 64 - left;

    if (left && ( ((datalen >> 3) & 0x3F) >= (unsigned) fill))
    {
        memcpy((void *) (ctx->buf + left), (void *) data, fill);
        ctx->t[0] += 512;
        if (ctx->t[0] == 0) ctx->t[1]++;
        blake256_compress(ctx, ctx->buf);
        data += fill;
        datalen  -= (fill << 3);
        left = 0;
    }

    while (datalen >= 512)
    {
        ctx->t[0] += 512;
        if (ctx->t[0] == 0) ctx->t[1]++;
        blake256_compress(ctx, data);
        data += 64;
        datalen  -= 512;
    }

    if (datalen > 0)
    {
        memcpy((void *) (ctx->buf + left), (void *) data, datalen >> 3);
        ctx->buflen = (left << 3) + (int)datalen;
    }
    else
    {
        ctx->buflen=0;
    }
}

void blake2561_final(blake256_ctx *ctx, uint8_t *digest)
{
    uint8_t msglen[8], zo = 0x01, oo = 0x81;
    uint32_t lo = ctx->t[0] + ctx->buflen, hi = ctx->t[1];

    if (lo < (unsigned)ctx->buflen) hi++;
    U32TO8(msglen + 0, hi);
    U32TO8(msglen + 4, lo);

    if (ctx->buflen == 440)
    {
        ctx->t[0] -= 8;
        blake2561_update(ctx, &oo, 8);
    }
    else
    {
        if (ctx->buflen < 440)
        {
            if (!ctx->buflen) ctx->nullt = 1;
            ctx->t[0] -= 440 - ctx->buflen;
            blake2561_update(ctx, padding, 440 - ctx->buflen);
        }
        else
        {
            ctx->t[0] -= 512 - ctx->buflen;
            blake2561_update(ctx, padding, 512 - ctx->buflen);
            ctx->t[0] -= 440;
            blake2561_update(ctx, padding+1, 440);
            ctx->nullt = 1;
        }
        blake2561_update(ctx, &zo, 8);
        ctx->t[0] -= 8;
    }
    ctx->t[0] -= 64;
    blake2561_update(ctx, msglen, 64);

    U32TO8(digest +  0, ctx->h[0]);
    U32TO8(digest +  4, ctx->h[1]);
    U32TO8(digest +  8, ctx->h[2]);
    U32TO8(digest + 12, ctx->h[3]);
    U32TO8(digest + 16, ctx->h[4]);
    U32TO8(digest + 20, ctx->h[5]);
    U32TO8(digest + 24, ctx->h[6]);
    U32TO8(digest + 28, ctx->h[7]);
}

// inlen = number of bytes
void blake2561_hash(uint8_t *out, const uint8_t *in, uint64_t inlen)
{
    blake256_ctx ctx;
    blake2561_init(&ctx);
    blake2561_update(&ctx, in, inlen * 8);
    blake2561_final(&ctx, out);
}

// keylen = number of bytes
void hmac_blake2561_init(hmac_ctx *ctx, const uint8_t *_key, uint64_t keylen)
{
    const uint8_t *key = _key;
    uint8_t keyhash[32];
    uint8_t pad[64];
    uint64_t i;

    if (keylen > 64) {
        blake2561_hash(keyhash, key, keylen);
        key = keyhash;
        keylen = 32;
    }

    blake2561_init(&ctx->inner);
    memset(pad, 0x36, 64);
    for (i = 0; i < keylen; ++i) {
        pad[i] ^= key[i];
    }
    blake2561_update(&ctx->inner, pad, 512);

    blake2561_init(&ctx->outer);
    memset(pad, 0x5c, 64);
    for (i = 0; i < keylen; ++i) {
        pad[i] ^= key[i];
    }
    blake2561_update(&ctx->outer, pad, 512);

    memset(keyhash, 0, 32);
}

// datalen = number of bits
void hmac_blake2561_update(hmac_ctx *ctx, const uint8_t *data, uint64_t datalen)
{
    // update the inner state
    blake2561_update(&ctx->inner, data, datalen);
}

void hmac_blake2561_final(hmac_ctx *ctx, uint8_t *digest)
{
    uint8_t ihash[32];
    blake2561_final(&ctx->inner, ihash);
    blake2561_update(&ctx->outer, ihash, 256);
    blake2561_final(&ctx->outer, digest);
    memset(ihash, 0, 32);
}

// keylen = number of bytes; inlen = number of bytes
void hmac_blake2561_hash(uint8_t *out, const uint8_t *key, uint64_t keylen, const uint8_t *in, uint64_t inlen)
{
    hmac_ctx ctx;
    hmac_blake2561_init(&ctx, key, keylen);
    hmac_blake2561_update(&ctx, in, inlen * 8);
    hmac_blake2561_final(&ctx, out);
}

void pbkdf2_blake256(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
  size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen)
{
    hmac_ctx PShctx, hctx;
    size_t i;
    uint8_t ivec[4];
    uint8_t U[32];
    uint8_t T[32];
    uint64_t j;
    int k;
    size_t clen;

    /* Compute HMAC state after processing P and S. */
    hmac_blake2561_init(&PShctx, passwd, passwdlen);
    hmac_blake2561_update(&PShctx, salt, saltlen);

    /* Iterate through the blocks. */
    for (i = 0; i * 32 < dkLen; i++)
    {
        /* Generate INT(i + 1). */
        be32enc(ivec, (uint32_t)(i + 1));

        /* Compute U_1 = PRF(P, S || INT(i)). */
        memcpy(&hctx, &PShctx, sizeof(hmac_ctx));
        hmac_blake2561_update(&hctx, ivec, 4);
        hmac_blake2561_final(&hctx, U);

        /* T_i = U_1 ... */
        memcpy(T, U, 32);

        for (j = 2; j <= c; j++)
        {
            /* Compute U_j. */
            hmac_blake2561_init(&hctx, passwd, passwdlen);
            hmac_blake2561_update(&hctx, U, 32);
            hmac_blake2561_final(&hctx, U);

            /* ... xor U_j ... */
            for (k = 0; k < 32; k++)
            {
                T[k] ^= U[k];
            }
        }

        /* Copy as many bytes as necessary into buf. */
        clen = dkLen - i * 32;
        if (clen > 32)
        {
            clen = 32;
        }
        memcpy(&buf[i * 32], T, clen);
    }

    /* Clean PShctx, since we never called _Final on it. */
    memset(&PShctx, 0, sizeof(hmac_ctx));
}
