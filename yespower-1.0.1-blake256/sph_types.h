/* $Id: sph_types.h 260 2011-07-21 01:02:38Z tp $ */
/**
 * Basic type definitions.
 *
 * This header file defines the generic integer types that will be used
 * for the implementation of hash functions; it also contains helper
 * functions which encode and decode multi-byte integer values, using
 * either little-endian or big-endian conventions.
 *
 * This file contains a compile-time test on the size of a byte
 * (the <code>unsigned char</code> C type). If bytes are not octets,
 * i.e. if they do not have a size of exactly 8 bits, then compilation
 * is aborted. Architectures where bytes are not octets are relatively
 * rare, even in the embedded devices market. We forbid non-octet bytes
 * because there is no clear convention on how octet streams are encoded
 * on such systems.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @file     sph_types.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SPH_TYPES_H__
#define SPH_TYPES_H__

#include <limits.h>

/*
 * All our I/O functions are defined over octet streams. We do not know
 * how to handle input data if bytes are not octets.
 */
#if CHAR_BIT != 8
#error This code requires 8-bit bytes
#endif

/* ============= BEGIN documentation block for Doxygen ============ */

#ifdef DOXYGEN_IGNORE

/** @mainpage sphlib C code documentation
 *
 * @section overview Overview
 *
 * <code>sphlib</code> is a library which contains implementations of
 * various cryptographic hash functions. These pages have been generated
 * with <a href="http://www.doxygen.org/index.html">doxygen</a> and
 * document the API for the C implementations.
 *
 * The API is described in appropriate header files, which are available
 * in the "Files" section. Each hash function family has its own header,
 * whose name begins with <code>"sph_"</code> and contains the family
 * name. For instance, the API for the RIPEMD hash functions is available
 * in the header file <code>sph_ripemd.h</code>.
 *
 * @section principles API structure and conventions
 *
 * @subsection io Input/output conventions
 *
 * In all generality, hash functions operate over strings of bits.
 * Individual bits are rarely encountered in C programming or actual
 * communication protocols; most protocols converge on the ubiquitous
 * "octet" which is a group of eight bits. Data is thus expressed as a
 * stream of octets. The C programming language contains the notion of a
 * "byte", which is a data unit managed under the type <code>"unsigned
 * char"</code>. The C standard prescribes that a byte should hold at
 * least eight bits, but possibly more. Most modern architectures, even
 * in the embedded world, feature eight-bit bytes, i.e. map bytes to
 * octets.
 *
 * Nevertheless, for some of the implemented hash functions, an extra
 * API has been added, which allows the input of arbitrary sequences of
 * bits: when the computation is about to be closed, 1 to 7 extra bits
 * can be added. The functions for which this API is implemented include
 * the SHA-2 functions and all SHA-3 candidates.
 *
 * <code>sphlib</code> defines hash function which may hash octet streams,
 * i.e. streams of bits where the number of bits is a multiple of eight.
 * The data input functions in the <code>sphlib</code> API expect data
 * as anonymous pointers (<code>"const void *"</code>) with a length
 * (of type <code>"size_t"</code>) which gives the input data chunk length
 * in bytes. A byte is assumed to be an octet; the <code>sph_types.h</code>
 * header contains a compile-time test which prevents compilation on
 * architectures where this property is not met.
 *
 * The hash function output is also converted into bytes. All currently
 * implemented hash functions have an output width which is a multiple of
 * eight, and this is likely to remain true for new designs.
 *
 * Most hash functions internally convert input data into 32-bit of 64-bit
 * words, using either little-endian or big-endian conversion. The hash
 * output also often consists of such words, which are encoded into output
 * bytes with a similar endianness convention. Some hash functions have
 * been only loosely specified on that subject; when necessary,
 * <code>sphlib</code> has been tested against published "reference"
 * implementations in order to use the same conventions.
 *
 * @subsection shortname Function short name
 *
 * Each implemented hash function has a "short name" which is used
 * internally to derive the identifiers for the functions and context
 * structures which the function uses. For instance, MD5 has the short
 * name <code>"md5"</code>. Short names are listed in the next section,
 * for the implemented hash functions. In subsequent sections, the
 * short name will be assumed to be <code>"XXX"</code>: replace with the
 * actual hash function name to get the C identifier.
 *
 * Note: some functions within the same family share the same core
 * elements, such as update function or context structure. Correspondingly,
 * some of the defined types or functions may actually be macros which
 * transparently evaluate to another type or function name.
 *
 * @subsection context Context structure
 *
 * Each implemented hash fonction has its own context structure, available
 * under the type name <code>"sph_XXX_context"</code> for the hash function
 * with short name <code>"XXX"</code>. This structure holds all needed
 * state for a running hash computation.
 *
 * The contents of these structures are meant to be opaque, and private
 * to the implementation. However, these contents are specified in the
 * header files so that application code which uses <code>sphlib</code>
 * may access the size of those structures.
 *
 * The caller is responsible for allocating the context structure,
 * whether by dynamic allocation (<code>malloc()</code> or equivalent),
 * static allocation (a global permanent variable), as an automatic
 * variable ("on the stack"), or by any other mean which ensures proper
 * structure alignment. <code>sphlib</code> code performs no dynamic
 * allocation by itself.
 *
 * The context must be initialized before use, using the
 * <code>sph_XXX_init()</code> function. This function sets the context
 * state to proper initial values for hashing.
 *
 * Since all state data is contained within the context structure,
 * <code>sphlib</code> is thread-safe and reentrant: several hash
 * computations may be performed in parallel, provided that they do not
 * operate on the same context. Moreover, a running computation can be
 * cloned by copying the context (with a simple <code>memcpy()</code>):
 * the context and its clone are then independant and may be updated
 * with new data and/or closed without interfering with each other.
 * Similarly, a context structure can be moved in memory at will:
 * context structures contain no pointer, in particular no pointer to
 * themselves.
 *
 * @subsection dataio Data input
 *
 * Hashed data is input with the <code>sph_XXX()</code> fonction, which
 * takes as parameters a pointer to the context, a pointer to the data
 * to hash, and the number of data bytes to hash. The context is updated
 * with the new data.
 *
 * Data can be input in one or several calls, with arbitrary input lengths.
 * However, it is best, performance wise, to input data by relatively big
 * chunks (say a few kilobytes), because this allows <code>sphlib</code> to
 * optimize things and avoid internal copying.
 *
 * When all data has been input, the context can be closed with
 * <code>sph_XXX_close()</code>. The hash output is computed and written
 * into the provided buffer. The caller must take care to provide a
 * buffer of appropriate length; e.g., when using SHA-1, the output is
 * a 20-byte word, therefore the output buffer must be at least 20-byte
 * long.
 *
 * For some hash functions, the <code>sph_XXX_addbits_and_close()</code>
 * function can be used instead of <code>sph_XXX_close()</code>. This
 * function can take a few extra <strong>bits</strong> to be added at
 * the end of the input message. This allows hashing messages with a
 * bit length which is not a multiple of 8. The extra bits are provided
 * as an unsigned integer value, and a bit count. The bit count must be
 * between 0 and 7, inclusive. The extra bits are provided as bits 7 to
 * 0 (bits of numerical value 128, 64, 32... downto 0), in that order.
 * For instance, to add three bits of value 1, 1 and 0, the unsigned
 * integer will have value 192 (1*128 + 1*64 + 0*32) and the bit count
 * will be 3.
 *
 * The <code>SPH_SIZE_XXX</code> macro is defined for each hash function;
 * it evaluates to the function output size, expressed in bits. For instance,
 * <code>SPH_SIZE_sha1</code> evaluates to <code>160</code>.
 *
 * When closed, the context is automatically reinitialized and can be
 * immediately used for another computation. It is not necessary to call
 * <code>sph_XXX_init()</code> after a close. Note that
 * <code>sph_XXX_init()</code> can still be called to "reset" a context,
 * i.e. forget previously input data, and get back to the initial state.
 *
 * @subsection alignment Data alignment
 *
 * "Alignment" is a property of data, which is said to be "properly
 * aligned" when its emplacement in memory is such that the data can
 * be optimally read by full words. This depends on the type of access;
 * basically, some hash functions will read data by 32-bit or 64-bit
 * words. <code>sphlib</code> does not mandate such alignment for input
 * data, but using aligned data can substantially improve performance.
 *
 * As a rule, it is best to input data by chunks whose length (in bytes)
 * is a multiple of eight, and which begins at "generally aligned"
 * addresses, such as the base address returned by a call to
 * <code>malloc()</code>.
 *
 * @section functions Implemented functions
 *
 * We give here the list of implemented functions. They are grouped by
 * family; to each family corresponds a specific header file. Each
 * individual function has its associated "short name". Please refer to
 * the documentation for that header file to get details on the hash
 * function denomination and provenance.
 *
 * Note: the functions marked with a '(64)' in the list below are
 * available only if the C compiler provides an integer type of length
 * 64 bits or more. Such a type is mandatory in the latest C standard
 * (ISO 9899:1999, aka "C99") and is present in several older compilers
 * as well, so chances are that such a type is available.
 *
 * - HAVAL family: file <code>sph_haval.h</code>
 *   - HAVAL-128/3 (128-bit, 3 passes): short name: <code>haval128_3</code>
 *   - HAVAL-128/4 (128-bit, 4 passes): short name: <code>haval128_4</code>
 *   - HAVAL-128/5 (128-bit, 5 passes): short name: <code>haval128_5</code>
 *   - HAVAL-160/3 (160-bit, 3 passes): short name: <code>haval160_3</code>
 *   - HAVAL-160/4 (160-bit, 4 passes): short name: <code>haval160_4</code>
 *   - HAVAL-160/5 (160-bit, 5 passes): short name: <code>haval160_5</code>
 *   - HAVAL-192/3 (192-bit, 3 passes): short name: <code>haval192_3</code>
 *   - HAVAL-192/4 (192-bit, 4 passes): short name: <code>haval192_4</code>
 *   - HAVAL-192/5 (192-bit, 5 passes): short name: <code>haval192_5</code>
 *   - HAVAL-224/3 (224-bit, 3 passes): short name: <code>haval224_3</code>
 *   - HAVAL-224/4 (224-bit, 4 passes): short name: <code>haval224_4</code>
 *   - HAVAL-224/5 (224-bit, 5 passes): short name: <code>haval224_5</code>
 *   - HAVAL-256/3 (256-bit, 3 passes): short name: <code>haval256_3</code>
 *   - HAVAL-256/4 (256-bit, 4 passes): short name: <code>haval256_4</code>
 *   - HAVAL-256/5 (256-bit, 5 passes): short name: <code>haval256_5</code>
 * - MD2: file <code>sph_md2.h</code>, short name: <code>md2</code>
 * - MD4: file <code>sph_md4.h</code>, short name: <code>md4</code>
 * - MD5: file <code>sph_md5.h</code>, short name: <code>md5</code>
 * - PANAMA: file <code>sph_panama.h</code>, short name: <code>panama</code>
 * - RadioGatun family: file <code>sph_radiogatun.h</code>
 *   - RadioGatun[32]: short name: <code>radiogatun32</code>
 *   - RadioGatun[64]: short name: <code>radiogatun64</code> (64)
 * - RIPEMD family: file <code>sph_ripemd.h</code>
 *   - RIPEMD: short name: <code>ripemd</code>
 *   - RIPEMD-128: short name: <code>ripemd128</code>
 *   - RIPEMD-160: short name: <code>ripemd160</code>
 * - SHA-0: file <code>sph_sha0.h</code>, short name: <code>sha0</code>
 * - SHA-1: file <code>sph_sha1.h</code>, short name: <code>sha1</code>
 * - SHA-2 family, 32-bit hashes: file <code>sph_sha2.h</code>
 *   - SHA-224: short name: <code>sha224</code>
 *   - SHA-256: short name: <code>sha256</code>
 *   - SHA-384: short name: <code>sha384</code> (64)
 *   - SHA-512: short name: <code>sha512</code> (64)
 * - Tiger family: file <code>sph_tiger.h</code>
 *   - Tiger: short name: <code>tiger</code> (64)
 *   - Tiger2: short name: <code>tiger2</code> (64)
 * - WHIRLPOOL family: file <code>sph_whirlpool.h</code>
 *   - WHIRLPOOL-0: short name: <code>whirlpool0</code> (64)
 *   - WHIRLPOOL-1: short name: <code>whirlpool1</code> (64)
 *   - WHIRLPOOL: short name: <code>whirlpool</code> (64)
 *
 * The fourteen second-round SHA-3 candidates are also implemented;
 * when applicable, the implementations follow the "final" specifications
 * as published for the third round of the SHA-3 competition (BLAKE,
 * Groestl, JH, Keccak and Skein have been tweaked for third round).
 *
 * - BLAKE family: file <code>sph_blake.h</code>
 *   - BLAKE-224: short name: <code>blake224</code>
 *   - BLAKE-256: short name: <code>blake256</code>
 *   - BLAKE-384: short name: <code>blake384</code>
 *   - BLAKE-512: short name: <code>blake512</code>
 * - BMW (Blue Midnight Wish) family: file <code>sph_bmw.h</code>
 *   - BMW-224: short name: <code>bmw224</code>
 *   - BMW-256: short name: <code>bmw256</code>
 *   - BMW-384: short name: <code>bmw384</code> (64)
 *   - BMW-512: short name: <code>bmw512</code> (64)
 * - CubeHash family: file <code>sph_cubehash.h</code> (specified as
 *   CubeHash16/32 in the CubeHash specification)
 *   - CubeHash-224: short name: <code>cubehash224</code>
 *   - CubeHash-256: short name: <code>cubehash256</code>
 *   - CubeHash-384: short name: <code>cubehash384</code>
 *   - CubeHash-512: short name: <code>cubehash512</code>
 * - ECHO family: file <code>sph_echo.h</code>
 *   - ECHO-224: short name: <code>echo224</code>
 *   - ECHO-256: short name: <code>echo256</code>
 *   - ECHO-384: short name: <code>echo384</code>
 *   - ECHO-512: short name: <code>echo512</code>
 * - Fugue family: file <code>sph_fugue.h</code>
 *   - Fugue-224: short name: <code>fugue224</code>
 *   - Fugue-256: short name: <code>fugue256</code>
 *   - Fugue-384: short name: <code>fugue384</code>
 *   - Fugue-512: short name: <code>fugue512</code>
 * - Groestl family: file <code>sph_groestl.h</code>
 *   - Groestl-224: short name: <code>groestl224</code>
 *   - Groestl-256: short name: <code>groestl256</code>
 *   - Groestl-384: short name: <code>groestl384</code>
 *   - Groestl-512: short name: <code>groestl512</code>
 * - Hamsi family: file <code>sph_hamsi.h</code>
 *   - Hamsi-224: short name: <code>hamsi224</code>
 *   - Hamsi-256: short name: <code>hamsi256</code>
 *   - Hamsi-384: short name: <code>hamsi384</code>
 *   - Hamsi-512: short name: <code>hamsi512</code>
 * - JH family: file <code>sph_jh.h</code>
 *   - JH-224: short name: <code>jh224</code>
 *   - JH-256: short name: <code>jh256</code>
 *   - JH-384: short name: <code>jh384</code>
 *   - JH-512: short name: <code>jh512</code>
 * - Keccak family: file <code>sph_keccak.h</code>
 *   - Keccak-224: short name: <code>keccak224</code>
 *   - Keccak-256: short name: <code>keccak256</code>
 *   - Keccak-384: short name: <code>keccak384</code>
 *   - Keccak-512: short name: <code>keccak512</code>
 * - Luffa family: file <code>sph_luffa.h</code>
 *   - Luffa-224: short name: <code>luffa224</code>
 *   - Luffa-256: short name: <code>luffa256</code>
 *   - Luffa-384: short name: <code>luffa384</code>
 *   - Luffa-512: short name: <code>luffa512</code>
 * - Shabal family: file <code>sph_shabal.h</code>
 *   - Shabal-192: short name: <code>shabal192</code>
 *   - Shabal-224: short name: <code>shabal224</code>
 *   - Shabal-256: short name: <code>shabal256</code>
 *   - Shabal-384: short name: <code>shabal384</code>
 *   - Shabal-512: short name: <code>shabal512</code>
 * - SHAvite-3 family: file <code>sph_shavite.h</code>
 *   - SHAvite-224 (nominally "SHAvite-3 with 224-bit output"):
 *     short name: <code>shabal224</code>
 *   - SHAvite-256 (nominally "SHAvite-3 with 256-bit output"):
 *     short name: <code>shabal256</code>
 *   - SHAvite-384 (nominally "SHAvite-3 with 384-bit output"):
 *     short name: <code>shabal384</code>
 *   - SHAvite-512 (nominally "SHAvite-3 with 512-bit output"):
 *     short name: <code>shabal512</code>
 * - SIMD family: file <code>sph_simd.h</code>
 *   - SIMD-224: short name: <code>simd224</code>
 *   - SIMD-256: short name: <code>simd256</code>
 *   - SIMD-384: short name: <code>simd384</code>
 *   - SIMD-512: short name: <code>simd512</code>
 * - Skein family: file <code>sph_skein.h</code>
 *   - Skein-224 (nominally specified as Skein-512-224): short name:
 *     <code>skein224</code> (64)
 *   - Skein-256 (nominally specified as Skein-512-256): short name:
 *     <code>skein256</code> (64)
 *   - Skein-384 (nominally specified as Skein-512-384): short name:
 *     <code>skein384</code> (64)
 *   - Skein-512 (nominally specified as Skein-512-512): short name:
 *     <code>skein512</code> (64)
 *
 * For the second-round SHA-3 candidates, the functions are as specified
 * for round 2, i.e. with the "tweaks" that some candidates added
 * between round 1 and round 2. Also, some of the submitted packages for
 * round 2 contained errors, in the specification, reference code, or
 * both. <code>sphlib</code> implements the corrected versions.
 */

/** @hideinitializer
 * Unsigned integer type whose length is at least 32 bits; on most
 * architectures, it will have a width of exactly 32 bits. Unsigned C
 * types implement arithmetics modulo a power of 2; use the
 * <code>SPH_T32()</code> macro to ensure that the value is truncated
 * to exactly 32 bits. Unless otherwise specified, all macros and
 * functions which accept <code>sph_u32</code> values assume that these
 * values fit on 32 bits, i.e. do not exceed 2^32-1, even on architectures
 * where <code>sph_u32</code> is larger than that.
 */
typedef __arch_dependant__ sph_u32;

/** @hideinitializer
 * Signed integer type corresponding to <code>sph_u32</code>; it has
 * width 32 bits or more.
 */
typedef __arch_dependant__ sph_s32;

/** @hideinitializer
 * Unsigned integer type whose le
