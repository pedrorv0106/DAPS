/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_TESTRAND_IMPL_H_
#define _SECP256K1_TESTRAND_IMPL_H_

#include <stdint.h>
#include <string.h>

#include "testrand.h"
#include "hash.h"

static uint32_t secp256k1_Rz = 11, secp256k1_Rw = 11;
static secp256k1_rfc6979_hmac_sha256 secp256k1_test_rng;
static uint32_t secp256k1_test_rng_precomputed[8];
static int secp256k1_test_rng_precomputed_used = 8;
static uint64_t secp256k1_test_rng_integer;
static int secp256k1_test_rng_integer_bits_left = 0;

SECP256K1_INLINE static void secp256k1_rand_seed2(const unsigned char *seed16) {
    secp256k1_rfc6979_hmac_sha256_initialize(&secp256k1_test_rng, seed16, 16);
}

SECP256K1_INLINE static void secp256k1_rand_seed(uint64_t v) {
    secp256k1_Rz = v >> 32;
    secp256k1_Rw = v;

    if (secp256k1_Rz == 0 || secp256k1_Rz == 0x9068ffffU) {
        secp256k1_Rz = 111;
    }
    if (secp256k1_Rw == 0 || secp256k1_Rw == 0x464fffffU) {
        secp256k1_Rw = 111;
    }
}

SECP256K1_INLINE static uint32_t secp256k1_rand32(void) {
    secp256k1_Rz = 36969 * (secp256k1_Rz & 0xFFFF) + (secp256k1_Rz >> 16);
    secp256k1_Rw = 18000 * (secp256k1_Rw & 0xFFFF) + (secp256k1_Rw >> 16);
    return (secp256k1_Rw << 16) + (secp256k1_Rw >> 16) + secp256k1_Rz;
}

static uint32_t secp256k1_rand_bits(int bits) {
    uint32_t ret;
    if (secp256k1_test_rng_integer_bits_left < bits) {
        secp256k1_test_rng_integer |= (((uint64_t)secp256k1_rand32()) << secp256k1_test_rng_integer_bits_left);
        secp256k1_test_rng_integer_bits_left += 32;
    }
    ret = secp256k1_test_rng_integer;
    secp256k1_test_rng_integer >>= bits;
    secp256k1_test_rng_integer_bits_left -= bits;
    ret &= ((~((uint32_t)0)) >> (32 - bits));
    return ret;
}

static uint32_t secp256k1_rand_int(uint32_t range) {
    /* We want a uniform integer between 0 and range-1, inclusive.
     * B is the smallest number such that range <= 2**B.
     * two mechanisms implemented here:
     * - generate B bits numbers until one below range is found, and return it
     * - find the largest multiple M of range that is <= 2**(B+A), generate B+A
     *   bits numbers until one below M is found, and return it modulo range
     * The second mechanism consumes A more bits of entropy in every iteration,
     * but may need fewer iterations due to M being closer to 2**(B+A) then
     * range is to 2**B. The array below (indexed by B) contains a 0 when the
     * first mechanism is to be used, and the number A otherwise.
     */
    static const int addbits[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 1, 0};
    uint32_t trange, mult;
    int bits = 0;
    if (range <= 1) {
        return 0;
    }
    trange = range - 1;
    while (trange > 0) {
        trange >>= 1;
        bits++;
    }
    if (addbits[bits]) {
        bits = bits + addbits[bits];
        mult = ((~((uint32_t)0)) >> (32 - bits)) / range;
        trange = range * mult;
    } else {
        trange = range;
        mult = 1;
    }
    while(1) {
        uint32_t x = secp256k1_rand_bits(bits);
        if (x < trange) {
            return (mult == 1) ? x : (x % range);
        }
    }
}

static void secp256k1_rand256(unsigned char *b32) {
    for (int i=0; i<8; i++) {
        uint32_t r = secp256k1_rand32();
        b32[i*4 + 0] = (r >>  0) & 0xFF;
        b32[i*4 + 1] = (r >>  8) & 0xFF;
        b32[i*4 + 2] = (r >> 16) & 0xFF;
        b32[i*4 + 3] = (r >> 24) & 0xFF;
    }
}

static void secp256k1_rand_bytes_test(unsigned char *bytes, size_t len) {
    size_t bits = 0;
    memset(bytes, 0, len);
    while (bits < len * 8) {
        int now;
        uint32_t val;
        now = 1 + (secp256k1_rand_bits(6) * secp256k1_rand_bits(5) + 16) / 31;
        val = secp256k1_rand_bits(1);
        while (now > 0 && bits < len * 8) {
            bytes[bits / 8] |= val << (bits % 8);
            now--;
            bits++;
        }
    }
}

static void secp256k1_rand256_test(unsigned char *b32) {
    int bits=0;
    memset(b32, 0, 32);
    while (bits < 256) {
        uint32_t ent = secp256k1_rand32();
        int now = 1 + ((ent % 64)*((ent >> 6) % 32)+16)/31;
        uint32_t val = 1 & (ent >> 11);
        while (now > 0 && bits < 256) {
            b32[bits / 8] |= val << (bits % 8);
            now--;
            bits++;
        }
    }
}

SECP256K1_INLINE static int64_t secp256k1_rands64(uint64_t min, uint64_t max) {
uint64_t range;
uint64_t r;
uint64_t clz;
VERIFY_CHECK(max >= min);
if (max == min) {
return min;
}
range = max - min;
clz = secp256k1_clz64_var(range);
do {
r = ((uint64_t)secp256k1_rand32() << 32) | secp256k1_rand32();
r >>= clz;
} while (r > range);
return min + (int64_t)r;
}

#endif
