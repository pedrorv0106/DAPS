/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_ECMULT_GEN_IMPL_H_
#define _SECP256K1_ECMULT_GEN_IMPL_H_

#include "scalar.h"
#include "group.h"
#include "ecmult_gen.h"
#include "hash_impl.h"
#ifdef USE_ECMULT_STATIC_PRECOMPUTATION
#include "ecmult_static_context.h"
#endif
static void secp256k1_ecmult_gen_context_init(secp256k1_ecmult_gen_context *ctx) {
    ctx->prec = NULL;
}

static void secp256k1_ecmult_gen_context_build(secp256k1_ecmult_gen_context *ctx, const secp256k1_callback* cb) {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    secp256k1_ge prec[1024];
    secp256k1_gej gj;
    secp256k1_gej nums_gej;
    int i, j;
#endif

    if (ctx->prec != NULL) {
        return;
    }
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    ctx->prec = (secp256k1_ge_storage (*)[64][16])checked_malloc(cb, sizeof(*ctx->prec));

    /* get the generator */
    secp256k1_gej_set_ge(&gj, &secp256k1_ge_const_g);

    /* Construct a group element with no known corresponding scalar (nothing up my sleeve). */
    {
        static const unsigned char nums_b32[33] = "The scalar for this x is unknown";
        secp256k1_fe nums_x;
        secp256k1_ge nums_ge;
        int r;
        r = secp256k1_fe_set_b32(&nums_x, nums_b32);
        (void)r;
        VERIFY_CHECK(r);
        r = secp256k1_ge_set_xo_var(&nums_ge, &nums_x, 0);
        (void)r;
        VERIFY_CHECK(r);
        secp256k1_gej_set_ge(&nums_gej, &nums_ge);
        /* Add G to make the bits in x uniformly distributed. */
        secp256k1_gej_add_ge_var2(&nums_gej, &nums_gej, &secp256k1_ge_const_g, NULL);
    }

    /* compute prec. */
    {
        secp256k1_gej precj[1024]; /* Jacobian versions of prec. */
        secp256k1_gej gbase;
        secp256k1_gej numsbase;
        gbase = gj; /* 16^j * G */
        numsbase = nums_gej; /* 2^j * nums. */
        for (j = 0; j < 64; j++) {
            /* Set precj[j*16 .. j*16+15] to (numsbase, numsbase + gbase, ..., numsbase + 15*gbase). */
            precj[j*16] = numsbase;
            for (i = 1; i < 16; i++) {
                secp256k1_gej_add_var2(&precj[j*16 + i], &precj[j*16 + i - 1], &gbase, NULL);
            }
            /* Multiply gbase by 16. */
            for (i = 0; i < 4; i++) {
                secp256k1_gej_double_var2(&gbase, &gbase, NULL);
            }
            /* Multiply numbase by 2. */
            secp256k1_gej_double_var2(&numsbase, &numsbase, NULL);
            if (j == 62) {
                /* In the last iteration, numsbase is (1 - 2^j) * nums instead. */
                secp256k1_gej_neg(&numsbase, &numsbase);
                secp256k1_gej_add_var2(&numsbase, &numsbase, &nums_gej, NULL);
            }
        }
        secp256k1_ge_set_all_gej_var2(prec, precj, 1024, cb);
    }
    for (j = 0; j < 64; j++) {
        for (i = 0; i < 16; i++) {
            secp256k1_ge_to_storage(&(*ctx->prec)[j][i], &prec[j*16 + i]);
        }
    }
#else
    (void)cb;
    ctx->prec = (secp256k1_ge_storage (*)[64][16])secp256k1_ecmult_static_context;
#endif
    secp256k1_ecmult_gen_blind(ctx, NULL);
}

static int secp256k1_ecmult_gen_context_is_built(const secp256k1_ecmult_gen_context* ctx) {
    return ctx->prec != NULL;
}

static void secp256k1_ecmult_gen_context_clone(secp256k1_ecmult_gen_context *dst,
                                               const secp256k1_ecmult_gen_context *src, const secp256k1_callback* cb) {
    if (src->prec == NULL) {
        dst->prec = NULL;
    } else {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
        dst->prec = (secp256k1_ge_storage (*)[64][16])checked_malloc(cb, sizeof(*dst->prec));
        memcpy(dst->prec, src->prec, sizeof(*dst->prec));
#else
        (void)cb;
        dst->prec = src->prec;
#endif
        dst->initial = src->initial;
        dst->blind = src->blind;
    }
}

static void secp256k1_ecmult_gen_context_clear(secp256k1_ecmult_gen_context *ctx) {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    free(ctx->prec);
#endif
    secp256k1_scalar_clear(&ctx->blind);
    secp256k1_gej_clear(&ctx->initial);
    ctx->prec = NULL;
}

static void secp256k1_ecmult_gen2(const secp256k1_ecmult_gen_context *ctx, secp256k1_gej *r, const secp256k1_scalar *gn) {
    secp256k1_ge add;
    secp256k1_ge_storage adds;
    secp256k1_scalar gnb;
    int bits;
    int i, j;
    memset(&adds, 0, sizeof(adds));
    *r = ctx->initial;
    /* Blind scalar/point multiplication by computing (n-b)G + bG instead of nG. */
    secp256k1_scalar_add(&gnb, gn, &ctx->blind);
    add.infinity = 0;
    for (j = 0; j < 64; j++) {
        bits = secp256k1_scalar_get_bits(&gnb, j * 4, 4);
        for (i = 0; i < 16; i++) {
            /** This uses a conditional move to avoid any secret data in array indexes.
             *   _Any_ use of secret indexes has been demonstrated to result in timing
             *   sidechannels, even when the cache-line access patterns are uniform.
             *  See also:
             *   "A word of warning", CHES 2013 Rump Session, by Daniel J. Bernstein and Peter Schwabe
             *    (https://cryptojedi.org/peter/data/chesrump-20130822.pdf) and
             *   "Cache Attacks and Countermeasures: the Case of AES", RSA 2006,
             *    by Dag Arne Osvik, Adi Shamir, and Eran Tromer
             *    (http://www.tau.ac.il/~tromer/papers/cache.pdf)
             */
            secp256k1_ge_storage_cmov(&adds, &(*ctx->prec)[j][i], i == bits);
        }
        secp256k1_ge_from_storage(&add, &adds);
        secp256k1_gej_add_ge(r, r, &add);
    }
    bits = 0;
    secp256k1_ge_clear(&add);
    secp256k1_scalar_clear(&gnb);
}

/* Setup blinding values for secp256k1_ecmult_gen. */
static void secp256k1_ecmult_gen_blind(secp256k1_ecmult_gen_context *ctx, const unsigned char *seed32) {
    secp256k1_scalar b;
    secp256k1_gej gb;
    secp256k1_fe s;
    unsigned char nonce32[32];
    secp256k1_rfc6979_hmac_sha256 rng;
    int retry;
    unsigned char keydata[64] = {0};
    if (seed32 == NULL) {
        /* When seed is NULL, reset the initial point and blinding value. */
        secp256k1_gej_set_ge(&ctx->initial, &secp256k1_ge_const_g);
        secp256k1_gej_neg(&ctx->initial, &ctx->initial);
        secp256k1_scalar_set_int(&ctx->blind, 1);
    }
    /* The prior blinding value (if not reset) is chained forward by including it in the hash. */
    secp256k1_scalar_get_b32(nonce32, &ctx->blind);
    /** Using a CSPRNG allows a failure free interface, avoids needing large amounts of random data,
     *   and guards against weak or adversarial seeds.  This is a simpler and safer interface than
     *   asking the caller for blinding values directly and expecting them to retry on failure.
     */
    memcpy(keydata, nonce32, 32);
    if (seed32 != NULL) {
        memcpy(keydata + 32, seed32, 32);
    }
    secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, seed32 ? 64 : 32);
    memset(keydata, 0, sizeof(keydata));
    /* Retry for out of range results to achieve uniformity. */
    do {
        secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
        retry = !secp256k1_fe_set_b32(&s, nonce32);
        retry |= secp256k1_fe_is_zero(&s);
    } while (retry); /* This branch true is cryptographically unreachable. Requires sha256_hmac output > Fp. */
    /* Randomize the projection to defend against multiplier sidechannels. */
    secp256k1_gej_rescale(&ctx->initial, &s);
    secp256k1_fe_clear(&s);
    do {
        secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
        secp256k1_scalar_set_b32(&b, nonce32, &retry);
        /* A blinding value of 0 works, but would undermine the projection hardening. */
        retry |= secp256k1_scalar_is_zero(&b);
    } while (retry); /* This branch true is cryptographically unreachable. Requires sha256_hmac output > order. */
    secp256k1_rfc6979_hmac_sha256_finalize(&rng);
    memset(nonce32, 0, 32);
    secp256k1_ecmult_gen2(ctx, &gb, &b);
    secp256k1_scalar_negate(&b, &b);
    ctx->blind = b;
    ctx->initial = gb;
    secp256k1_scalar_clear(&b);
    secp256k1_gej_clear(&gb);
}

typedef struct {
    /* For accelerating the computation of a*G:
     * To harden against timing attacks, use the following mechanism:
     * * Break up the multiplicand into groups of 4 bits, called n_0, n_1, n_2, ..., n_63.
     * * Compute sum(n_i * 16^i * G + U_i, i=0..63), where:
     *   * U_i = U * 2^i (for i=0..62)
     *   * U_i = U * (1-2^63) (for i=63)
     *   where U is a point with no known corresponding scalar. Note that sum(U_i, i=0..63) = 0.
     * For each i, and each of the 16 possible values of n_i, (n_i * 16^i * G + U_i) is
     * precomputed (call it prec(i, n_i)). The formula now becomes sum(prec(i, n_i), i=0..63).
     * None of the resulting prec group elements have a known scalar, and neither do any of
     * the intermediate sums while computing a*G.
     */
    secp256k1_fe_t prec[64][16][2]; /* prec[j][i] = (16^j * i * G + U_i).{x,y} */
} secp256k1_ecmult_gen_consts_t;

static const secp256k1_ecmult_gen_consts_t *secp256k1_ecmult_gen_consts = NULL;

static void secp256k1_ecmult_gen_start(void) {
    if (secp256k1_ecmult_gen_consts != NULL)
        return;

    /* Allocate the precomputation table. */
    secp256k1_ecmult_gen_consts_t *ret = (secp256k1_ecmult_gen_consts_t*)malloc(sizeof(secp256k1_ecmult_gen_consts_t));

    /* get the generator */
    const secp256k1_ge_t *g = &secp256k1_ge_consts->g;
    secp256k1_gej_t gj; secp256k1_gej_set_ge(&gj, g);

    /* Construct a group element with no known corresponding scalar (nothing up my sleeve). */
    secp256k1_gej_t nums_gej;
    {
        static const unsigned char nums_b32[32] = "The scalar for this x is unknown";
        secp256k1_fe_t nums_x;
        VERIFY_CHECK(secp256k1_fe_set_b32(&nums_x, nums_b32));
        secp256k1_ge_t nums_ge;
        VERIFY_CHECK(secp256k1_ge_set_xo(&nums_ge, &nums_x, 0));
        secp256k1_gej_set_ge(&nums_gej, &nums_ge);
        /* Add G to make the bits in x uniformly distributed. */
        secp256k1_gej_add_ge_var(&nums_gej, &nums_gej, g);
    }

    /* compute prec. */
    secp256k1_ge_t prec[1024];
    {
        secp256k1_gej_t precj[1024]; /* Jacobian versions of prec. */
        secp256k1_gej_t gbase; gbase = gj; /* 16^j * G */
        secp256k1_gej_t numsbase; numsbase = nums_gej; /* 2^j * nums. */
        for (int j=0; j<64; j++) {
            /* Set precj[j*16 .. j*16+15] to (numsbase, numsbase + gbase, ..., numsbase + 15*gbase). */
            precj[j*16] = numsbase;
            for (int i=1; i<16; i++) {
                secp256k1_gej_add_var(&precj[j*16 + i], &precj[j*16 + i - 1], &gbase);
            }
            /* Multiply gbase by 16. */
            for (int i=0; i<4; i++) {
                secp256k1_gej_double_var(&gbase, &gbase);
            }
            /* Multiply numbase by 2. */
            secp256k1_gej_double_var(&numsbase, &numsbase);
            if (j == 62) {
                /* In the last iteration, numsbase is (1 - 2^j) * nums instead. */
                secp256k1_gej_neg(&numsbase, &numsbase);
                secp256k1_gej_add_var(&numsbase, &numsbase, &nums_gej);
            }
        }
        secp256k1_ge_set_all_gej_var(1024, prec, precj);
    }
    for (int j=0; j<64; j++) {
        for (int i=0; i<16; i++) {
            VERIFY_CHECK(!secp256k1_ge_is_infinity(&prec[j*16 + i]));
            ret->prec[j][i][0] = prec[j*16 + i].x;
            ret->prec[j][i][1] = prec[j*16 + i].y;
        }
    }

    /* Set the global pointer to the precomputation table. */
    secp256k1_ecmult_gen_consts = ret;
}

static void secp256k1_ecmult_gen_stop(void) {
    if (secp256k1_ecmult_gen_consts == NULL)
        return;

    secp256k1_ecmult_gen_consts_t *c = (secp256k1_ecmult_gen_consts_t*)secp256k1_ecmult_gen_consts;
    secp256k1_ecmult_gen_consts = NULL;
    free(c);
}

static void secp256k1_ecmult_gen(secp256k1_gej_t *r, const secp256k1_scalar_t *gn) {
    const secp256k1_ecmult_gen_consts_t *c = secp256k1_ecmult_gen_consts;
    secp256k1_gej_set_infinity(r);
    secp256k1_ge_t add;
    add.infinity = 0;
    int bits;
    for (int j=0; j<64; j++) {
        bits = secp256k1_scalar_get_bits(gn, j * 4, 4);
        for (int i=0; i<16; i++) {
            secp256k1_fe_cmov(&add.x, &c->prec[j][i][0], i == bits);
            secp256k1_fe_cmov(&add.y, &c->prec[j][i][1], i == bits);
        }
        secp256k1_gej_add_ge(r, r, &add);
    }
    bits = 0;
    secp256k1_ge_clear(&add);
}

#endif
