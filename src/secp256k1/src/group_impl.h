/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_GROUP_IMPL_H_
#define _SECP256K1_GROUP_IMPL_H_

#include <string.h>

#include "num.h"
#include "field.h"
#include "group.h"

#define secp256k1_gej secp256k1_gej_t
#define secp256k1_fe secp256k1_fe_t
#define secp256k1_ge secp256k1_ge_t


/* These points can be generated in sage as follows:
 *
 * 0. Setup a worksheet with the following parameters.
 *   b = 4  # whatever CURVE_B will be set to
 *   F = FiniteField (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
 *   C = EllipticCurve ([F (0), F (b)])
 *
 * 1. Determine all the small orders available to you. (If there are
 *    no satisfactory ones, go back and change b.)
 *   print C.order().factor(limit=1000)
 *
 * 2. Choose an order as one of the prime factors listed in the above step.
 *    (You can also multiply some to get a composite order, though the
 *    tests will crash trying to invert scalars during signing.) We take a
 *    random point and scale it to drop its order to the desired value.
 *    There is some probability this won't work; just try again.
 *   order = 199
 *   P = C.random_point()
 *   P = (int(P.order()) / int(order)) * P
 *   assert(P.order() == order)
 *
 * 3. Print the values. You'll need to use a vim macro or something to
 *    split the hex output into 4-byte chunks.
 *   print "%x %x" % P.xy()
 */
#if defined(EXHAUSTIVE_TEST_ORDER)
#  if EXHAUSTIVE_TEST_ORDER == 199
const secp256k1_ge secp256k1_ge_const_g = SECP256K1_GE_CONST(
    0xFA7CC9A7, 0x0737F2DB, 0xA749DD39, 0x2B4FB069,
    0x3B017A7D, 0xA808C2F1, 0xFB12940C, 0x9EA66C18,
    0x78AC123A, 0x5ED8AEF3, 0x8732BC91, 0x1F3A2868,
    0x48DF246C, 0x808DAE72, 0xCFE52572, 0x7F0501ED
);

const int CURVE_B = 4;
#  elif EXHAUSTIVE_TEST_ORDER == 13
const secp256k1_ge secp256k1_ge_const_g = SECP256K1_GE_CONST(
    0xedc60018, 0xa51a786b, 0x2ea91f4d, 0x4c9416c0,
    0x9de54c3b, 0xa1316554, 0x6cf4345c, 0x7277ef15,
    0x54cb1b6b, 0xdc8c1273, 0x087844ea, 0x43f4603e,
    0x0eaf9a43, 0xf6effe55, 0x939f806d, 0x37adf8ac
);
const int CURVE_B = 2;
#  else
#    error No known generator for the specified exhaustive test group order.
#  endif
#else
/** Generator for secp256k1, value 'g' defined in
 *  "Standards for Efficient Cryptography" (SEC2) 2.7.1.
 */
static const secp256k1_ge secp256k1_ge_const_g = SECP256K1_GE_CONST(
        0x79BE667EUL, 0xF9DCBBACUL, 0x55A06295UL, 0xCE870B07UL,
        0x029BFCDBUL, 0x2DCE28D9UL, 0x59F2815BUL, 0x16F81798UL,
        0x483ADA77UL, 0x26A3C465UL, 0x5DA4FBFCUL, 0x0E1108A8UL,
        0xFD17B448UL, 0xA6855419UL, 0x9C47D08FUL, 0xFB10D4B8UL
);

const int CURVE_B = 7;
#endif

static int secp256k1_gej_eq_x_var(const secp256k1_fe *x, const secp256k1_gej *a) {
    secp256k1_fe r, r2;
    VERIFY_CHECK(!a->infinity);
    secp256k1_fe_sqr(&r, &a->z);
    secp256k1_fe_mul(&r, &r, x);
    r2 = a->x;
    secp256k1_fe_normalize_weak(&r2);
}

static void secp256k1_gej_rescale(secp256k1_gej *r, const secp256k1_fe *s) {
    /* Operations: 4 mul, 1 sqr */
    secp256k1_fe zz;
    VERIFY_CHECK(!secp256k1_fe_is_zero(s));
    secp256k1_fe_sqr(&zz, s);
    secp256k1_fe_mul(&r->x, &r->x, &zz);                /* r->x *= s^2 */
    secp256k1_fe_mul(&r->y, &r->y, &zz);
    secp256k1_fe_mul(&r->y, &r->y, s);                  /* r->y *= s^3 */
    secp256k1_fe_mul(&r->z, &r->z, s);                  /* r->z *= s   */
}

static void secp256k1_ge_set_gej_zinv(secp256k1_ge_t *r, const secp256k1_gej_t *a, const secp256k1_fe_t *zi) {
    secp256k1_fe_t zi2;
    secp256k1_fe_t zi3;
    secp256k1_fe_sqr(&zi2, zi);
    secp256k1_fe_mul(&zi3, &zi2, zi);
    secp256k1_fe_mul(&r->x, &a->x, &zi2);
    secp256k1_fe_mul(&r->y, &a->y, &zi3);
    r->infinity = a->infinity;
}

static void secp256k1_ge_set_infinity(secp256k1_ge_t *r) {
    r->infinity = 1;
}

static void secp256k1_ge_set_xy(secp256k1_ge_t *r, const secp256k1_fe_t *x, const secp256k1_fe_t *y) {
    r->infinity = 0;
    r->x = *x;
    r->y = *y;
}

static int secp256k1_ge_is_infinity(const secp256k1_ge_t *a) {
    return a->infinity;
}

static void secp256k1_ge_neg(secp256k1_ge_t *r, const secp256k1_ge_t *a) {
    r->infinity = a->infinity;
    r->x = a->x;
    r->y = a->y;
    secp256k1_fe_normalize(&r->y);
    secp256k1_fe_negate(&r->y, &r->y, 1);
}

static void secp256k1_ge_get_hex(char *r, int *rlen, const secp256k1_ge_t *a) {
    char cx[65]; int lx=65;
    char cy[65]; int ly=65;
    secp256k1_fe_get_hex(cx, &lx, &a->x);
    secp256k1_fe_get_hex(cy, &ly, &a->y);
    lx = strlen(cx);
    ly = strlen(cy);
    int len = lx + ly + 3 + 1;
    if (*rlen < len) {
        *rlen = len;
        return;
    }
    *rlen = len;
    r[0] = '(';
    memcpy(r+1, cx, lx);
    r[1+lx] = ',';
    memcpy(r+2+lx, cy, ly);
    r[2+lx+ly] = ')';
    r[3+lx+ly] = 0;
}

static SECP256K1_INLINE void secp256k1_gej_double_nonzero(secp256k1_gej *r, const secp256k1_gej *a, secp256k1_fe *rzr) {
    VERIFY_CHECK(!secp256k1_gej_is_infinity(a));
    secp256k1_gej_double_var2(r, a, rzr);
}

static void secp256k1_ge_set_all_gej_var2(secp256k1_ge *r, const secp256k1_gej *a, size_t len, const secp256k1_callback *cb) {
    secp256k1_fe *az;
    secp256k1_fe *azi;
    size_t i;
    size_t count = 0;
    az = (secp256k1_fe *)checked_malloc(cb, sizeof(secp256k1_fe) * len);
    for (i = 0; i < len; i++) {
        if (!a[i].infinity) {
            az[count++] = a[i].z;
        }
    }

    azi = (secp256k1_fe *)checked_malloc(cb, sizeof(secp256k1_fe) * count);
    secp256k1_fe_inv_all_var(azi, az, count);
    free(az);

    count = 0;
    for (i = 0; i < len; i++) {
        r[i].infinity = a[i].infinity;
        if (!a[i].infinity) {
            secp256k1_ge_set_gej_zinv(&r[i], &a[i], &azi[count++]);
        }
    }
    free(azi);
}

static void secp256k1_ge_set_gej(secp256k1_ge_t *r, secp256k1_gej_t *a) {
    r->infinity = a->infinity;
    secp256k1_fe_inv(&a->z, &a->z);
    secp256k1_fe_t z2; secp256k1_fe_sqr(&z2, &a->z);
    secp256k1_fe_t z3; secp256k1_fe_mul(&z3, &a->z, &z2);
    secp256k1_fe_mul(&a->x, &a->x, &z2);
    secp256k1_fe_mul(&a->y, &a->y, &z3);
    secp256k1_fe_set_int(&a->z, 1);
    r->x = a->x;
    r->y = a->y;
}

static void secp256k1_ge_set_gej_var(secp256k1_ge_t *r, secp256k1_gej_t *a) {
    r->infinity = a->infinity;
    if (a->infinity) {
        return;
    }
    secp256k1_fe_inv_var(&a->z, &a->z);
    secp256k1_fe_t z2; secp256k1_fe_sqr(&z2, &a->z);
    secp256k1_fe_t z3; secp256k1_fe_mul(&z3, &a->z, &z2);
    secp256k1_fe_mul(&a->x, &a->x, &z2);
    secp256k1_fe_mul(&a->y, &a->y, &z3);
    secp256k1_fe_set_int(&a->z, 1);
    r->x = a->x;
    r->y = a->y;
}

static void secp256k1_ge_set_all_gej_var(size_t len, secp256k1_ge_t r[len], const secp256k1_gej_t a[len]) {
    size_t count = 0;
    secp256k1_fe_t az[len];
    for (size_t i=0; i<len; i++) {
        if (!a[i].infinity) {
            az[count++] = a[i].z;
        }
    }

    secp256k1_fe_t azi[count];
    secp256k1_fe_inv_all_var(count, azi, az);

    count = 0;
    for (size_t i=0; i<len; i++) {
        r[i].infinity = a[i].infinity;
        if (!a[i].infinity) {
            secp256k1_fe_t *zi = &azi[count++];
            secp256k1_fe_t zi2; secp256k1_fe_sqr(&zi2, zi);
            secp256k1_fe_t zi3; secp256k1_fe_mul(&zi3, &zi2, zi);
            secp256k1_fe_mul(&r[i].x, &a[i].x, &zi2);
            secp256k1_fe_mul(&r[i].y, &a[i].y, &zi3);
        }
    }
}

static void secp256k1_ge_set_table_gej_var(secp256k1_ge *r, const secp256k1_gej *a, const secp256k1_fe *zr, size_t len) {
    size_t i = len - 1;
    secp256k1_fe zi;

    if (len > 0) {
        /* Compute the inverse of the last z coordinate, and use it to compute the last affine output. */
        secp256k1_fe_inv(&zi, &a[i].z);
        secp256k1_ge_set_gej_zinv(&r[i], &a[i], &zi);

        /* Work out way backwards, using the z-ratios to scale the x/y values. */
        while (i > 0) {
            secp256k1_fe_mul(&zi, &zi, &zr[i]);
            i--;
            secp256k1_ge_set_gej_zinv(&r[i], &a[i], &zi);
        }
    }
}

static void secp256k1_ge_globalz_set_table_gej(size_t len, secp256k1_ge *r, secp256k1_fe *globalz, const secp256k1_gej *a, const secp256k1_fe *zr) {
    size_t i = len - 1;
    secp256k1_fe zs;

    if (len > 0) {
        /* The z of the final point gives us the "global Z" for the table. */
        r[i].x = a[i].x;
        r[i].y = a[i].y;
        *globalz = a[i].z;
        r[i].infinity = 0;
        zs = zr[i];

        /* Work our way backwards, using the z-ratios to scale the x/y values. */
        while (i > 0) {
            if (i != len - 1) {
                secp256k1_fe_mul(&zs, &zs, &zr[i]);
            }
            i--;
            secp256k1_ge_set_gej_zinv(&r[i], &a[i], &zs);
        }
    }
}

static void secp256k1_gej_set_infinity(secp256k1_gej_t *r) {
    r->infinity = 1;
    secp256k1_fe_set_int(&r->x, 0);
    secp256k1_fe_set_int(&r->y, 0);
    secp256k1_fe_set_int(&r->z, 0);
}

static void secp256k1_gej_set_xy(secp256k1_gej_t *r, const secp256k1_fe_t *x, const secp256k1_fe_t *y) {
    r->infinity = 0;
    r->x = *x;
    r->y = *y;
    secp256k1_fe_set_int(&r->z, 1);
}

static void secp256k1_gej_clear(secp256k1_gej_t *r) {
    r->infinity = 0;
    secp256k1_fe_clear(&r->x);
    secp256k1_fe_clear(&r->y);
    secp256k1_fe_clear(&r->z);
}

static void secp256k1_ge_clear(secp256k1_ge_t *r) {
    r->infinity = 0;
    secp256k1_fe_clear(&r->x);
    secp256k1_fe_clear(&r->y);
}

static int secp256k1_ge_set_xo(secp256k1_ge_t *r, const secp256k1_fe_t *x, int odd) {
    r->x = *x;
    secp256k1_fe_t x2; secp256k1_fe_sqr(&x2, x);
    secp256k1_fe_t x3; secp256k1_fe_mul(&x3, x, &x2);
    r->infinity = 0;
    secp256k1_fe_t c; secp256k1_fe_set_int(&c, 7);
    secp256k1_fe_add(&c, &x3);
    if (!secp256k1_fe_sqrt(&r->y, &c))
        return 0;
    secp256k1_fe_normalize(&r->y);
    if (secp256k1_fe_is_odd(&r->y) != odd)
        secp256k1_fe_negate(&r->y, &r->y, 1);
    return 1;
}

static void secp256k1_gej_set_ge(secp256k1_gej_t *r, const secp256k1_ge_t *a) {
   r->infinity = a->infinity;
   r->x = a->x;
   r->y = a->y;
   secp256k1_fe_set_int(&r->z, 1);
}

static void secp256k1_gej_get_x_var(secp256k1_fe_t *r, const secp256k1_gej_t *a) {
    secp256k1_fe_t zi2; secp256k1_fe_inv_var(&zi2, &a->z); secp256k1_fe_sqr(&zi2, &zi2);
    secp256k1_fe_mul(r, &a->x, &zi2);
}

static void secp256k1_gej_neg(secp256k1_gej_t *r, const secp256k1_gej_t *a) {
    r->infinity = a->infinity;
    r->x = a->x;
    r->y = a->y;
    r->z = a->z;
    secp256k1_fe_normalize(&r->y);
    secp256k1_fe_negate(&r->y, &r->y, 1);
}

static int secp256k1_gej_is_infinity(const secp256k1_gej_t *a) {
    return a->infinity;
}

static int secp256k1_gej_is_valid(const secp256k1_gej_t *a) {
    if (a->infinity)
        return 0;
    /** y^2 = x^3 + 7
     *  (Y/Z^3)^2 = (X/Z^2)^3 + 7
     *  Y^2 / Z^6 = X^3 / Z^6 + 7
     *  Y^2 = X^3 + 7*Z^6
     */
    secp256k1_fe_t y2; secp256k1_fe_sqr(&y2, &a->y);
    secp256k1_fe_t x3; secp256k1_fe_sqr(&x3, &a->x); secp256k1_fe_mul(&x3, &x3, &a->x);
    secp256k1_fe_t z2; secp256k1_fe_sqr(&z2, &a->z);
    secp256k1_fe_t z6; secp256k1_fe_sqr(&z6, &z2); secp256k1_fe_mul(&z6, &z6, &z2);
    secp256k1_fe_mul_int(&z6, 7);
    secp256k1_fe_add(&x3, &z6);
    secp256k1_fe_normalize(&y2);
    secp256k1_fe_normalize(&x3);
    return secp256k1_fe_equal(&y2, &x3);
}

static int secp256k1_ge_is_valid(const secp256k1_ge_t *a) {
    if (a->infinity)
        return 0;
    /* y^2 = x^3 + 7 */
    secp256k1_fe_t y2; secp256k1_fe_sqr(&y2, &a->y);
    secp256k1_fe_t x3; secp256k1_fe_sqr(&x3, &a->x); secp256k1_fe_mul(&x3, &x3, &a->x);
    secp256k1_fe_t c; secp256k1_fe_set_int(&c, 7);
    secp256k1_fe_add(&x3, &c);
    secp256k1_fe_normalize(&y2);
    secp256k1_fe_normalize(&x3);
    return secp256k1_fe_equal(&y2, &x3);
}

static void secp256k1_gej_double_var(secp256k1_gej_t *r, const secp256k1_gej_t *a) {
    // For secp256k1, 2Q is infinity if and only if Q is infinity. This is because if 2Q = infinity,
    // Q must equal -Q, or that Q.y == -(Q.y), or Q.y is 0. For a point on y^2 = x^3 + 7 to have
    // y=0, x^3 must be -7 mod p. However, -7 has no cube root mod p.
    r->infinity = a->infinity;
    if (r->infinity) {
        return;
    }

    secp256k1_fe_t t1,t2,t3,t4;
    secp256k1_fe_mul(&r->z, &a->z, &a->y);
    secp256k1_fe_mul_int(&r->z, 2);       /* Z' = 2*Y*Z (2) */
    secp256k1_fe_sqr(&t1, &a->x);
    secp256k1_fe_mul_int(&t1, 3);         /* T1 = 3*X^2 (3) */
    secp256k1_fe_sqr(&t2, &t1);           /* T2 = 9*X^4 (1) */
    secp256k1_fe_sqr(&t3, &a->y);
    secp256k1_fe_mul_int(&t3, 2);         /* T3 = 2*Y^2 (2) */
    secp256k1_fe_sqr(&t4, &t3);
    secp256k1_fe_mul_int(&t4, 2);         /* T4 = 8*Y^4 (2) */
    secp256k1_fe_mul(&t3, &t3, &a->x);    /* T3 = 2*X*Y^2 (1) */
    r->x = t3;
    secp256k1_fe_mul_int(&r->x, 4);       /* X' = 8*X*Y^2 (4) */
    secp256k1_fe_negate(&r->x, &r->x, 4); /* X' = -8*X*Y^2 (5) */
    secp256k1_fe_add(&r->x, &t2);         /* X' = 9*X^4 - 8*X*Y^2 (6) */
    secp256k1_fe_negate(&t2, &t2, 1);     /* T2 = -9*X^4 (2) */
    secp256k1_fe_mul_int(&t3, 6);         /* T3 = 12*X*Y^2 (6) */
    secp256k1_fe_add(&t3, &t2);           /* T3 = 12*X*Y^2 - 9*X^4 (8) */
    secp256k1_fe_mul(&r->y, &t1, &t3);    /* Y' = 36*X^3*Y^2 - 27*X^6 (1) */
    secp256k1_fe_negate(&t2, &t4, 2);     /* T2 = -8*Y^4 (3) */
    secp256k1_fe_add(&r->y, &t2);         /* Y' = 36*X^3*Y^2 - 27*X^6 - 8*Y^4 (4) */
}

static void secp256k1_gej_double_var2(secp256k1_gej_t *r, const secp256k1_gej_t *a, secp256k1_fe_t *rzr) {
    /* Operations: 3 mul, 4 sqr, 0 normalize, 12 mul_int/add/negate.
     *
     * Note that there is an implementation described at
     *     https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
     * which trades a multiply for a square, but in practice this is actually slower,
     * mainly because it requires more normalizations.
     */
    secp256k1_fe_t t1,t2,t3,t4;
    /** For secp256k1, 2Q is infinity if and only if Q is infinity. This is because if 2Q = infinity,
     *  Q must equal -Q, or that Q.y == -(Q.y), or Q.y is 0. For a point on y^2 = x^3 + 7 to have
     *  y=0, x^3 must be -7 mod p. However, -7 has no cube root mod p.
     *
     *  Having said this, if this function receives a point on a sextic twist, e.g. by
     *  a fault attack, it is possible for y to be 0. This happens for y^2 = x^3 + 6,
     *  since -6 does have a cube root mod p. For this point, this function will not set
     *  the infinity flag even though the point doubles to infinity, and the result
     *  point will be gibberish (z = 0 but infinity = 0).
     */
    r->infinity = a->infinity;
    if (r->infinity) {
        if (rzr != NULL) {
            secp256k1_fe_set_int(rzr, 1);
        }
        return;
    }

    if (rzr != NULL) {
        *rzr = a->y;
        secp256k1_fe_normalize_weak(rzr);
        secp256k1_fe_mul_int(rzr, 2);
    }

    secp256k1_fe_mul(&r->z, &a->z, &a->y);
    secp256k1_fe_mul_int(&r->z, 2);       /* Z' = 2*Y*Z (2) */
    secp256k1_fe_sqr(&t1, &a->x);
    secp256k1_fe_mul_int(&t1, 3);         /* T1 = 3*X^2 (3) */
    secp256k1_fe_sqr(&t2, &t1);           /* T2 = 9*X^4 (1) */
    secp256k1_fe_sqr(&t3, &a->y);
    secp256k1_fe_mul_int(&t3, 2);         /* T3 = 2*Y^2 (2) */
    secp256k1_fe_sqr(&t4, &t3);
    secp256k1_fe_mul_int(&t4, 2);         /* T4 = 8*Y^4 (2) */
    secp256k1_fe_mul(&t3, &t3, &a->x);    /* T3 = 2*X*Y^2 (1) */
    r->x = t3;
    secp256k1_fe_mul_int(&r->x, 4);       /* X' = 8*X*Y^2 (4) */
    secp256k1_fe_negate(&r->x, &r->x, 4); /* X' = -8*X*Y^2 (5) */
    secp256k1_fe_add(&r->x, &t2);         /* X' = 9*X^4 - 8*X*Y^2 (6) */
    secp256k1_fe_negate(&t2, &t2, 1);     /* T2 = -9*X^4 (2) */
    secp256k1_fe_mul_int(&t3, 6);         /* T3 = 12*X*Y^2 (6) */
    secp256k1_fe_add(&t3, &t2);           /* T3 = 12*X*Y^2 - 9*X^4 (8) */
    secp256k1_fe_mul(&r->y, &t1, &t3);    /* Y' = 36*X^3*Y^2 - 27*X^6 (1) */
    secp256k1_fe_negate(&t2, &t4, 2);     /* T2 = -8*Y^4 (3) */
    secp256k1_fe_add(&r->y, &t2);         /* Y' = 36*X^3*Y^2 - 27*X^6 - 8*Y^4 (4) */
}

static void secp256k1_gej_add_ge_var2(secp256k1_gej_t *r, const secp256k1_gej_t *a, const secp256k1_ge_t *b, secp256k1_fe_t *rzr) {
    /* 8 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
    secp256k1_fe_t z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;
    if (a->infinity) {
        VERIFY_CHECK(rzr == NULL);
        secp256k1_gej_set_ge(r, b);
        return;
    }
    if (b->infinity) {
        if (rzr != NULL) {
            secp256k1_fe_set_int(rzr, 1);
        }
        *r = *a;
        return;
    }
    r->infinity = 0;

    secp256k1_fe_sqr(&z12, &a->z);
    u1 = a->x; secp256k1_fe_normalize_weak(&u1);
    secp256k1_fe_mul(&u2, &b->x, &z12);
    s1 = a->y; secp256k1_fe_normalize_weak(&s1);
    secp256k1_fe_mul(&s2, &b->y, &z12); secp256k1_fe_mul(&s2, &s2, &a->z);
    secp256k1_fe_negate(&h, &u1, 1); secp256k1_fe_add(&h, &u2);
    secp256k1_fe_negate(&i, &s1, 1); secp256k1_fe_add(&i, &s2);
    if (secp256k1_fe_normalizes_to_zero_var(&h)) {
        if (secp256k1_fe_normalizes_to_zero_var(&i)) {
            secp256k1_gej_double_var2(r, a, rzr);
        } else {
            if (rzr != NULL) {
                secp256k1_fe_set_int(rzr, 0);
            }
            r->infinity = 1;
        }
        return;
    }
    secp256k1_fe_sqr(&i2, &i);
    secp256k1_fe_sqr(&h2, &h);
    secp256k1_fe_mul(&h3, &h, &h2);
    if (rzr != NULL) {
        *rzr = h;
    }
    secp256k1_fe_mul(&r->z, &a->z, &h);
    secp256k1_fe_mul(&t, &u1, &h2);
    r->x = t; secp256k1_fe_mul_int(&r->x, 2); secp256k1_fe_add(&r->x, &h3); secp256k1_fe_negate(&r->x, &r->x, 3); secp256k1_fe_add(&r->x, &i2);
    secp256k1_fe_negate(&r->y, &r->x, 5); secp256k1_fe_add(&r->y, &t); secp256k1_fe_mul(&r->y, &r->y, &i);
    secp256k1_fe_mul(&h3, &h3, &s1); secp256k1_fe_negate(&h3, &h3, 1);
    secp256k1_fe_add(&r->y, &h3);
}

static void secp256k1_gej_add_var(secp256k1_gej_t *r, const secp256k1_gej_t *a, const secp256k1_gej_t *b) {
    if (a->infinity) {
        *r = *b;
        return;
    }
    if (b->infinity) {
        *r = *a;
        return;
    }
    r->infinity = 0;
    secp256k1_fe_t z22; secp256k1_fe_sqr(&z22, &b->z);
    secp256k1_fe_t z12; secp256k1_fe_sqr(&z12, &a->z);
    secp256k1_fe_t u1; secp256k1_fe_mul(&u1, &a->x, &z22);
    secp256k1_fe_t u2; secp256k1_fe_mul(&u2, &b->x, &z12);
    secp256k1_fe_t s1; secp256k1_fe_mul(&s1, &a->y, &z22); secp256k1_fe_mul(&s1, &s1, &b->z);
    secp256k1_fe_t s2; secp256k1_fe_mul(&s2, &b->y, &z12); secp256k1_fe_mul(&s2, &s2, &a->z);
    secp256k1_fe_normalize(&u1);
    secp256k1_fe_normalize(&u2);
    if (secp256k1_fe_equal(&u1, &u2)) {
        secp256k1_fe_normalize(&s1);
        secp256k1_fe_normalize(&s2);
        if (secp256k1_fe_equal(&s1, &s2)) {
            secp256k1_gej_double_var(r, a);
        } else {
            r->infinity = 1;
        }
        return;
    }
    secp256k1_fe_t h; secp256k1_fe_negate(&h, &u1, 1); secp256k1_fe_add(&h, &u2);
    secp256k1_fe_t i; secp256k1_fe_negate(&i, &s1, 1); secp256k1_fe_add(&i, &s2);
    secp256k1_fe_t i2; secp256k1_fe_sqr(&i2, &i);
    secp256k1_fe_t h2; secp256k1_fe_sqr(&h2, &h);
    secp256k1_fe_t h3; secp256k1_fe_mul(&h3, &h, &h2);
    secp256k1_fe_mul(&r->z, &a->z, &b->z); secp256k1_fe_mul(&r->z, &r->z, &h);
    secp256k1_fe_t t; secp256k1_fe_mul(&t, &u1, &h2);
    r->x = t; secp256k1_fe_mul_int(&r->x, 2); secp256k1_fe_add(&r->x, &h3); secp256k1_fe_negate(&r->x, &r->x, 3); secp256k1_fe_add(&r->x, &i2);
    secp256k1_fe_negate(&r->y, &r->x, 5); secp256k1_fe_add(&r->y, &t); secp256k1_fe_mul(&r->y, &r->y, &i);
    secp256k1_fe_mul(&h3, &h3, &s1); secp256k1_fe_negate(&h3, &h3, 1);
    secp256k1_fe_add(&r->y, &h3);
}

static void secp256k1_gej_add_ge_var(secp256k1_gej_t *r, const secp256k1_gej_t *a, const secp256k1_ge_t *b) {
    if (a->infinity) {
        r->infinity = b->infinity;
        r->x = b->x;
        r->y = b->y;
        secp256k1_fe_set_int(&r->z, 1);
        return;
    }
    if (b->infinity) {
        *r = *a;
        return;
    }
    r->infinity = 0;
    secp256k1_fe_t z12; secp256k1_fe_sqr(&z12, &a->z);
    secp256k1_fe_t u1 = a->x; secp256k1_fe_normalize(&u1);
    secp256k1_fe_t u2; secp256k1_fe_mul(&u2, &b->x, &z12);
    secp256k1_fe_t s1 = a->y; secp256k1_fe_normalize(&s1);
    secp256k1_fe_t s2; secp256k1_fe_mul(&s2, &b->y, &z12); secp256k1_fe_mul(&s2, &s2, &a->z);
    secp256k1_fe_normalize(&u1);
    secp256k1_fe_normalize(&u2);
    if (secp256k1_fe_equal(&u1, &u2)) {
        secp256k1_fe_normalize(&s1);
        secp256k1_fe_normalize(&s2);
        if (secp256k1_fe_equal(&s1, &s2)) {
            secp256k1_gej_double_var(r, a);
        } else {
            r->infinity = 1;
        }
        return;
    }
    secp256k1_fe_t h; secp256k1_fe_negate(&h, &u1, 1); secp256k1_fe_add(&h, &u2);
    secp256k1_fe_t i; secp256k1_fe_negate(&i, &s1, 1); secp256k1_fe_add(&i, &s2);
    secp256k1_fe_t i2; secp256k1_fe_sqr(&i2, &i);
    secp256k1_fe_t h2; secp256k1_fe_sqr(&h2, &h);
    secp256k1_fe_t h3; secp256k1_fe_mul(&h3, &h, &h2);
    r->z = a->z; secp256k1_fe_mul(&r->z, &r->z, &h);
    secp256k1_fe_t t; secp256k1_fe_mul(&t, &u1, &h2);
    r->x = t; secp256k1_fe_mul_int(&r->x, 2); secp256k1_fe_add(&r->x, &h3); secp256k1_fe_negate(&r->x, &r->x, 3); secp256k1_fe_add(&r->x, &i2);
    secp256k1_fe_negate(&r->y, &r->x, 5); secp256k1_fe_add(&r->y, &t); secp256k1_fe_mul(&r->y, &r->y, &i);
    secp256k1_fe_mul(&h3, &h3, &s1); secp256k1_fe_negate(&h3, &h3, 1);
    secp256k1_fe_add(&r->y, &h3);
}

static void secp256k1_ge_from_storage(secp256k1_ge_t *r, const secp256k1_ge_storage *a) {
    secp256k1_fe_from_storage(&r->x, &a->x);
    secp256k1_fe_from_storage(&r->y, &a->y);
    r->infinity = 0;
}

static void secp256k1_ge_to_storage(secp256k1_ge_storage *r, const secp256k1_ge_t *a) {
    secp256k1_fe x, y;
    VERIFY_CHECK(!a->infinity);
    x = a->x;
    secp256k1_fe_normalize(&x);
    y = a->y;
    secp256k1_fe_normalize(&y);
    secp256k1_fe_to_storage(&r->x, &x);
    secp256k1_fe_to_storage(&r->y, &y);
}

static void secp256k1_gej_add_var2(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_gej *b, secp256k1_fe *rzr) {
    /* Operations: 12 mul, 4 sqr, 2 normalize, 12 mul_int/add/negate */
    secp256k1_fe z22, z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;

    if (a->infinity) {
        VERIFY_CHECK(rzr == NULL);
        *r = *b;
        return;
    }

    if (b->infinity) {
        if (rzr != NULL) {
            secp256k1_fe_set_int(rzr, 1);
        }
        *r = *a;
        return;
    }

    r->infinity = 0;
    secp256k1_fe_sqr(&z22, &b->z);
    secp256k1_fe_sqr(&z12, &a->z);
    secp256k1_fe_mul(&u1, &a->x, &z22);
    secp256k1_fe_mul(&u2, &b->x, &z12);
    secp256k1_fe_mul(&s1, &a->y, &z22); secp256k1_fe_mul(&s1, &s1, &b->z);
    secp256k1_fe_mul(&s2, &b->y, &z12); secp256k1_fe_mul(&s2, &s2, &a->z);
    secp256k1_fe_negate(&h, &u1, 1); secp256k1_fe_add(&h, &u2);
    secp256k1_fe_negate(&i, &s1, 1); secp256k1_fe_add(&i, &s2);
    if (secp256k1_fe_normalizes_to_zero_var(&h)) {
        if (secp256k1_fe_normalizes_to_zero_var(&i)) {
            secp256k1_gej_double_var2(r, a, rzr);
        } else {
            if (rzr != NULL) {
                secp256k1_fe_set_int(rzr, 0);
            }
            r->infinity = 1;
        }
        return;
    }
    secp256k1_fe_sqr(&i2, &i);
    secp256k1_fe_sqr(&h2, &h);
    secp256k1_fe_mul(&h3, &h, &h2);
    secp256k1_fe_mul(&h, &h, &b->z);
    if (rzr != NULL) {
        *rzr = h;
    }
    secp256k1_fe_mul(&r->z, &a->z, &h);
    secp256k1_fe_mul(&t, &u1, &h2);
    r->x = t; secp256k1_fe_mul_int(&r->x, 2); secp256k1_fe_add(&r->x, &h3); secp256k1_fe_negate(&r->x, &r->x, 3); secp256k1_fe_add(&r->x, &i2);
    secp256k1_fe_negate(&r->y, &r->x, 5); secp256k1_fe_add(&r->y, &t); secp256k1_fe_mul(&r->y, &r->y, &i);
    secp256k1_fe_mul(&h3, &h3, &s1); secp256k1_fe_negate(&h3, &h3, 1);
    secp256k1_fe_add(&r->y, &h3);
}

static SECP256K1_INLINE void secp256k1_ge_storage_cmov(secp256k1_ge_storage *r, const secp256k1_ge_storage *a, int flag) {
    secp256k1_fe_storage_cmov(&r->x, &a->x, flag);
    secp256k1_fe_storage_cmov(&r->y, &a->y, flag);
}

static int secp256k1_ge_set_xquad(secp256k1_ge_t *r, const secp256k1_fe_t *x) {
    secp256k1_fe_t x2, x3, c;
    r->x = *x;
    secp256k1_fe_sqr(&x2, x);
    secp256k1_fe_mul(&x3, x, &x2);
    r->infinity = 0;
    secp256k1_fe_set_int(&c, CURVE_B);
    secp256k1_fe_add(&c, &x3);
    return secp256k1_fe_sqrt(&r->y, &c);
}

static int secp256k1_ge_set_xo_var(secp256k1_ge_t *r, const secp256k1_fe_t *x, int odd) {
    if (!secp256k1_ge_set_xquad(r, x)) {
        return 0;
    }
    secp256k1_fe_normalize_var(&r->y);
    if (secp256k1_fe_is_odd(&r->y) != odd) {
        secp256k1_fe_negate(&r->y, &r->y, 1);
    }
    return 1;

}

static void secp256k1_gej_add_ge(secp256k1_gej_t *r, const secp256k1_gej_t *a, const secp256k1_ge_t *b) {
    VERIFY_CHECK(!b->infinity);
    VERIFY_CHECK(a->infinity == 0 || a->infinity == 1);

    /** In:
     *    Eric Brier and Marc Joye, Weierstrass Elliptic Curves and Side-Channel Attacks.
     *    In D. Naccache and P. Paillier, Eds., Public Key Cryptography, vol. 2274 of Lecture Notes in Computer Science, pages 335-345. Springer-Verlag, 2002.
     *  we find as solution for a unified addition/doubling formula:
     *    lambda = ((x1 + x2)^2 - x1 * x2 + a) / (y1 + y2), with a = 0 for secp256k1's curve equation.
     *    x3 = lambda^2 - (x1 + x2)
     *    2*y3 = lambda * (x1 + x2 - 2 * x3) - (y1 + y2).
     *
     *  Substituting x_i = Xi / Zi^2 and yi = Yi / Zi^3, for i=1,2,3, gives:
     *    U1 = X1*Z2^2, U2 = X2*Z1^2
     *    S1 = Y1*Z2^3, S2 = Y2*Z1^3
     *    Z = Z1*Z2
     *    T = U1+U2
     *    M = S1+S2
     *    Q = T*M^2
     *    R = T^2-U1*U2
     *    X3 = 4*(R^2-Q)
     *    Y3 = 4*(R*(3*Q-2*R^2)-M^4)
     *    Z3 = 2*M*Z
     *  (Note that the paper uses xi = Xi / Zi and yi = Yi / Zi instead.)
     */

    secp256k1_fe_t zz; secp256k1_fe_sqr(&zz, &a->z);                /* z = Z1^2 */
    secp256k1_fe_t u1 = a->x; secp256k1_fe_normalize(&u1);          /* u1 = U1 = X1*Z2^2 (1) */
    secp256k1_fe_t u2; secp256k1_fe_mul(&u2, &b->x, &zz);           /* u2 = U2 = X2*Z1^2 (1) */
    secp256k1_fe_t s1 = a->y; secp256k1_fe_normalize(&s1);          /* s1 = S1 = Y1*Z2^3 (1) */
    secp256k1_fe_t s2; secp256k1_fe_mul(&s2, &b->y, &zz);           /* s2 = Y2*Z2^2 (1) */
    secp256k1_fe_mul(&s2, &s2, &a->z);                              /* s2 = S2 = Y2*Z1^3 (1) */
    secp256k1_fe_t z = a->z;                                        /* z = Z = Z1*Z2 (8) */
    secp256k1_fe_t t = u1; secp256k1_fe_add(&t, &u2);               /* t = T = U1+U2 (2) */
    secp256k1_fe_t m = s1; secp256k1_fe_add(&m, &s2);               /* m = M = S1+S2 (2) */
    secp256k1_fe_t n; secp256k1_fe_sqr(&n, &m);                     /* n = M^2 (1) */
    secp256k1_fe_t q; secp256k1_fe_mul(&q, &n, &t);                 /* q = Q = T*M^2 (1) */
    secp256k1_fe_sqr(&n, &n);                                       /* n = M^4 (1) */
    secp256k1_fe_t rr; secp256k1_fe_sqr(&rr, &t);                   /* rr = T^2 (1) */
    secp256k1_fe_mul(&t, &u1, &u2); secp256k1_fe_negate(&t, &t, 1); /* t = -U1*U2 (2) */
    secp256k1_fe_add(&rr, &t);                                      /* rr = R = T^2-U1*U2 (3) */
    secp256k1_fe_sqr(&t, &rr);                                      /* t = R^2 (1) */
    secp256k1_fe_mul(&r->z, &m, &z);                                /* r->z = M*Z (1) */
    secp256k1_fe_normalize(&r->z);
    int infinity = secp256k1_fe_is_zero(&r->z) * (1 - a->infinity);
    secp256k1_fe_mul_int(&r->z, 2 * (1 - a->infinity)); /* r->z = Z3 = 2*M*Z (2) */
    r->x = t;                                           /* r->x = R^2 (1) */
    secp256k1_fe_negate(&q, &q, 1);                     /* q = -Q (2) */
    secp256k1_fe_add(&r->x, &q);                        /* r->x = R^2-Q (3) */
    secp256k1_fe_normalize(&r->x);
    secp256k1_fe_mul_int(&q, 3);                        /* q = -3*Q (6) */
    secp256k1_fe_mul_int(&t, 2);                        /* t = 2*R^2 (2) */
    secp256k1_fe_add(&t, &q);                           /* t = 2*R^2-3*Q (8) */
    secp256k1_fe_mul(&t, &t, &rr);                      /* t = R*(2*R^2-3*Q) (1) */
    secp256k1_fe_add(&t, &n);                           /* t = R*(2*R^2-3*Q)+M^4 (2) */
    secp256k1_fe_negate(&r->y, &t, 2);                  /* r->y = R*(3*Q-2*R^2)-M^4 (3) */
    secp256k1_fe_normalize(&r->y);
    secp256k1_fe_mul_int(&r->x, 4 * (1 - a->infinity)); /* r->x = X3 = 4*(R^2-Q) */
    secp256k1_fe_mul_int(&r->y, 4 * (1 - a->infinity)); /* r->y = Y3 = 4*R*(3*Q-2*R^2)-4*M^4 (4) */

    /** In case a->infinity == 1, the above code results in r->x, r->y, and r->z all equal to 0.
     *  Add b->x to x, b->y to y, and 1 to z in that case.
     */
    t = b->x; secp256k1_fe_mul_int(&t, a->infinity);
    secp256k1_fe_add(&r->x, &t);
    t = b->y; secp256k1_fe_mul_int(&t, a->infinity);
    secp256k1_fe_add(&r->y, &t);
    secp256k1_fe_set_int(&t, a->infinity);
    secp256k1_fe_add(&r->z, &t);
    r->infinity = infinity;
}



static void secp256k1_gej_get_hex(char *r, int *rlen, const secp256k1_gej_t *a) {
    secp256k1_gej_t c = *a;
    secp256k1_ge_t t; secp256k1_ge_set_gej(&t, &c);
    secp256k1_ge_get_hex(r, rlen, &t);
}

#ifdef USE_ENDOMORPHISM
static void secp256k1_gej_mul_lambda(secp256k1_gej_t *r, const secp256k1_gej_t *a) {
    const secp256k1_fe_t *beta = &secp256k1_ge_consts->beta;
    *r = *a;
    secp256k1_fe_mul(&r->x, &r->x, beta);
}
#endif

static void secp256k1_ge_start(void) {
    static const unsigned char secp256k1_ge_consts_g_x[] = {
        0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,
        0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
        0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,
        0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98
    };
    static const unsigned char secp256k1_ge_consts_g_y[] = {
        0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,
        0x5D,0xA4,0xFB,0xFC,0x0E,0x11,0x08,0xA8,
        0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,
        0x9C,0x47,0xD0,0x8F,0xFB,0x10,0xD4,0xB8
    };
#ifdef USE_ENDOMORPHISM
    /* properties of secp256k1's efficiently computable endomorphism */
    static const unsigned char secp256k1_ge_consts_beta[] = {
        0x7a,0xe9,0x6a,0x2b,0x65,0x7c,0x07,0x10,
        0x6e,0x64,0x47,0x9e,0xac,0x34,0x34,0xe9,
        0x9c,0xf0,0x49,0x75,0x12,0xf5,0x89,0x95,
        0xc1,0x39,0x6c,0x28,0x71,0x95,0x01,0xee
    };
#endif
    if (secp256k1_ge_consts == NULL) {
        secp256k1_ge_consts_t *ret = (secp256k1_ge_consts_t*)malloc(sizeof(secp256k1_ge_consts_t));
#ifdef USE_ENDOMORPHISM
        VERIFY_CHECK(secp256k1_fe_set_b32(&ret->beta, secp256k1_ge_consts_beta));
#endif
        secp256k1_fe_t g_x, g_y;
        VERIFY_CHECK(secp256k1_fe_set_b32(&g_x, secp256k1_ge_consts_g_x));
        VERIFY_CHECK(secp256k1_fe_set_b32(&g_y, secp256k1_ge_consts_g_y));
        secp256k1_ge_set_xy(&ret->g, &g_x, &g_y);
        secp256k1_ge_consts = ret;
    }
}

static void secp256k1_ge_stop(void) {
    if (secp256k1_ge_consts != NULL) {
        secp256k1_ge_consts_t *c = (secp256k1_ge_consts_t*)secp256k1_ge_consts;
        free((void*)c);
        secp256k1_ge_consts = NULL;
    }
}

static void secp256k1_gej_add_zinv_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b, const secp256k1_fe *bzinv) {
    /* 9 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
    secp256k1_fe az, z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;

    if (b->infinity) {
        *r = *a;
        return;
    }
    if (a->infinity) {
        secp256k1_fe bzinv2, bzinv3;
        r->infinity = b->infinity;
        secp256k1_fe_sqr(&bzinv2, bzinv);
        secp256k1_fe_mul(&bzinv3, &bzinv2, bzinv);
        secp256k1_fe_mul(&r->x, &b->x, &bzinv2);
        secp256k1_fe_mul(&r->y, &b->y, &bzinv3);
        secp256k1_fe_set_int(&r->z, 1);
        return;
    }
    r->infinity = 0;

    /** We need to calculate (rx,ry,rz) = (ax,ay,az) + (bx,by,1/bzinv). Due to
     *  secp256k1's isomorphism we can multiply the Z coordinates on both sides
     *  by bzinv, and get: (rx,ry,rz*bzinv) = (ax,ay,az*bzinv) + (bx,by,1).
     *  This means that (rx,ry,rz) can be calculated as
     *  (ax,ay,az*bzinv) + (bx,by,1), when not applying the bzinv factor to rz.
     *  The variable az below holds the modified Z coordinate for a, which is used
     *  for the computation of rx and ry, but not for rz.
     */
    secp256k1_fe_mul(&az, &a->z, bzinv);

    secp256k1_fe_sqr(&z12, &az);
    u1 = a->x; secp256k1_fe_normalize_weak(&u1);
    secp256k1_fe_mul(&u2, &b->x, &z12);
    s1 = a->y; secp256k1_fe_normalize_weak(&s1);
    secp256k1_fe_mul(&s2, &b->y, &z12); secp256k1_fe_mul(&s2, &s2, &az);
    secp256k1_fe_negate(&h, &u1, 1); secp256k1_fe_add(&h, &u2);
    secp256k1_fe_negate(&i, &s1, 1); secp256k1_fe_add(&i, &s2);
    if (secp256k1_fe_normalizes_to_zero_var(&h)) {
        if (secp256k1_fe_normalizes_to_zero_var(&i)) {
            secp256k1_gej_double_var2(r, a, NULL);
        } else {
            r->infinity = 1;
        }
        return;
    }
    secp256k1_fe_sqr(&i2, &i);
    secp256k1_fe_sqr(&h2, &h);
    secp256k1_fe_mul(&h3, &h, &h2);
    r->z = a->z; secp256k1_fe_mul(&r->z, &r->z, &h);
    secp256k1_fe_mul(&t, &u1, &h2);
    r->x = t; secp256k1_fe_mul_int(&r->x, 2); secp256k1_fe_add(&r->x, &h3); secp256k1_fe_negate(&r->x, &r->x, 3); secp256k1_fe_add(&r->x, &i2);
    secp256k1_fe_negate(&r->y, &r->x, 5); secp256k1_fe_add(&r->y, &t); secp256k1_fe_mul(&r->y, &r->y, &i);
    secp256k1_fe_mul(&h3, &h3, &s1); secp256k1_fe_negate(&h3, &h3, 1);
    secp256k1_fe_add(&r->y, &h3);
}

#endif
