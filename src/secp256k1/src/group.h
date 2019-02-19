/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_GROUP_
#define _SECP256K1_GROUP_

#include "num.h"
#include "field.h"

#define secp256k1_gej secp256k1_gej_t
#define secp256k1_fe secp256k1_fe_t
#define secp256k1_ge secp256k1_ge_t


/** A group element of the secp256k1 curve, in affine coordinates. */
typedef struct {
    secp256k1_fe_t x;
    secp256k1_fe_t y;
    int infinity; /* whether this represents the point at infinity */
} secp256k1_ge_t;

#define SECP256K1_GE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), 0}
#define SECP256K1_GE_CONST_INFINITY {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}

/** A group element of the secp256k1 curve, in jacobian coordinates. */
typedef struct {
    secp256k1_fe_t x; /* actual X: x/z^2 */
    secp256k1_fe_t y; /* actual Y: y/z^3 */
    secp256k1_fe_t z;
    int infinity; /* whether this represents the point at infinity */
} secp256k1_gej_t;

#define SECP256K1_GEJ_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), 0}
#define SECP256K1_GEJ_CONST_INFINITY {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}

/** Global constants related to the group */
typedef struct {
    secp256k1_ge_t g; /* the generator point */

#ifdef USE_ENDOMORPHISM
    /* constants related to secp256k1's efficiently computable endomorphism */
    secp256k1_fe_t beta;
#endif
} secp256k1_ge_consts_t;

typedef struct {
    secp256k1_fe_storage x;
    secp256k1_fe_storage y;
} secp256k1_ge_storage;

#define SECP256K1_GE_STORAGE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_STORAGE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_STORAGE_CONST((i),(j),(k),(l),(m),(n),(o),(p))}

#define SECP256K1_GE_STORAGE_CONST_GET(t) SECP256K1_FE_STORAGE_CONST_GET(t.x), SECP256K1_FE_STORAGE_CONST_GET(t.y)

static const secp256k1_ge_consts_t *secp256k1_ge_consts = NULL;

/** Initialize the group module. */
static void secp256k1_ge_start(void);

/** De-initialize the group module. */
static void secp256k1_ge_stop(void);

/** Set a group element equal to the point at infinity */
static void secp256k1_ge_set_infinity(secp256k1_ge_t *r);

/** Set a group element equal to the point with given X and Y coordinates */
static void secp256k1_ge_set_xy(secp256k1_ge_t *r, const secp256k1_fe_t *x, const secp256k1_fe_t *y);

/** Set a group element (affine) equal to the point with the given X coordinate
 *  and a Y coordinate that is a quadratic residue modulo p. The return value
 *  is true iff a coordinate with the given X coordinate exists.
 */
static int secp256k1_ge_set_xquad(secp256k1_ge_t *r, const secp256k1_fe_t *x);

/** Set a group element (affine) equal to the point with the given X coordinate, and given oddness
 *  for Y. Return value indicates whether the result is valid. */
static int secp256k1_ge_set_xo(secp256k1_ge_t *r, const secp256k1_fe_t *x, int odd);

/** Check whether a group element is the point at infinity. */
static int secp256k1_ge_is_infinity(const secp256k1_ge_t *a);

/** Check whether a group element is valid (i.e., on the curve). */
static int secp256k1_ge_is_valid(const secp256k1_ge_t *a);

static void secp256k1_ge_neg(secp256k1_ge_t *r, const secp256k1_ge_t *a);

/** Get a hex representation of a point. *rlen will be overwritten with the real length. */
static void secp256k1_ge_get_hex(char *r, int *rlen, const secp256k1_ge_t *a);

/** Set a group element equal to another which is given in jacobian coordinates */
static void secp256k1_ge_set_gej(secp256k1_ge_t *r, secp256k1_gej_t *a);

/** Set a batch of group elements equal to the inputs given in jacobian coordinates */
static void secp256k1_ge_set_all_gej_var(size_t len, secp256k1_ge_t r[len], const secp256k1_gej_t a[len]);

/** Set a batch of group elements equal to the inputs given in jacobian coordinates */
static void secp256k1_ge_set_all_gej_var2(secp256k1_ge *r, const secp256k1_gej *a, size_t len, const secp256k1_callback *cb);

/** Set a batch of group elements equal to the inputs given in jacobian
 *  coordinates (with known z-ratios). zr must contain the known z-ratios such
 *  that mul(a[i].z, zr[i+1]) == a[i+1].z. zr[0] is ignored. */
static void secp256k1_ge_set_table_gej_var(secp256k1_ge *r, const secp256k1_gej *a, const secp256k1_fe *zr, size_t len);

/** Bring a batch inputs given in jacobian coordinates (with known z-ratios) to
 *  the same global z "denominator". zr must contain the known z-ratios such
 *  that mul(a[i].z, zr[i+1]) == a[i+1].z. zr[0] is ignored. The x and y
 *  coordinates of the result are stored in r, the common z coordinate is
 *  stored in globalz. */
static void secp256k1_ge_globalz_set_table_gej(size_t len, secp256k1_ge *r, secp256k1_fe *globalz, const secp256k1_gej *a, const secp256k1_fe *zr);

/** Set a group element (affine) equal to the point at infinity. */
static void secp256k1_ge_set_infinity(secp256k1_ge *r);

/** Set a group element (jacobian) equal to the point at infinity. */
static void secp256k1_gej_set_infinity(secp256k1_gej_t *r);

static void secp256k1_gej_add_ge_var2(secp256k1_gej_t *r, const secp256k1_gej_t *a, const secp256k1_ge_t *b, secp256k1_fe_t *rzr);

static void secp256k1_ge_set_all_gej_var2(secp256k1_ge *r, const secp256k1_gej *a, size_t len, const secp256k1_callback *cb);

/** Set a group element (jacobian) equal to the point with given X and Y coordinates. */
static void secp256k1_gej_set_xy(secp256k1_gej_t *r, const secp256k1_fe_t *x, const secp256k1_fe_t *y);

/** Set a group element (jacobian) equal to another which is given in affine coordinates. */
static void secp256k1_gej_set_ge(secp256k1_gej_t *r, const secp256k1_ge_t *a);

/** Get the X coordinate of a group element (jacobian). */
static void secp256k1_gej_get_x_var(secp256k1_fe_t *r, const secp256k1_gej_t *a);

/** Set r equal to the inverse of a (i.e., mirrored around the X axis) */
static void secp256k1_gej_neg(secp256k1_gej_t *r, const secp256k1_gej_t *a);

/** Check whether a group element is the point at infinity. */
static int secp256k1_gej_is_infinity(const secp256k1_gej_t *a);

static void secp256k1_ge_from_storage(secp256k1_ge_t *r, const secp256k1_ge_storage *a);

/** Convert a group element to the storage type. */
static void secp256k1_ge_to_storage(secp256k1_ge_storage *r, const secp256k1_ge_t *a);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time. */
static void secp256k1_ge_storage_cmov(secp256k1_ge_storage *r, const secp256k1_ge_storage *a, int flag);

/** Set r equal to the double of a. */
static void secp256k1_gej_double_var(secp256k1_gej_t *r, const secp256k1_gej_t *a);
static void secp256k1_gej_double_var2(secp256k1_gej *r, const secp256k1_gej *a, secp256k1_fe *rzr);

/** Set r equal to the sum of a and b. */
static void secp256k1_gej_add_var(secp256k1_gej_t *r, const secp256k1_gej_t *a, const secp256k1_gej_t *b);

/** Set r equal to the sum of a and b. If rzr is non-NULL, r->z = a->z * *rzr (a cannot be infinity in that case). */
static void secp256k1_gej_add_var2(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_gej *b, secp256k1_fe *rzr);

/** Set r equal to the sum of a and b (with b given in affine coordinates, and not infinity). */
static void secp256k1_gej_add_ge(secp256k1_gej_t *r, const secp256k1_gej_t *a, const secp256k1_ge_t *b);

/** Set r equal to the sum of a and b (with b given in affine coordinates). This is more efficient
    than secp256k1_gej_add_var. It is identical to secp256k1_gej_add_ge but without constant-time
    guarantee, and b is allowed to be infinity. */
static void secp256k1_gej_add_ge_var(secp256k1_gej_t *r, const secp256k1_gej_t *a, const secp256k1_ge_t *b);

/** Get a hex representation of a point. *rlen will be overwritten with the real length. */
static void secp256k1_gej_get_hex(char *r, int *rlen, const secp256k1_gej_t *a);

/** Set a group element (affine) equal to the point with the given X coordinate, and given oddness
 *  for Y. Return value indicates whether the result is valid. */
static int secp256k1_ge_set_xo_var(secp256k1_ge_t *r, const secp256k1_fe_t *x, int odd);
/** Set a group element (affine) equal to the point with the given X coordinate
 *  and a Y coordinate that is a quadratic residue modulo p. The return value
 *  is true iff a coordinate with the given X coordinate exists.
 */
static int secp256k1_ge_set_xquad(secp256k1_ge_t *r, const secp256k1_fe_t *x);

/** Compare the X coordinate of a group element (jacobian). */
static int secp256k1_gej_eq_x_var(const secp256k1_fe *x, const secp256k1_gej *a);

/** Set r equal to the sum of a and b (with the inverse of b's Z coordinate passed as bzinv). */
static void secp256k1_gej_add_zinv_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b, const secp256k1_fe *bzinv);

#ifdef USE_ENDOMORPHISM
/** Set r to be equal to lambda times a, where lambda is chosen in a way such that this is very fast. */
static void secp256k1_gej_mul_lambda(secp256k1_gej_t *r, const secp256k1_gej_t *a);
#endif

/** Clear a secp256k1_gej_t to prevent leaking sensitive information. */
static void secp256k1_gej_clear(secp256k1_gej_t *r);

/** Clear a secp256k1_ge_t to prevent leaking sensitive information. */
static void secp256k1_ge_clear(secp256k1_ge_t *r);

/** Rescale a jacobian point by b which must be non-zero. Constant-time. */
static void secp256k1_gej_rescale(secp256k1_gej *r, const secp256k1_fe *b);

/** Set r equal to the double of a. If rzr is not-NULL, r->z = a->z * *rzr (where infinity means an implicit z = 0).
 * a may not be zero. Constant time. */
static void secp256k1_gej_double_nonzero(secp256k1_gej *r, const secp256k1_gej *a, secp256k1_fe *rzr);

#endif
