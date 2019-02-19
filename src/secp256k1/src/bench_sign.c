/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include <stdio.h>
#include <string.h>

#include "include/secp256k1.h"
#include "util.h"
#include "bench.h"

typedef struct {
    secp256k1_context* ctx;
    unsigned char msg[32];
    unsigned char key[32];
} bench_sign;

static void bench_sign_setup(void* arg) {
    int i;
    bench_sign *data = (bench_sign*)arg;

    for (i = 0; i < 32; i++) {
        data->msg[i] = i + 1;
    }
    for (i = 0; i < 32; i++) {
        data->key[i] = i + 65;
    }
}

static void bench_sign_run(void* arg) {
    int i;
    bench_sign *data = (bench_sign*)arg;

    unsigned char sig[74];
    for (i = 0; i < 20000; i++) {
        size_t siglen = 74;
        int j;
        secp256k1_ecdsa_signature signature;
        CHECK(secp256k1_ecdsa_sign(data->ctx, &signature, data->msg, data->key, NULL, NULL));
        CHECK(secp256k1_ecdsa_signature_serialize_der(data->ctx, sig, &siglen, &signature));
        for (j = 0; j < 32; j++) {
            data->msg[j] = sig[j];
            data->key[j] = sig[j + 32];
        }
    }
}int main(void) {
    secp256k1_start(SECP256K1_START_SIGN);

    unsigned char msg[32];
    unsigned char nonce[32];
    unsigned char key[32];

    for (int i = 0; i < 32; i++) msg[i] = i + 1;
    for (int i = 0; i < 32; i++) nonce[i] = i + 33;
    for (int i = 0; i < 32; i++) key[i] = i + 65;

    unsigned char sig[64];

    for (int i=0; i<1000000; i++) {
        int recid = 0;
        CHECK(secp256k1_ecdsa_sign_compact(msg, 32, sig, key, nonce, &recid));
        for (int j = 0; j < 32; j++) {
            nonce[j] = key[j];     /* Move former key to nonce  */
            msg[j] = sig[j];       /* Move former R to message. */
            key[j] = sig[j + 32];  /* Move former S to key.     */
        }
    }

    static const unsigned char fini[64] = {
        0x92, 0x03, 0xef, 0xf1, 0x58, 0x0b, 0x49, 0x8d,
        0x22, 0x3d, 0x49, 0x0e, 0xbf, 0x26, 0x50, 0x0e,
        0x2d, 0x62, 0x90, 0xd7, 0x82, 0xbd, 0x3d, 0x5c,
        0xa9, 0x10, 0xa5, 0x49, 0xb1, 0xd8, 0x8c, 0xc0,
        0x5b, 0x5e, 0x9e, 0x68, 0x51, 0x3d, 0xe8, 0xec,
        0x82, 0x30, 0x82, 0x88, 0x8c, 0xfd, 0xe7, 0x71,
        0x15, 0x92, 0xfc, 0x14, 0x59, 0x78, 0x31, 0xb3,
        0xf6, 0x07, 0x91, 0x18, 0x00, 0x8d, 0x4c, 0xb2
    };
    CHECK(memcmp(sig, fini, 64) == 0);

    secp256k1_stop();

    bench_sign data;

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    run_benchmark("ecdsa_sign", bench_sign_run, bench_sign_setup, NULL, &data, 10, 20000);

    secp256k1_context_destroy(data.ctx);
    return 0;
}
