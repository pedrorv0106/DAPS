/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BULLETPROOF_TESTS
#define SECP256K1_MODULE_BULLETPROOF_TESTS

#include <string.h>

#include "group.h"
#include "scalar.h"
#include "testrand.h"
#include "util.h"

#include "include/secp256k1_bulletproofs.h"



void test_new_apis(uint64_t *v, size_t nbits, size_t n_commits) {
    size_t plen;
    unsigned char proof[10*1024];
    unsigned char commits[20][64];
    CHECK(bulletproofs_prove_api(v, nbits, n_commits, &plen, proof, commits) == 1);
    printf("end of prove\n");
    CHECK(bulletproofs_verify_api(nbits, n_commits, plen, proof, commits) == 1);
}


void test_bulletproof_rangeproof_aggregate1(uint64_t *v, size_t nbits, size_t n_commits, size_t expected_size) {
    unsigned char proof[20000];
    const unsigned char *proof_ptr = proof;
    size_t plen = sizeof(proof);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_scalar_t *blind = (secp256k1_scalar_t *)checked_malloc(&both->error_callback, n_commits * sizeof(*blind));
    secp256k1_ge *commitp = (secp256k1_ge *)checked_malloc(&both->error_callback, n_commits * sizeof(*commitp));
    secp256k1_pedersen_commitment *commitpederson = (secp256k1_pedersen_commitment *)checked_malloc(&both->error_callback, n_commits * sizeof(*commitpederson));
    const secp256k1_ge *constptr = commitp;
    secp256k1_ge value_gen;
    unsigned char commit[32] = {0};
    unsigned char nonce[32] = "mary, mary quite contrary how do";
    size_t i;
    unsigned char commits[10][65];
    secp256k1_scratch *scratch = secp256k1_scratch_space_create(both, 100000000);
    secp256k1_bulletproof_generators *gens = secp256k1_bulletproof_generators_create(both, &secp256k1_generator_const_h, 256);


    secp256k1_generator_load(&value_gen, &secp256k1_generator_const_g);
    for (i = 0; i < n_commits; i++) {
        secp256k1_scalar vs;
        secp256k1_gej commitj;

        if (v[i] >> nbits > 0) {
            v[i] = 0;
        }
        secp256k1_scalar_set_u64(&vs, v[i]);
        random_scalar_order(&blind[i]);
        secp256k1_pedersen_ecmult(&commitj, &blind[i], v[i], &value_gen, &gens->blinding_gen[0]);
        secp256k1_ge_set_gej(&commitp[i], &commitj);

        secp256k1_bulletproof_update_commit(commit, &commitp[i], &value_gen);
    }

    CHECK(secp256k1_bulletproof_rangeproof_prove_impl(both, scratch, proof, &plen, nbits, v, NULL, blind, commitp, n_commits, &value_gen, gens, nonce, NULL, 0) == 1);

    for (i = 0; i < n_commits; i++) {
        secp256k1_pedersen_commitment_save(&commitpederson[i], &commitp[i]);
        secp256k1_pedersen_commitment_serialize(both, commits[i], &commitpederson[i]);
    }

    secp256k1_context *both_reconstructed = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_ge *commitp_reconstructed = (secp256k1_ge *)checked_malloc(&both_reconstructed->error_callback, n_commits * sizeof(*commitp));
    secp256k1_pedersen_commitment *commitpederson_reconstructed = (secp256k1_pedersen_commitment *)checked_malloc(&both_reconstructed->error_callback, n_commits * sizeof(*commitpederson_reconstructed));

    for (i = 0; i < n_commits; i++) {
        secp256k1_pedersen_commitment_parse(both_reconstructed, &commitpederson_reconstructed[i], commits[i]);
        secp256k1_pedersen_commitment_load(&commitp_reconstructed[i], &commitpederson_reconstructed[i]);
    }
    const secp256k1_ge *constptr1 = commitp_reconstructed;
    secp256k1_scratch *scratch_reconstructed = secp256k1_scratch_space_create(both_reconstructed, 100000000);
    secp256k1_ge value_gen_reconstructed;
    secp256k1_bulletproof_generators *gens_reconstructed = secp256k1_bulletproof_generators_create(both_reconstructed, &secp256k1_generator_const_h, 256);

    secp256k1_generator_load(&value_gen_reconstructed, &secp256k1_generator_const_g);

    //CHECK(plen == expected_size);
    CHECK(secp256k1_bulletproof_rangeproof_verify_impl(both_reconstructed, scratch_reconstructed, &proof_ptr, 1, plen, nbits, NULL, &constptr1, n_commits, &value_gen_reconstructed, gens_reconstructed, NULL, 0) == 1);

    secp256k1_scratch_destroy(scratch);
    secp256k1_scratch_destroy(gens);
    secp256k1_scratch_destroy(gens_reconstructed);
    secp256k1_scratch_destroy(scratch_reconstructed);

    free(commitp);
    //free(v);
    free(blind);
    free(commitp_reconstructed);
    free(commitpederson_reconstructed);
}

/*static void test_build_verify() {
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_scratch *scratch = secp256k1_scratch_space_create(both, 1024 * 10240);
    secp256k1_generator value_gen;
    secp256k1_bulletproof_generators *gens;
    secp256k1_pedersen_commitment pcommit[4];
    const secp256k1_pedersen_commitment *pcommit_arr[4];
    unsigned char proof[10000];
    const unsigned char *proof_ptr = proof;
    const unsigned char blind[32] = "   i am not a blinding factor   ";
    const unsigned char *blind_ptr[4];
    size_t blindlen = sizeof(blind);
    size_t plen = sizeof(proof);
    uint64_t value[4] = { 1234, 2345, 3456, 3456 } ;

    int32_t ecount = 0;

    blind_ptr[0] = blind;
    blind_ptr[1] = blind;
    blind_ptr[2] = blind;
    blind_ptr[3] = blind;
    pcommit_arr[0] = pcommit;

    //secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);

    secp256k1_context_set_error_callback(both, counting_illegal_callback_fn, &ecount);
    //secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);

    CHECK(secp256k1_generator_generate(both, &value_gen, blind) != 0);
    CHECK(secp256k1_pedersen_commit(both, &pcommit[0], blind, value[0], &value_gen, &secp256k1_generator_const_h) != 0);
    CHECK(secp256k1_pedersen_commit(both, &pcommit[1], blind, value[1], &value_gen, &secp256k1_generator_const_h) != 0);
    CHECK(secp256k1_pedersen_commit(both, &pcommit[2], blind, value[2], &value_gen, &secp256k1_generator_const_h) != 0);
    CHECK(secp256k1_pedersen_commit(both, &pcommit[3], blind, value[3], &value_gen, &secp256k1_generator_const_h) != 0);

    gens = secp256k1_bulletproof_generators_create(both, NULL, 256);
    CHECK(gens == NULL && ecount == 1);
    gens = secp256k1_bulletproof_generators_create(both, &secp256k1_generator_const_h, 256);
    CHECK(gens != NULL && ecount == 1);

    CHECK(secp256k1_bulletproof_rangeproof_prove(both, scratch, gens, proof, &plen, value, NULL, blind_ptr, 2, &value_gen, 64, blind, NULL, 0) == 1);

    CHECK(secp256k1_bulletproof_rangeproof_verify(both, scratch, gens, proof, plen, NULL, pcommit, 2, 64, &value_gen, NULL, 0) == 1);
}*/



#define MAX_WIDTH (1ul << 20)
typedef struct {
    const secp256k1_scalar *a;
    const secp256k1_scalar *b;
    const secp256k1_ge *g;
    const secp256k1_ge *h;
    size_t n;
} test_bulletproof_ecmult_context;



void run_bulletproofs_tests(void) {
    size_t i;
    /* Make a ton of generators */
    //secp256k1_bulletproof_generators * gens = secp256k1_bulletproof_generators_create(ctx, &secp256k1_generator_const_h, 1000000);
    uint64_t vals[] = {1000, 2000, 3000, 4000, 5000, 6000};

    printf("Testing bulletproof range proof\n");
    //test_new_apis(vals, 64, 2);

    test_bulletproof_rangeproof_aggregate1(vals, 64, 2, 675);
    //test_bulletproof_inner_product(1024, gens);
    test_bulletproof_api();

    /* sanity checks */
//    CHECK(secp256k1_bulletproof_innerproduct_proof_length(0) == 32);  /* encoding of 1 */
//    CHECK(secp256k1_bulletproof_innerproduct_proof_length(1) == 96);  /* encoding a*b, a, b */
//    CHECK(secp256k1_bulletproof_innerproduct_proof_length(2) == 160); /* dot prod, a, b, L, R, parity of L, R */
//    CHECK(secp256k1_bulletproof_innerproduct_proof_length(4) == 225); /* dot prod, a, b, a, b, L, R, parity of L, R */
//    CHECK(secp256k1_bulletproof_innerproduct_proof_length(8) == 289); /* dot prod, a, b, a, b, L, R, L, R, parity of L, R */

    printf("Testing bulletproof inner product\n");
//    test_bulletproof_inner_product(0, gens);
//    test_bulletproof_inner_product(1, gens);
//    test_bulletproof_inner_product(2, gens);
//    test_bulletproof_inner_product(4, gens);
//    test_bulletproof_inner_product(8, gens);
//    for (i = 0; i < (size_t) count; i++) {
//        test_bulletproof_inner_product(32, gens);
//        test_bulletproof_inner_product(64, gens);
//    }

    printf("testing verify");
    test_build_verify();



    /*test_bulletproof_rangeproof(1, 289, gens);
    test_bulletproof_rangeproof(2, 353, gens);
    test_bulletproof_rangeproof(16, 546, gens);
    test_bulletproof_rangeproof(32, 610, gens);
    test_bulletproof_rangeproof(64, 675, gens);*/



    //test_bulletproof_rangeproof_aggregate(64, 2, 675, gens);
    //test_bulletproof_rangeproof_aggregate(32, 4, 546, gens);
    //test_bulletproof_rangeproof_aggregate(8, 10, 610, gens);
    //test_bulletproof_rangeproof_aggregate(8, 16, 610, gens);

    //test_bulletproof_circuit(gens);

    //secp256k1_bulletproof_generators_destroy(ctx, gens);
}
#undef MAX_WIDTH

#endif
