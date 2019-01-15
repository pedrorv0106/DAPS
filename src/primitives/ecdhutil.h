//
// Created by Akira Cam on 2019-01-15.
//

#ifndef DAPSCOIN_ECDHUTIL_H
#define DAPSCOIN_ECDHUTIL_H
#include "./crypto/crypto-ops.h"
//Elliptic Curve Diffie Helman: encodes and decodes the amount b and mask a
// where C= aG + bH
void ecdhEncode(unsigned char * unmasked, unsigned char * amount, unsigned char * sharedSec, int size);
void ecdhDecode(unsigned char * masked, unsigned char * amount, unsigned char * sharedSec, int size);

#endif //DAPSCOIN_ECDHUTIL_H
