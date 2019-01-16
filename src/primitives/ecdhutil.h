//
// Created by Akira Cam on 2019-01-15.
//

#ifndef DAPSCOIN_ECDHUTIL_H
#define DAPSCOIN_ECDHUTIL_H
#include "./crypto/crypto-ops.h"
#include "key.h"
#include "amount.h"

//Elliptic Curve Diffie Helman: encodes and decodes the amount b and mask a
// where C= aG + bH
void ecdhEncode(unsigned char * unmasked, unsigned char * amount, unsigned char * sharedSec, int size);
void ecdhDecode(unsigned char * masked, unsigned char * amount, unsigned char * sharedSec, int size);

class ECDHInfo {
public:
    static void Encode(const CKey& mask, const CAmount& amount, const CPubKey& sharedSec, unsigned char* encodedMask, unsigned char* encodedAmount);
    static void Decode(unsigned char* encodedMask, unsigned char* encodedAmount, const CPubKey sharedSec, CKey& decodedMask, CAmount& decodedAmount);
    static void ComputeSharedSec(const CKey& priv, const CPubKey& pubKey, CPubKey& sharedSec);
};

#endif //DAPSCOIN_ECDHUTIL_H
