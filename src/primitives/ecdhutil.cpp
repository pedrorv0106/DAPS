#include "hash.h"
#include "./crypto/crypto-ops.h"
#include "ecdhutil.h"
#include "uint256.h"

//Elliptic Curve Diffie Helman: encodes and decodes the amount b and mask a
void ecdhEncode(unsigned char * unmasked, unsigned char * amount, unsigned char * sharedSec, int size)
{
    uint256 sharedSec1 = Hash(sharedSec, sharedSec + size);
    uint256 sharedSec2 = Hash(sharedSec1.begin(), sharedSec1.end());
    //encode
    sc_add(unmasked, unmasked, sharedSec1.begin());
    sc_add(amount, amount, sharedSec2.begin());
}
void ecdhDecode(unsigned char * masked, unsigned char * amount, unsigned char * sharedSec, int size)
{
    uint256 sharedSec1 = Hash(sharedSec, sharedSec + size);
    uint256 sharedSec2 = Hash(sharedSec1.begin(), sharedSec1.end());
    //decode
    sc_sub(masked, masked, sharedSec1.begin());
    sc_sub(amount, amount, sharedSec2.begin());
}

void ECDHInfo::ComputeSharedSec(const CKey& priv, const CPubKey& pubKey, CPubKey& sharedSec) {
    sharedSec.Set(pubKey.begin(), pubKey.end());
    secp256k1_ec_pubkey_tweak_mul(sharedSec.begin(), sharedSec.size(), priv.begin());
}

void ECDHInfo::Encode(const CKey& mask, const CAmount& amount, const CPubKey& sharedSec, uint256& encodedMask, uint256 encodedAmount)
{
    memcpy(encodedMask.begin(), mask.begin(), 32);
    memcpy(encodedAmount.begin(), amount.begin(), 32);
    ecdhEncode(encodedMask.begin(), encodedAmount.begin(), sharedSec.begin(), sharedSec.size());
}

void ECDHInfo::Decode(unsigned char* encodedMask, unsigned char* encodedAmount, const CPubKey sharedSec, CKey& decodedMask, CAmount& decodedAmount)
{
    unsigned char[32] tempAmount;
    memcpy(decodedMask.begin(), encodedMask, 32);
    memcpy(tempAmount, encodedAmount, 32);
    ecdhDecode(decodedMask.begin(), tempAmount, sharedSec.begin(), sharedSec.size());
}