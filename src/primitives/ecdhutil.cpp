#include "hash.h"
#include "./crypto/crypto-ops.h"

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