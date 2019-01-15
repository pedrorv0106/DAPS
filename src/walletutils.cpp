//
// Created by Akira Cam on 2019-01-15.
//
#include "wallet.h"
#include "secp256k1.h"
#include "ecdhutil.h"

bool CWallet::RevealTxOutAmount(const CTransaction& tx, const CTxOut& out, CAmount& amount) {
    std::set<CKeyID> keyIDs;
    GetKeys(keyIDs);
    unsigned char sharedSec[65];
    BOOST_FOREACH(const CKeyID& keyID, keyIDs) {
        CBitcoinAddress address(keyID);
        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CKey privKey;
        if (scriptPubKey == out.scriptPubKey && GetKey(keyID, privKey)) {
            CPubKey txPub(&(tx.txPub[0]), &(tx.txPub[0]) + 33);
            memcpy(sharedSec, txPub.begin(), txPub.size());
            if (secp256k1_ec_pubkey_tweak_mul(sharedSec, txPub.size(), privKey.begin())) {
                uint256 val = out.maskValue.amount;
                uint256 mask = out.maskValue.mask;
                ecdhDecode(mask.begin(), val.begin(), sharedSec, 33);
                amount = (CAmount)val.Get64();
                return true;
            }
        }
    }

    //Do we need to reconstruct the private to spend the tx out put?
    return false;
}

bool CWallet::EncodeTxOutAmount(CTxOut& out, const CAmount& amount, const char * sharedSec) {
    if (amount < 0) {
        return false;
    }
    //generate random mask
    CKey mask;
    mask.MakeNewKey(true);
    memcpy(out.maskValue.mask.begin(), mask.begin(), 32);
    uint256 tempAmount((uint64_t) amount);
    memcpy(out.maskValue.amount.begin(), tempAmount.begin(), 32);
    ecdhEncode(out.maskValue.mask.begin(), out.maskValue.amount.begin(), sharedSec, 33);
    return true;
}
