//
// Created by Akira Cam on 2019-01-15.
//
#include "wallet.h"
#include "secp256k1.h"
#include "ecdhutil.h"

bool CWallet::RevealTxOutAmount(const CTransaction& tx, const CTxOut& out, CAmount& amount) {
    if (tx.IsCoinBase()) {
        //Coinbase transaction output is not hidden, not need to decrypt
        amount = out.nValue;
        return true;
    }
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
            CKey view;
            if (myViewPrivateKey(view) && secp256k1_ec_pubkey_tweak_mul(sharedSec, txPub.size(), view.begin()) {
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

bool CWallet::findCorrespondingPrivateKey(const CTransaction& tx, CKey& key) {
    std::set<CKeyID> keyIDs;
    GetKeys(keyIDs);
    unsigned char sharedSec[65];
    BOOST_FOREACH(const CKeyID& keyID, keyIDs) {
        CBitcoinAddress address(keyID);
        CScript scriptPubKey = GetScriptForDestination(address.Get());
        if (scriptPubKey == out.scriptPubKey && GetKey(keyID, key)) {
            return true;
        }
    }
    return false;
}

bool CWallet::EncodeTxOutAmount(CTxOut& out, const CAmount& amount, const unsigned char * sharedSec) {
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

CAmount CWallet::getCOutPutValue(COutput& output) 
{
    CTxOut& out = output.tx->vout[output.i];
    CAmount amount;
    RevealTxOutAmount(output.tx, out, amount);
    return amount;
}

CAmount CWallet::getCTxOutValue(const CTransaction& tx, const CTxOut& out) 
{
    CAmount amount;
    RevealTxOutAmount(out, amount);
    return amount;
}