// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2018-2019 The DAPScoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

#include "amount.h"
#include "script/script.h"
#include "serialize.h"
#include "uint256.h"
#include "../bip38.h"
#include <iostream>
#include "key.h"

#include <list>

class CTransaction;

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    uint256 hash;
    uint32_t n;

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, uint32_t nIn) { hash = hashIn; n = nIn; }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(FLATDATA(*this));
    }

    void SetNull() { hash.SetNull(); n = (uint32_t) -1; }
    bool IsNull() const { return (hash.IsNull() && n == (uint32_t) -1); }
    bool IsMasternodeReward(const CTransaction* tx) const;

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
    std::string ToStringShort() const;

    uint256 GetHash();

};

/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;
    CScript prevPubKey;

    CTxIn()
    {
        nSequence = std::numeric_limits<unsigned int>::max();
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=std::numeric_limits<unsigned int>::max());
    CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=std::numeric_limits<uint32_t>::max());

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(nSequence);
    }

    bool IsFinal() const
    {
        return (nSequence == std::numeric_limits<uint32_t>::max());
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

typedef struct MaskValue {
    CPubKey sharedSec;  //secret is computed based on the transaction pubkey, using diffie hellman
                        //sharedSec = txPub * viewPrivateKey of receiver = txPriv * viewPublicKey of receiver
    uint256 amount;
    uint256 mask;  //Commitment C = mask * G + amount * H, H = Hp(G), Hp = toHashPoint
};

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    CAmount nValue; //should always be 0
    CScript scriptPubKey;
    int nRounds;
    //ECDH encoded value for the amount: the idea is the use the shared secret and a key derivation function to
    //encode the value and the mask so that only the sender and the receiver of the tx output can decode the encoded amount
    MaskValue maskValue;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nValue);
        READWRITE(scriptPubKey);
        READWRITE(maskValue.amount);
        READWRITE(maskValue.mask);
    }

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
        nRounds = -10; // an initial value, should be no way to get this by calculations
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    void SetEmpty()
    {
        nValue = 0;
        scriptPubKey.clear();
    }

    bool IsEmpty() const
    {
        return (nValue == 0 && scriptPubKey.empty());
    }

    uint256 GetHash() const;

    bool IsDust(CFeeRate minRelayTxFee) const
    {
        // "Dust" is defined in terms of CTransaction::minRelayTxFee, which has units duffs-per-kilobyte.
        // If you'd pay more than 1/3 in fees to spend something, then we consider it dust.
        // A typical txout is 34 bytes big, and will need a CTxIn of at least 148 bytes to spend
        // i.e. total is 148 + 32 = 182 bytes. Default -minrelaytxfee is 10000 duffs per kB
        // and that means that fee per txout is 182 * 10000 / 1000 = 1820 duffs.
        // So dust is a txout less than 1820 *3 = 5460 duffs
        // with default -minrelaytxfee = minRelayTxFee = 10000 duffs per kB.
        size_t nSize = GetSerializeSize(SER_DISK,0)+148u;
        return (nValue < 3*minRelayTxFee.GetFee(nSize));
    }

    bool IsZerocoinMint() const
    {
        return !scriptPubKey.empty() && scriptPubKey.IsZerocoinMint();
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey &&
                a.nRounds      == b.nRounds);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

struct CMutableTransaction;

enum {
    TX_TYPE_FULL  =  0, //used for any normal transaction
    //transaction with no hidden amount (used for collateral transaction, rewarding transaction
    // (for masternode and staking node), and PoA mining rew)
    TX_TYPE_REVEAL_AMOUNT,
    TX_TYPE_REVEAL_SENDER    //transaction with no ring signature (used for decollateral transaction + reward transaction
};

/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
private:
    /** Memory only. */
    const uint256 hash;
    void UpdateHash() const;

public:
    static const int32_t CURRENT_VERSION=1;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const int32_t nVersion;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    const uint32_t nLockTime;

    //For stealth transactions
    std::vector<unsigned char> txPub;
    CKey txPriv;    //only  in-memory
    char hasPaymentID;
    uint64_t paymentID;
    //const unsigned int nTime;
    uint32_t txType;

    std::vector<unsigned char> masternodeStealthAddress;    //masternode stealth address for receiving rewards

    std::vector<unsigned char> bulletproofs;

    std::vector<CKeyImage> keyImages;   //have the same number element as vin
    std::vector<std::vector<CTxIn>> decoys;

    CAmount nTxFee;

    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();

    /** Convert a CMutableTransaction into a CTransaction. */
    CTransaction(const CMutableTransaction &tx);

    CTransaction& operator=(const CTransaction& tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(*const_cast<int32_t*>(&this->nVersion));
        nVersion = this->nVersion;
        READWRITE(*const_cast<std::vector<CTxIn>*>(&vin));
        READWRITE(*const_cast<std::vector<CTxOut>*>(&vout));
        READWRITE(*const_cast<uint32_t*>(&nLockTime));
        READWRITE(txPub);
        READWRITE(hasPaymentID);
        if (hasPaymentID != 0) {
            READWRITE(paymentID);
        }
        READWRITE(txType);
        if (IsMNCollateralTx()) {
            READWRITE(masternodeStealthAddress);
        }
        READWRITE(bulletproofs);

        READWRITE(keyImages);
        READWRITE(decoys);
        READWRITE(nTxFee);
        if (ser_action.ForRead())
            UpdateHash();
    }

    bool IsNull() const {
        return vin.empty() && vout.empty();
    }

    const uint256& GetHash() const {
        UpdateHash();
        return hash;
    }

    // Return sum of txouts.
    CAmount GetValueOut() const;
    // GetValueIn() is a method on CCoinsViewCache, because
    // inputs must be known to compute value in.

    // Compute priority, given priority of inputs and (optionally) tx size
    double ComputePriority(double dPriorityInputs, unsigned int nTxSize=0) const;

    // Compute modified tx size for priority calculation (optionally given tx size)
    unsigned int CalculateModifiedSize(unsigned int nTxSize=0) const;

    bool IsZerocoinSpend() const
    {
        return !IsCoinAudit() && (vin.size() > 0 && vin[0].prevout.IsNull() && vin[0].scriptSig[0] == OP_ZEROCOINSPEND);
    }

    bool IsZerocoinMint() const
    {
    	if (IsCoinAudit()) {
    		return false;
    	}
        for(const CTxOut& txout : vout) {
            if (txout.scriptPubKey.IsZerocoinMint())
                return true;
        }
        return false;
    }

    bool ContainsZerocoins() const
    {
        return !IsCoinAudit() && (IsZerocoinSpend() || IsZerocoinMint());
    }

    CAmount GetZerocoinMinted() const;
    CAmount GetZerocoinSpent() const;
    int GetZerocoinMintCount() const;

    bool UsesUTXO(const COutPoint out);
    std::list<COutPoint> GetOutPoints() const;

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull() && !ContainsZerocoins());
    }

    bool IsCoinAudit() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    bool IsCoinStake() const
    {
        // ppcoin: the coin stake transaction is marked with the first output empty
        return (vin.size() > 0 && (!vin[0].prevout.IsNull()) && vout.size() >= 2 && vout[0].IsEmpty());
    }

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return a.hash == b.hash;
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return a.hash != b.hash;
    }

    bool IsMNCollateralTx() const {
        if (txType == TX_TYPE_REVEAL_AMOUNT) {
            uint32_t numCollateral = 0;
            for (int i = 0; i < vout.size(); i++) {
                if (vout[i].nValue == 1000000 * COIN) {
                    numCollateral++;
                }
            }
            if (numCollateral == 1) {
                return true;
            }
        }
        return false;
    }

    std::string ToString() const;

    bool GetCoinAge(uint64_t& nCoinAge) const;  // ppcoin: get transaction coin age
};

/** A mutable version of CTransaction. */
struct CMutableTransaction
{
    int32_t nVersion;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nLockTime;
    //For stealth transactions
    std::vector<unsigned char> txPub;
    char hasPaymentID;
    uint64_t paymentID;
    uint32_t txType;
    std::vector<unsigned char> masternodeStealthAddress;    //masternode stealth address for receiving rewards
    std::vector<unsigned char> bulletproofs;

    std::vector<CKeyImage> keyImages;   //have the same number element as vin
    std::vector<std::vector<CTxIn>> decoys;
    CAmount nTxFee;

    CMutableTransaction();
    CMutableTransaction(const CTransaction& tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
        READWRITE(txPub);
        READWRITE(hasPaymentID);
        if (hasPaymentID != 0) {
            READWRITE(paymentID);
        }
        READWRITE(txType);
        if (IsMNCollateralTx()) {
            READWRITE(masternodeStealthAddress);
        }

        READWRITE(bulletproofs);

        READWRITE(keyImages);
        READWRITE(decoys);
        READWRITE(nTxFee);
    }

    /** Compute the hash of this CMutableTransaction. This is computed on the
     * fly, as opposed to GetHash() in CTransaction, which uses a cached result.
     */
    uint256 GetHash() const;

    std::string ToString() const;

    friend bool operator==(const CMutableTransaction& a, const CMutableTransaction& b)
    {
        return a.GetHash() == b.GetHash();
    }

    friend bool operator!=(const CMutableTransaction& a, const CMutableTransaction& b)
    {
        return !(a == b);
    }

    bool IsMNCollateralTx() const {
        if (txType == TX_TYPE_REVEAL_AMOUNT) {
            uint32_t numCollateral = 0;
            for (int i = 0; i < vout.size(); i++) {
                if (vout[i].nValue == 1000000 * COIN) {
                    numCollateral++;
                }
            }
            if (numCollateral == 1) {
                return true;
            }
        }
        return false;
    }

};

#endif // BITCOIN_PRIMITIVES_TRANSACTION_H
