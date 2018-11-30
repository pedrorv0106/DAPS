// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The DAPScoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_H
#define BITCOIN_WALLET_H

#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/options_description.hpp>

#include "amount.h"
#include "base58.h"
#include "crypter.h"
#include "kernel.h"
#include "key.h"
#include "keystore.h"
#include "main.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "primitives/zerocoin.h"
#include "ui_interface.h"
#include "util.h"
#include "validationinterface.h"
#include "wallet_ismine.h"
#include "walletdb.h"
#include "privacy/common/password.h"
#include "privacy/device/device.hpp"
#include "privacy/cryptonote_config.h"
#include "privacy/cryptonote_basic/cryptonote_basic.h"
#include "privacy/cryptonote_core/cryptonote_tx_utils.h"
#include "privacy/epee/include/net/http_auth.h"
#include "privacy/epee/include/net/http_client.h"
#include "privacy/epee/include/storages/http_abstract_invoke.h"
#include "privacy/wallet/ringdb.h"
#include "privacy/wallet/node_rpc_proxy.h"
#include "privacy/common/notify.h"
#include "privacy/rpc/core_rpc_server_commands_defs.h"
#include "privacy/checkpoints/checkpoints.h"

#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

/**
 * Settings
 */
extern CFeeRate payTxFee;
extern CAmount maxTxFee;
extern unsigned int nTxConfirmTarget;
extern bool bSpendZeroConfChange;
extern bool bdisableSystemnotifications;
extern bool fSendFreeTransactions;
extern bool fPayAtLeastCustomFee;

//using namespace tools;

//! -paytxfee default
static const CAmount DEFAULT_TRANSACTION_FEE = 0;
//! -paytxfee will warn if called with a higher fee than this amount (in satoshis) per KB
static const CAmount nHighTransactionFeeWarning = 0.1 * COIN;
//! -maxtxfee default
static const CAmount DEFAULT_TRANSACTION_MAXFEE = 1 * COIN;
//! -maxtxfee will warn if called with a higher fee than this amount (in satoshis)
static const CAmount nHighTransactionMaxFeeWarning = 100 * nHighTransactionFeeWarning;
//! Largest (in bytes) free transaction we're willing to create
static const unsigned int MAX_FREE_TRANSACTION_CREATE_SIZE = 1000;

// Zerocoin denomination which creates exactly one of each denominations:
// 6666 = 1*5000 + 1*1000 + 1*500 + 1*100 + 1*50 + 1*10 + 1*5 + 1
static const int ZQ_6666 = 6666;

class CAccountingEntry;
class CCoinControl;
class COutput;
class CReserveKey;
class CScript;
class CWalletTx;
class Serialization_portability_wallet_Test;

/** (client) version numbers for particular wallet features */
enum WalletFeature {
    FEATURE_BASE = 10500, // the earliest version new wallets supports (only useful for getinfo's clientversion output)

    FEATURE_WALLETCRYPT = 40000, // wallet encryption
    FEATURE_COMPRPUBKEY = 60000, // compressed public keys

    FEATURE_LATEST = 61000
};

enum AvailableCoinsType {
    ALL_COINS = 1,
    ONLY_DENOMINATED = 2,
    ONLY_NOT10000IFMN = 3,
    ONLY_NONDENOMINATED_NOT10000IFMN = 4, // ONLY_NONDENOMINATED and not 10000 DAPS at the same time
    ONLY_10000 = 5,                        // find masternode outputs including locked ones (use with caution)
    STAKABLE_COINS = 6                          // UTXO's that are valid for staking
};

// Possible states for zDAPS send
enum ZerocoinSpendStatus {
    ZDAPS_SPEND_OKAY = 0,                            // No error
    ZDAPS_SPEND_ERROR = 1,                           // Unspecified class of errors, more details are (hopefully) in the returning text
    ZDAPS_WALLET_LOCKED = 2,                         // Wallet was locked
    ZDAPS_COMMIT_FAILED = 3,                         // Commit failed, reset status
    ZDAPS_ERASE_SPENDS_FAILED = 4,                   // Erasing spends during reset failed
    ZDAPS_ERASE_NEW_MINTS_FAILED = 5,                // Erasing new mints during reset failed
    ZDAPS_TRX_FUNDS_PROBLEMS = 6,                    // Everything related to available funds
    ZDAPS_TRX_CREATE = 7,                            // Everything related to create the transaction
    ZDAPS_TRX_CHANGE = 8,                            // Everything related to transaction change
    ZDAPS_TXMINT_GENERAL = 9,                        // General errors in MintToTxIn
    ZDAPS_INVALID_COIN = 10,                         // Selected mint coin is not valid
    ZDAPS_FAILED_ACCUMULATOR_INITIALIZATION = 11,    // Failed to initialize witness
    ZDAPS_INVALID_WITNESS = 12,                      // Spend coin transaction did not verify
    ZDAPS_BAD_SERIALIZATION = 13,                    // Transaction verification failed
    ZDAPS_SPENT_USED_ZDAPS = 14,                      // Coin has already been spend
    ZDAPS_TX_TOO_LARGE = 15                          // The transaction is larger than the max tx size
};

struct CompactTallyItem {
    CBitcoinAddress address;
    CAmount nAmount;
    std::vector<CTxIn> vecTxIn;
    CompactTallyItem()
    {
        nAmount = 0;
    }
};

/** A key pool entry */
class CKeyPool
{
public:
    int64_t nTime;
    CPubKey vchPubKey;

    CKeyPool();
    CKeyPool(const CPubKey& vchPubKeyIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(nTime);
        READWRITE(vchPubKey);
    }
};

/** Address book data */
class CAddressBookData
{
public:
    std::string name;
    std::string purpose;

    CAddressBookData()
    {
        purpose = "unknown";
    }

    typedef std::map<std::string, std::string> StringMap;
    StringMap destdata;
};

class i_wallet2_callback
{
public:
    // Full wallet callbacks
    virtual void on_new_block(uint64_t height, const cryptonote::block& block) {}
    virtual void on_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index) {}
    virtual void on_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index) {}
    virtual void on_money_spent(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& in_tx, uint64_t amount, const cryptonote::transaction& spend_tx, const cryptonote::subaddress_index& subaddr_index) {}
    virtual void on_skip_transaction(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx) {}
    virtual boost::optional<epee::wipeable_string> on_get_password(const char *reason) { return boost::none; }
    // Light wallet callbacks
    virtual void on_lw_new_block(uint64_t height) {}
    virtual void on_lw_money_received(uint64_t height, const crypto::hash &txid, uint64_t amount) {}
    virtual void on_lw_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, uint64_t amount) {}
    virtual void on_lw_money_spent(uint64_t height, const crypto::hash &txid, uint64_t amount) {}
    // Common callbacks
    virtual void on_pool_tx_removed(const crypto::hash &txid) {}
    virtual ~i_wallet2_callback() {}
};

struct tx_dust_policy
{
    uint64_t dust_threshold;
    bool add_to_fee;
    cryptonote::account_public_address addr_for_dust;

    tx_dust_policy(uint64_t a_dust_threshold = 0, bool an_add_to_fee = true, cryptonote::account_public_address an_addr_for_dust = cryptonote::account_public_address())
            : dust_threshold(a_dust_threshold)
            , add_to_fee(an_add_to_fee)
            , addr_for_dust(an_addr_for_dust)
    {
    }
};

class hashchain
{
public:
    hashchain(): m_genesis(crypto::null_hash), m_offset(0) {}

    size_t size() const { return m_blockchain.size() + m_offset; }
    size_t offset() const { return m_offset; }
    const crypto::hash &genesis() const { return m_genesis; }
    void push_back(const crypto::hash &hash) { if (m_offset == 0 && m_blockchain.empty()) m_genesis = hash; m_blockchain.push_back(hash); }
    bool is_in_bounds(size_t idx) const { return idx >= m_offset && idx < size(); }
    const crypto::hash &operator[](size_t idx) const { return m_blockchain[idx - m_offset]; }
    crypto::hash &operator[](size_t idx) { return m_blockchain[idx - m_offset]; }
    void crop(size_t height) { m_blockchain.resize(height - m_offset); }
    void clear() { m_offset = 0; m_blockchain.clear(); }
    bool empty() const { return m_blockchain.empty() && m_offset == 0; }
    void trim(size_t height) { while (height > m_offset && m_blockchain.size() > 1) { m_blockchain.pop_front(); ++m_offset; } m_blockchain.shrink_to_fit(); }
    void refill(const crypto::hash &hash) { m_blockchain.push_back(hash); --m_offset; }

    template <class t_archive>
    inline void serialize(t_archive &a, const unsigned int ver)
    {
        a & m_offset;
        a & m_genesis;
        a & m_blockchain;
    }

private:
    size_t m_offset;
    crypto::hash m_genesis;
    std::deque<crypto::hash> m_blockchain;
};

/**
 * A CWallet is an extension of a keystore, which also maintains a set of transactions and balances,
 * and provides the ability to create new transactions.
 */
class CWallet : public CCryptoKeyStore, public CValidationInterface
{
private:
    bool SelectCoins(const CAmount& nTargetValue, std::set<std::pair<const CWalletTx*, unsigned int> >& setCoinsRet, CAmount& nValueRet, const CCoinControl* coinControl = NULL, AvailableCoinsType coin_type = ALL_COINS, bool useIX = true) const;
    //it was public bool SelectCoins(int64_t nTargetValue, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet, const CCoinControl *coinControl = NULL, AvailableCoinsType coin_type=ALL_COINS, bool useIX = true) const;

    CWalletDB* pwalletdbEncryption;

    //! the current wallet version: clients below this version are not able to load the wallet
    int nWalletVersion;

    //! the maximum wallet format version: memory-only variable that specifies to what version this wallet may be upgraded
    int nWalletMaxVersion;

    int64_t nNextResend;
    int64_t nLastResend;

    /**
     * Used to keep track of spent outpoints, and
     * detect and report conflicts (double-spends or
     * mutated transactions where the mutant gets mined).
     */
    typedef std::multimap<COutPoint, uint256> TxSpends;
    TxSpends mapTxSpends;
    void AddToSpends(const COutPoint& outpoint, const uint256& wtxid);
    void AddToSpends(const uint256& wtxid);

    void SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator>);

public:
    //Need to initialize this property
    boost::program_options::variables_map vm;

    bool MintableCoins();
    bool SelectStakeCoins(std::set<std::pair<const CWalletTx*, unsigned int> >& setCoins, CAmount nTargetAmount) const;
    bool SelectCoinsDark(CAmount nValueMin, CAmount nValueMax, std::vector<CTxIn>& setCoinsRet, CAmount& nValueRet, int nObfuscationRoundsMin, int nObfuscationRoundsMax) const;
    bool SelectCoinsByDenominations(int nDenom, CAmount nValueMin, CAmount nValueMax, std::vector<CTxIn>& vCoinsRet, std::vector<COutput>& vCoinsRet2, CAmount& nValueRet, int nObfuscationRoundsMin, int nObfuscationRoundsMax);
    bool SelectCoinsDarkDenominated(CAmount nTargetValue, std::vector<CTxIn>& setCoinsRet, CAmount& nValueRet) const;
    bool HasCollateralInputs(bool fOnlyConfirmed = true) const;
    bool IsCollateralAmount(CAmount nInputAmount) const;
    int CountInputsWithAmount(CAmount nInputAmount);

    bool SelectCoinsCollateral(std::vector<CTxIn>& setCoinsRet, CAmount& nValueRet) const;

    // Zerocoin additions
    bool CreateZerocoinMintTransaction(const CAmount nValue, CMutableTransaction& txNew, vector<CZerocoinMint>& vMints, CReserveKey* reservekey, int64_t& nFeeRet, std::string& strFailReason, const CCoinControl* coinControl = NULL, const bool isZCSpendChange = false);
    bool CreateZerocoinSpendTransaction(CAmount nValue, int nSecurityLevel, CWalletTx& wtxNew, CReserveKey& reserveKey, CZerocoinSpendReceipt& receipt, vector<CZerocoinMint>& vSelectedMints, vector<CZerocoinMint>& vNewMints, bool fMintChange,  bool fMinimizeChange, CBitcoinAddress* address = NULL);
    bool MintToTxIn(CZerocoinMint zerocoinSelected, int nSecurityLevel, const uint256& hashTxOut, CTxIn& newTxIn, CZerocoinSpendReceipt& receipt);
    std::string MintZerocoin(CAmount nValue, CWalletTx& wtxNew, vector<CZerocoinMint>& vMints, const CCoinControl* coinControl = NULL);
    bool SpendZerocoin(CAmount nValue, int nSecurityLevel, CWalletTx& wtxNew, CZerocoinSpendReceipt& receipt, vector<CZerocoinMint>& vMintsSelected, bool fMintChange, bool fMinimizeChange, CBitcoinAddress* addressTo = NULL);
    std::string ResetMintZerocoin(bool fExtendedSearch);
    std::string ResetSpentZerocoin();
    void ReconsiderZerocoins(std::list<CZerocoinMint>& listMintsRestored);
    void ZDapsBackupWallet();

    /** Zerocin entry changed.
    * @note called with lock cs_wallet held.
    */
    boost::signals2::signal<void(CWallet* wallet, const std::string& pubCoin, const std::string& isUsed, ChangeType status)> NotifyZerocoinChanged;
    /*
     * Main wallet lock.
     * This lock protects all the fields added by CWallet
     *   except for:
     *      fFileBacked (immutable after instantiation)
     *      strWalletFile (immutable after instantiation)
     */
    mutable CCriticalSection cs_wallet;

    bool fFileBacked;
    bool fWalletUnlockAnonymizeOnly;
    std::string strWalletFile;
    bool fBackupMints;

    std::set<int64_t> setKeyPool;
    std::map<CKeyID, CKeyMetadata> mapKeyMetadata;

    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys;
    unsigned int nMasterKeyMaxID;

    // Stake Settings
    unsigned int nHashDrift;
    unsigned int nHashInterval;
    uint64_t nStakeSplitThreshold;
    int nStakeSetUpdateTime;

    //MultiSend
    std::vector<std::pair<std::string, int> > vMultiSend;
    bool fMultiSendStake;
    bool fMultiSendMasternodeReward;
    bool fMultiSendNotify;
    std::string strMultiSendChangeAddress;
    int nLastMultiSendHeight;
    std::vector<std::string> vDisabledAddresses;

    //Auto Combine Inputs
    bool fCombineDust;
    CAmount nAutoCombineThreshold;

    CWallet(std::string strWalletFileIn): m_node_rpc_proxy(m_http_client, m_daemon_rpc_mutex)
    {
        SetNull();

        strWalletFile = strWalletFileIn;
        fFileBacked = true;
    }

    ~CWallet()
    {
        delete pwalletdbEncryption;
    }

    void SetNull()
    {
        nWalletVersion = FEATURE_BASE;
        nWalletMaxVersion = FEATURE_BASE;
        fFileBacked = false;
        nMasterKeyMaxID = 0;
        pwalletdbEncryption = NULL;
        nOrderPosNext = 0;
        nNextResend = 0;
        nLastResend = 0;
        nTimeFirstKey = 0;
        fWalletUnlockAnonymizeOnly = false;
        fBackupMints = false;

        // Stake Settings
        nHashDrift = 45;
        nStakeSplitThreshold = 2000;
        nHashInterval = 22;
        nStakeSetUpdateTime = 300; // 5 minutes

        //MultiSend
        vMultiSend.clear();
        fMultiSendStake = false;
        fMultiSendMasternodeReward = false;
        fMultiSendNotify = false;
        strMultiSendChangeAddress = "";
        nLastMultiSendHeight = 0;
        vDisabledAddresses.clear();

        //Auto Combine Dust
        fCombineDust = false;
        nAutoCombineThreshold = 0;
    }

    bool isZeromintEnabled()
    {
        return fEnableZeromint;
    }

    void setZDapsAutoBackups(bool fEnabled)
    {
        fBackupMints = fEnabled;
    }
    
    bool isMultiSendEnabled()
    {
        return fMultiSendMasternodeReward || fMultiSendStake;
    }

    void setMultiSendDisabled()
    {
        fMultiSendMasternodeReward = false;
        fMultiSendStake = false;
    }

    std::map<uint256, CWalletTx> mapWallet;

    int64_t nOrderPosNext;
    std::map<uint256, int> mapRequestCount;

    std::map<CTxDestination, CAddressBookData> mapAddressBook;

    CPubKey vchDefaultKey;

    std::set<COutPoint> setLockedCoins;

    int64_t nTimeFirstKey;

    const CWalletTx* GetWalletTx(const uint256& hash) const;

    //! check whether we are allowed to upgrade (or already support) to the named feature
    bool CanSupportFeature(enum WalletFeature wf)
    {
        AssertLockHeld(cs_wallet);
        return nWalletMaxVersion >= wf;
    }

    void AvailableCoins(std::vector<COutput>& vCoins, bool fOnlyConfirmed = true, const CCoinControl* coinControl = NULL, bool fIncludeZeroValue = false, AvailableCoinsType nCoinType = ALL_COINS, bool fUseIX = false) const;
    std::map<CBitcoinAddress, std::vector<COutput> > AvailableCoinsByAddress(bool fConfirmed = true, CAmount maxCoinValue = 0);
    bool SelectCoinsMinConf(const CAmount& nTargetValue, int nConfMine, int nConfTheirs, std::vector<COutput> vCoins, std::set<std::pair<const CWalletTx*, unsigned int> >& setCoinsRet, CAmount& nValueRet) const;

    /// Get 1000DASH output and keys which can be used for the Masternode
    bool GetMasternodeVinAndKeys(CTxIn& txinRet, CPubKey& pubKeyRet, CKey& keyRet, std::string strTxHash = "", std::string strOutputIndex = "");
    /// Extract txin information and keys from output
    bool GetVinAndKeysFromOutput(COutput out, CTxIn& txinRet, CPubKey& pubKeyRet, CKey& keyRet);

    bool IsSpent(const uint256& hash, unsigned int n) const;

    bool IsLockedCoin(uint256 hash, unsigned int n) const;
    void LockCoin(COutPoint& output);
    void UnlockCoin(COutPoint& output);
    void UnlockAllCoins();
    void ListLockedCoins(std::vector<COutPoint>& vOutpts);
    CAmount GetTotalValue(std::vector<CTxIn> vCoins);

    //  keystore implementation
    // Generate a new key
    CPubKey GenerateNewKey();

    //! Adds a key to the store, and saves it to disk.
    bool AddKeyPubKey(const CKey& key, const CPubKey& pubkey);
    //! Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey& key, const CPubKey& pubkey) { return CCryptoKeyStore::AddKeyPubKey(key, pubkey); }
    //! Load metadata (used by LoadWallet)
    bool LoadKeyMetadata(const CPubKey& pubkey, const CKeyMetadata& metadata);

    bool LoadMinVersion(int nVersion)
    {
        AssertLockHeld(cs_wallet);
        nWalletVersion = nVersion;
        nWalletMaxVersion = std::max(nWalletMaxVersion, nVersion);
        return true;
    }

    //! Adds an encrypted key to the store, and saves it to disk.
    bool AddCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret);
    //! Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret);
    bool AddCScript(const CScript& redeemScript);
    bool LoadCScript(const CScript& redeemScript);

    //! Adds a destination data tuple to the store, and saves it to disk
    bool AddDestData(const CTxDestination& dest, const std::string& key, const std::string& value);
    //! Erases a destination data tuple in the store and on disk
    bool EraseDestData(const CTxDestination& dest, const std::string& key);
    //! Adds a destination data tuple to the store, without saving it to disk
    bool LoadDestData(const CTxDestination& dest, const std::string& key, const std::string& value);
    //! Look up a destination data tuple in the store, return true if found false otherwise
    bool GetDestData(const CTxDestination& dest, const std::string& key, std::string* value) const;

    //! Adds a watch-only address to the store, and saves it to disk.
    bool AddWatchOnly(const CScript& dest);
    bool RemoveWatchOnly(const CScript& dest);
    //! Adds a watch-only address to the store, without saving it to disk (used by LoadWallet)
    bool LoadWatchOnly(const CScript& dest);

    //! Adds a MultiSig address to the store, and saves it to disk.
    bool AddMultiSig(const CScript& dest);
    bool RemoveMultiSig(const CScript& dest);
    //! Adds a MultiSig address to the store, without saving it to disk (used by LoadWallet)
    bool LoadMultiSig(const CScript& dest);

    bool Unlock(const SecureString& strWalletPassphrase, bool anonimizeOnly = false);
    bool ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase);
    bool EncryptWallet(const SecureString& strWalletPassphrase);

    void GetKeyBirthTimes(std::map<CKeyID, int64_t>& mapKeyBirth) const;

    /**
     * Increment the next transaction order id
     * @return next transaction order id
     */
    int64_t IncOrderPosNext(CWalletDB* pwalletdb = NULL);

    typedef std::pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef std::multimap<int64_t, TxPair> TxItems;

    /**
     * Get the wallet's activity log
     * @return multimap of ordered transactions and accounting entries
     * @warning Returned pointers are *only* valid within the scope of passed acentries
     */
    TxItems OrderedTxItems(std::list<CAccountingEntry>& acentries, std::string strAccount = "");

    void MarkDirty();
    bool AddToWallet(const CWalletTx& wtxIn, bool fFromLoadWallet = false);
    void SyncTransaction(const CTransaction& tx, const CBlock* pblock);
    bool AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate);
    void EraseFromWallet(const uint256& hash);
    int ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate = false);
    void ReacceptWalletTransactions();
    void ResendWalletTransactions();
    CAmount GetBalance() const;
    CAmount GetZerocoinBalance(bool fMatureOnly) const;
    CAmount GetUnconfirmedZerocoinBalance() const;
    CAmount GetImmatureZerocoinBalance() const;
    CAmount GetLockedCoins() const;
    CAmount GetUnlockedCoins() const;
    std::map<libzerocoin::CoinDenomination, CAmount> GetMyZerocoinDistribution() const;
    CAmount GetUnconfirmedBalance() const;
    CAmount GetImmatureBalance() const;
    CAmount GetAnonymizableBalance() const;
    CAmount GetAnonymizedBalance() const;
    double GetAverageAnonymizedRounds() const;
    CAmount GetNormalizedAnonymizedBalance() const;
    CAmount GetDenominatedBalance(bool unconfirmed = false) const;
    CAmount GetWatchOnlyBalance() const;
    CAmount GetUnconfirmedWatchOnlyBalance() const;
    CAmount GetImmatureWatchOnlyBalance() const;
    bool CreateTransaction(CScript scriptPubKey, int64_t nValue, CWalletTx& wtxNew, CReserveKey& reservekey, int64_t& nFeeRet, std::string& strFailReason, const CCoinControl* coinControl);
    bool CreateTransaction(const std::vector<std::pair<CScript, CAmount> >& vecSend,
        CWalletTx& wtxNew,
        CReserveKey& reservekey,
        CAmount& nFeeRet,
        std::string& strFailReason,
        const CCoinControl* coinControl = NULL,
        AvailableCoinsType coin_type = ALL_COINS,
        bool useIX = false,
        CAmount nFeePay = 0);
    bool CreateTransaction(CScript scriptPubKey, const CAmount& nValue, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet, std::string& strFailReason, const CCoinControl* coinControl = NULL, AvailableCoinsType coin_type = ALL_COINS, bool useIX = false, CAmount nFeePay = 0);
    bool CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey, std::string strCommand = "tx");
    std::string PrepareObfuscationDenominate(int minRounds, int maxRounds);
    int GenerateObfuscationOutputs(int nTotalValue, std::vector<CTxOut>& vout);
    bool CreateCollateralTransaction(CMutableTransaction& txCollateral, std::string& strReason);
    bool ConvertList(std::vector<CTxIn> vCoins, std::vector<int64_t>& vecAmounts);
    bool CreateCoinStake(const CKeyStore& keystore, unsigned int nBits, int64_t nSearchInterval, CMutableTransaction& txNew, unsigned int& nTxNewTime);
    bool CreateCoinAudit(const CKeyStore& keystore, unsigned int nBits, int64_t nSearchInterval, CMutableTransaction& txNew, unsigned int& nTxNewTime);
    bool MultiSend();
    void AutoCombineDust();
    void AutoZeromint();

    static CFeeRate minTxFee;
    static CAmount GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool& pool);

    bool NewKeyPool();
    bool TopUpKeyPool(unsigned int kpSize = 0);
    void ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool);
    void KeepKey(int64_t nIndex);
    void ReturnKey(int64_t nIndex);
    bool GetKeyFromPool(CPubKey& key);
    int64_t GetOldestKeyPoolTime();
    void GetAllReserveKeys(std::set<CKeyID>& setAddress) const;

    std::set<std::set<CTxDestination> > GetAddressGroupings();
    std::map<CTxDestination, CAmount> GetAddressBalances();

    std::set<CTxDestination> GetAccountAddresses(std::string strAccount) const;

    bool GetBudgetSystemCollateralTX(CTransaction& tx, uint256 hash, bool useIX);
    bool GetBudgetSystemCollateralTX(CWalletTx& tx, uint256 hash, bool useIX);

    // get the Obfuscation chain depth for a given input
    int GetRealInputObfuscationRounds(CTxIn in, int rounds) const;
    // respect current settings
    int GetInputObfuscationRounds(CTxIn in) const;

    bool IsDenominated(const CTxIn& txin) const;
    bool IsDenominated(const CTransaction& tx) const;

    bool IsDenominatedAmount(CAmount nInputAmount) const;

    isminetype IsMine(const CTxIn& txin) const;
    CAmount GetDebit(const CTxIn& txin, const isminefilter& filter) const;
    isminetype IsMine(const CTxOut& txout) const
    {
        return ::IsMine(*this, txout.scriptPubKey);
    }
    bool IsMyZerocoinSpend(const CBigNum& bnSerial) const;
    CAmount GetCredit(const CTxOut& txout, const isminefilter& filter) const
    {
        if (!MoneyRange(txout.nValue))
            throw std::runtime_error("CWallet::GetCredit() : value out of range");
        return ((IsMine(txout) & filter) ? txout.nValue : 0);
    }
    bool IsChange(const CTxOut& txout) const;
    CAmount GetChange(const CTxOut& txout) const
    {
        if (!MoneyRange(txout.nValue))
            throw std::runtime_error("CWallet::GetChange() : value out of range");
        return (IsChange(txout) ? txout.nValue : 0);
    }
    bool IsMine(const CTransaction& tx) const
    {
        BOOST_FOREACH (const CTxOut& txout, tx.vout)
            if (IsMine(txout))
                return true;
        return false;
    }
    /** should probably be renamed to IsRelevantToMe */
    bool IsFromMe(const CTransaction& tx) const
    {
        return (GetDebit(tx, ISMINE_ALL) > 0);
    }
    CAmount GetDebit(const CTransaction& tx, const isminefilter& filter) const
    {
        CAmount nDebit = 0;
        BOOST_FOREACH (const CTxIn& txin, tx.vin) {
            nDebit += GetDebit(txin, filter);
            if (!MoneyRange(nDebit))
                throw std::runtime_error("CWallet::GetDebit() : value out of range");
        }
        return nDebit;
    }
    CAmount GetCredit(const CTransaction& tx, const isminefilter& filter) const
    {
        CAmount nCredit = 0;
        BOOST_FOREACH (const CTxOut& txout, tx.vout) {
            nCredit += GetCredit(txout, filter);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWallet::GetCredit() : value out of range");
        }
        return nCredit;
    }
    CAmount GetChange(const CTransaction& tx) const
    {
        CAmount nChange = 0;
        BOOST_FOREACH (const CTxOut& txout, tx.vout) {
            nChange += GetChange(txout);
            if (!MoneyRange(nChange))
                throw std::runtime_error("CWallet::GetChange() : value out of range");
        }
        return nChange;
    }
    void SetBestChain(const CBlockLocator& loc);

    DBErrors LoadWallet(bool& fFirstRunRet);
    DBErrors ZapWalletTx(std::vector<CWalletTx>& vWtx);

    bool SetAddressBook(const CTxDestination& address, const std::string& strName, const std::string& purpose);

    bool DelAddressBook(const CTxDestination& address);

    bool UpdatedTransaction(const uint256& hashTx);

    void Inventory(const uint256& hash)
    {
        {
            LOCK(cs_wallet);
            std::map<uint256, int>::iterator mi = mapRequestCount.find(hash);
            if (mi != mapRequestCount.end())
                (*mi).second++;
        }
    }

    unsigned int GetKeyPoolSize()
    {
        AssertLockHeld(cs_wallet); // setKeyPool
        return setKeyPool.size();
    }

    bool SetDefaultKey(const CPubKey& vchPubKey);

    //! signify that a particular wallet feature is now used. this may change nWalletVersion and nWalletMaxVersion if those are lower
    bool SetMinVersion(enum WalletFeature, CWalletDB* pwalletdbIn = NULL, bool fExplicit = false);

    //! change which version we're allowed to upgrade to (note that this does not immediately imply upgrading to that format)
    bool SetMaxVersion(int nVersion);

    //! get the current wallet format (the oldest client version guaranteed to understand this wallet)
    int GetVersion()
    {
        LOCK(cs_wallet);
        return nWalletVersion;
    }

    //! Get wallet transactions that conflict with given transaction (spend same outputs)
    std::set<uint256> GetConflicts(const uint256& txid) const;

    /**
     * Address book entry changed.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void(CWallet* wallet, const CTxDestination& address, const std::string& label, bool isMine, const std::string& purpose, ChangeType status)> NotifyAddressBookChanged;

    /**
     * Wallet transaction added, removed or updated.
     * @note called with lock cs_wallet held.
     */
    boost::signals2::signal<void(CWallet* wallet, const uint256& hashTx, ChangeType status)> NotifyTransactionChanged;

    /** Show progress e.g. for rescan */
    boost::signals2::signal<void(const std::string& title, int nProgress)> ShowProgress;

    /** Watch-only address added */
    boost::signals2::signal<void(bool fHaveWatchOnly)> NotifyWatchonlyChanged;

    /** MultiSig address added */
    boost::signals2::signal<void(bool fHaveMultiSig)> NotifyMultiSigChanged;


    //All these methods are copied from monero wallet2 and refactored
    friend class ::Serialization_portability_wallet_Test;
    friend class wallet_keys_unlocker;
public:
    static constexpr const std::chrono::seconds rpc_timeout = std::chrono::minutes(3) + std::chrono::seconds(30);

    enum RefreshType {
        RefreshFull,
        RefreshOptimizeCoinbase,
        RefreshNoCoinbase,
        RefreshDefault = RefreshOptimizeCoinbase,
    };

    enum AskPasswordType {
        AskPasswordNever = 0,
        AskPasswordOnAction = 1,
        AskPasswordToDecrypt = 2,
    };

    static const char* tr(const char* str);

    static bool has_testnet_option(const boost::program_options::variables_map& vm);
    static bool has_stagenet_option(const boost::program_options::variables_map& vm);
    static std::string device_name_option(const boost::program_options::variables_map& vm);
    static void init_options(boost::program_options::options_description& desc_params);

    //! Uses stdin and stdout. Returns a wallet2 if no errors.
    //static std::pair<std::unique_ptr<wallet2>, tools::password_container> make_from_json(const boost::program_options::variables_map& vm, bool unattended, const std::string& json_file, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter);

    //! Uses stdin and stdout. Returns a wallet2 and password for `wallet_file` if no errors.
    //static std::pair<std::unique_ptr<wallet2>, tools::password_container>
    //make_from_file(const boost::program_options::variables_map& vm, bool unattended, const std::string& wallet_file, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter);

    //! Uses stdin and stdout. Returns a wallet2 and password for wallet with no file if no errors.
    static std::pair<std::unique_ptr<CWallet>, tools::password_container> make_new(const boost::program_options::variables_map& vm, bool unattended, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter);

    //! Just parses variables.
    static std::unique_ptr<CWallet> make_dummy(const boost::program_options::variables_map& vm, bool unattended, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter);

    static bool verify_password(const std::string& keys_file_name, const epee::wipeable_string& password, bool no_spend_key, hw::device &hwdev, uint64_t kdf_rounds);
    static bool query_device(hw::device::device_type& device_type, const std::string& keys_file_name, const epee::wipeable_string& password, uint64_t kdf_rounds = 1);

    CWallet(cryptonote::network_type nettype = cryptonote::MAINNET, uint64_t kdf_rounds = 1, bool unattended = false);
    //~CWallet();

    /*struct multisig_info
    {
        struct LR
        {
            rct::key m_L;
            rct::key m_R;

            BEGIN_SERIALIZE_OBJECT()
                FIELD(m_L)
                FIELD(m_R)
            END_SERIALIZE()
        };

        crypto::public_key m_signer;
        std::vector<LR> m_LR;
        std::vector<crypto::key_image> m_partial_key_images; // one per key the participant has

        BEGIN_SERIALIZE_OBJECT()
            FIELD(m_signer)
            FIELD(m_LR)
            FIELD(m_partial_key_images)
        END_SERIALIZE()
    };*/

    struct tx_scan_info_t
    {
        cryptonote::keypair in_ephemeral;
        crypto::key_image ki;
        rct::key mask;
        uint64_t amount;
        uint64_t money_transfered;
        bool error;
        boost::optional<cryptonote::subaddress_receive_info> received;

        tx_scan_info_t(): money_transfered(0), error(true) {}
    };

    struct transfer_details
    {
        uint64_t m_block_height;
        cryptonote::transaction_prefix m_tx;
        crypto::hash m_txid;
        size_t m_internal_output_index;
        uint64_t m_global_output_index;
        bool m_spent;
        uint64_t m_spent_height;
        crypto::key_image m_key_image; //TODO: key_image stored twice :(
        rct::key m_mask;
        uint64_t m_amount;
        bool m_rct;
        bool m_key_image_known;
        size_t m_pk_index;
        cryptonote::subaddress_index m_subaddr_index;
        bool m_key_image_partial;
        //std::vector<rct::key> m_multisig_k;
        //std::vector<multisig_info> m_multisig_info; // one per other participant

        bool is_rct() const { return m_rct; }
        uint64_t amount() const { return m_amount; }
        const crypto::public_key &get_public_key() const { return boost::get<const cryptonote::txout_to_key>(m_tx.vout[m_internal_output_index].target).key; }

        BEGIN_SERIALIZE_OBJECT()
            FIELD(m_block_height)
            FIELD(m_tx)
            FIELD(m_txid)
            FIELD(m_internal_output_index)
            FIELD(m_global_output_index)
            FIELD(m_spent)
            FIELD(m_spent_height)
            FIELD(m_key_image)
            FIELD(m_mask)
            FIELD(m_amount)
            FIELD(m_rct)
            FIELD(m_key_image_known)
            FIELD(m_pk_index)
            FIELD(m_subaddr_index)
            FIELD(m_key_image_partial)
            //FIELD(m_multisig_k)
            //FIELD(m_multisig_info)
        END_SERIALIZE()
    };

    struct payment_details
    {
        crypto::hash m_tx_hash;
        uint64_t m_amount;
        uint64_t m_fee;
        uint64_t m_block_height;
        uint64_t m_unlock_time;
        uint64_t m_timestamp;
        bool m_coinbase;
        cryptonote::subaddress_index m_subaddr_index;
    };

    struct address_tx : payment_details
    {
        bool m_mempool;
        bool m_incoming;
    };

    struct pool_payment_details
    {
        payment_details m_pd;
        bool m_double_spend_seen;
    };

    struct unconfirmed_transfer_details
    {
        cryptonote::transaction_prefix m_tx;
        uint64_t m_amount_in;
        uint64_t m_amount_out;
        uint64_t m_change;
        time_t m_sent_time;
        std::vector<cryptonote::tx_destination_entry> m_dests;
        crypto::hash m_payment_id;
        enum { pending, pending_not_in_pool, failed } m_state;
        uint64_t m_timestamp;
        uint32_t m_subaddr_account;   // subaddress account of your wallet to be used in this transfer
        std::set<uint32_t> m_subaddr_indices;  // set of address indices used as inputs in this transfer
        std::vector<std::pair<crypto::key_image, std::vector<uint64_t>>> m_rings; // relative
    };

    struct confirmed_transfer_details
    {
        uint64_t m_amount_in;
        uint64_t m_amount_out;
        uint64_t m_change;
        uint64_t m_block_height;
        std::vector<cryptonote::tx_destination_entry> m_dests;
        crypto::hash m_payment_id;
        uint64_t m_timestamp;
        uint64_t m_unlock_time;
        uint32_t m_subaddr_account;   // subaddress account of your wallet to be used in this transfer
        std::set<uint32_t> m_subaddr_indices;  // set of address indices used as inputs in this transfer
        std::vector<std::pair<crypto::key_image, std::vector<uint64_t>>> m_rings; // relative

        confirmed_transfer_details(): m_amount_in(0), m_amount_out(0), m_change((uint64_t)-1), m_block_height(0), m_payment_id(crypto::null_hash), m_timestamp(0), m_unlock_time(0), m_subaddr_account((uint32_t)-1) {}
        confirmed_transfer_details(const unconfirmed_transfer_details &utd, uint64_t height):
                m_amount_in(utd.m_amount_in), m_amount_out(utd.m_amount_out), m_change(utd.m_change), m_block_height(height), m_dests(utd.m_dests), m_payment_id(utd.m_payment_id), m_timestamp(utd.m_timestamp), m_unlock_time(utd.m_tx.unlock_time), m_subaddr_account(utd.m_subaddr_account), m_subaddr_indices(utd.m_subaddr_indices), m_rings(utd.m_rings) {}
    };

    struct tx_construction_data
    {
        std::vector<cryptonote::tx_source_entry> sources;
        cryptonote::tx_destination_entry change_dts;
        std::vector<cryptonote::tx_destination_entry> splitted_dsts; // split, includes change
        std::vector<size_t> selected_transfers;
        std::vector<uint8_t> extra;
        uint64_t unlock_time;
        bool use_rct;
        bool use_bulletproofs;
        std::vector<cryptonote::tx_destination_entry> dests; // original setup, does not include change
        uint32_t subaddr_account;   // subaddress account of your wallet to be used in this transfer
        std::set<uint32_t> subaddr_indices;  // set of address indices used as inputs in this transfer

        BEGIN_SERIALIZE_OBJECT()
            FIELD(sources)
            FIELD(change_dts)
            FIELD(splitted_dsts)
            FIELD(selected_transfers)
            FIELD(extra)
            FIELD(unlock_time)
            FIELD(use_rct)
            FIELD(use_bulletproofs)
            FIELD(dests)
            FIELD(subaddr_account)
            FIELD(subaddr_indices)
        END_SERIALIZE()
    };

    typedef std::vector<transfer_details> transfer_container;
    typedef std::unordered_multimap<crypto::hash, payment_details> payment_container;

    struct multisig_sig
    {
        rct::rctSig sigs;
        crypto::public_key ignore;
        std::unordered_set<rct::key> used_L;
        std::unordered_set<crypto::public_key> signing_keys;
        rct::multisig_out msout;
    };

    // The convention for destinations is:
    // dests does not include change
    // splitted_dsts (in construction_data) does
    struct pending_tx
    {
        cryptonote::transaction tx;
        uint64_t dust, fee;
        bool dust_added_to_fee;
        cryptonote::tx_destination_entry change_dts;
        std::vector<size_t> selected_transfers;
        std::string key_images;
        crypto::secret_key tx_key;
        std::vector<crypto::secret_key> additional_tx_keys;
        std::vector<cryptonote::tx_destination_entry> dests;
        std::vector<multisig_sig> multisig_sigs;

        tx_construction_data construction_data;

        BEGIN_SERIALIZE_OBJECT()
            FIELD(tx)
            FIELD(dust)
            FIELD(fee)
            FIELD(dust_added_to_fee)
            FIELD(change_dts)
            FIELD(selected_transfers)
            FIELD(key_images)
            FIELD(tx_key)
            FIELD(additional_tx_keys)
            FIELD(dests)
            FIELD(construction_data)
            FIELD(multisig_sigs)
        END_SERIALIZE()
    };

    // The term "Unsigned tx" is not really a tx since it's not signed yet.
    // It doesnt have tx hash, key and the integrated address is not separated into addr + payment id.
    struct unsigned_tx_set
    {
        std::vector<tx_construction_data> txes;
        transfer_container transfers;
    };

    struct signed_tx_set
    {
        std::vector<pending_tx> ptx;
        std::vector<crypto::key_image> key_images;
    };

    struct multisig_tx_set
    {
        std::vector<pending_tx> m_ptx;
        std::unordered_set<crypto::public_key> m_signers;

        BEGIN_SERIALIZE_OBJECT()
            FIELD(m_ptx)
            FIELD(m_signers)
        END_SERIALIZE()
    };

    struct keys_file_data
    {
        crypto::chacha_iv iv;
        std::string account_data;

        BEGIN_SERIALIZE_OBJECT()
            FIELD(iv)
            FIELD(account_data)
        END_SERIALIZE()
    };

    struct cache_file_data
    {
        crypto::chacha_iv iv;
        std::string cache_data;

        BEGIN_SERIALIZE_OBJECT()
            FIELD(iv)
            FIELD(cache_data)
        END_SERIALIZE()
    };

    // GUI Address book
    struct address_book_row
    {
        cryptonote::account_public_address m_address;
        crypto::hash m_payment_id;
        std::string m_description;
        bool m_is_subaddress;
    };

    struct reserve_proof_entry
    {
        crypto::hash txid;
        uint64_t index_in_tx;
        crypto::public_key shared_secret;
        crypto::key_image key_image;
        crypto::signature shared_secret_sig;
        crypto::signature key_image_sig;
    };

    typedef std::tuple<uint64_t, crypto::public_key, rct::key> get_outs_entry;

    struct parsed_block
    {
        crypto::hash hash;
        cryptonote::block block;
        std::vector<cryptonote::transaction> txes;
        cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices o_indices;
        bool error;
    };

    struct is_out_data
    {
        crypto::public_key pkey;
        crypto::key_derivation derivation;
        std::vector<boost::optional<cryptonote::subaddress_receive_info>> received;
    };

    struct tx_cache_data
    {
        std::vector<cryptonote::tx_extra_field> tx_extra_fields;
        std::vector<is_out_data> primary;
        std::vector<is_out_data> additional;
    };

    /*!
     * \brief  Generates a wallet or restores one.
     * \param  wallet_              Name of wallet file
     * \param  password             Password of wallet file
     * \param  multisig_data        The multisig restore info and keys
     * \param  create_address_file  Whether to create an address file
     */
    void generate(const std::string& wallet_, const epee::wipeable_string& password,
                  const epee::wipeable_string& multisig_data, bool create_address_file = false);

    /*!
     * \brief Generates a wallet or restores one.
     * \param  wallet_              Name of wallet file
     * \param  password             Password of wallet file
     * \param  recovery_param       If it is a restore, the recovery key
     * \param  recover              Whether it is a restore
     * \param  two_random           Whether it is a non-deterministic wallet
     * \param  create_address_file  Whether to create an address file
     * \return                      The secret key of the generated wallet
     */
    crypto::secret_key generate(const std::string& wallet, const epee::wipeable_string& password,
                                const crypto::secret_key& recovery_param = crypto::secret_key(), bool recover = false,
                                bool two_random = false, bool create_address_file = false);
    /*!
     * \brief Creates a wallet from a public address and a spend/view secret key pair.
     * \param  wallet_                 Name of wallet file
     * \param  password                Password of wallet file
     * \param  account_public_address  The account's public address
     * \param  spendkey                spend secret key
     * \param  viewkey                 view secret key
     * \param  create_address_file     Whether to create an address file
     */
    void generate(const std::string& wallet, const epee::wipeable_string& password,
                  const cryptonote::account_public_address &account_public_address,
                  const crypto::secret_key& spendkey, const crypto::secret_key& viewkey, bool create_address_file = false);
    /*!
     * \brief Creates a watch only wallet from a public address and a view secret key.
     * \param  wallet_                 Name of wallet file
     * \param  password                Password of wallet file
     * \param  account_public_address  The account's public address
     * \param  viewkey                 view secret key
     * \param  create_address_file     Whether to create an address file
     */
    void generate(const std::string& wallet, const epee::wipeable_string& password,
                  const cryptonote::account_public_address &account_public_address,
                  const crypto::secret_key& viewkey = crypto::secret_key(), bool create_address_file = false);
    /*!
     * \brief Restore a wallet hold by an HW.
     * \param  wallet_        Name of wallet file
     * \param  password       Password of wallet file
     * \param  device_name    name of HW to use
     * \param  create_address_file     Whether to create an address file
     */
    void restore(const std::string& wallet_, const epee::wipeable_string& password, const std::string &device_name, bool create_address_file = false);

    /*!
     * \brief Creates a multisig wallet
     * \return empty if done, non empty if we need to send another string
     * to other participants
     */
    /*std::string make_multisig(const epee::wipeable_string &password,
                              const std::vector<std::string> &info,
                              uint32_t threshold);*/
    /*!
     * \brief Creates a multisig wallet
     * \return empty if done, non empty if we need to send another string
     * to other participants
     */
    /*std::string make_multisig(const epee::wipeable_string &password,
                              const std::vector<crypto::secret_key> &view_keys,
                              const std::vector<crypto::public_key> &spend_keys,
                              uint32_t threshold);
    std::string exchange_multisig_keys(const epee::wipeable_string &password,
                                       const std::vector<std::string> &info);*/
    /*!
     * \brief Any but first round of keys exchange
     */
    /*std::string exchange_multisig_keys(const epee::wipeable_string &password,
                                       std::unordered_set<crypto::public_key> pkeys,
                                       std::vector<crypto::public_key> signers);*/
    /*!
     * \brief Finalizes creation of a multisig wallet
     */
    //bool finalize_multisig(const epee::wipeable_string &password, const std::vector<std::string> &info);
    /*!
     * \brief Finalizes creation of a multisig wallet
     */
    //bool finalize_multisig(const epee::wipeable_string &password, std::unordered_set<crypto::public_key> pkeys, std::vector<crypto::public_key> signers);
    /*!
     * Get a packaged multisig information string
     */
    //std::string get_multisig_info() const;
    /*!
     * Verifies and extracts keys from a packaged multisig information string
     */
    //static bool verify_multisig_info(const std::string &data, crypto::secret_key &skey, crypto::public_key &pkey);
    /*!
     * Verifies and extracts keys from a packaged multisig information string
     */
    //static bool verify_extra_multisig_info(const std::string &data, std::unordered_set<crypto::public_key> &pkeys, crypto::public_key &signer);
    /*!
     * Export multisig info
     * This will generate and remember new k values
     */
    //cryptonote::blobdata export_multisig();
    /*!
     * Import a set of multisig info from multisig partners
     * \return the number of inputs which were imported
     */
    //size_t import_multisig(std::vector<cryptonote::blobdata> info);
    /*!
     * \brief Rewrites to the wallet file for wallet upgrade (doesn't generate key, assumes it's already there)
     * \param wallet_name Name of wallet file (should exist)
     * \param password    Password for wallet file
     */
    void rewrite(const std::string& wallet_name, const epee::wipeable_string& password);
    void write_watch_only_wallet(const std::string& wallet_name, const epee::wipeable_string& password, std::string &new_keys_filename);
    void load(const std::string& wallet, const epee::wipeable_string& password);
    void store();
    /*!
     * \brief store_to  Stores wallet to another file(s), deleting old ones
     * \param path      Path to the wallet file (keys and address filenames will be generated based on this filename)
     * \param password  Password to protect new wallet (TODO: probably better save the password in the wallet object?)
     */
    void store_to(const std::string &path, const epee::wipeable_string &password);

    std::string path() const;

    /*!
     * \brief verifies given password is correct for default wallet keys file
     */
    bool verify_password(const epee::wipeable_string& password);
    cryptonote::account_base& get_account(){return m_account;}
    const cryptonote::account_base& get_account()const{return m_account;}

    void encrypt_keys(const crypto::chacha_key &key);
    void encrypt_keys(const epee::wipeable_string &password);
    void decrypt_keys(const crypto::chacha_key &key);
    void decrypt_keys(const epee::wipeable_string &password);

    void set_refresh_from_block_height(uint64_t height) {m_refresh_from_block_height = height;}
    uint64_t get_refresh_from_block_height() const {return m_refresh_from_block_height;}

    void explicit_refresh_from_block_height(bool expl) {m_explicit_refresh_from_block_height = expl;}
    bool explicit_refresh_from_block_height() const {return m_explicit_refresh_from_block_height;}

    bool deinit();
    bool init(std::string daemon_address = "http://localhost:8080",
              boost::optional<epee::net_utils::http::login> daemon_login = boost::none, uint64_t upper_transaction_weight_limit = 0, bool ssl = false, bool trusted_daemon = false);

    void stop() { m_run.store(false, std::memory_order_relaxed); }

    i_wallet2_callback* callback() const { return m_callback; }
    void callback(i_wallet2_callback* callback) { m_callback = callback; }

    bool is_trusted_daemon() const { return m_trusted_daemon; }
    void set_trusted_daemon(bool trusted) { m_trusted_daemon = trusted; }

    /*!
     * \brief Checks if deterministic wallet
     */
    bool is_deterministic() const;
    bool get_seed(epee::wipeable_string& electrum_words, const epee::wipeable_string &passphrase = epee::wipeable_string()) const;

    /*!
    * \brief Checks if light wallet. A light wallet sends view key to a server where the blockchain is scanned.
    */
    bool light_wallet() const { return m_light_wallet; }
    void set_light_wallet(bool light_wallet) { m_light_wallet = light_wallet; }
    uint64_t get_light_wallet_scanned_block_height() const { return m_light_wallet_scanned_block_height; }
    uint64_t get_light_wallet_blockchain_height() const { return m_light_wallet_blockchain_height; }

    /*!
     * \brief Gets the seed language
     */
    const std::string &get_seed_language() const;
    /*!
     * \brief Sets the seed language
     */
    void set_seed_language(const std::string &language);

    // Subaddress scheme
    cryptonote::account_public_address get_subaddress(const cryptonote::subaddress_index& index) const;
    cryptonote::account_public_address get_address() const { return get_subaddress({0,0}); }
    boost::optional<cryptonote::subaddress_index> get_subaddress_index(const cryptonote::account_public_address& address) const;
    crypto::public_key get_subaddress_spend_public_key(const cryptonote::subaddress_index& index) const;
    std::vector<crypto::public_key> get_subaddress_spend_public_keys(uint32_t account, uint32_t begin, uint32_t end) const;
    std::string get_subaddress_as_str(const cryptonote::subaddress_index& index) const;
    std::string get_address_as_str() const { return get_subaddress_as_str({0, 0}); }
    std::string get_integrated_address_as_str(const crypto::hash8& payment_id) const;
    void add_subaddress_account(const std::string& label);
    size_t get_num_subaddress_accounts() const { return m_subaddress_labels.size(); }
    size_t get_num_subaddresses(uint32_t index_major) const { return index_major < m_subaddress_labels.size() ? m_subaddress_labels[index_major].size() : 0; }
    void add_subaddress(uint32_t index_major, const std::string& label); // throws when index is out of bound
    void expand_subaddresses(const cryptonote::subaddress_index& index);
    std::string get_subaddress_label(const cryptonote::subaddress_index& index) const;
    void set_subaddress_label(const cryptonote::subaddress_index &index, const std::string &label);
    void set_subaddress_lookahead(size_t major, size_t minor);
    std::pair<size_t, size_t> get_subaddress_lookahead() const { return {m_subaddress_lookahead_major, m_subaddress_lookahead_minor}; }
    /*!
     * \brief Tells if the wallet file is deprecated.
     */
    bool is_deprecated() const;
    void refresh(bool trusted_daemon);
    void refresh(bool trusted_daemon, uint64_t start_height, uint64_t & blocks_fetched);
    void refresh(bool trusted_daemon, uint64_t start_height, uint64_t & blocks_fetched, bool& received_money);
    bool refresh(bool trusted_daemon, uint64_t & blocks_fetched, bool& received_money, bool& ok);

    void set_refresh_type(RefreshType refresh_type) { m_refresh_type = refresh_type; }
    RefreshType get_refresh_type() const { return m_refresh_type; }

    cryptonote::network_type nettype() const { return m_nettype; }
    bool watch_only() const { return m_watch_only; }
    //bool multisig(bool *ready = NULL, uint32_t *threshold = NULL, uint32_t *total = NULL) const;
    //bool has_multisig_partial_key_images() const;
    bool has_unknown_key_images() const;
    //bool get_multisig_seed(epee::wipeable_string& seed, const epee::wipeable_string &passphrase = std::string(), bool raw = true) const;
    bool key_on_device() const { return get_device_type() != hw::device::device_type::SOFTWARE; }
    hw::device::device_type get_device_type() const { return m_key_device_type; }
    bool reconnect_device();

    // locked & unlocked balance of given or current subaddress account
    uint64_t balance(uint32_t subaddr_index_major) const;
    uint64_t unlocked_balance(uint32_t subaddr_index_major) const;
    // locked & unlocked balance per subaddress of given or current subaddress account
    std::map<uint32_t, uint64_t> balance_per_subaddress(uint32_t subaddr_index_major) const;
    std::map<uint32_t, uint64_t> unlocked_balance_per_subaddress(uint32_t subaddr_index_major) const;
    // all locked & unlocked balances of all subaddress accounts
    uint64_t balance_all() const;
    uint64_t unlocked_balance_all() const;
    template<typename T>
    void transfer_selected(const std::vector<cryptonote::tx_destination_entry>& dsts, const std::vector<size_t>& selected_transfers, size_t fake_outputs_count,
                           std::vector<std::vector<CWallet::get_outs_entry>> &outs,
                           uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, T destination_split_strategy, const tx_dust_policy& dust_policy, cryptonote::transaction& tx, pending_tx &ptx);
    void transfer_selected_rct(std::vector<cryptonote::tx_destination_entry> dsts, const std::vector<size_t>& selected_transfers, size_t fake_outputs_count,
                               std::vector<std::vector<CWallet::get_outs_entry>> &outs,
                               uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, cryptonote::transaction& tx, pending_tx &ptx, rct::RangeProofType range_proof_type);

    void commit_tx(pending_tx& ptx_vector);
    void commit_tx(std::vector<pending_tx>& ptx_vector);
    bool save_tx(const std::vector<pending_tx>& ptx_vector, const std::string &filename) const;
    std::string dump_tx_to_str(const std::vector<pending_tx> &ptx_vector) const;
    //std::string save_multisig_tx(multisig_tx_set txs);
    //bool save_multisig_tx(const multisig_tx_set &txs, const std::string &filename);
    //std::string save_multisig_tx(const std::vector<pending_tx>& ptx_vector);
    //bool save_multisig_tx(const std::vector<pending_tx>& ptx_vector, const std::string &filename);
    //multisig_tx_set make_multisig_tx_set(const std::vector<pending_tx>& ptx_vector) const;
    // load unsigned tx from file and sign it. Takes confirmation callback as argument. Used by the cli wallet
    bool sign_tx(const std::string &unsigned_filename, const std::string &signed_filename, std::vector<CWallet::pending_tx> &ptx, std::function<bool(const unsigned_tx_set&)> accept_func = NULL, bool export_raw = false);
    // sign unsigned tx. Takes unsigned_tx_set as argument. Used by GUI
    bool sign_tx(unsigned_tx_set &exported_txs, const std::string &signed_filename, std::vector<CWallet::pending_tx> &ptx, bool export_raw = false);
    bool sign_tx(unsigned_tx_set &exported_txs, std::vector<CWallet::pending_tx> &ptx, signed_tx_set &signed_txs);
    std::string sign_tx_dump_to_str(unsigned_tx_set &exported_txs, std::vector<CWallet::pending_tx> &ptx, signed_tx_set &signed_txes);
    // load unsigned_tx_set from file.
    bool load_unsigned_tx(const std::string &unsigned_filename, unsigned_tx_set &exported_txs) const;
    bool parse_unsigned_tx_from_str(const std::string &unsigned_tx_st, unsigned_tx_set &exported_txs) const;
    bool load_tx(const std::string &signed_filename, std::vector<CWallet::pending_tx> &ptx, std::function<bool(const signed_tx_set&)> accept_func = NULL);
    bool parse_tx_from_str(const std::string &signed_tx_st, std::vector<CWallet::pending_tx> &ptx, std::function<bool(const signed_tx_set &)> accept_func);
    std::vector<CWallet::pending_tx> create_transactions_2(std::vector<cryptonote::tx_destination_entry> dsts, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices);     // pass subaddr_indices by value on purpose
    std::vector<CWallet::pending_tx> create_transactions_all(uint64_t below, const cryptonote::account_public_address &address, bool is_subaddress, const size_t outputs, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices);
    std::vector<CWallet::pending_tx> create_transactions_single(const crypto::key_image &ki, const cryptonote::account_public_address &address, bool is_subaddress, const size_t outputs, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra);
    std::vector<CWallet::pending_tx> create_transactions_from(const cryptonote::account_public_address &address, bool is_subaddress, const size_t outputs, std::vector<size_t> unused_transfers_indices, std::vector<size_t> unused_dust_indices, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra);
    bool load_multisig_tx(cryptonote::blobdata blob, multisig_tx_set &exported_txs, std::function<bool(const multisig_tx_set&)> accept_func = NULL);
    bool load_multisig_tx_from_file(const std::string &filename, multisig_tx_set &exported_txs, std::function<bool(const multisig_tx_set&)> accept_func = NULL);
    bool sign_multisig_tx_from_file(const std::string &filename, std::vector<crypto::hash> &txids, std::function<bool(const multisig_tx_set&)> accept_func);
    bool sign_multisig_tx(multisig_tx_set &exported_txs, std::vector<crypto::hash> &txids);
    bool sign_multisig_tx_to_file(multisig_tx_set &exported_txs, const std::string &filename, std::vector<crypto::hash> &txids);
    std::vector<pending_tx> create_unmixable_sweep_transactions();
    void discard_unmixable_outputs();
    bool check_connection(uint32_t *version = NULL, uint32_t timeout = 200000);
    void get_transfers(CWallet::transfer_container& incoming_transfers) const;
    void get_payments(const crypto::hash& payment_id, std::list<CWallet::payment_details>& payments, uint64_t min_height = 0, const boost::optional<uint32_t>& subaddr_account = boost::none, const std::set<uint32_t>& subaddr_indices = {}) const;
    void get_payments(std::list<std::pair<crypto::hash,CWallet::payment_details>>& payments, uint64_t min_height, uint64_t max_height = (uint64_t)-1, const boost::optional<uint32_t>& subaddr_account = boost::none, const std::set<uint32_t>& subaddr_indices = {}) const;
    void get_payments_out(std::list<std::pair<crypto::hash,CWallet::confirmed_transfer_details>>& confirmed_payments,
                          uint64_t min_height, uint64_t max_height = (uint64_t)-1, const boost::optional<uint32_t>& subaddr_account = boost::none, const std::set<uint32_t>& subaddr_indices = {}) const;
    void get_unconfirmed_payments_out(std::list<std::pair<crypto::hash,CWallet::unconfirmed_transfer_details>>& unconfirmed_payments, const boost::optional<uint32_t>& subaddr_account = boost::none, const std::set<uint32_t>& subaddr_indices = {}) const;
    void get_unconfirmed_payments(std::list<std::pair<crypto::hash,CWallet::pool_payment_details>>& unconfirmed_payments, const boost::optional<uint32_t>& subaddr_account = boost::none, const std::set<uint32_t>& subaddr_indices = {}) const;

    uint64_t get_blockchain_current_height() const { return m_light_wallet_blockchain_height ? m_light_wallet_blockchain_height : m_blockchain.size(); }
    void rescan_spent();
    void rescan_blockchain(bool refresh = true);
    bool is_transfer_unlocked(const transfer_details& td) const;
    bool is_transfer_unlocked(uint64_t unlock_time, uint64_t block_height) const;

    uint64_t get_last_block_reward() const { return m_last_block_reward; }

    template <class t_archive>
    inline void serialize(t_archive &a, const unsigned int ver)
    {
        uint64_t dummy_refresh_height = 0; // moved to keys file
        if(ver < 5)
            return;
        if (ver < 19)
        {
            std::vector<crypto::hash> blockchain;
            a & blockchain;
            for (const auto &b: blockchain)
            {
                m_blockchain.push_back(b);
            }
        }
        else
        {
            a & m_blockchain;
        }
        a & m_transfers;
        a & m_account_public_address;
        a & m_key_images;
        if(ver < 6)
            return;
        a & m_unconfirmed_txs;
        if(ver < 7)
            return;
        a & m_payments;
        if(ver < 8)
            return;
        a & m_tx_keys;
        if(ver < 9)
            return;
        a & m_confirmed_txs;
        if(ver < 11)
            return;
        a & dummy_refresh_height;
        if(ver < 12)
            return;
        a & m_tx_notes;
        if(ver < 13)
            return;
        if (ver < 17)
        {
            // we're loading an old version, where m_unconfirmed_payments was a std::map
            std::unordered_map<crypto::hash, payment_details> m;
            a & m;
            for (std::unordered_map<crypto::hash, payment_details>::const_iterator i = m.begin(); i != m.end(); ++i)
                m_unconfirmed_payments.insert(std::make_pair(i->first, pool_payment_details{i->second, false}));
        }
        if(ver < 14)
            return;
        if(ver < 15)
        {
            // we're loading an older wallet without a pubkey map, rebuild it
            for (size_t i = 0; i < m_transfers.size(); ++i)
            {
                const transfer_details &td = m_transfers[i];
                const cryptonote::tx_out &out = td.m_tx.vout[td.m_internal_output_index];
                const cryptonote::txout_to_key &o = boost::get<const cryptonote::txout_to_key>(out.target);
                m_pub_keys.emplace(o.key, i);
            }
            return;
        }
        a & m_pub_keys;
        if(ver < 16)
            return;
        a & m_address_book;
        if(ver < 17)
            return;
        if (ver < 22)
        {
            // we're loading an old version, where m_unconfirmed_payments payload was payment_details
            std::unordered_multimap<crypto::hash, payment_details> m;
            a & m;
            for (const auto &i: m)
                m_unconfirmed_payments.insert(std::make_pair(i.first, pool_payment_details{i.second, false}));
        }
        if(ver < 18)
            return;
        a & m_scanned_pool_txs[0];
        a & m_scanned_pool_txs[1];
        if (ver < 20)
            return;
        a & m_subaddresses;
        std::unordered_map<cryptonote::subaddress_index, crypto::public_key> dummy_subaddresses_inv;
        a & dummy_subaddresses_inv;
        a & m_subaddress_labels;
        a & m_additional_tx_keys;
        if(ver < 21)
            return;
        a & m_attributes;
        if(ver < 22)
            return;
        a & m_unconfirmed_payments;
        if(ver < 23)
            return;
        a & m_account_tags;
        if(ver < 24)
            return;
        a & m_ring_history_saved;
        if(ver < 25)
            return;
        a & m_last_block_reward;
    }

    /*!
     * \brief  Check if wallet keys and bin files exist
     * \param  file_path           Wallet file path
     * \param  keys_file_exists    Whether keys file exists
     * \param  wallet_file_exists  Whether bin file exists
     */
    static void wallet_exists(const std::string& file_path, bool& keys_file_exists, bool& wallet_file_exists);
    /*!
     * \brief  Check if wallet file path is valid format
     * \param  file_path      Wallet file path
     * \return                Whether path is valid format
     */
    static bool wallet_valid_path_format(const std::string& file_path);
    static bool parse_long_payment_id(const std::string& payment_id_str, crypto::hash& payment_id);
    static bool parse_short_payment_id(const std::string& payment_id_str, crypto::hash8& payment_id);
    static bool parse_payment_id(const std::string& payment_id_str, crypto::hash& payment_id);

    bool always_confirm_transfers() const { return m_always_confirm_transfers; }
    void always_confirm_transfers(bool always) { m_always_confirm_transfers = always; }
    bool print_ring_members() const { return m_print_ring_members; }
    void print_ring_members(bool value) { m_print_ring_members = value; }
    bool store_tx_info() const { return m_store_tx_info; }
    void store_tx_info(bool store) { m_store_tx_info = store; }
    uint32_t default_mixin() const { return m_default_mixin; }
    void default_mixin(uint32_t m) { m_default_mixin = m; }
    uint32_t get_default_priority() const { return m_default_priority; }
    void set_default_priority(uint32_t p) { m_default_priority = p; }
    bool auto_refresh() const { return m_auto_refresh; }
    void auto_refresh(bool r) { m_auto_refresh = r; }
    bool confirm_missing_payment_id() const { return m_confirm_missing_payment_id; }
    void confirm_missing_payment_id(bool always) { m_confirm_missing_payment_id = always; }
    AskPasswordType ask_password() const { return m_ask_password; }
    void ask_password(AskPasswordType ask) { m_ask_password = ask; }
    void set_min_output_count(uint32_t count) { m_min_output_count = count; }
    uint32_t get_min_output_count() const { return m_min_output_count; }
    void set_min_output_value(uint64_t value) { m_min_output_value = value; }
    uint64_t get_min_output_value() const { return m_min_output_value; }
    void merge_destinations(bool merge) { m_merge_destinations = merge; }
    bool merge_destinations() const { return m_merge_destinations; }
    bool confirm_backlog() const { return m_confirm_backlog; }
    void confirm_backlog(bool always) { m_confirm_backlog = always; }
    void set_confirm_backlog_threshold(uint32_t threshold) { m_confirm_backlog_threshold = threshold; };
    uint32_t get_confirm_backlog_threshold() const { return m_confirm_backlog_threshold; };
    bool confirm_export_overwrite() const { return m_confirm_export_overwrite; }
    void confirm_export_overwrite(bool always) { m_confirm_export_overwrite = always; }
    bool auto_low_priority() const { return m_auto_low_priority; }
    void auto_low_priority(bool value) { m_auto_low_priority = value; }
    bool segregate_pre_fork_outputs() const { return m_segregate_pre_fork_outputs; }
    void segregate_pre_fork_outputs(bool value) { m_segregate_pre_fork_outputs = value; }
    bool key_reuse_mitigation2() const { return m_key_reuse_mitigation2; }
    void key_reuse_mitigation2(bool value) { m_key_reuse_mitigation2 = value; }
    uint64_t segregation_height() const { return m_segregation_height; }
    void segregation_height(uint64_t height) { m_segregation_height = height; }
    bool ignore_fractional_outputs() const { return m_ignore_fractional_outputs; }
    void ignore_fractional_outputs(bool value) { m_ignore_fractional_outputs = value; }
    bool confirm_non_default_ring_size() const { return m_confirm_non_default_ring_size; }
    void confirm_non_default_ring_size(bool always) { m_confirm_non_default_ring_size = always; }
    const std::string & device_name() const { return m_device_name; }
    void device_name(const std::string & device_name) { m_device_name = device_name; }

    bool get_tx_key(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys) const;
    void set_tx_key(const crypto::hash &txid, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys);
    void check_tx_key(const crypto::hash &txid, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, const cryptonote::account_public_address &address, uint64_t &received, bool &in_pool, uint64_t &confirmations);
    void check_tx_key_helper(const crypto::hash &txid, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, const cryptonote::account_public_address &address, uint64_t &received, bool &in_pool, uint64_t &confirmations);
    std::string get_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address, bool is_subaddress, const std::string &message);
    bool check_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address, bool is_subaddress, const std::string &message, const std::string &sig_str, uint64_t &received, bool &in_pool, uint64_t &confirmations);

    std::string get_spend_proof(const crypto::hash &txid, const std::string &message);
    bool check_spend_proof(const crypto::hash &txid, const std::string &message, const std::string &sig_str);

    /*!
     * \brief  Generates a proof that proves the reserve of unspent funds
     * \param  account_minreserve       When specified, collect outputs only belonging to the given account and prove the smallest reserve above the given amount
     *                                  When unspecified, proves for all unspent outputs across all accounts
     * \param  message                  Arbitrary challenge message to be signed together
     * \return                          Signature string
     */
    std::string get_reserve_proof(const boost::optional<std::pair<uint32_t, uint64_t>> &account_minreserve, const std::string &message);
    /*!
     * \brief  Verifies a proof of reserve
     * \param  address                  The signer's address
     * \param  message                  Challenge message used for signing
     * \param  sig_str                  Signature string
     * \param  total                    [OUT] the sum of funds included in the signature
     * \param  spent                    [OUT] the sum of spent funds included in the signature
     * \return                          true if the signature verifies correctly
     */
    bool check_reserve_proof(const cryptonote::account_public_address &address, const std::string &message, const std::string &sig_str, uint64_t &total, uint64_t &spent);

    /*!
     * \brief GUI Address book get/store
     */
    std::vector<address_book_row> get_address_book() const { return m_address_book; }
    bool add_address_book_row(const cryptonote::account_public_address &address, const crypto::hash &payment_id, const std::string &description, bool is_subaddress);
    bool delete_address_book_row(std::size_t row_id);

    uint64_t get_num_rct_outputs();
    size_t get_num_transfer_details() const { return m_transfers.size(); }
    const transfer_details &get_transfer_details(size_t idx) const;

    void get_hard_fork_info(uint8_t version, uint64_t &earliest_height) const;
    bool use_fork_rules(uint8_t version, int64_t early_blocks = 0) const;
    int get_fee_algorithm() const;

    std::string get_wallet_file() const;
    std::string get_keys_file() const;
    std::string get_daemon_address() const;
    const boost::optional<epee::net_utils::http::login>& get_daemon_login() const { return m_daemon_login; }
    uint64_t get_daemon_blockchain_height(std::string& err) const;
    uint64_t get_daemon_blockchain_target_height(std::string& err);
    /*!
     * \brief Calculates the approximate blockchain height from current date/time.
     */
    uint64_t get_approximate_blockchain_height() const;
    uint64_t estimate_blockchain_height();
    std::vector<size_t> select_available_outputs_from_histogram(uint64_t count, bool atleast, bool unlocked, bool allow_rct);
    std::vector<size_t> select_available_outputs(const std::function<bool(const transfer_details &td)> &f) const;
    std::vector<size_t> select_available_unmixable_outputs();
    std::vector<size_t> select_available_mixable_outputs();

    size_t pop_best_value_from(const transfer_container &transfers, std::vector<size_t> &unused_dust_indices, const std::vector<size_t>& selected_transfers, bool smallest = false) const;
    size_t pop_best_value(std::vector<size_t> &unused_dust_indices, const std::vector<size_t>& selected_transfers, bool smallest = false) const;

    void set_tx_note(const crypto::hash &txid, const std::string &note);
    std::string get_tx_note(const crypto::hash &txid) const;

    void set_description(const std::string &description);
    std::string get_description() const;

    /*!
     * \brief  Get the list of registered account tags.
     * \return first.Key=(tag's name), first.Value=(tag's label), second[i]=(i-th account's tag)
     */
    const std::pair<std::map<std::string, std::string>, std::vector<std::string>>& get_account_tags();
    /*!
     * \brief  Set a tag to the given accounts.
     * \param  account_indices  Indices of accounts.
     * \param  tag              Tag's name. If empty, the accounts become untagged.
     */
    void set_account_tag(const std::set<uint32_t> account_indices, const std::string& tag);
    /*!
     * \brief  Set the label of the given tag.
     * \param  tag            Tag's name (which must be non-empty).
     * \param  description    Tag's description.
     */
    void set_account_tag_description(const std::string& tag, const std::string& description);

    std::string sign(const std::string &data) const;
    bool verify(const std::string &data, const cryptonote::account_public_address &address, const std::string &signature) const;

    /*!
     * \brief sign_multisig_participant signs given message with the multisig public signer key
     * \param data                      message to sign
     * \throws                          if wallet is not multisig
     * \return                          signature
     */
    std::string sign_multisig_participant(const std::string& data) const;
    /*!
     * \brief verify_with_public_key verifies message was signed with given public key
     * \param data                   message
     * \param public_key             public key to check signature
     * \param signature              signature of the message
     * \return                       true if the signature is correct
     */
    bool verify_with_public_key(const std::string &data, const crypto::public_key &public_key, const std::string &signature) const;

    // Import/Export wallet data
    std::vector<CWallet::transfer_details> export_outputs() const;
    std::string export_outputs_to_str() const;
    size_t import_outputs(const std::vector<CWallet::transfer_details> &outputs);
    size_t import_outputs_from_str(const std::string &outputs_st);
    payment_container export_payments() const;
    void import_payments(const payment_container &payments);
    void import_payments_out(const std::list<std::pair<crypto::hash,CWallet::confirmed_transfer_details>> &confirmed_payments);
    std::tuple<size_t, crypto::hash, std::vector<crypto::hash>> export_blockchain() const;
    void import_blockchain(const std::tuple<size_t, crypto::hash, std::vector<crypto::hash>> &bc);
    bool export_key_images(const std::string &filename) const;
    std::vector<std::pair<crypto::key_image, crypto::signature>> export_key_images() const;
    uint64_t import_key_images(const std::vector<std::pair<crypto::key_image, crypto::signature>> &signed_key_images, uint64_t &spent, uint64_t &unspent, bool check_spent = true);
    uint64_t import_key_images(const std::string &filename, uint64_t &spent, uint64_t &unspent);

    void update_pool_state(bool refreshed = false);
    void remove_obsolete_pool_txs(const std::vector<crypto::hash> &tx_hashes);

    std::string encrypt(const char *plaintext, size_t len, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string encrypt(const epee::span<char> &span, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string encrypt(const std::string &plaintext, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string encrypt(const epee::wipeable_string &plaintext, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string encrypt_with_view_secret_key(const std::string &plaintext, bool authenticated = true) const;
    template<typename T=std::string> T decrypt(const std::string &ciphertext, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string decrypt_with_view_secret_key(const std::string &ciphertext, bool authenticated = true) const;

    std::string make_uri(const std::string &address, const std::string &payment_id, uint64_t amount, const std::string &tx_description, const std::string &recipient_name, std::string &error) const;
    bool parse_uri(const std::string &uri, std::string &address, std::string &payment_id, uint64_t &amount, std::string &tx_description, std::string &recipient_name, std::vector<std::string> &unknown_parameters, std::string &error);

    uint64_t get_blockchain_height_by_date(uint16_t year, uint8_t month, uint8_t day);    // 1<=month<=12, 1<=day<=31

    bool is_synced() const;

    std::vector<std::pair<uint64_t, uint64_t>> estimate_backlog(const std::vector<std::pair<double, double>> &fee_levels);
    std::vector<std::pair<uint64_t, uint64_t>> estimate_backlog(uint64_t min_tx_weight, uint64_t max_tx_weight, const std::vector<uint64_t> &fees);

    uint64_t get_fee_multiplier(uint32_t priority, int fee_algorithm = -1) const;
    uint64_t get_base_fee() const;
    uint64_t get_fee_quantization_mask() const;
    uint64_t get_min_ring_size() const;
    uint64_t get_max_ring_size() const;
    uint64_t adjust_mixin(uint64_t mixin) const;
    uint32_t adjust_priority(uint32_t priority);

    bool is_unattended() const { return m_unattended; }

    // Light wallet specific functions
    // fetch unspent outs from lw node and store in m_transfers
    void light_wallet_get_unspent_outs();
    // fetch txs and store in m_payments
    void light_wallet_get_address_txs();
    // get_address_info
    bool light_wallet_get_address_info(cryptonote::COMMAND_RPC_GET_ADDRESS_INFO::response &response);
    // Login. new_address is true if address hasn't been used on lw node before.
    bool light_wallet_login(bool &new_address);
    // Send an import request to lw node. returns info about import fee, address and payment_id
    bool light_wallet_import_wallet_request(cryptonote::COMMAND_RPC_IMPORT_WALLET_REQUEST::response &response);
    // get random outputs from light wallet server
    void light_wallet_get_outs(std::vector<std::vector<get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count);
    // Parse rct string
    bool light_wallet_parse_rct_str(const std::string& rct_string, const crypto::public_key& tx_pub_key, uint64_t internal_output_index, rct::key& decrypted_mask, rct::key& rct_commit, bool decrypt) const;
    // check if key image is ours
    bool light_wallet_key_image_is_ours(const crypto::key_image& key_image, const crypto::public_key& tx_public_key, uint64_t out_index);

    /*
     * "attributes" are a mechanism to store an arbitrary number of string values
     * on the level of the wallet as a whole, identified by keys. Their introduction,
     * technically the unordered map m_attributes stored as part of a wallet file,
     * led to a new wallet file version, but now new singular pieces of info may be added
     * without the need for a new version.
     *
     * The first and so far only value stored as such an attribute is the description.
     * It's stored under the standard key ATTRIBUTE_DESCRIPTION (see method set_description).
     *
     * The mechanism is open to all clients and allows them to use it for storing basically any
     * single string values in a wallet. To avoid the problem that different clients possibly
     * overwrite or misunderstand each other's attributes, a two-part key scheme is
     * proposed: <client name>.<value name>
     */
    const char* const ATTRIBUTE_DESCRIPTION = "wallet.description";
    void set_attribute(const std::string &key, const std::string &value);
    std::string get_attribute(const std::string &key) const;

    crypto::public_key get_multisig_signer_public_key(const crypto::secret_key &spend_skey) const;
    crypto::public_key get_multisig_signer_public_key() const;
    crypto::public_key get_multisig_signing_public_key(size_t idx) const;
    crypto::public_key get_multisig_signing_public_key(const crypto::secret_key &skey) const;

    template<class t_request, class t_response>
    inline bool invoke_http_json(const boost::string_ref uri, const t_request& req, t_response& res, std::chrono::milliseconds timeout = std::chrono::seconds(15), const boost::string_ref http_method = "GET")
    {
        boost::lock_guard<boost::mutex> lock(m_daemon_rpc_mutex);
        return epee::net_utils::invoke_http_json(uri, req, res, m_http_client, timeout, http_method);
    }
    template<class t_request, class t_response>
    inline bool invoke_http_bin(const boost::string_ref uri, const t_request& req, t_response& res, std::chrono::milliseconds timeout = std::chrono::seconds(15), const boost::string_ref http_method = "GET")
    {
        boost::lock_guard<boost::mutex> lock(m_daemon_rpc_mutex);
        return epee::net_utils::invoke_http_bin(uri, req, res, m_http_client, timeout, http_method);
    }
    template<class t_request, class t_response>
    inline bool invoke_http_json_rpc(const boost::string_ref uri, const std::string& method_name, const t_request& req, t_response& res, std::chrono::milliseconds timeout = std::chrono::seconds(15), const boost::string_ref http_method = "GET", const std::string& req_id = "0")
    {
        boost::lock_guard<boost::mutex> lock(m_daemon_rpc_mutex);
        return epee::net_utils::invoke_http_json_rpc(uri, method_name, req, res, m_http_client, timeout, http_method, req_id);
    }

    bool set_ring_database(const std::string &filename);
    const std::string get_ring_database() const { return m_ring_database; }
    bool get_ring(const crypto::key_image &key_image, std::vector<uint64_t> &outs);
    bool get_rings(const crypto::hash &txid, std::vector<std::pair<crypto::key_image, std::vector<uint64_t>>> &outs);
    bool set_ring(const crypto::key_image &key_image, const std::vector<uint64_t> &outs, bool relative);
    bool find_and_save_rings(bool force = true);

    bool blackball_output(const std::pair<uint64_t, uint64_t> &output);
    bool set_blackballed_outputs(const std::vector<std::pair<uint64_t, uint64_t>> &outputs, bool add = false);
    bool unblackball_output(const std::pair<uint64_t, uint64_t> &output);
    bool is_output_blackballed(const std::pair<uint64_t, uint64_t> &output) const;

    bool lock_keys_file();
    bool unlock_keys_file();
    bool is_keys_file_locked() const;

    void change_password(const std::string &filename, const epee::wipeable_string &original_password, const epee::wipeable_string &new_password);

    void set_tx_notify(const std::shared_ptr<tools::Notify> &notify) { m_tx_notify = notify; }

private:
    /*!
     * \brief  Stores wallet information to wallet file.
     * \param  keys_file_name Name of wallet file
     * \param  password       Password of wallet file
     * \param  watch_only     true to save only view key, false to save both spend and view keys
     * \return                Whether it was successful.
     */
    bool store_keys(const std::string& keys_file_name, const epee::wipeable_string& password, bool watch_only = false);
    /*!
     * \brief Load wallet information from wallet file.
     * \param keys_file_name Name of wallet file
     * \param password       Password of wallet file
     */
    bool load_keys(const std::string& keys_file_name, const epee::wipeable_string& password);
    void process_new_transaction(const crypto::hash &txid, const cryptonote::transaction& tx, const std::vector<uint64_t> &o_indices, uint64_t height, uint64_t ts, bool miner_tx, bool pool, bool double_spend_seen, const tx_cache_data &tx_cache_data);
    void process_new_blockchain_entry(const cryptonote::block& b, const cryptonote::block_complete_entry& bche, const parsed_block &parsed_block, const crypto::hash& bl_id, uint64_t height, const std::vector<tx_cache_data> &tx_cache_data, size_t tx_cache_data_offset);
    void detach_blockchain(uint64_t height);
    void get_short_chain_history(std::list<crypto::hash>& ids, uint64_t granularity = 1) const;
    bool is_tx_spendtime_unlocked(uint64_t unlock_time, uint64_t block_height) const;
    bool clear();
    void pull_blocks(uint64_t start_height, uint64_t& blocks_start_height, const std::list<crypto::hash> &short_chain_history, std::vector<cryptonote::block_complete_entry> &blocks, std::vector<cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices> &o_indices);
    void pull_hashes(uint64_t start_height, uint64_t& blocks_start_height, const std::list<crypto::hash> &short_chain_history, std::vector<crypto::hash> &hashes);
    void fast_refresh(uint64_t stop_height, uint64_t &blocks_start_height, std::list<crypto::hash> &short_chain_history, bool force = false);
    void pull_and_parse_next_blocks(uint64_t start_height, uint64_t &blocks_start_height, std::list<crypto::hash> &short_chain_history, const std::vector<cryptonote::block_complete_entry> &prev_blocks, const std::vector<parsed_block> &prev_parsed_blocks, std::vector<cryptonote::block_complete_entry> &blocks, std::vector<parsed_block> &parsed_blocks, bool &error);
    void process_parsed_blocks(uint64_t start_height, const std::vector<cryptonote::block_complete_entry> &blocks, const std::vector<parsed_block> &parsed_blocks, uint64_t& blocks_added);
    uint64_t select_transfers(uint64_t needed_money, std::vector<size_t> unused_transfers_indices, std::vector<size_t>& selected_transfers) const;
    bool prepare_file_names(const std::string& file_path);
    void process_unconfirmed(const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t height);
    void process_outgoing(const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t height, uint64_t ts, uint64_t spent, uint64_t received, uint32_t subaddr_account, const std::set<uint32_t>& subaddr_indices);
    void add_unconfirmed_tx(const cryptonote::transaction& tx, uint64_t amount_in, const std::vector<cryptonote::tx_destination_entry> &dests, const crypto::hash &payment_id, uint64_t change_amount, uint32_t subaddr_account, const std::set<uint32_t>& subaddr_indices);
    void generate_genesis(cryptonote::block& b) const;
    void check_genesis(const crypto::hash& genesis_hash) const; //throws
    bool generate_chacha_key_from_secret_keys(crypto::chacha_key &key) const;
    void generate_chacha_key_from_password(const epee::wipeable_string &pass, crypto::chacha_key &key) const;
    crypto::hash get_payment_id(const pending_tx &ptx) const;
    void check_acc_out_precomp(const cryptonote::tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, tx_scan_info_t &tx_scan_info) const;
    void check_acc_out_precomp(const cryptonote::tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, const is_out_data *is_out_data, tx_scan_info_t &tx_scan_info) const;
    void check_acc_out_precomp_once(const cryptonote::tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, const is_out_data *is_out_data, tx_scan_info_t &tx_scan_info, bool &already_seen) const;
    void parse_block_round(const cryptonote::blobdata &blob, cryptonote::block &bl, crypto::hash &bl_id, bool &error) const;
    uint64_t get_upper_transaction_weight_limit() const;
    std::vector<uint64_t> get_unspent_amounts_vector() const;
    uint64_t get_dynamic_base_fee_estimate() const;
    float get_output_relatedness(const transfer_details &td0, const transfer_details &td1) const;
    std::vector<size_t> pick_preferred_rct_inputs(uint64_t needed_money, uint32_t subaddr_account, const std::set<uint32_t> &subaddr_indices) const;
    void set_spent(size_t idx, uint64_t height);
    void set_unspent(size_t idx);
    void get_outs(std::vector<std::vector<get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count);
    bool tx_add_fake_output(std::vector<std::vector<CWallet::get_outs_entry>> &outs, uint64_t global_index, const crypto::public_key& tx_public_key, const rct::key& mask, uint64_t real_index, bool unlocked) const;
    crypto::public_key get_tx_pub_key_from_received_outs(const CWallet::transfer_details &td) const;
    bool should_pick_a_second_output(bool use_rct, size_t n_transfers, const std::vector<size_t> &unused_transfers_indices, const std::vector<size_t> &unused_dust_indices) const;
    std::vector<size_t> get_only_rct(const std::vector<size_t> &unused_dust_indices, const std::vector<size_t> &unused_transfers_indices) const;
    void scan_output(const cryptonote::transaction &tx, const crypto::public_key &tx_pub_key, size_t i, tx_scan_info_t &tx_scan_info, int &num_vouts_received, std::unordered_map<cryptonote::subaddress_index, uint64_t> &tx_money_got_in_outs, std::vector<size_t> &outs);
    void trim_hashchain();
    //crypto::key_image get_multisig_composite_key_image(size_t n) const;
    //rct::multisig_kLRki get_multisig_composite_kLRki(size_t n, const crypto::public_key &ignore, std::unordered_set<rct::key> &used_L, std::unordered_set<rct::key> &new_used_L) const;
    //rct::multisig_kLRki get_multisig_kLRki(size_t n, const rct::key &k) const;
    //rct::key get_multisig_k(size_t idx, const std::unordered_set<rct::key> &used_L) const;
    //void update_multisig_rescan_info(const std::vector<std::vector<rct::key>> &multisig_k, const std::vector<std::vector<CWallet::multisig_info>> &info, size_t n);
    bool add_rings(const crypto::chacha_key &key, const cryptonote::transaction_prefix &tx);
    bool add_rings(const cryptonote::transaction_prefix &tx);
    bool remove_rings(const cryptonote::transaction_prefix &tx);
    bool get_ring(const crypto::chacha_key &key, const crypto::key_image &key_image, std::vector<uint64_t> &outs);
    crypto::chacha_key get_ringdb_key();
    void setup_keys(const epee::wipeable_string &password);

    bool get_rct_distribution(uint64_t &start_height, std::vector<uint64_t> &distribution);

    uint64_t get_segregation_fork_height() const;
    /*void unpack_multisig_info(const std::vector<std::string>& info,
                              std::vector<crypto::public_key> &public_keys,
                              std::vector<crypto::secret_key> &secret_keys) const;
    bool unpack_extra_multisig_info(const std::vector<std::string>& info,
                                    std::vector<crypto::public_key> &signers,
                                    std::unordered_set<crypto::public_key> &pkeys) const;*/

    void cache_tx_data(const cryptonote::transaction& tx, const crypto::hash &txid, tx_cache_data &tx_cache_data) const;

    void setup_new_blockchain();
    void create_keys_file(const std::string &wallet_, bool watch_only, const epee::wipeable_string &password, bool create_address_file);

    cryptonote::account_base m_account;
    boost::optional<epee::net_utils::http::login> m_daemon_login;
    std::string m_daemon_address;
    std::string m_wallet_file;
    std::string m_keys_file;
    epee::net_utils::http::http_simple_client m_http_client;
    hashchain m_blockchain;
    std::unordered_map<crypto::hash, unconfirmed_transfer_details> m_unconfirmed_txs;
    std::unordered_map<crypto::hash, confirmed_transfer_details> m_confirmed_txs;
    std::unordered_multimap<crypto::hash, pool_payment_details> m_unconfirmed_payments;
    std::unordered_map<crypto::hash, crypto::secret_key> m_tx_keys;
    cryptonote::checkpoints m_checkpoints;
    std::unordered_map<crypto::hash, std::vector<crypto::secret_key>> m_additional_tx_keys;

    transfer_container m_transfers;
    payment_container m_payments;
    std::unordered_map<crypto::key_image, size_t> m_key_images;
    std::unordered_map<crypto::public_key, size_t> m_pub_keys;
    cryptonote::account_public_address m_account_public_address;
    std::unordered_map<crypto::public_key, cryptonote::subaddress_index> m_subaddresses;
    std::vector<std::vector<std::string>> m_subaddress_labels;
    std::unordered_map<crypto::hash, std::string> m_tx_notes;
    std::unordered_map<std::string, std::string> m_attributes;
    std::vector<CWallet::address_book_row> m_address_book;
    std::pair<std::map<std::string, std::string>, std::vector<std::string>> m_account_tags;
    uint64_t m_upper_transaction_weight_limit; //TODO: auto-calc this value or request from daemon, now use some fixed value
    //const std::vector<std::vector<CWallet::multisig_info>> *m_multisig_rescan_info;
    //const std::vector<std::vector<rct::key>> *m_multisig_rescan_k;

    std::atomic<bool> m_run;

    boost::mutex m_daemon_rpc_mutex;

    bool m_trusted_daemon;
    i_wallet2_callback* m_callback;
    hw::device::device_type m_key_device_type;
    cryptonote::network_type m_nettype;
    uint64_t m_kdf_rounds;
    std::string seed_language; /*!< Language of the mnemonics (seed). */
    bool is_old_file_format; /*!< Whether the wallet file is of an old file format */
    bool m_watch_only; /*!< no spend key */
    //bool m_multisig; /*!< if > 1 spend secret key will not match spend public key */
    //uint32_t m_multisig_threshold;
    //std::vector<crypto::public_key> m_multisig_signers;
    //in case of general M/N multisig wallet we should perform N - M + 1 key exchange rounds and remember how many rounds are passed.
    //uint32_t m_multisig_rounds_passed;
    //std::vector<crypto::public_key> m_multisig_derivations;
    bool m_always_confirm_transfers;
    bool m_print_ring_members;
    bool m_store_tx_info; /*!< request txkey to be returned in RPC, and store in the wallet cache file */
    uint32_t m_default_mixin;
    uint32_t m_default_priority;
    RefreshType m_refresh_type;
    bool m_auto_refresh;
    bool m_first_refresh_done;
    uint64_t m_refresh_from_block_height;
    // If m_refresh_from_block_height is explicitly set to zero we need this to differentiate it from the case that
    // m_refresh_from_block_height was defaulted to zero.*/
    bool m_explicit_refresh_from_block_height;
    bool m_confirm_missing_payment_id;
    bool m_confirm_non_default_ring_size;
    AskPasswordType m_ask_password;
    uint32_t m_min_output_count;
    uint64_t m_min_output_value;
    bool m_merge_destinations;
    bool m_confirm_backlog;
    uint32_t m_confirm_backlog_threshold;
    bool m_confirm_export_overwrite;
    bool m_auto_low_priority;
    bool m_segregate_pre_fork_outputs;
    bool m_key_reuse_mitigation2;
    uint64_t m_segregation_height;
    bool m_ignore_fractional_outputs;
    bool m_is_initialized;
    tools::NodeRPCProxy m_node_rpc_proxy;
    std::unordered_set<crypto::hash> m_scanned_pool_txs[2];
    size_t m_subaddress_lookahead_major, m_subaddress_lookahead_minor;
    std::string m_device_name;

    // Light wallet
    bool m_light_wallet; /* sends view key to daemon for scanning */
    uint64_t m_light_wallet_scanned_block_height;
    uint64_t m_light_wallet_blockchain_height;
    uint64_t m_light_wallet_per_kb_fee = FEE_PER_KB;
    bool m_light_wallet_connected;
    uint64_t m_light_wallet_balance;
    uint64_t m_light_wallet_unlocked_balance;
    // Light wallet info needed to populate m_payment requires 2 separate api calls (get_address_txs and get_unspent_outs)
    // We save the info from the first call in m_light_wallet_address_txs for easier lookup.
    std::unordered_map<crypto::hash, address_tx> m_light_wallet_address_txs;
    // store calculated key image for faster lookup
    std::unordered_map<crypto::public_key, std::map<uint64_t, crypto::key_image> > m_key_image_cache;

    std::string m_ring_database;
    bool m_ring_history_saved;
    std::unique_ptr<tools::ringdb> m_ringdb;
    boost::optional<crypto::chacha_key> m_ringdb_key;

    uint64_t m_last_block_reward;
    std::unique_ptr<tools::file_locker> m_keys_file_locker;

    crypto::chacha_key m_cache_key;
    boost::optional<epee::wipeable_string> m_encrypt_keys_after_refresh;

    bool m_unattended;

    std::shared_ptr<tools::Notify> m_tx_notify;
};


/** A key allocated from the key pool. */
class CReserveKey
{
protected:
    CWallet* pwallet;
    int64_t nIndex;
    CPubKey vchPubKey;

public:
    CReserveKey(CWallet* pwalletIn)
    {
        nIndex = -1;
        pwallet = pwalletIn;
    }

    ~CReserveKey()
    {
        ReturnKey();
    }

    void ReturnKey();
    bool GetReservedKey(CPubKey& pubkey);
    void KeepKey();
};


typedef std::map<std::string, std::string> mapValue_t;


static void ReadOrderPos(int64_t& nOrderPos, mapValue_t& mapValue)
{
    if (!mapValue.count("n")) {
        nOrderPos = -1; // TODO: calculate elsewhere
        return;
    }
    nOrderPos = atoi64(mapValue["n"].c_str());
}


static void WriteOrderPos(const int64_t& nOrderPos, mapValue_t& mapValue)
{
    if (nOrderPos == -1)
        return;
    mapValue["n"] = i64tostr(nOrderPos);
}

struct COutputEntry {
    CTxDestination destination;
    CAmount amount;
    int vout;
};

/** A transaction with a merkle branch linking it to the block chain. */
class CMerkleTx : public CTransaction
{
private:
    int GetDepthInMainChainINTERNAL(const CBlockIndex*& pindexRet) const;

public:
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;
    int nIndex;

    // memory only
    mutable bool fMerkleVerified;


    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = 0;
        nIndex = -1;
        fMerkleVerified = false;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(*(CTransaction*)this);
        nVersion = this->nVersion;
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    }

    int SetMerkleBranch(const CBlock& block);


    /**
     * Return depth of transaction in blockchain:
     * -1  : not in blockchain, and not in memory pool (conflicted transaction)
     *  0  : in memory pool, waiting to be included in a block
     * >=1 : this many blocks deep in the main chain
     */
    int GetDepthInMainChain(const CBlockIndex*& pindexRet, bool enableIX = true) const;
    int GetDepthInMainChain(bool enableIX = true) const
    {
        const CBlockIndex* pindexRet;
        return GetDepthInMainChain(pindexRet, enableIX);
    }
    bool IsInMainChain() const
    {
        const CBlockIndex* pindexRet;
        return GetDepthInMainChainINTERNAL(pindexRet) > 0;
    }
    int GetBlocksToMaturity() const;
    bool AcceptToMemoryPool(bool fLimitFree = true, bool fRejectInsaneFee = true, bool ignoreFees = false);
    int GetTransactionLockSignatures() const;
    bool IsTransactionLockTimedOut() const;
};

/**
 * A transaction with a bunch of additional info that only the owner cares about.
 * It includes any unrecorded transactions needed to link it back to the block chain.
 */
class CWalletTx : public CMerkleTx
{
private:
    const CWallet* pwallet;

public:
    mapValue_t mapValue;
    std::vector<std::pair<std::string, std::string> > vOrderForm;
    unsigned int fTimeReceivedIsTxTime;
    unsigned int nTimeReceived; //! time received by this node
    unsigned int nTimeSmart;
    char fFromMe;
    std::string strFromAccount;
    int64_t nOrderPos; //! position in ordered transaction list

    // memory only
    mutable bool fDebitCached;
    mutable bool fCreditCached;
    mutable bool fImmatureCreditCached;
    mutable bool fAvailableCreditCached;
    mutable bool fAnonymizableCreditCached;
    mutable bool fAnonymizedCreditCached;
    mutable bool fDenomUnconfCreditCached;
    mutable bool fDenomConfCreditCached;
    mutable bool fWatchDebitCached;
    mutable bool fWatchCreditCached;
    mutable bool fImmatureWatchCreditCached;
    mutable bool fAvailableWatchCreditCached;
    mutable bool fChangeCached;
    mutable CAmount nDebitCached;
    mutable CAmount nCreditCached;
    mutable CAmount nImmatureCreditCached;
    mutable CAmount nAvailableCreditCached;
    mutable CAmount nAnonymizableCreditCached;
    mutable CAmount nAnonymizedCreditCached;
    mutable CAmount nDenomUnconfCreditCached;
    mutable CAmount nDenomConfCreditCached;
    mutable CAmount nWatchDebitCached;
    mutable CAmount nWatchCreditCached;
    mutable CAmount nImmatureWatchCreditCached;
    mutable CAmount nAvailableWatchCreditCached;
    mutable CAmount nChangeCached;

    CWalletTx()
    {
        Init(NULL);
    }

    CWalletTx(const CWallet* pwalletIn)
    {
        Init(pwalletIn);
    }

    CWalletTx(const CWallet* pwalletIn, const CMerkleTx& txIn) : CMerkleTx(txIn)
    {
        Init(pwalletIn);
    }

    CWalletTx(const CWallet* pwalletIn, const CTransaction& txIn) : CMerkleTx(txIn)
    {
        Init(pwalletIn);
    }

    void Init(const CWallet* pwalletIn)
    {
        pwallet = pwalletIn;
        mapValue.clear();
        vOrderForm.clear();
        fTimeReceivedIsTxTime = false;
        nTimeReceived = 0;
        nTimeSmart = 0;
        fFromMe = false;
        strFromAccount.clear();
        fDebitCached = false;
        fCreditCached = false;
        fImmatureCreditCached = false;
        fAvailableCreditCached = false;
        fAnonymizableCreditCached = false;
        fAnonymizedCreditCached = false;
        fDenomUnconfCreditCached = false;
        fDenomConfCreditCached = false;
        fWatchDebitCached = false;
        fWatchCreditCached = false;
        fImmatureWatchCreditCached = false;
        fAvailableWatchCreditCached = false;
        fChangeCached = false;
        nDebitCached = 0;
        nCreditCached = 0;
        nImmatureCreditCached = 0;
        nAvailableCreditCached = 0;
        nAnonymizableCreditCached = 0;
        nAnonymizedCreditCached = 0;
        nDenomUnconfCreditCached = 0;
        nDenomConfCreditCached = 0;
        nWatchDebitCached = 0;
        nWatchCreditCached = 0;
        nAvailableWatchCreditCached = 0;
        nImmatureWatchCreditCached = 0;
        nChangeCached = 0;
        nOrderPos = -1;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        if (ser_action.ForRead())
            Init(NULL);
        char fSpent = false;

        if (!ser_action.ForRead()) {
            mapValue["fromaccount"] = strFromAccount;

            WriteOrderPos(nOrderPos, mapValue);

            if (nTimeSmart)
                mapValue["timesmart"] = strprintf("%u", nTimeSmart);
        }

        READWRITE(*(CMerkleTx*)this);
        std::vector<CMerkleTx> vUnused; //! Used to be vtxPrev
        READWRITE(vUnused);
        READWRITE(mapValue);
        READWRITE(vOrderForm);
        READWRITE(fTimeReceivedIsTxTime);
        READWRITE(nTimeReceived);
        READWRITE(fFromMe);
        READWRITE(fSpent);

        if (ser_action.ForRead()) {
            strFromAccount = mapValue["fromaccount"];

            ReadOrderPos(nOrderPos, mapValue);

            nTimeSmart = mapValue.count("timesmart") ? (unsigned int)atoi64(mapValue["timesmart"]) : 0;
        }

        mapValue.erase("fromaccount");
        mapValue.erase("version");
        mapValue.erase("spent");
        mapValue.erase("n");
        mapValue.erase("timesmart");
    }

    //! make sure balances are recalculated
    void MarkDirty()
    {
        fCreditCached = false;
        fAvailableCreditCached = false;
        fAnonymizableCreditCached = false;
        fAnonymizedCreditCached = false;
        fDenomUnconfCreditCached = false;
        fDenomConfCreditCached = false;
        fWatchDebitCached = false;
        fWatchCreditCached = false;
        fAvailableWatchCreditCached = false;
        fImmatureWatchCreditCached = false;
        fDebitCached = false;
        fChangeCached = false;
    }

    void BindWallet(CWallet* pwalletIn)
    {
        pwallet = pwalletIn;
        MarkDirty();
    }

    //! filter decides which addresses will count towards the debit
    CAmount GetDebit(const isminefilter& filter) const
    {
        if (vin.empty())
            return 0;

        CAmount debit = 0;
        if (filter & ISMINE_SPENDABLE) {
            if (fDebitCached)
                debit += nDebitCached;
            else {
                nDebitCached = pwallet->GetDebit(*this, ISMINE_SPENDABLE);
                fDebitCached = true;
                debit += nDebitCached;
            }
        }
        if (filter & ISMINE_WATCH_ONLY) {
            if (fWatchDebitCached)
                debit += nWatchDebitCached;
            else {
                nWatchDebitCached = pwallet->GetDebit(*this, ISMINE_WATCH_ONLY);
                fWatchDebitCached = true;
                debit += nWatchDebitCached;
            }
        }
        return debit;
    }

    CAmount GetCredit(const isminefilter& filter) const
    {
        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;

        CAmount credit = 0;
        if (filter & ISMINE_SPENDABLE) {
            // GetBalance can assume transactions in mapWallet won't change
            if (fCreditCached)
                credit += nCreditCached;
            else {
                nCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE);
                fCreditCached = true;
                credit += nCreditCached;
            }
        }
        if (filter & ISMINE_WATCH_ONLY) {
            if (fWatchCreditCached)
                credit += nWatchCreditCached;
            else {
                nWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY);
                fWatchCreditCached = true;
                credit += nWatchCreditCached;
            }
        }
        return credit;
    }

    CAmount GetImmatureCredit(bool fUseCache = true) const
    {
        if ((IsCoinBase() || IsCoinStake()) && GetBlocksToMaturity() > 0 && IsInMainChain()) {
            if (fUseCache && fImmatureCreditCached)
                return nImmatureCreditCached;
            nImmatureCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE);
            fImmatureCreditCached = true;
            return nImmatureCreditCached;
        }

        return 0;
    }

    CAmount GetAvailableCredit(bool fUseCache = true) const
    {
        if (pwallet == 0)
            return 0;

        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;

        if (fUseCache && fAvailableCreditCached)
            return nAvailableCreditCached;

        CAmount nCredit = 0;
        uint256 hashTx = GetHash();
        for (unsigned int i = 0; i < vout.size(); i++) {
            if (!pwallet->IsSpent(hashTx, i)) {
                const CTxOut& txout = vout[i];
                nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
                if (!MoneyRange(nCredit))
                    throw std::runtime_error("CWalletTx::GetAvailableCredit() : value out of range");
            }
        }

        nAvailableCreditCached = nCredit;
        fAvailableCreditCached = true;
        return nCredit;
    }

    CAmount GetAnonymizableCredit(bool fUseCache = true) const
    {
        if (pwallet == 0)
            return 0;

        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;

        if (fUseCache && fAnonymizableCreditCached)
            return nAnonymizableCreditCached;

        CAmount nCredit = 0;
        uint256 hashTx = GetHash();
        for (unsigned int i = 0; i < vout.size(); i++) {
            const CTxOut& txout = vout[i];
            const CTxIn vin = CTxIn(hashTx, i);

            if (pwallet->IsSpent(hashTx, i) || pwallet->IsLockedCoin(hashTx, i)) continue;
            if (fMasterNode && vout[i].nValue == 10000 * COIN) continue; // do not count MN-like outputs

            const int rounds = pwallet->GetInputObfuscationRounds(vin);
            if (rounds >= -2 && rounds < nZeromintPercentage) {
                nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
                if (!MoneyRange(nCredit))
                    throw std::runtime_error("CWalletTx::GetAnonamizableCredit() : value out of range");
            }
        }

        nAnonymizableCreditCached = nCredit;
        fAnonymizableCreditCached = true;
        return nCredit;
    }

    CAmount GetAnonymizedCredit(bool fUseCache = true) const
    {
        if (pwallet == 0)
            return 0;

        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;

        if (fUseCache && fAnonymizedCreditCached)
            return nAnonymizedCreditCached;

        CAmount nCredit = 0;
        uint256 hashTx = GetHash();
        for (unsigned int i = 0; i < vout.size(); i++) {
            const CTxOut& txout = vout[i];
            const CTxIn vin = CTxIn(hashTx, i);

            if (pwallet->IsSpent(hashTx, i) || !pwallet->IsDenominated(vin)) continue;

            const int rounds = pwallet->GetInputObfuscationRounds(vin);
            if (rounds >= nZeromintPercentage) {
                nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
                if (!MoneyRange(nCredit))
                    throw std::runtime_error("CWalletTx::GetAnonymizedCredit() : value out of range");
            }
        }

        nAnonymizedCreditCached = nCredit;
        fAnonymizedCreditCached = true;
        return nCredit;
    }

    // Return sum of unlocked coins
    CAmount GetUnlockedCredit() const
    {
        if (pwallet == 0)
            return 0;

        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;

        CAmount nCredit = 0;
        uint256 hashTx = GetHash();
        for (unsigned int i = 0; i < vout.size(); i++) {
            const CTxOut& txout = vout[i];

            if (pwallet->IsSpent(hashTx, i) || pwallet->IsLockedCoin(hashTx, i)) continue;
            if (fMasterNode && vout[i].nValue == 10000 * COIN) continue; // do not count MN-like outputs

            nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetUnlockedCredit() : value out of range");
        }

        return nCredit;
    }

        // Return sum of unlocked coins
    CAmount GetLockedCredit() const
    {
        if (pwallet == 0)
            return 0;

        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;

        CAmount nCredit = 0;
        uint256 hashTx = GetHash();
        for (unsigned int i = 0; i < vout.size(); i++) {
            const CTxOut& txout = vout[i];

            // Skip spent coins
            if (pwallet->IsSpent(hashTx, i)) continue;

            // Add locked coins
            if (pwallet->IsLockedCoin(hashTx, i)) {
                nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
            }

            // Add masternode collaterals which are handled likc locked coins
            if (fMasterNode && vout[i].nValue == 10000 * COIN) {
                nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
            }

            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetLockedCredit() : value out of range");
        }

        return nCredit;
    }

    CAmount GetDenominatedCredit(bool unconfirmed, bool fUseCache = true) const
    {
        if (pwallet == 0)
            return 0;

        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;

        int nDepth = GetDepthInMainChain(false);
        if (nDepth < 0) return 0;

        bool isUnconfirmed = !IsFinalTx(*this) || (!IsTrusted() && nDepth == 0);
        if (unconfirmed != isUnconfirmed) return 0;

        if (fUseCache) {
            if (unconfirmed && fDenomUnconfCreditCached)
                return nDenomUnconfCreditCached;
            else if (!unconfirmed && fDenomConfCreditCached)
                return nDenomConfCreditCached;
        }

        CAmount nCredit = 0;
        uint256 hashTx = GetHash();
        for (unsigned int i = 0; i < vout.size(); i++) {
            const CTxOut& txout = vout[i];

            if (pwallet->IsSpent(hashTx, i) || !pwallet->IsDenominatedAmount(vout[i].nValue)) continue;

            nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetDenominatedCredit() : value out of range");
        }

        if (unconfirmed) {
            nDenomUnconfCreditCached = nCredit;
            fDenomUnconfCreditCached = true;
        } else {
            nDenomConfCreditCached = nCredit;
            fDenomConfCreditCached = true;
        }
        return nCredit;
    }

    CAmount GetImmatureWatchOnlyCredit(const bool& fUseCache = true) const
    {
        if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain()) {
            if (fUseCache && fImmatureWatchCreditCached)
                return nImmatureWatchCreditCached;
            nImmatureWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY);
            fImmatureWatchCreditCached = true;
            return nImmatureWatchCreditCached;
        }

        return 0;
    }

    CAmount GetAvailableWatchOnlyCredit(const bool& fUseCache = true) const
    {
        if (pwallet == 0)
            return 0;

        // Must wait until coinbase is safely deep enough in the chain before valuing it
        if (IsCoinBase() && GetBlocksToMaturity() > 0)
            return 0;

        if (fUseCache && fAvailableWatchCreditCached)
            return nAvailableWatchCreditCached;

        CAmount nCredit = 0;
        for (unsigned int i = 0; i < vout.size(); i++) {
            if (!pwallet->IsSpent(GetHash(), i)) {
                const CTxOut& txout = vout[i];
                nCredit += pwallet->GetCredit(txout, ISMINE_WATCH_ONLY);
                if (!MoneyRange(nCredit))
                    throw std::runtime_error("CWalletTx::GetAvailableCredit() : value out of range");
            }
        }

        nAvailableWatchCreditCached = nCredit;
        fAvailableWatchCreditCached = true;
        return nCredit;
    }

    CAmount GetChange() const
    {
        if (fChangeCached)
            return nChangeCached;
        nChangeCached = pwallet->GetChange(*this);
        fChangeCached = true;
        return nChangeCached;
    }

    void GetAmounts(std::list<COutputEntry>& listReceived,
        std::list<COutputEntry>& listSent,
        CAmount& nFee,
        std::string& strSentAccount,
        const isminefilter& filter) const;

    void GetAccountAmounts(const std::string& strAccount, CAmount& nReceived, CAmount& nSent, CAmount& nFee, const isminefilter& filter) const;

    bool IsFromMe(const isminefilter& filter) const
    {
        return (GetDebit(filter) > 0);
    }

    bool InMempool() const;

    bool IsTrusted() const
    {
        // Quick answer in most cases
        if (!IsFinalTx(*this))
            return false;
        int nDepth = GetDepthInMainChain();
        if (nDepth >= 1)
            return true;
        if (nDepth < 0)
            return false;
        if (!bSpendZeroConfChange || !IsFromMe(ISMINE_ALL)) // using wtx's cached debit
            return false;

        // Trusted if all inputs are from us and are in the mempool:
        BOOST_FOREACH (const CTxIn& txin, vin) {
            // Transactions not sent by us: not trusted
            const CWalletTx* parent = pwallet->GetWalletTx(txin.prevout.hash);
            if (parent == NULL)
                return false;
            const CTxOut& parentOut = parent->vout[txin.prevout.n];
            if (pwallet->IsMine(parentOut) != ISMINE_SPENDABLE)
                return false;
        }
        return true;
    }

    bool WriteToDisk();

    int64_t GetTxTime() const;
    int64_t GetComputedTxTime() const;
    int GetRequestCount() const;
    void RelayWalletTransaction(std::string strCommand = "tx");

    std::set<uint256> GetConflicts() const;
};


class COutput
{
public:
    const CWalletTx* tx;
    int i;
    int nDepth;
    bool fSpendable;

    COutput(const CWalletTx* txIn, int iIn, int nDepthIn, bool fSpendableIn)
    {
        tx = txIn;
        i = iIn;
        nDepth = nDepthIn;
        fSpendable = fSpendableIn;
    }

    //Used with Obfuscation. Will return largest nondenom, then denominations, then very small inputs
    int Priority() const
    {
        BOOST_FOREACH (CAmount d, obfuScationDenominations)
            if (tx->vout[i].nValue == d) return 10000;
        if (tx->vout[i].nValue < 1 * COIN) return 20000;

        //nondenom return largest first
        return -(tx->vout[i].nValue / COIN);
    }

    CAmount Value() const
    {
        return tx->vout[i].nValue;
    }

    std::string ToString() const;
};


/** Private key that includes an expiration date in case it never gets used. */
class CWalletKey
{
public:
    CPrivKey vchPrivKey;
    int64_t nTimeCreated;
    int64_t nTimeExpires;
    std::string strComment;
    //! todo: add something to note what created it (user, getnewaddress, change)
    //!   maybe should have a map<string, string> property map

    CWalletKey(int64_t nExpires = 0);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPrivKey);
        READWRITE(nTimeCreated);
        READWRITE(nTimeExpires);
        READWRITE(LIMITED_STRING(strComment, 65536));
    }
};


/**
 * Account information.
 * Stored in wallet with key "acc"+string account name.
 */
class CAccount
{
public:
    CPubKey vchPubKey;

    CAccount()
    {
        SetNull();
    }

    void SetNull()
    {
        vchPubKey = CPubKey();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vchPubKey);
    }
};


/**
 * Internal transfers.
 * Database key is acentry<account><counter>.
 */
class CAccountingEntry
{
public:
    std::string strAccount;
    CAmount nCreditDebit;
    int64_t nTime;
    std::string strOtherAccount;
    std::string strComment;
    mapValue_t mapValue;
    int64_t nOrderPos; //! position in ordered transaction list
    uint64_t nEntryNo;

    CAccountingEntry()
    {
        SetNull();
    }

    void SetNull()
    {
        nCreditDebit = 0;
        nTime = 0;
        strAccount.clear();
        strOtherAccount.clear();
        strComment.clear();
        nOrderPos = -1;
        nEntryNo = 0;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        //! Note: strAccount is serialized as part of the key, not here.
        READWRITE(nCreditDebit);
        READWRITE(nTime);
        READWRITE(LIMITED_STRING(strOtherAccount, 65536));

        if (!ser_action.ForRead()) {
            WriteOrderPos(nOrderPos, mapValue);

            if (!(mapValue.empty() && _ssExtra.empty())) {
                CDataStream ss(nType, nVersion);
                ss.insert(ss.begin(), '\0');
                ss << mapValue;
                ss.insert(ss.end(), _ssExtra.begin(), _ssExtra.end());
                strComment.append(ss.str());
            }
        }

        READWRITE(LIMITED_STRING(strComment, 65536));

        size_t nSepPos = strComment.find("\0", 0, 1);
        if (ser_action.ForRead()) {
            mapValue.clear();
            if (std::string::npos != nSepPos) {
                CDataStream ss(std::vector<char>(strComment.begin() + nSepPos + 1, strComment.end()), nType, nVersion);
                ss >> mapValue;
                _ssExtra = std::vector<char>(ss.begin(), ss.end());
            }
            ReadOrderPos(nOrderPos, mapValue);
        }
        if (std::string::npos != nSepPos)
            strComment.erase(nSepPos);

        mapValue.erase("n");
    }

private:
    std::vector<char> _ssExtra;
};

#endif // BITCOIN_WALLET_H
