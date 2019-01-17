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

bool CWallet::generate_key_image_helper(const CPubKey& pubkey, CKeyImage& img) {

}

//---------------------------------------------------------------
  bool CWallet::construct_tx_with_tx_key(std::vector<tx_source_entry>& sources, std::vector<tx_destination_entry>& destinations, const boost::optional<CStealthAccount>& change_addr, const std::vector<uint8_t> &extra, CTransaction& tx, const CKey &tx_key, bool shuffle_outs)
  {
    if (sources.empty())
    {
      LogPrintf("Empty sources");
      return false;
    }

    std::vector<rct::key> amount_keys;
    tx.set_null();
    amount_keys.clear();

    //Key image used for spending a transaction input
    struct input_generation_context_data
    {
      Keypair in_ephemeral;
    };
    std::vector<input_generation_context_data> in_contexts;

    uint64_t summary_inputs_money = 0;
    //fill inputs
    int idx = -1;
    for(const tx_source_entry& src_entr:  sources)
    {
      ++idx;
      if(src_entr.real_output >= src_entr.outputs.size())
      {
        LogPrintf("real_output index (" << src_entr.real_output << ")bigger than output_keys.size()=" << src_entr.outputs.size());
        return false;
      }
      summary_inputs_money += src_entr.amount;

      //key_derivation recv_derivation;
      in_contexts.push_back(input_generation_context_data());
      Keypair& in_ephemeral = in_contexts.back().in_ephemeral;
      CKeyImage img;
      const auto& out_key = reinterpret_cast<const CPubKey&>(src_entr.outputs[src_entr.real_output].second.dest);
      if(!generate_key_image_helper(out_key, img))
      {
        LogPrintf("Key image generation failed!");
        return false;
      }

      //check that derivated key is equal with real output key (if non multisig)
      if(!(in_ephemeral.pub == src_entr.outputs[src_entr.real_output].second.dest) )
      {
        LogPrintf("derived public key mismatch with output public key at index " << idx << ", real out " << src_entr.real_output << "! "<< ENDL << "derived_key:"
          << string_tools::pod_to_hex(in_ephemeral.pub) << ENDL << "real output_public_key:"
          << string_tools::pod_to_hex(src_entr.outputs[src_entr.real_output].second.dest) );
        LogPrintf("amount " << src_entr.amount);
        LogPrintf("tx pubkey " << src_entr.real_out_tx_key << ", real_output_in_tx_index " << src_entr.real_output_in_tx_index);
        return false;
      }

      tx.keyImages.push_back(img);
    }

    if (shuffle_outs)
    {
      std::shuffle(destinations.begin(), destinations.end(), std::default_random_engine(crypto::rand<unsigned int>()));
    }

    // sort ins by their key image
    std::vector<size_t> ins_order(sources.size());
    for (size_t n = 0; n < sources.size(); ++n)
      ins_order[n] = n;
      std::sort(ins_order.begin(), ins_order.end(), [&](const size_t i0, const size_t i1) {
        const txin_to_key &tk0 = boost::get<txin_to_key>(tx.vin[i0]);
        const txin_to_key &tk1 = boost::get<txin_to_key>(tx.vin[i1]);
        return memcmp(&tk0.k_image, &tk1.k_image, sizeof(tk0.k_image)) > 0;
      });
    tools::apply_permutation(ins_order, [&] (size_t i0, size_t i1) {
      std::swap(tx.vin[i0], tx.vin[i1]);
      std::swap(in_contexts[i0], in_contexts[i1]);
      std::swap(sources[i0], sources[i1]);
    });

    // figure out if we need to make additional tx pubkeys
    size_t num_stdaddresses = 0;
    size_t num_subaddresses = 0;
    account_public_address single_dest_subaddress;
    classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);

    // if this is a single-destination transfer to a subaddress, we set the tx pubkey to R=s*D
    if (num_stdaddresses == 0 && num_subaddresses == 1)
    {
      txkey_pub = rct::rct2pk(hwdev.scalarmultKey(rct::pk2rct(single_dest_subaddress.m_spend_public_key), rct::sk2rct(tx_key)));
    }
    else
    {
      txkey_pub = rct::rct2pk(hwdev.scalarmultBase(rct::sk2rct(tx_key)));
    }
    remove_field_from_tx_extra(tx.extra, typeid(tx_extra_pub_key));
    add_tx_pub_key_to_extra(tx, txkey_pub);

    std::vector<crypto::public_key> additional_tx_public_keys;

    // we don't need to include additional tx keys if:
    //   - all the destinations are standard addresses
    //   - there's only one destination which is a subaddress
    bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
    if (need_additional_txkeys)
      CHECK_AND_ASSERT_MES(destinations.size() == additional_tx_keys.size(), false, "Wrong amount of additional tx keys");

    uint64_t summary_outs_money = 0;
    //fill outputs
    size_t output_index = 0;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      CHECK_AND_ASSERT_MES(dst_entr.amount > 0 || tx.version > 1, false, "Destination with wrong amount: " << dst_entr.amount);
      crypto::key_derivation derivation;
      crypto::public_key out_eph_public_key;

      // make additional tx pubkey if necessary
      keypair additional_txkey;
      if (need_additional_txkeys)
      {
        additional_txkey.sec = additional_tx_keys[output_index];
        if (dst_entr.is_subaddress)
          additional_txkey.pub = rct::rct2pk(hwdev.scalarmultKey(rct::pk2rct(dst_entr.addr.m_spend_public_key), rct::sk2rct(additional_txkey.sec)));
        else
          additional_txkey.pub = rct::rct2pk(hwdev.scalarmultBase(rct::sk2rct(additional_txkey.sec)));
      }

      bool r;
      if (change_addr && dst_entr.addr == *change_addr)
      {
        // sending change to yourself; derivation = a*R
        r = hwdev.generate_key_derivation(txkey_pub, sender_account_keys.m_view_secret_key, derivation);
        CHECK_AND_ASSERT_MES(r, false, "at creation outs: failed to generate_key_derivation(" << txkey_pub << ", " << sender_account_keys.m_view_secret_key << ")");
      }
      else
      {
        // sending to the recipient; derivation = r*A (or s*C in the subaddress scheme)
        r = hwdev.generate_key_derivation(dst_entr.addr.m_view_public_key, dst_entr.is_subaddress && need_additional_txkeys ? additional_txkey.sec : tx_key, derivation);
        CHECK_AND_ASSERT_MES(r, false, "at creation outs: failed to generate_key_derivation(" << dst_entr.addr.m_view_public_key << ", " << (dst_entr.is_subaddress && need_additional_txkeys ? additional_txkey.sec : tx_key) << ")");
      }

      if (need_additional_txkeys)
      {
        additional_tx_public_keys.push_back(additional_txkey.pub);
      }

      if (tx.version > 1)
      {
        crypto::secret_key scalar1;
        hwdev.derivation_to_scalar(derivation, output_index, scalar1);
        amount_keys.push_back(rct::sk2rct(scalar1));
      }
      r = hwdev.derive_public_key(derivation, output_index, dst_entr.addr.m_spend_public_key, out_eph_public_key);
      CHECK_AND_ASSERT_MES(r, false, "at creation outs: failed to derive_public_key(" << derivation << ", " << output_index << ", "<< dst_entr.addr.m_spend_public_key << ")");

      hwdev.add_output_key_mapping(dst_entr.addr.m_view_public_key, dst_entr.addr.m_spend_public_key, dst_entr.is_subaddress, output_index, amount_keys.back(), out_eph_public_key);

      tx_out out;
      out.amount = dst_entr.amount;
      txout_to_key tk;
      tk.key = out_eph_public_key;
      out.target = tk;
      tx.vout.push_back(out);
      output_index++;
      summary_outs_money += dst_entr.amount;
    }
    CHECK_AND_ASSERT_MES(additional_tx_public_keys.size() == additional_tx_keys.size(), false, "Internal error creating additional public keys");

    remove_field_from_tx_extra(tx.extra, typeid(tx_extra_additional_pub_keys));

    LOG_PRINT_L2("tx pubkey: " << txkey_pub);
    if (need_additional_txkeys)
    {
      LOG_PRINT_L2("additional tx pubkeys: ");
      for (size_t i = 0; i < additional_tx_public_keys.size(); ++i)
        LOG_PRINT_L2(additional_tx_public_keys[i]);
      add_additional_tx_pub_keys_to_extra(tx.extra, additional_tx_public_keys);
    }

    if (!sort_tx_extra(tx.extra, tx.extra))
      return false;

    //check money
    if(summary_outs_money > summary_inputs_money )
    {
      LOG_ERROR("Transaction inputs money ("<< summary_inputs_money << ") less than outputs money (" << summary_outs_money << ")");
      return false;
    }

    // check for watch only wallet
    bool zero_secret_key = true;
    for (size_t i = 0; i < sizeof(sender_account_keys.m_spend_secret_key); ++i)
      zero_secret_key &= (sender_account_keys.m_spend_secret_key.data[i] == 0);
    if (zero_secret_key)
    {
      MDEBUG("Null secret key, skipping signatures");
    }

    if (tx.version == 1)
    {
      //generate ring signatures
      crypto::hash tx_prefix_hash;
      get_transaction_prefix_hash(tx, tx_prefix_hash);

      std::stringstream ss_ring_s;
      size_t i = 0;
      for(const tx_source_entry& src_entr:  sources)
      {
        ss_ring_s << "pub_keys:" << ENDL;
        std::vector<const crypto::public_key*> keys_ptrs;
        std::vector<crypto::public_key> keys(src_entr.outputs.size());
        size_t ii = 0;
        for(const tx_source_entry::output_entry& o: src_entr.outputs)
        {
          keys[ii] = rct2pk(o.second.dest);
          keys_ptrs.push_back(&keys[ii]);
          ss_ring_s << o.second.dest << ENDL;
          ++ii;
        }

        tx.signatures.push_back(std::vector<crypto::signature>());
        std::vector<crypto::signature>& sigs = tx.signatures.back();
        sigs.resize(src_entr.outputs.size());
        if (!zero_secret_key)
          crypto::generate_ring_signature(tx_prefix_hash, boost::get<txin_to_key>(tx.vin[i]).k_image, keys_ptrs, in_contexts[i].in_ephemeral.sec, src_entr.real_output, sigs.data());
        ss_ring_s << "signatures:" << ENDL;
        std::for_each(sigs.begin(), sigs.end(), [&](const crypto::signature& s){ss_ring_s << s << ENDL;});
        ss_ring_s << "prefix_hash:" << tx_prefix_hash << ENDL << "in_ephemeral_key: " << in_contexts[i].in_ephemeral.sec << ENDL << "real_output: " << src_entr.real_output << ENDL;
        i++;
      }

      MCINFO("construct_tx", "transaction_created: " << get_transaction_hash(tx) << ENDL << obj_to_json_str(tx) << ENDL << ss_ring_s.str());
    }
    else
    {
      size_t n_total_outs = sources[0].outputs.size(); // only for non-simple rct

      // the non-simple version is slightly smaller, but assumes all real inputs
      // are on the same index, so can only be used if there just one ring.
      bool use_simple_rct = sources.size() > 1 || range_proof_type != rct::RangeProofBorromean;

      if (!use_simple_rct)
      {
        // non simple ringct requires all real inputs to be at the same index for all inputs
        for(const tx_source_entry& src_entr:  sources)
        {
          if(src_entr.real_output != sources.begin()->real_output)
          {
            LOG_ERROR("All inputs must have the same index for non-simple ringct");
            return false;
          }
        }

        // enforce same mixin for all outputs
        for (size_t i = 1; i < sources.size(); ++i) {
          if (n_total_outs != sources[i].outputs.size()) {
            LOG_ERROR("Non-simple ringct transaction has varying ring size");
            return false;
          }
        }
      }

      uint64_t amount_in = 0, amount_out = 0;
      rct::ctkeyV inSk;
      inSk.reserve(sources.size());
      // mixRing indexing is done the other way round for simple
      rct::ctkeyM mixRing(use_simple_rct ? sources.size() : n_total_outs);
      rct::keyV destinations;
      std::vector<uint64_t> inamounts, outamounts;
      std::vector<unsigned int> index;
      std::vector<rct::multisig_kLRki> kLRki;
      for (size_t i = 0; i < sources.size(); ++i)
      {
        rct::ctkey ctkey;
        amount_in += sources[i].amount;
        inamounts.push_back(sources[i].amount);
        index.push_back(sources[i].real_output);
        // inSk: (secret key, mask)
        ctkey.dest = rct::sk2rct(in_contexts[i].in_ephemeral.sec);
        ctkey.mask = sources[i].mask;
        inSk.push_back(ctkey);
        memwipe(&ctkey, sizeof(rct::ctkey));
        // inPk: (public key, commitment)
        // will be done when filling in mixRing
        if (msout)
        {
          kLRki.push_back(sources[i].multisig_kLRki);
        }
      }
      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        destinations.push_back(rct::pk2rct(boost::get<txout_to_key>(tx.vout[i].target).key));
        outamounts.push_back(tx.vout[i].amount);
        amount_out += tx.vout[i].amount;
      }

      if (use_simple_rct)
      {
        // mixRing indexing is done the other way round for simple
        for (size_t i = 0; i < sources.size(); ++i)
        {
          mixRing[i].resize(sources[i].outputs.size());
          for (size_t n = 0; n < sources[i].outputs.size(); ++n)
          {
            mixRing[i][n] = sources[i].outputs[n].second;
          }
        }
      }
      else
      {
        for (size_t i = 0; i < n_total_outs; ++i) // same index assumption
        {
          mixRing[i].resize(sources.size());
          for (size_t n = 0; n < sources.size(); ++n)
          {
            mixRing[i][n] = sources[n].outputs[i].second;
          }
        }
      }

      // fee
      if (!use_simple_rct && amount_in > amount_out)
        outamounts.push_back(amount_in - amount_out);

      // zero out all amounts to mask rct outputs, real amounts are now encrypted
      for (size_t i = 0; i < tx.vin.size(); ++i)
      {
        if (sources[i].rct)
          boost::get<txin_to_key>(tx.vin[i]).amount = 0;
      }
      for (size_t i = 0; i < tx.vout.size(); ++i)
        tx.vout[i].amount = 0;

      crypto::hash tx_prefix_hash;
      get_transaction_prefix_hash(tx, tx_prefix_hash);
      rct::ctkeyV outSk;
      if (use_simple_rct)
        tx.rct_signatures = rct::genRctSimple(rct::hash2rct(tx_prefix_hash), inSk, destinations, inamounts, outamounts, amount_in - amount_out, mixRing, amount_keys, msout ? &kLRki : NULL, msout, index, outSk, range_proof_type, hwdev);
      else
        tx.rct_signatures = rct::genRct(rct::hash2rct(tx_prefix_hash), inSk, destinations, outamounts, mixRing, amount_keys, msout ? &kLRki[0] : NULL, msout, sources[0].real_output, outSk, hwdev); // same index assumption
      memwipe(inSk.data(), inSk.size() * sizeof(rct::ctkey));

      CHECK_AND_ASSERT_MES(tx.vout.size() == outSk.size(), false, "outSk size does not match vout");

      MCINFO("construct_tx", "transaction_created: " << get_transaction_hash(tx) << ENDL << obj_to_json_str(tx) << ENDL);
    }

    tx.invalidate_hashes();

    return true;
  }
  //---------------------------------------------------------------
  bool construct_tx_and_get_tx_key(std::vector<tx_source_entry>& sources, 
        std::vector<tx_destination_entry>& destinations, 
        const boost::optional<CStealthAccount>& change_addr, 
        const std::vector<uint8_t> &extra, 
        CTransaction& tx, 
        CKey& txPrivKey)
  {
    // TODO: figure out if we need to make additional tx pubkeys
    bool r = construct_tx_with_tx_key(sources, destinations, change_addr, extra, tx, unlock_time, tx_key, additional_tx_keys, rct, range_proof_type, msout);
    return r;
  }