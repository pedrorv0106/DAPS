// Copyright (c) 2014-2018, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// make_new
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <numeric>
#include <random>
#include <tuple>
#include <boost/format.hpp>
#include <boost/optional/optional.hpp>
#include <boost/utility/value_init.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/split.hpp>
#include "privacy/epee/include/include_base_utils.h"
using namespace epee;

#include "privacy/cryptonote_config.h"
#include "privacy/cryptonote_basic/cryptonote_format_utils.h"
#include "privacy/rpc/core_rpc_server_commands_defs.h"
#include "privacy/epee/include/misc_language.h"
#include "privacy/cryptonote_basic/cryptonote_basic_impl.h"
#include "privacy/common/boost_serialization_helper.h"
#include "privacy/common/command_line.h"
#include "privacy/common/threadpool.h"
//#include "profile_tools.h"
#include "privacy/crypto/crypto.h"
#include "privacy/serialization/binary_utils.h"
#include "privacy/serialization/string.h"
//#include "privacy/cryptonote_basic/blobdatatype.h"
#include "privacy/mnemonics/electrum-words.h"
#include "privacy/common/i18n.h"
#include "privacy/common/util.h"
#include "privacy/common/apply_permutation.h"
//#include "rapidjson/document.h"
//#include "rapidjson/writer.h"
//#include "rapidjson/stringbuffer.h"
#include "privacy/common/json_util.h"
#include "privacy/epee/include/memwipe.h"
#include "privacy/common/base58.h"
#include "privacy/common/dns_utils.h"
#include "privacy/common/notify.h"
#include "privacy/ringct/rctSigs.h"
#include "privacy/wallet/ringdb.h"
#include "wallet.h"

extern "C"
{
#include "privacy/crypto/keccak.h"
#include "privacy/crypto/crypto-ops.h"
}
using namespace std;
using namespace crypto;
using namespace cryptonote;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.CWallet"

// used to choose when to stop adding outputs to a tx
#define APPROXIMATE_INPUT_BYTES 80

// used to target a given block weight (additional outputs may be added on top to build fee)
#define TX_WEIGHT_TARGET(bytes) (bytes*2/3)

// arbitrary, used to generate different hashes from the same input
#define CHACHA8_KEY_TAIL 0x8c
#define CACHE_KEY_TAIL 0x8d

#define UNSIGNED_TX_PREFIX "Monero unsigned tx set\004"
#define SIGNED_TX_PREFIX "Monero signed tx set\004"
#define MULTISIG_UNSIGNED_TX_PREFIX "Monero multisig unsigned tx set\001"

#define RECENT_OUTPUT_RATIO (0.5) // 50% of outputs are from the recent zone
#define RECENT_OUTPUT_DAYS (1.8) // last 1.8 day makes up the recent zone (taken from monerolink.pdf, Miller et al)
#define RECENT_OUTPUT_ZONE ((time_t)(RECENT_OUTPUT_DAYS * 86400))
#define RECENT_OUTPUT_BLOCKS (RECENT_OUTPUT_DAYS * 720)

#define FEE_ESTIMATE_GRACE_BLOCKS 10 // estimate fee valid for that many blocks

#define SECOND_OUTPUT_RELATEDNESS_THRESHOLD 0.0f

#define SUBADDRESS_LOOKAHEAD_MAJOR 50
#define SUBADDRESS_LOOKAHEAD_MINOR 200

#define KEY_IMAGE_EXPORT_FILE_MAGIC "Monero key image export\002"

#define MULTISIG_EXPORT_FILE_MAGIC "Monero multisig export\001"

#define OUTPUT_EXPORT_FILE_MAGIC "Monero output export\003"

#define SEGREGATION_FORK_HEIGHT 99999999
#define TESTNET_SEGREGATION_FORK_HEIGHT 99999999
#define STAGENET_SEGREGATION_FORK_HEIGHT 99999999
#define SEGREGATION_FORK_VICINITY 1500 /* blocks */

#define FIRST_REFRESH_GRANULARITY     1024

#define GAMMA_PICK_HALF_WINDOW 5

static const std::string MULTISIG_SIGNATURE_MAGIC = "SigMultisigPkV1";
static const std::string MULTISIG_EXTRA_INFO_MAGIC = "MultisigxV1";

namespace
{
  std::string get_default_ringdb_path()
  {
    boost::filesystem::path dir = tools::get_default_data_dir();
    // remove .bitmonero, replace with .shared-ringdb
    dir = dir.remove_filename();
    dir /= ".shared-ringdb";
    return dir.string();
  }

  std::vector<crypto::public_key> secret_keys_to_public_keys(const std::vector<crypto::secret_key>& keys)
  {
    std::vector<crypto::public_key> public_keys;
    public_keys.reserve(keys.size());

    std::transform(keys.begin(), keys.end(), std::back_inserter(public_keys), [] (const crypto::secret_key& k) -> crypto::public_key {
      crypto::public_key p;
      CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(k, p), "Failed to derive public spend key");
      return p;
    });

    return public_keys;
  }
}

namespace
{
// Create on-demand to prevent static initialization order fiasco issues.
struct options {
  const command_line::arg_descriptor<std::string> daemon_address = {"daemon-address", CWallet::tr("Use daemon instance at <host>:<port>"), ""};
  const command_line::arg_descriptor<std::string> daemon_host = {"daemon-host", CWallet::tr("Use daemon instance at host <arg> instead of localhost"), ""};
  const command_line::arg_descriptor<bool> trusted_daemon = {"trusted-daemon", CWallet::tr("Enable commands which rely on a trusted daemon"), false};
  const command_line::arg_descriptor<bool> untrusted_daemon = {"untrusted-daemon", CWallet::tr("Disable commands which rely on a trusted daemon"), false};
  const command_line::arg_descriptor<std::string> password = {"password", CWallet::tr("Wallet password (escape/quote as needed)"), "", true};
  const command_line::arg_descriptor<std::string> password_file = {"password-file", CWallet::tr("Wallet password file"), "", true};
  const command_line::arg_descriptor<int> daemon_port = {"daemon-port", CWallet::tr("Use daemon instance at port <arg> instead of 18081"), 0};
  const command_line::arg_descriptor<std::string> daemon_login = {"daemon-login", CWallet::tr("Specify username[:password] for daemon RPC client"), "", true};
  const command_line::arg_descriptor<bool> testnet = {"testnet", CWallet::tr("For testnet. Daemon must also be launched with --testnet flag"), false};
  const command_line::arg_descriptor<bool> stagenet = {"stagenet", CWallet::tr("For stagenet. Daemon must also be launched with --stagenet flag"), false};
  const command_line::arg_descriptor<std::string, false, true, 2> shared_ringdb_dir = {
    "shared-ringdb-dir", CWallet::tr("Set shared ring database path"),
    get_default_ringdb_path(),
    {{ &testnet, &stagenet }},
    [](std::array<bool, 2> testnet_stagenet, bool defaulted, std::string val)->std::string {
      if (testnet_stagenet[0])
        return (boost::filesystem::path(val) / "testnet").string();
      else if (testnet_stagenet[1])
        return (boost::filesystem::path(val) / "stagenet").string();
      return val;
    }
  };
  const command_line::arg_descriptor<uint64_t> kdf_rounds = {"kdf-rounds", CWallet::tr("Number of rounds for the key derivation function"), 1};
  const command_line::arg_descriptor<std::string> hw_device = {"hw-device", CWallet::tr("HW device to use"), ""};
  const command_line::arg_descriptor<std::string> tx_notify = { "tx-notify" , "Run a program for each new incoming transaction, '%s' will be replaced by the transaction hash" , "" };
};

void do_prepare_file_names(const std::string& file_path, std::string& keys_file, std::string& wallet_file)
{
  keys_file = file_path;
  wallet_file = file_path;
  boost::system::error_code e;
  if(string_tools::get_extension(keys_file) == "keys")
  {//provided keys file name
    wallet_file = string_tools::cut_off_extension(wallet_file);
  }else
  {//provided wallet file name
    keys_file += ".keys";
  }
}

uint64_t calculate_fee(uint64_t fee_per_kb, size_t bytes, uint64_t fee_multiplier)
{
  uint64_t kB = (bytes + 1023) / 1024;
  return kB * fee_per_kb * fee_multiplier;
}

uint64_t calculate_fee_from_weight(uint64_t base_fee, uint64_t weight, uint64_t fee_multiplier, uint64_t fee_quantization_mask)
{
  uint64_t fee = weight * base_fee * fee_multiplier;
  fee = (fee + fee_quantization_mask - 1) / fee_quantization_mask * fee_quantization_mask;
  return fee;
}

std::string get_weight_string(size_t weight)
{
  return std::to_string(weight) + " weight";
}

std::string get_weight_string(const cryptonote::transaction &tx, size_t blob_size)
{
  return get_weight_string(get_transaction_weight(tx, blob_size));
}

std::unique_ptr<CWallet> make_basic(const boost::program_options::variables_map& vm, bool unattended, const options& opts, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const bool testnet = command_line::get_arg(vm, opts.testnet);
  const bool stagenet = command_line::get_arg(vm, opts.stagenet);
  const network_type nettype = testnet ? TESTNET : stagenet ? STAGENET : MAINNET;
  const uint64_t kdf_rounds = command_line::get_arg(vm, opts.kdf_rounds);
  THROW_WALLET_EXCEPTION_IF(kdf_rounds == 0, tools::error::wallet_internal_error, "KDF rounds must not be 0");

  auto daemon_address = command_line::get_arg(vm, opts.daemon_address);
  auto daemon_host = command_line::get_arg(vm, opts.daemon_host);
  auto daemon_port = command_line::get_arg(vm, opts.daemon_port);
  auto device_name = command_line::get_arg(vm, opts.hw_device);

  THROW_WALLET_EXCEPTION_IF(!daemon_address.empty() && !daemon_host.empty() && 0 != daemon_port,
      tools::error::wallet_internal_error, CWallet::tr("can't specify daemon host or port more than once"));

  boost::optional<epee::net_utils::http::login> login{};
  if (command_line::has_arg(vm, opts.daemon_login))
  {
    auto parsed = tools::login::parse(
      command_line::get_arg(vm, opts.daemon_login), false, [password_prompter](bool verify) {
        return password_prompter("Daemon client password", verify);
      }
    );
    if (!parsed)
      return nullptr;

    login.emplace(std::move(parsed->username), std::move(parsed->password).password());
  }

  if (daemon_host.empty())
    daemon_host = "localhost";

  if (!daemon_port)
  {
    daemon_port = get_config(nettype).RPC_DEFAULT_PORT;
  }

  if (daemon_address.empty())
    daemon_address = std::string("http://") + daemon_host + ":" + std::to_string(daemon_port);

  boost::optional<bool> trusted_daemon;
  if (!command_line::is_arg_defaulted(vm, opts.trusted_daemon) || !command_line::is_arg_defaulted(vm, opts.untrusted_daemon))
    trusted_daemon = command_line::get_arg(vm, opts.trusted_daemon) && !command_line::get_arg(vm, opts.untrusted_daemon);
  THROW_WALLET_EXCEPTION_IF(!command_line::is_arg_defaulted(vm, opts.trusted_daemon) && !command_line::is_arg_defaulted(vm, opts.untrusted_daemon),
    tools::error::wallet_internal_error, CWallet::tr("--trusted-daemon and --untrusted-daemon are both seen, assuming untrusted"));

  // set --trusted-daemon if local and not overridden
  if (!trusted_daemon)
  {
    try
    {
      trusted_daemon = false;
      if (tools::is_local_address(daemon_address))
      {
        MINFO(CWallet::tr("Daemon is local, assuming trusted"));
        trusted_daemon = true;
      }
    }
    catch (const std::exception &e) { }
  }

  std::unique_ptr<CWallet> wallet(new CWallet(nettype, kdf_rounds, unattended));
  wallet->init(std::move(daemon_address), std::move(login), 0, false, *trusted_daemon);
  boost::filesystem::path ringdb_path = command_line::get_arg(vm, opts.shared_ringdb_dir);
  wallet->set_ring_database(ringdb_path.string());
  wallet->device_name(device_name);

  try
  {
    if (!command_line::is_arg_defaulted(vm, opts.tx_notify))
      wallet->set_tx_notify(std::shared_ptr<tools::Notify>(new tools::Notify(command_line::get_arg(vm, opts.tx_notify).c_str())));
  }
  catch (const std::exception &e)
  {
    MERROR("Failed to parse tx notify spec");
  }

  return wallet;
}

boost::optional<tools::password_container> get_password(const boost::program_options::variables_map& vm, const options& opts, const std::function<boost::optional<tools::password_container>(const char*, bool)> &password_prompter, const bool verify)
{
  if (command_line::has_arg(vm, opts.password) && command_line::has_arg(vm, opts.password_file))
  {
    THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("can't specify more than one of --password and --password-file"));
  }

  if (command_line::has_arg(vm, opts.password))
  {
    return tools::password_container{command_line::get_arg(vm, opts.password)};
  }

  if (command_line::has_arg(vm, opts.password_file))
  {
    std::string password;
    bool r = epee::file_io_utils::load_file_to_string(command_line::get_arg(vm, opts.password_file),
                                                      password);
    THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, CWallet::tr("the password file specified could not be read"));

    // Remove line breaks the user might have inserted
    boost::trim_right_if(password, boost::is_any_of("\r\n"));
    return {tools::password_container{std::move(password)}};
  }

  THROW_WALLET_EXCEPTION_IF(!password_prompter, tools::error::wallet_internal_error, CWallet::tr("no password specified; use --prompt-for-password to prompt for a password"));

  return password_prompter(verify ? CWallet::tr("Enter a new password for the wallet") : CWallet::tr("Wallet password"), verify);
}

std::pair<std::unique_ptr<CWallet>, tools::password_container> generate_from_json(const std::string& json_file, const boost::program_options::variables_map& vm, bool unattended, const options& opts, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const bool testnet = command_line::get_arg(vm, opts.testnet);
  const bool stagenet = command_line::get_arg(vm, opts.stagenet);
  const network_type nettype = testnet ? TESTNET : stagenet ? STAGENET : MAINNET;

  /* GET_FIELD_FROM_JSON_RETURN_ON_ERROR Is a generic macro that can return
  false. Gcc will coerce this into unique_ptr(nullptr), but clang correctly
  fails. This large wrapper is for the use of that macro */
  std::unique_ptr<CWallet> wallet;
  epee::wipeable_string password;
  const auto do_generate = [&]() -> bool {
    std::string buf;
    if (!epee::file_io_utils::load_file_to_string(json_file, buf)) {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, std::string(CWallet::tr("Failed to load file ")) + json_file);
      return false;
    }

    rapidjson::Document json;
    if (json.Parse(buf.c_str()).HasParseError()) {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("Failed to parse JSON"));
      return false;
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, version, unsigned, Uint, true, 0);
    const int current_version = 1;
    THROW_WALLET_EXCEPTION_IF(field_version > current_version, tools::error::wallet_internal_error,
      ((boost::format(CWallet::tr("Version %u too new, we can only grok up to %u")) % field_version % current_version)).str());

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, filename, std::string, String, true, std::string());

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, scan_from_height, uint64_t, Uint64, false, 0);
    const bool recover = field_scan_from_height_found;

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, password, std::string, String, false, std::string());

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, viewkey, std::string, String, false, std::string());
    crypto::secret_key viewkey;
    if (field_viewkey_found)
    {
      cryptonote::blobdata viewkey_data;
      if(!epee::string_tools::parse_hexstr_to_binbuff(field_viewkey, viewkey_data) || viewkey_data.size() != sizeof(crypto::secret_key))
      {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("failed to parse view key secret key"));
      }
      viewkey = *reinterpret_cast<const crypto::secret_key*>(viewkey_data.data());
      crypto::public_key pkey;
      if (!crypto::secret_key_to_public_key(viewkey, pkey)) {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("failed to verify view key secret key"));
      }
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, spendkey, std::string, String, false, std::string());
    crypto::secret_key spendkey;
    if (field_spendkey_found)
    {
      cryptonote::blobdata spendkey_data;
      if(!epee::string_tools::parse_hexstr_to_binbuff(field_spendkey, spendkey_data) || spendkey_data.size() != sizeof(crypto::secret_key))
      {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("failed to parse spend key secret key"));
      }
      spendkey = *reinterpret_cast<const crypto::secret_key*>(spendkey_data.data());
      crypto::public_key pkey;
      if (!crypto::secret_key_to_public_key(spendkey, pkey)) {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("failed to verify spend key secret key"));
      }
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, seed, std::string, String, false, std::string());
    std::string old_language;
    crypto::secret_key recovery_key;
    bool restore_deterministic_wallet = false;
    if (field_seed_found)
    {
      if (!crypto::ElectrumWords::words_to_bytes(field_seed, recovery_key, old_language))
      {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("Electrum-style word list failed verification"));
      }
      restore_deterministic_wallet = true;

      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, seed_passphrase, std::string, String, false, std::string());
      if (field_seed_passphrase_found)
      {
        if (!field_seed_passphrase.empty())
          recovery_key = cryptonote::decrypt_key(recovery_key, field_seed_passphrase);
      }
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, address, std::string, String, false, std::string());

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, create_address_file, int, Int, false, false);
    bool create_address_file = field_create_address_file;

    // compatibility checks
    if (!field_seed_found && !field_viewkey_found && !field_spendkey_found)
    {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("At least one of either an Electrum-style word list, private view key, or private spend key must be specified"));
    }
    if (field_seed_found && (field_viewkey_found || field_spendkey_found))
    {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("Both Electrum-style word list and private key(s) specified"));
    }

    // if an address was given, we check keys against it, and deduce the spend
    // public key if it was not given
    if (field_address_found)
    {
      cryptonote::address_parse_info info;
      if(!get_account_address_from_str(info, nettype, field_address))
      {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("invalid address"));
      }
      if (field_viewkey_found)
      {
        crypto::public_key pkey;
        if (!crypto::secret_key_to_public_key(viewkey, pkey)) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("failed to verify view key secret key"));
        }
        if (info.address.m_view_public_key != pkey) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("view key does not match standard address"));
        }
      }
      if (field_spendkey_found)
      {
        crypto::public_key pkey;
        if (!crypto::secret_key_to_public_key(spendkey, pkey)) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("failed to verify spend key secret key"));
        }
        if (info.address.m_spend_public_key != pkey) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("spend key does not match standard address"));
        }
      }
    }

    const bool deprecated_wallet = restore_deterministic_wallet && ((old_language == crypto::ElectrumWords::old_language_name) ||
      crypto::ElectrumWords::get_is_old_style_seed(field_seed));
    THROW_WALLET_EXCEPTION_IF(deprecated_wallet, tools::error::wallet_internal_error,
      CWallet::tr("Cannot generate deprecated wallets from JSON"));

    wallet.reset(make_basic(vm, unattended, opts, password_prompter).release());
    wallet->set_refresh_from_block_height(field_scan_from_height);
    wallet->explicit_refresh_from_block_height(field_scan_from_height_found);

    try
    {
      if (!field_seed.empty())
      {
        wallet->generate(field_filename, field_password, recovery_key, recover, false, create_address_file);
        password = field_password;
      }
      else if (field_viewkey.empty() && !field_spendkey.empty())
      {
        wallet->generate(field_filename, field_password, spendkey, recover, false, create_address_file);
        password = field_password;
      }
      else
      {
        cryptonote::account_public_address address;
        if (!crypto::secret_key_to_public_key(viewkey, address.m_view_public_key)) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("failed to verify view key secret key"));
        }

        if (field_spendkey.empty())
        {
          // if we have an address but no spend key, we can deduce the spend public key
          // from the address
          if (field_address_found)
          {
            cryptonote::address_parse_info info;
            if(!get_account_address_from_str(info, nettype, field_address))
            {
              THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, std::string(CWallet::tr("failed to parse address: ")) + field_address);
            }
            address.m_spend_public_key = info.address.m_spend_public_key;
          }
          else
          {
            THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("Address must be specified in order to create watch-only wallet"));
          }
          wallet->generate(field_filename, field_password, address, viewkey, create_address_file);
          password = field_password;
        }
        else
        {
          if (!crypto::secret_key_to_public_key(spendkey, address.m_spend_public_key)) {
            THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, CWallet::tr("failed to verify spend key secret key"));
          }
          wallet->generate(field_filename, field_password, address, spendkey, viewkey, create_address_file);
          password = field_password;
        }
      }
    }
    catch (const std::exception& e)
    {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, std::string(CWallet::tr("failed to generate new wallet: ")) + e.what());
    }
    return true;
  };

  if (do_generate())
  {
    return {std::move(wallet), tools::password_container(password)};
  }
  return {nullptr, tools::password_container{}};
}

static void throw_on_rpc_response_error(const boost::optional<std::string> &status, const char *method)
{
  // no error
  if (!status)
    return;

  // empty string -> not connection
  THROW_WALLET_EXCEPTION_IF(status->empty(), tools::error::no_connection_to_daemon, method);

  THROW_WALLET_EXCEPTION_IF(*status == CORE_RPC_STATUS_BUSY, tools::error::daemon_busy, method);
  THROW_WALLET_EXCEPTION_IF(*status != CORE_RPC_STATUS_OK, tools::error::wallet_generic_rpc_error, method, *status);
}

std::string strjoin(const std::vector<size_t> &V, const char *sep)
{
  std::stringstream ss;
  bool first = true;
  for (const auto &v: V)
  {
    if (!first)
      ss << sep;
    ss << std::to_string(v);
    first = false;
  }
  return ss.str();
}

static void emplace_or_replace(std::unordered_multimap<crypto::hash, CWallet::pool_payment_details> &container,
  const crypto::hash &key, const CWallet::pool_payment_details &pd)
{
  auto range = container.equal_range(key);
  for (auto i = range.first; i != range.second; ++i)
  {
    if (i->second.m_pd.m_tx_hash == pd.m_pd.m_tx_hash && i->second.m_pd.m_subaddr_index == pd.m_pd.m_subaddr_index)
    {
      i->second = pd;
      return;
    }
  }
  container.emplace(key, pd);
}

void drop_from_short_history(std::list<crypto::hash> &short_chain_history, size_t N)
{
  std::list<crypto::hash>::iterator right;
  // drop early N off, skipping the genesis block
  if (short_chain_history.size() > N) {
    right = short_chain_history.end();
    std::advance(right,-1);
    std::list<crypto::hash>::iterator left = right;
    std::advance(left, -N);
    short_chain_history.erase(left, right);
  }
}

size_t estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof)
{
  size_t size = 0;

  // tx prefix

  // first few bytes
  size += 1 + 6;

  // vin
  size += n_inputs * (1+6+(mixin+1)*2+32);

  // vout
  size += n_outputs * (6+32);

  // extra
  size += extra_size;

  // rct signatures

  // type
  size += 1;

  // rangeSigs
  if (bulletproof)
  {
    size_t log_padded_outputs = 0;
    while ((1<<log_padded_outputs) < n_outputs)
      ++log_padded_outputs;
    size += (2 * (6 + log_padded_outputs) + 4 + 5) * 32 + 3;
  }
  else
    size += (2*64*32+32+64*32) * n_outputs;

  // MGs
  size += n_inputs * (64 * (mixin+1) + 32);

  // pseudoOuts
  size += 32 * n_inputs;
  // ecdhInfo
  size += 2 * 32 * n_outputs;
  // outPk - only commitment is saved
  size += 32 * n_outputs;
  // txnFee
  size += 4;

  LOG_PRINT_L2("estimated " << (bulletproof ? "bulletproof" : "borromean") << " rct tx size for " << n_inputs << " inputs with ring size " << (mixin+1) << " and " << n_outputs << " outputs: " << size << " (" << ((32 * n_inputs/*+1*/) + 2 * 32 * (mixin+1) * n_inputs + 32 * n_outputs) << " saved)");
  return size;
}

size_t estimate_tx_size(bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof)
{
  if (use_rct)
    return estimate_rct_tx_size(n_inputs, mixin, n_outputs, extra_size, bulletproof);
  else
    return n_inputs * (mixin+1) * APPROXIMATE_INPUT_BYTES + extra_size;
}

uint64_t estimate_tx_weight(bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof)
{
  size_t size = estimate_tx_size(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof);
  if (use_rct && bulletproof && n_outputs > 2)
  {
    const uint64_t bp_base = 368;
    size_t log_padded_outputs = 2;
    while ((1<<log_padded_outputs) < n_outputs)
      ++log_padded_outputs;
    uint64_t nlr = 2 * (6 + log_padded_outputs);
    const uint64_t bp_size = 32 * (9 + nlr);
    const uint64_t bp_clawback = (bp_base * (1<<log_padded_outputs) - bp_size) * 4 / 5;
    MDEBUG("clawback on size " << size << ": " << bp_clawback);
    size += bp_clawback;
  }
  return size;
}

uint8_t get_bulletproof_fork()
{
  return 8;
}

uint64_t estimate_fee(bool use_per_byte_fee, bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof, uint64_t base_fee, uint64_t fee_multiplier, uint64_t fee_quantization_mask)
{
  if (use_per_byte_fee)
  {
    const size_t estimated_tx_weight = estimate_tx_weight(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof);
    return calculate_fee_from_weight(base_fee, estimated_tx_weight, fee_multiplier, fee_quantization_mask);
  }
  else
  {
    const size_t estimated_tx_size = estimate_tx_size(use_rct, n_inputs, mixin, n_outputs, extra_size, bulletproof);
    return calculate_fee(base_fee, estimated_tx_size, fee_multiplier);
  }
}

uint64_t calculate_fee(bool use_per_byte_fee, const cryptonote::transaction &tx, size_t blob_size, uint64_t base_fee, uint64_t fee_multiplier, uint64_t fee_quantization_mask)
{
  if (use_per_byte_fee)
    return calculate_fee_from_weight(base_fee, cryptonote::get_transaction_weight(tx, blob_size), fee_multiplier, fee_quantization_mask);
  else
    return calculate_fee(base_fee, blob_size, fee_multiplier);
}

crypto::hash8 get_short_payment_id(const CWallet::pending_tx &ptx, hw::device &hwdev)
{
  crypto::hash8 payment_id8 = null_hash8;
  std::vector<tx_extra_field> tx_extra_fields;
  parse_tx_extra(ptx.tx.extra, tx_extra_fields); // ok if partially parsed
  cryptonote::tx_extra_nonce extra_nonce;
  if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
  {
    if(get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
    {
      if (ptx.dests.empty())
      {
        MWARNING("Encrypted payment id found, but no destinations public key, cannot decrypt");
        return crypto::null_hash8;
      }
      hwdev.decrypt_payment_id(payment_id8, ptx.dests[0].addr.m_view_public_key, ptx.tx_key);
    }
  }
  return payment_id8;
}

CWallet::tx_construction_data get_construction_data_with_decrypted_short_payment_id(const CWallet::pending_tx &ptx, hw::device &hwdev)
{
  CWallet::tx_construction_data construction_data = ptx.construction_data;
  crypto::hash8 payment_id = get_short_payment_id(ptx,hwdev);
  if (payment_id != null_hash8)
  {
    // Remove encrypted
    remove_field_from_tx_extra(construction_data.extra, typeid(cryptonote::tx_extra_nonce));
    // Add decrypted
    std::string extra_nonce;
    set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
    THROW_WALLET_EXCEPTION_IF(!add_extra_nonce_to_tx_extra(construction_data.extra, extra_nonce),
        tools::error::wallet_internal_error, "Failed to add decrypted payment id to tx extra");
    LOG_PRINT_L1("Decrypted payment ID: " << payment_id);
  }
  return construction_data;
}

uint32_t get_subaddress_clamped_sum(uint32_t idx, uint32_t extra)
{
  static constexpr uint32_t uint32_max = std::numeric_limits<uint32_t>::max();
  if (idx > uint32_max - extra)
    return uint32_max;
  return idx + extra;
}

  //-----------------------------------------------------------------
} //namespace

namespace tools
{
// for now, limit to 30 attempts.  TODO: discuss a good number to limit to.
const size_t MAX_SPLIT_ATTEMPTS = 30;

constexpr const std::chrono::seconds CWallet::rpc_timeout;
const char* CWallet::tr(const char* str) { return i18n_translate(str, "CWallet"); }

wallet_keys_unlocker::wallet_keys_unlocker(CWallet &w, const boost::optional<tools::password_container> &password):
  w(w),
  locked(password != boost::none)
{
  if (!locked || w.is_unattended() || w.ask_password() != CWallet::AskPasswordToDecrypt)
  {
    locked = false;
    return;
  }
  const epee::wipeable_string pass = password->password();
  w.generate_chacha_key_from_password(pass, key);
  w.decrypt_keys(key);
}

wallet_keys_unlocker::wallet_keys_unlocker(CWallet &w, bool locked, const epee::wipeable_string &password):
  w(w),
  locked(locked)
{
  if (!locked)
    return;
  w.generate_chacha_key_from_password(password, key);
  w.decrypt_keys(key);
}

wallet_keys_unlocker::~wallet_keys_unlocker()
{
  if (!locked)
    return;
  w.encrypt_keys(key);
}

CWallet::CWallet(network_type nettype, uint64_t kdf_rounds, bool unattended):
  m_multisig_rescan_info(NULL),
  m_multisig_rescan_k(NULL),
  m_run(true),
  m_callback(0),
  m_trusted_daemon(false),
  m_nettype(nettype),
  m_multisig_rounds_passed(0),
  m_always_confirm_transfers(true),
  m_print_ring_members(false),
  m_store_tx_info(true),
  m_default_mixin(0),
  m_default_priority(0),
  m_refresh_type(RefreshOptimizeCoinbase),
  m_auto_refresh(true),
  m_first_refresh_done(false),
  m_refresh_from_block_height(0),
  m_explicit_refresh_from_block_height(true),
  m_confirm_missing_payment_id(true),
  m_confirm_non_default_ring_size(true),
  m_ask_password(AskPasswordToDecrypt),
  m_min_output_count(0),
  m_min_output_value(0),
  m_merge_destinations(false),
  m_confirm_backlog(true),
  m_confirm_backlog_threshold(0),
  m_confirm_export_overwrite(true),
  m_auto_low_priority(true),
  m_segregate_pre_fork_outputs(true),
  m_key_reuse_mitigation2(true),
  m_segregation_height(0),
  m_ignore_fractional_outputs(true),
  m_is_initialized(false),
  m_kdf_rounds(kdf_rounds),
  is_old_file_format(false),
  m_node_rpc_proxy(m_http_client, m_daemon_rpc_mutex),
  m_subaddress_lookahead_major(SUBADDRESS_LOOKAHEAD_MAJOR),
  m_subaddress_lookahead_minor(SUBADDRESS_LOOKAHEAD_MINOR),
  m_light_wallet(false),
  m_light_wallet_scanned_block_height(0),
  m_light_wallet_blockchain_height(0),
  m_light_wallet_connected(false),
  m_light_wallet_balance(0),
  m_light_wallet_unlocked_balance(0),
  m_key_device_type(hw::device::device_type::SOFTWARE),
  m_ring_history_saved(false),
  m_ringdb(),
  m_last_block_reward(0),
  m_encrypt_keys_after_refresh(boost::none),
  m_unattended(unattended)
{
    SetNull();
}

CWallet::~CWallet()
{
}

bool CWallet::has_testnet_option(const boost::program_options::variables_map& vm)
{
  return command_line::get_arg(vm, options().testnet);
}

bool CWallet::has_stagenet_option(const boost::program_options::variables_map& vm)
{
  return command_line::get_arg(vm, options().stagenet);
}

std::string CWallet::device_name_option(const boost::program_options::variables_map& vm)
{
  return command_line::get_arg(vm, options().hw_device);
}

void CWallet::init_options(boost::program_options::options_description& desc_params)
{
  const options opts{};
  command_line::add_arg(desc_params, opts.daemon_address);
  command_line::add_arg(desc_params, opts.daemon_host);
  command_line::add_arg(desc_params, opts.trusted_daemon);
  command_line::add_arg(desc_params, opts.untrusted_daemon);
  command_line::add_arg(desc_params, opts.password);
  command_line::add_arg(desc_params, opts.password_file);
  command_line::add_arg(desc_params, opts.daemon_port);
  command_line::add_arg(desc_params, opts.daemon_login);
  command_line::add_arg(desc_params, opts.testnet);
  command_line::add_arg(desc_params, opts.stagenet);
  command_line::add_arg(desc_params, opts.shared_ringdb_dir);
  command_line::add_arg(desc_params, opts.kdf_rounds);
  command_line::add_arg(desc_params, opts.hw_device);
  command_line::add_arg(desc_params, opts.tx_notify);
}

std::pair<std::unique_ptr<CWallet>, tools::password_container> CWallet::make_from_json(const boost::program_options::variables_map& vm, bool unattended, const std::string& json_file, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const options opts{};
  return generate_from_json(json_file, vm, unattended, opts, password_prompter);
}

std::pair<std::unique_ptr<CWallet>, password_container> CWallet::make_from_file(
  const boost::program_options::variables_map& vm, bool unattended, const std::string& wallet_file, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const options opts{};
  auto pwd = get_password(vm, opts, password_prompter, false);
  if (!pwd)
  {
    return {nullptr, password_container{}};
  }
  auto wallet = make_basic(vm, unattended, opts, password_prompter);
  if (wallet)
  {
    wallet->load(wallet_file, pwd->password());
  }
  return {std::move(wallet), std::move(*pwd)};
}

std::pair<std::unique_ptr<CWallet>, password_container> CWallet::make_new(const boost::program_options::variables_map& vm, bool unattended, const std::function<boost::optional<password_container>(const char *, bool)> &password_prompter)
{
  const options opts{};
  auto pwd = get_password(vm, opts, password_prompter, true);
  if (!pwd)
  {
    return {nullptr, password_container{}};
  }
  return {make_basic(vm, unattended, opts, password_prompter), std::move(*pwd)};
}

std::unique_ptr<CWallet> CWallet::make_dummy(const boost::program_options::variables_map& vm, bool unattended, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  const options opts{};
  return make_basic(vm, unattended, opts, password_prompter);
}

bool CWallet::is_deterministic() const
{
  crypto::secret_key second;
  keccak((uint8_t *)&get_account().get_keys().m_spend_secret_key, sizeof(crypto::secret_key), (uint8_t *)&second, sizeof(crypto::secret_key));
  sc_reduce32((uint8_t *)&second);
  return memcmp(second.data,get_account().get_keys().m_view_secret_key.data, sizeof(crypto::secret_key)) == 0;
}
//----------------------------------------------------------------------------------------------------
bool CWallet::get_seed(epee::wipeable_string& electrum_words, const epee::wipeable_string &passphrase) const
{
  bool keys_deterministic = is_deterministic();
  if (!keys_deterministic)
  {
    std::cout << "This is not a deterministic wallet" << std::endl;
    return false;
  }
  if (seed_language.empty())
  {
    std::cout << "seed_language not set" << std::endl;
    return false;
  }

  crypto::secret_key key = get_account().get_keys().m_spend_secret_key;
  if (!passphrase.empty())
    key = cryptonote::encrypt_key(key, passphrase);
  if (!crypto::ElectrumWords::bytes_to_words(key, electrum_words, seed_language))
  {
    std::cout << "Failed to create seed from key for language: " << seed_language << std::endl;
    return false;
  }

  return true;
}

bool CWallet::reconnect_device()
{
  bool r = true;
  hw::device &hwdev = hw::get_device(m_device_name);
  hwdev.set_name(m_device_name);
  r = hwdev.init();
  if (!r){
    LOG_PRINT_L2("Could not init device");
    return false;
  }

  r = hwdev.connect();
  if (!r){
    LOG_PRINT_L2("Could not connect to the device");
    return false;
  }

  m_account.set_device(hwdev);
  return true;
}
//----------------------------------------------------------------------------------------------------
/*!
 * \brief Gets the seed language
 */
const std::string &CWallet::get_seed_language() const
{
  return seed_language;
}
/*!
 * \brief Sets the seed language
 * \param language  Seed language to set to
 */
void CWallet::set_seed_language(const std::string &language)
{
  seed_language = language;
}
//----------------------------------------------------------------------------------------------------
cryptonote::account_public_address CWallet::get_subaddress(const cryptonote::subaddress_index& index) const
{
  hw::device &hwdev = m_account.get_device();
  return hwdev.get_subaddress(m_account.get_keys(), index);
}
//----------------------------------------------------------------------------------------------------
boost::optional<cryptonote::subaddress_index> CWallet::get_subaddress_index(const cryptonote::account_public_address& address) const
{
  auto index = m_subaddresses.find(address.m_spend_public_key);
  if (index == m_subaddresses.end())
    return boost::none;
  return index->second;
}
//----------------------------------------------------------------------------------------------------
crypto::public_key CWallet::get_subaddress_spend_public_key(const cryptonote::subaddress_index& index) const
{
  hw::device &hwdev = m_account.get_device();
  return hwdev.get_subaddress_spend_public_key(m_account.get_keys(), index);
}
//----------------------------------------------------------------------------------------------------
std::string CWallet::get_subaddress_as_str(const cryptonote::subaddress_index& index) const
{
  cryptonote::account_public_address address = get_subaddress(index);
  return cryptonote::get_account_address_as_str(m_nettype, !index.is_zero(), address);
}
//----------------------------------------------------------------------------------------------------
std::string CWallet::get_integrated_address_as_str(const crypto::hash8& payment_id) const
{
  return cryptonote::get_account_integrated_address_as_str(m_nettype, get_address(), payment_id);
}
//----------------------------------------------------------------------------------------------------
void CWallet::add_subaddress_account(const std::string& label)
{
  uint32_t index_major = (uint32_t)get_num_subaddress_accounts();
  expand_subaddresses({index_major, 0});
  m_subaddress_labels[index_major][0] = label;
}
//----------------------------------------------------------------------------------------------------
void CWallet::add_subaddress(uint32_t index_major, const std::string& label)
{
  THROW_WALLET_EXCEPTION_IF(index_major >= m_subaddress_labels.size(), error::account_index_outofbound);
  uint32_t index_minor = (uint32_t)get_num_subaddresses(index_major);
  expand_subaddresses({index_major, index_minor});
  m_subaddress_labels[index_major][index_minor] = label;
}
//----------------------------------------------------------------------------------------------------
void CWallet::expand_subaddresses(const cryptonote::subaddress_index& index)
{
  hw::device &hwdev = m_account.get_device();
  if (m_subaddress_labels.size() <= index.major)
  {
    // add new accounts
    cryptonote::subaddress_index index2;
    const uint32_t major_end = get_subaddress_clamped_sum(index.major, m_subaddress_lookahead_major);
    for (index2.major = m_subaddress_labels.size(); index2.major < major_end; ++index2.major)
    {
      const uint32_t end = get_subaddress_clamped_sum((index2.major == index.major ? index.minor : 0), m_subaddress_lookahead_minor);
      const std::vector<crypto::public_key> pkeys = hwdev.get_subaddress_spend_public_keys(m_account.get_keys(), index2.major, 0, end);
      for (index2.minor = 0; index2.minor < end; ++index2.minor)
      {
         const crypto::public_key &D = pkeys[index2.minor];
         m_subaddresses[D] = index2;
      }
    }
    m_subaddress_labels.resize(index.major + 1, {"Untitled account"});
    m_subaddress_labels[index.major].resize(index.minor + 1);
    get_account_tags();
  }
  else if (m_subaddress_labels[index.major].size() <= index.minor)
  {
    // add new subaddresses
    const uint32_t end = get_subaddress_clamped_sum(index.minor, m_subaddress_lookahead_minor);
    const uint32_t begin = m_subaddress_labels[index.major].size();
    cryptonote::subaddress_index index2 = {index.major, begin};
    const std::vector<crypto::public_key> pkeys = hwdev.get_subaddress_spend_public_keys(m_account.get_keys(), index2.major, index2.minor, end);
    for (; index2.minor < end; ++index2.minor)
    {
       const crypto::public_key &D = pkeys[index2.minor - begin];
       m_subaddresses[D] = index2;
    }
    m_subaddress_labels[index.major].resize(index.minor + 1);
  }
}
//----------------------------------------------------------------------------------------------------
std::string CWallet::get_subaddress_label(const cryptonote::subaddress_index& index) const
{
  if (index.major >= m_subaddress_labels.size() || index.minor >= m_subaddress_labels[index.major].size())
  {
    MERROR("Subaddress label doesn't exist");
    return "";
  }
  return m_subaddress_labels[index.major][index.minor];
}
//----------------------------------------------------------------------------------------------------
void CWallet::set_subaddress_label(const cryptonote::subaddress_index& index, const std::string &label)
{
  THROW_WALLET_EXCEPTION_IF(index.major >= m_subaddress_labels.size(), error::account_index_outofbound);
  THROW_WALLET_EXCEPTION_IF(index.minor >= m_subaddress_labels[index.major].size(), error::address_index_outofbound);
  m_subaddress_labels[index.major][index.minor] = label;
}
//----------------------------------------------------------------------------------------------------
void CWallet::set_subaddress_lookahead(size_t major, size_t minor)
{
  THROW_WALLET_EXCEPTION_IF(major > 0xffffffff, error::wallet_internal_error, "Subaddress major lookahead is too large");
  THROW_WALLET_EXCEPTION_IF(minor > 0xffffffff, error::wallet_internal_error, "Subaddress minor lookahead is too large");
  m_subaddress_lookahead_major = major;
  m_subaddress_lookahead_minor = minor;
}
//----------------------------------------------------------------------------------------------------
/*!
 * \brief Tells if the wallet file is deprecated.
 */
bool CWallet::is_deprecated() const
{
  return is_old_file_format;
}

static uint64_t decodeRct(const rct::rctSig & rv, const crypto::key_derivation &derivation, unsigned int i, rct::key & mask, hw::device &hwdev)
{
  crypto::secret_key scalar1;
  hwdev.derivation_to_scalar(derivation, i, scalar1);
  try
  {
    switch (rv.type)
    {
    case rct::RCTTypeSimple:
    case rct::RCTTypeBulletproof:
      return rct::decodeRctSimple(rv, rct::sk2rct(scalar1), i, mask, hwdev);
    case rct::RCTTypeFull:
      return rct::decodeRct(rv, rct::sk2rct(scalar1), i, mask, hwdev);
    default:
      LOG_ERROR("Unsupported rct type: " << rv.type);
      return 0;
    }
  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Failed to decode input " << i);
    return 0;
  }
}

bool CWallet::add_address_book_row(const cryptonote::account_public_address &address, const crypto::hash &payment_id, const std::string &description, bool is_subaddress)
{
  CWallet::address_book_row a;
  a.m_address = address;
  a.m_payment_id = payment_id;
  a.m_description = description;
  a.m_is_subaddress = is_subaddress;
  
  auto old_size = m_address_book.size();
  m_address_book.push_back(a);
  if(m_address_book.size() == old_size+1)
    return true;
  return false;
}

bool CWallet::delete_address_book_row(std::size_t row_id) {
  if(m_address_book.size() <= row_id)
    return false;
  
  m_address_book.erase(m_address_book.begin()+row_id);

  return true;
}

//----------------------------------------------------------------------------------------------------
void CWallet::refresh(bool trusted_daemon, uint64_t start_height, uint64_t & blocks_fetched, bool& received_money)
{
  if(m_light_wallet) {

    // MyMonero get_address_info needs to be called occasionally to trigger wallet sync.
    // This call is not really needed for other purposes and can be removed if mymonero changes their backend.
    cryptonote::COMMAND_RPC_GET_ADDRESS_INFO::response res;

    // Get basic info
    if(light_wallet_get_address_info(res)) {
      // Last stored block height
      uint64_t prev_height = m_light_wallet_blockchain_height;
      // Update lw heights
      m_light_wallet_scanned_block_height = res.scanned_block_height;
      m_light_wallet_blockchain_height = res.blockchain_height;
      // If new height - call new_block callback
      if(m_light_wallet_blockchain_height != prev_height)
      {
        MDEBUG("new block since last time!");
        m_callback->on_lw_new_block(m_light_wallet_blockchain_height - 1);
      }
      m_light_wallet_connected = true;
      MDEBUG("lw scanned block height: " <<  m_light_wallet_scanned_block_height);
      MDEBUG("lw blockchain height: " <<  m_light_wallet_blockchain_height);
      MDEBUG(m_light_wallet_blockchain_height-m_light_wallet_scanned_block_height << " blocks behind");
      // TODO: add wallet created block info

      light_wallet_get_address_txs();
    } else
      m_light_wallet_connected = false;

    // Lighwallet refresh done
    return;
  }
  received_money = false;
  blocks_fetched = 0;
  uint64_t added_blocks = 0;
  size_t try_count = 0;
  crypto::hash last_tx_hash_id = m_transfers.size() ? m_transfers.back().m_txid : null_hash;
  std::list<crypto::hash> short_chain_history;
  tools::threadpool& tpool = tools::threadpool::getInstance();
  tools::threadpool::waiter waiter;
  uint64_t blocks_start_height;
  std::vector<cryptonote::block_complete_entry> blocks;
  std::vector<parsed_block> parsed_blocks;
  bool refreshed = false;

  // pull the first set of blocks
  get_short_chain_history(short_chain_history, (m_first_refresh_done || trusted_daemon) ? 1 : FIRST_REFRESH_GRANULARITY);
  m_run.store(true, std::memory_order_relaxed);
  if (start_height > m_blockchain.size() || m_refresh_from_block_height > m_blockchain.size()) {
    if (!start_height)
      start_height = m_refresh_from_block_height;
    // we can shortcut by only pulling hashes up to the start_height
    fast_refresh(start_height, blocks_start_height, short_chain_history);
    // regenerate the history now that we've got a full set of hashes
    short_chain_history.clear();
    get_short_chain_history(short_chain_history, (m_first_refresh_done || trusted_daemon) ? 1 : FIRST_REFRESH_GRANULARITY);
    start_height = 0;
    // and then fall through to regular refresh processing
  }

  // If stop() is called during fast refresh we don't need to continue
  if(!m_run.load(std::memory_order_relaxed))
    return;
  // always reset start_height to 0 to force short_chain_ history to be used on
  // subsequent pulls in this refresh.
  start_height = 0;

  auto keys_reencryptor = epee::misc_utils::create_scope_leave_handler([&, this]() {
    if (m_encrypt_keys_after_refresh)
    {
      encrypt_keys(*m_encrypt_keys_after_refresh);
      m_encrypt_keys_after_refresh = boost::none;
    }
  });

  bool first = true;
  while(m_run.load(std::memory_order_relaxed))
  {
    try
    {
      // pull the next set of blocks while we're processing the current one
      uint64_t next_blocks_start_height;
      std::vector<cryptonote::block_complete_entry> next_blocks;
      std::vector<parsed_block> next_parsed_blocks;
      bool error = false;
      added_blocks = 0;
      if (!first && blocks.empty())
      {
        refreshed = false;
        break;
      }
      tpool.submit(&waiter, [&]{pull_and_parse_next_blocks(start_height, next_blocks_start_height, short_chain_history, blocks, parsed_blocks, next_blocks, next_parsed_blocks, error);});

      if (!first)
      {
        try
        {
          process_parsed_blocks(blocks_start_height, blocks, parsed_blocks, added_blocks);
        }
        catch (const tools::error::out_of_hashchain_bounds_error&)
        {
          MINFO("Daemon claims next refresh block is out of hash chain bounds, resetting hash chain");
          uint64_t stop_height = m_blockchain.offset();
          std::vector<crypto::hash> tip(m_blockchain.size() - m_blockchain.offset());
          for (size_t i = m_blockchain.offset(); i < m_blockchain.size(); ++i)
            tip[i - m_blockchain.offset()] = m_blockchain[i];
          cryptonote::block b;
          generate_genesis(b);
          m_blockchain.clear();
          m_blockchain.push_back(get_block_hash(b));
          short_chain_history.clear();
          get_short_chain_history(short_chain_history);
          fast_refresh(stop_height, blocks_start_height, short_chain_history, true);
          THROW_WALLET_EXCEPTION_IF(m_blockchain.size() != stop_height, error::wallet_internal_error, "Unexpected hashchain size");
          THROW_WALLET_EXCEPTION_IF(m_blockchain.offset() != 0, error::wallet_internal_error, "Unexpected hashchain offset");
          for (const auto &h: tip)
            m_blockchain.push_back(h);
          short_chain_history.clear();
          get_short_chain_history(short_chain_history);
          start_height = stop_height;
          throw std::runtime_error(""); // loop again
        }
        blocks_fetched += added_blocks;
      }
      waiter.wait(&tpool);
      if(!first && blocks_start_height == next_blocks_start_height)
      {
        m_node_rpc_proxy.set_height(m_blockchain.size());
        refreshed = true;
        break;
      }

      first = false;

      // handle error from async fetching thread
      if (error)
      {
        throw std::runtime_error("proxy exception in refresh thread");
      }

      // switch to the new blocks from the daemon
      blocks_start_height = next_blocks_start_height;
      blocks = std::move(next_blocks);
      parsed_blocks = std::move(next_parsed_blocks);
    }
    catch (const tools::error::password_needed&)
    {
      blocks_fetched += added_blocks;
      waiter.wait(&tpool);
      throw;
    }
    catch (const std::exception&)
    {
      blocks_fetched += added_blocks;
      waiter.wait(&tpool);
      if(try_count < 3)
      {
        LOG_PRINT_L1("Another try pull_blocks (try_count=" << try_count << ")...");
        first = true;
        ++try_count;
      }
      else
      {
        LOG_ERROR("pull_blocks failed, try_count=" << try_count);
        throw;
      }
    }
  }
  if(last_tx_hash_id != (m_transfers.size() ? m_transfers.back().m_txid : null_hash))
    received_money = true;

  try
  {
    // If stop() is called we don't need to check pending transactions
    if(m_run.load(std::memory_order_relaxed))
      update_pool_state(refreshed);
  }
  catch (...)
  {
    LOG_PRINT_L1("Failed to check pending transactions");
  }

  m_first_refresh_done = true;

  LOG_PRINT_L1("Refresh done, blocks received: " << blocks_fetched << ", balance (all accounts): " << print_money(balance_all()) << ", unlocked: " << print_money(unlocked_balance_all()));
}
//----------------------------------------------------------------------------------------------------
bool CWallet::refresh(bool trusted_daemon, uint64_t & blocks_fetched, bool& received_money, bool& ok)
{
  try
  {
    refresh(trusted_daemon, 0, blocks_fetched, received_money);
    ok = true;
  }
  catch (...)
  {
    ok = false;
  }
  return ok;
}

bool CWallet::deinit()
{
  m_is_initialized=false;
  unlock_keys_file();
  return true;
}

bool CWallet::clear()
{
  return true;
}

/*!
 * \brief Stores wallet information to wallet file.
 * \param  keys_file_name Name of wallet file
 * \param  password       Password of wallet file
 * \param  watch_only     true to save only view key, false to save both spend and view keys
 * \return                Whether it was successful.
 */
bool CWallet::store_keys(const std::string& keys_file_name, const epee::wipeable_string& password, bool watch_only)
{
  std::string account_data;
  std::string multisig_signers;
  std::string multisig_derivations;
  cryptonote::account_base account = m_account;

  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);

  if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
  {
    account.encrypt_viewkey(key);
    account.decrypt_keys(key);
  }

  if (watch_only)
    account.forget_spend_key();

  account.encrypt_keys(key);

  bool r = epee::serialization::store_t_to_binary(account, account_data);
  CHECK_AND_ASSERT_MES(r, false, "failed to serialize wallet keys");
  CWallet::keys_file_data keys_file_data = boost::value_initialized<CWallet::keys_file_data>();

  // Create a JSON object with "key_data" and "seed_language" as keys.
  rapidjson::Document json;
  json.SetObject();
  rapidjson::Value value(rapidjson::kStringType);
  value.SetString(account_data.c_str(), account_data.length());
  json.AddMember("key_data", value, json.GetAllocator());
  if (!seed_language.empty())
  {
    value.SetString(seed_language.c_str(), seed_language.length());
    json.AddMember("seed_language", value, json.GetAllocator());
  }

  rapidjson::Value value2(rapidjson::kNumberType);

  value2.SetInt(m_key_device_type);
  json.AddMember("key_on_device", value2, json.GetAllocator());

  value2.SetInt(watch_only ? 1 :0); // WTF ? JSON has different true and false types, and not boolean ??
  json.AddMember("watch_only", value2, json.GetAllocator());

  value2.SetInt(m_multisig ? 1 :0);
  json.AddMember("multisig", value2, json.GetAllocator());

  value2.SetUint(m_multisig_threshold);
  json.AddMember("multisig_threshold", value2, json.GetAllocator());

  if (m_multisig)
  {
    bool r = ::serialization::dump_binary(m_multisig_signers, multisig_signers);
    CHECK_AND_ASSERT_MES(r, false, "failed to serialize wallet multisig signers");
    value.SetString(multisig_signers.c_str(), multisig_signers.length());
    json.AddMember("multisig_signers", value, json.GetAllocator());

    r = ::serialization::dump_binary(m_multisig_derivations, multisig_derivations);
    CHECK_AND_ASSERT_MES(r, false, "failed to serialize wallet multisig derivations");
    value.SetString(multisig_derivations.c_str(), multisig_derivations.length());
    json.AddMember("multisig_derivations", value, json.GetAllocator());

    value2.SetUint(m_multisig_rounds_passed);
    json.AddMember("multisig_rounds_passed", value2, json.GetAllocator());
  }

  value2.SetInt(m_always_confirm_transfers ? 1 :0);
  json.AddMember("always_confirm_transfers", value2, json.GetAllocator());

  value2.SetInt(m_print_ring_members ? 1 :0);
  json.AddMember("print_ring_members", value2, json.GetAllocator());

  value2.SetInt(m_store_tx_info ? 1 :0);
  json.AddMember("store_tx_info", value2, json.GetAllocator());

  value2.SetUint(m_default_mixin);
  json.AddMember("default_mixin", value2, json.GetAllocator());

  value2.SetUint(m_default_priority);
  json.AddMember("default_priority", value2, json.GetAllocator());

  value2.SetInt(m_auto_refresh ? 1 :0);
  json.AddMember("auto_refresh", value2, json.GetAllocator());

  value2.SetInt(m_refresh_type);
  json.AddMember("refresh_type", value2, json.GetAllocator());

  value2.SetUint64(m_refresh_from_block_height);
  json.AddMember("refresh_height", value2, json.GetAllocator());

  value2.SetInt(m_confirm_missing_payment_id ? 1 :0);
  json.AddMember("confirm_missing_payment_id", value2, json.GetAllocator());

  value2.SetInt(m_confirm_non_default_ring_size ? 1 :0);
  json.AddMember("confirm_non_default_ring_size", value2, json.GetAllocator());

  value2.SetInt(m_ask_password);
  json.AddMember("ask_password", value2, json.GetAllocator());

  value2.SetUint(m_min_output_count);
  json.AddMember("min_output_count", value2, json.GetAllocator());

  value2.SetUint64(m_min_output_value);
  json.AddMember("min_output_value", value2, json.GetAllocator());

  value2.SetInt(cryptonote::get_default_decimal_point());
  json.AddMember("default_decimal_point", value2, json.GetAllocator());

  value2.SetInt(m_merge_destinations ? 1 :0);
  json.AddMember("merge_destinations", value2, json.GetAllocator());

  value2.SetInt(m_confirm_backlog ? 1 :0);
  json.AddMember("confirm_backlog", value2, json.GetAllocator());

  value2.SetUint(m_confirm_backlog_threshold);
  json.AddMember("confirm_backlog_threshold", value2, json.GetAllocator());

  value2.SetInt(m_confirm_export_overwrite ? 1 :0);
  json.AddMember("confirm_export_overwrite", value2, json.GetAllocator());

  value2.SetInt(m_auto_low_priority ? 1 : 0);
  json.AddMember("auto_low_priority", value2, json.GetAllocator());

  value2.SetUint(m_nettype);
  json.AddMember("nettype", value2, json.GetAllocator());

  value2.SetInt(m_segregate_pre_fork_outputs ? 1 : 0);
  json.AddMember("segregate_pre_fork_outputs", value2, json.GetAllocator());

  value2.SetInt(m_key_reuse_mitigation2 ? 1 : 0);
  json.AddMember("key_reuse_mitigation2", value2, json.GetAllocator());

  value2.SetUint(m_segregation_height);
  json.AddMember("segregation_height", value2, json.GetAllocator());

  value2.SetInt(m_ignore_fractional_outputs ? 1 : 0);
  json.AddMember("ignore_fractional_outputs", value2, json.GetAllocator());

  value2.SetUint(m_subaddress_lookahead_major);
  json.AddMember("subaddress_lookahead_major", value2, json.GetAllocator());

  value2.SetUint(m_subaddress_lookahead_minor);
  json.AddMember("subaddress_lookahead_minor", value2, json.GetAllocator());

  value2.SetUint(1);
  json.AddMember("encrypted_secret_keys", value2, json.GetAllocator());

  value.SetString(m_device_name.c_str(), m_device_name.size());
  json.AddMember("device_name", value, json.GetAllocator());

  // Serialize the JSON object
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  json.Accept(writer);
  account_data = buffer.GetString();

  // Encrypt the entire JSON object.
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);
  std::string cipher;
  cipher.resize(account_data.size());
  keys_file_data.iv = crypto::rand<crypto::chacha_iv>();
  crypto::chacha20(account_data.data(), account_data.size(), key, keys_file_data.iv, &cipher[0]);
  keys_file_data.account_data = cipher;

  unlock_keys_file();
  std::string buf;
  r = ::serialization::dump_binary(keys_file_data, buf);
  r = r && epee::file_io_utils::save_string_to_file(keys_file_name, buf); //and never touch wallet_keys_file again, only read
  CHECK_AND_ASSERT_MES(r, false, "failed to generate wallet keys file " << keys_file_name);
  lock_keys_file();

  return true;
}
//----------------------------------------------------------------------------------------------------
void CWallet::setup_keys(const epee::wipeable_string &password)
{
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);

  // re-encrypt, but keep viewkey unencrypted
  if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
  {
    m_account.encrypt_keys(key);
    m_account.decrypt_viewkey(key);
  }

  static_assert(HASH_SIZE == sizeof(crypto::chacha_key), "Mismatched sizes of hash and chacha key");
  epee::mlocked<tools::scrubbed_arr<char, HASH_SIZE+1>> cache_key_data;
  memcpy(cache_key_data.data(), &key, HASH_SIZE);
  cache_key_data[HASH_SIZE] = CACHE_KEY_TAIL;
  cn_fast_hash(cache_key_data.data(), HASH_SIZE+1, (crypto::hash&)m_cache_key);
  get_ringdb_key();
}
//----------------------------------------------------------------------------------------------------
void CWallet::change_password(const std::string &filename, const epee::wipeable_string &original_password, const epee::wipeable_string &new_password)
{
  if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
    decrypt_keys(original_password);
  setup_keys(new_password);
  rewrite(filename, new_password);
  store();
}
//----------------------------------------------------------------------------------------------------
/*!
 * \brief Load wallet information from wallet file.
 * \param keys_file_name Name of wallet file
 * \param password       Password of wallet file
 */
bool CWallet::load_keys(const std::string& keys_file_name, const epee::wipeable_string& password)
{
  rapidjson::Document json;
  CWallet::keys_file_data keys_file_data;
  std::string buf;
  bool encrypted_secret_keys = false;
  bool r = epee::file_io_utils::load_file_to_string(keys_file_name, buf);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_read_error, keys_file_name);

  // Decrypt the contents
  r = ::serialization::parse_binary(buf, keys_file_data);
  THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "internal error: failed to deserialize \"" + keys_file_name + '\"');
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);
  std::string account_data;
  account_data.resize(keys_file_data.account_data.size());
  crypto::chacha20(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);
  if (json.Parse(account_data.c_str()).HasParseError() || !json.IsObject())
    crypto::chacha8(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);

  // The contents should be JSON if the wallet follows the new format.
  if (json.Parse(account_data.c_str()).HasParseError())
  {
    is_old_file_format = true;
    m_watch_only = false;
    m_multisig = false;
    m_multisig_threshold = 0;
    m_multisig_signers.clear();
    m_multisig_rounds_passed = 0;
    m_multisig_derivations.clear();
    m_always_confirm_transfers = false;
    m_print_ring_members = false;
    m_default_mixin = 0;
    m_default_priority = 0;
    m_auto_refresh = true;
    m_refresh_type = RefreshType::RefreshDefault;
    m_confirm_missing_payment_id = true;
    m_confirm_non_default_ring_size = true;
    m_ask_password = AskPasswordToDecrypt;
    m_min_output_count = 0;
    m_min_output_value = 0;
    m_merge_destinations = false;
    m_confirm_backlog = true;
    m_confirm_backlog_threshold = 0;
    m_confirm_export_overwrite = true;
    m_auto_low_priority = true;
    m_segregate_pre_fork_outputs = true;
    m_key_reuse_mitigation2 = true;
    m_segregation_height = 0;
    m_ignore_fractional_outputs = true;
    m_subaddress_lookahead_major = SUBADDRESS_LOOKAHEAD_MAJOR;
    m_subaddress_lookahead_minor = SUBADDRESS_LOOKAHEAD_MINOR;
    m_device_name = "";
    m_key_device_type = hw::device::device_type::SOFTWARE;
    encrypted_secret_keys = false;
  }
  else if(json.IsObject())
  {
    if (!json.HasMember("key_data"))
    {
      LOG_ERROR("Field key_data not found in JSON");
      return false;
    }
    if (!json["key_data"].IsString())
    {
      LOG_ERROR("Field key_data found in JSON, but not String");
      return false;
    }
    const char *field_key_data = json["key_data"].GetString();
    account_data = std::string(field_key_data, field_key_data + json["key_data"].GetStringLength());

    if (json.HasMember("key_on_device"))
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, key_on_device, int, Int, false, hw::device::device_type::SOFTWARE);
      m_key_device_type = static_cast<hw::device::device_type>(field_key_on_device);
    }

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, seed_language, std::string, String, false, std::string());
    if (field_seed_language_found)
    {
      set_seed_language(field_seed_language);
    }
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, watch_only, int, Int, false, false);
    m_watch_only = field_watch_only;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, multisig, int, Int, false, false);
    m_multisig = field_multisig;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, multisig_threshold, unsigned int, Uint, m_multisig, 0);
    m_multisig_threshold = field_multisig_threshold;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, multisig_rounds_passed, unsigned int, Uint, false, 0);
    m_multisig_rounds_passed = field_multisig_rounds_passed;
    if (m_multisig)
    {
      if (!json.HasMember("multisig_signers"))
      {
        LOG_ERROR("Field multisig_signers not found in JSON");
        return false;
      }
      if (!json["multisig_signers"].IsString())
      {
        LOG_ERROR("Field multisig_signers found in JSON, but not String");
        return false;
      }
      const char *field_multisig_signers = json["multisig_signers"].GetString();
      std::string multisig_signers = std::string(field_multisig_signers, field_multisig_signers + json["multisig_signers"].GetStringLength());
      r = ::serialization::parse_binary(multisig_signers, m_multisig_signers);
      if (!r)
      {
        LOG_ERROR("Field multisig_signers found in JSON, but failed to parse");
        return false;
      }

      //previous version of multisig does not have this field
      if (json.HasMember("multisig_derivations"))
      {
        if (!json["multisig_derivations"].IsString())
        {
          LOG_ERROR("Field multisig_derivations found in JSON, but not String");
          return false;
        }
        const char *field_multisig_derivations = json["multisig_derivations"].GetString();
        std::string multisig_derivations = std::string(field_multisig_derivations, field_multisig_derivations + json["multisig_derivations"].GetStringLength());
        r = ::serialization::parse_binary(multisig_derivations, m_multisig_derivations);
        if (!r)
        {
          LOG_ERROR("Field multisig_derivations found in JSON, but failed to parse");
          return false;
        }
      }
    }
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, always_confirm_transfers, int, Int, false, true);
    m_always_confirm_transfers = field_always_confirm_transfers;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, print_ring_members, int, Int, false, true);
    m_print_ring_members = field_print_ring_members;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, store_tx_keys, int, Int, false, true);
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, store_tx_info, int, Int, false, true);
    m_store_tx_info = ((field_store_tx_keys != 0) || (field_store_tx_info != 0));
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, default_mixin, unsigned int, Uint, false, 0);
    m_default_mixin = field_default_mixin;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, default_priority, unsigned int, Uint, false, 0);
    if (field_default_priority_found)
    {
      m_default_priority = field_default_priority;
    }
    else
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, default_fee_multiplier, unsigned int, Uint, false, 0);
      if (field_default_fee_multiplier_found)
        m_default_priority = field_default_fee_multiplier;
      else
        m_default_priority = 0;
    }
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, auto_refresh, int, Int, false, true);
    m_auto_refresh = field_auto_refresh;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, refresh_type, int, Int, false, RefreshType::RefreshDefault);
    m_refresh_type = RefreshType::RefreshDefault;
    if (field_refresh_type_found)
    {
      if (field_refresh_type == RefreshFull || field_refresh_type == RefreshOptimizeCoinbase || field_refresh_type == RefreshNoCoinbase)
        m_refresh_type = (RefreshType)field_refresh_type;
      else
        LOG_PRINT_L0("Unknown refresh-type value (" << field_refresh_type << "), using default");
    }
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, refresh_height, uint64_t, Uint64, false, 0);
    m_refresh_from_block_height = field_refresh_height;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, confirm_missing_payment_id, int, Int, false, true);
    m_confirm_missing_payment_id = field_confirm_missing_payment_id;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, confirm_non_default_ring_size, int, Int, false, true);
    m_confirm_non_default_ring_size = field_confirm_non_default_ring_size;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, ask_password, AskPasswordType, Int, false, AskPasswordToDecrypt);
    m_ask_password = field_ask_password;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, default_decimal_point, int, Int, false, CRYPTONOTE_DISPLAY_DECIMAL_POINT);
    cryptonote::set_default_decimal_point(field_default_decimal_point);
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, min_output_count, uint32_t, Uint, false, 0);
    m_min_output_count = field_min_output_count;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, min_output_value, uint64_t, Uint64, false, 0);
    m_min_output_value = field_min_output_value;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, merge_destinations, int, Int, false, false);
    m_merge_destinations = field_merge_destinations;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, confirm_backlog, int, Int, false, true);
    m_confirm_backlog = field_confirm_backlog;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, confirm_backlog_threshold, uint32_t, Uint, false, 0);
    m_confirm_backlog_threshold = field_confirm_backlog_threshold;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, confirm_export_overwrite, int, Int, false, true);
    m_confirm_export_overwrite = field_confirm_export_overwrite;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, auto_low_priority, int, Int, false, true);
    m_auto_low_priority = field_auto_low_priority;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, nettype, uint8_t, Uint, false, static_cast<uint8_t>(m_nettype));
    // The network type given in the program argument is inconsistent with the network type saved in the wallet
    THROW_WALLET_EXCEPTION_IF(static_cast<uint8_t>(m_nettype) != field_nettype, error::wallet_internal_error,
    (boost::format("%s wallet cannot be opened as %s wallet")
    % (field_nettype == 0 ? "Mainnet" : field_nettype == 1 ? "Testnet" : "Stagenet")
    % (m_nettype == MAINNET ? "mainnet" : m_nettype == TESTNET ? "testnet" : "stagenet")).str());
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, segregate_pre_fork_outputs, int, Int, false, true);
    m_segregate_pre_fork_outputs = field_segregate_pre_fork_outputs;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, key_reuse_mitigation2, int, Int, false, true);
    m_key_reuse_mitigation2 = field_key_reuse_mitigation2;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, segregation_height, int, Uint, false, 0);
    m_segregation_height = field_segregation_height;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, ignore_fractional_outputs, int, Int, false, true);
    m_ignore_fractional_outputs = field_ignore_fractional_outputs;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, subaddress_lookahead_major, uint32_t, Uint, false, SUBADDRESS_LOOKAHEAD_MAJOR);
    m_subaddress_lookahead_major = field_subaddress_lookahead_major;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, subaddress_lookahead_minor, uint32_t, Uint, false, SUBADDRESS_LOOKAHEAD_MINOR);
    m_subaddress_lookahead_minor = field_subaddress_lookahead_minor;

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, encrypted_secret_keys, uint32_t, Uint, false, false);
    encrypted_secret_keys = field_encrypted_secret_keys;

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, device_name, std::string, String, false, std::string());
    if (m_device_name.empty())
    {
      if (field_device_name_found)
      {
        m_device_name = field_device_name;
      }
      else
      {
        m_device_name = m_key_device_type == hw::device::device_type::LEDGER ? "Ledger" : "default";
      }
    }
  }
  else
  {
      THROW_WALLET_EXCEPTION(error::wallet_internal_error, "invalid password");
      return false;
  }

  r = epee::serialization::load_t_from_binary(m_account, account_data);
  THROW_WALLET_EXCEPTION_IF(!r, error::invalid_password);
  if (m_key_device_type == hw::device::device_type::LEDGER) {
    LOG_PRINT_L0("Account on device. Initing device...");
    hw::device &hwdev = hw::get_device(m_device_name);
    hwdev.set_name(m_device_name);
    hwdev.init();
    hwdev.connect();
    m_account.set_device(hwdev);
    LOG_PRINT_L0("Device inited...");
  } else if (key_on_device()) {
    THROW_WALLET_EXCEPTION(error::wallet_internal_error, "hardware device not supported");
  }

  if (r)
  {
    if (encrypted_secret_keys)
    {
      m_account.decrypt_keys(key);
    }
    else
    {
      // rewrite with encrypted keys, ignore errors
      if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
        encrypt_keys(key);
      bool saved_ret = store_keys(keys_file_name, password, m_watch_only);
      if (!saved_ret)
      {
        // just moan a bit, but not fatal
        MERROR("Error saving keys file with encrypted keys, not fatal");
      }
      if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
        decrypt_keys(key);
      m_keys_file_locker.reset();
    }
  }
  const cryptonote::account_keys& keys = m_account.get_keys();
  hw::device &hwdev = m_account.get_device();
  r = r && hwdev.verify_keys(keys.m_view_secret_key,  keys.m_account_address.m_view_public_key);
  if(!m_watch_only && !m_multisig)
    r = r && hwdev.verify_keys(keys.m_spend_secret_key, keys.m_account_address.m_spend_public_key);
  THROW_WALLET_EXCEPTION_IF(!r, error::invalid_password);

  if (r)
    setup_keys(password);

  return true;
}

/*!
 * \brief verify password for default wallet keys file.
 * \param password       Password to verify
 * \return               true if password is correct
 *
 * for verification only
 * should not mutate state, unlike load_keys()
 * can be used prior to rewriting wallet keys file, to ensure user has entered the correct password
 *
 */
bool CWallet::verify_password(const epee::wipeable_string& password)
{
  // this temporary unlocking is necessary for Windows (otherwise the file couldn't be loaded).
  unlock_keys_file();
  bool r = verify_password(m_keys_file, password, m_watch_only || m_multisig, m_account.get_device(), m_kdf_rounds);
  lock_keys_file();
  return r;
}

/*!
 * \brief verify password for specified wallet keys file.
 * \param keys_file_name  Keys file to verify password for
 * \param password        Password to verify
 * \param no_spend_key    If set = only verify view keys, otherwise also spend keys
 * \param hwdev           The hardware device to use
 * \return                true if password is correct
 *
 * for verification only
 * should not mutate state, unlike load_keys()
 * can be used prior to rewriting wallet keys file, to ensure user has entered the correct password
 *
 */
bool CWallet::verify_password(const std::string& keys_file_name, const epee::wipeable_string& password, bool no_spend_key, hw::device &hwdev, uint64_t kdf_rounds)
{
  rapidjson::Document json;
  CWallet::keys_file_data keys_file_data;
  std::string buf;
  bool encrypted_secret_keys = false;
  bool r = epee::file_io_utils::load_file_to_string(keys_file_name, buf);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_read_error, keys_file_name);

  // Decrypt the contents
  r = ::serialization::parse_binary(buf, keys_file_data);
  THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "internal error: failed to deserialize \"" + keys_file_name + '\"');
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, kdf_rounds);
  std::string account_data;
  account_data.resize(keys_file_data.account_data.size());
  crypto::chacha20(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);
  if (json.Parse(account_data.c_str()).HasParseError() || !json.IsObject())
    crypto::chacha8(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);

  // The contents should be JSON if the wallet follows the new format.
  if (json.Parse(account_data.c_str()).HasParseError())
  {
    // old format before JSON wallet key file format
  }
  else
  {
    account_data = std::string(json["key_data"].GetString(), json["key_data"].GetString() +
      json["key_data"].GetStringLength());
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, encrypted_secret_keys, uint32_t, Uint, false, false);
    encrypted_secret_keys = field_encrypted_secret_keys;
  }

  cryptonote::account_base account_data_check;

  r = epee::serialization::load_t_from_binary(account_data_check, account_data);

  if (encrypted_secret_keys)
    account_data_check.decrypt_keys(key);

  const cryptonote::account_keys& keys = account_data_check.get_keys();
  r = r && hwdev.verify_keys(keys.m_view_secret_key,  keys.m_account_address.m_view_public_key);
  if(!no_spend_key)
    r = r && hwdev.verify_keys(keys.m_spend_secret_key, keys.m_account_address.m_spend_public_key);
  return r;
}

void CWallet::encrypt_keys(const crypto::chacha_key &key)
{
  m_account.encrypt_keys(key);
  m_account.decrypt_viewkey(key);
}

void CWallet::decrypt_keys(const crypto::chacha_key &key)
{
  m_account.encrypt_viewkey(key);
  m_account.decrypt_keys(key);
}

void CWallet::encrypt_keys(const epee::wipeable_string &password)
{
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);
  encrypt_keys(key);
}

void CWallet::decrypt_keys(const epee::wipeable_string &password)
{
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);
  decrypt_keys(key);
}

void CWallet::create_keys_file(const std::string &wallet_, bool watch_only, const epee::wipeable_string &password, bool create_address_file)
{
  if (!wallet_.empty())
  {
    bool r = store_keys(m_keys_file, password, watch_only);
    THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_keys_file);

    if (create_address_file)
    {
      r = file_io_utils::save_string_to_file(m_wallet_file + ".address.txt", m_account.get_public_address_str(m_nettype));
      if(!r) MERROR("String with address text not saved");
    }
  }
}


/*!
 * \brief determine the key storage for the specified wallet file
 * \param device_type     (OUT) wallet backend as enumerated in hw::device::device_type
 * \param keys_file_name  Keys file to verify password for
 * \param password        Password to verify
 * \return                true if password correct, else false
 *
 * for verification only - determines key storage hardware
 *
 */
bool CWallet::query_device(hw::device::device_type& device_type, const std::string& keys_file_name, const epee::wipeable_string& password, uint64_t kdf_rounds)
{
  rapidjson::Document json;
  CWallet::keys_file_data keys_file_data;
  std::string buf;
  bool r = epee::file_io_utils::load_file_to_string(keys_file_name, buf);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_read_error, keys_file_name);

  // Decrypt the contents
  r = ::serialization::parse_binary(buf, keys_file_data);
  THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "internal error: failed to deserialize \"" + keys_file_name + '\"');
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key, kdf_rounds);
  std::string account_data;
  account_data.resize(keys_file_data.account_data.size());
  crypto::chacha20(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);
  if (json.Parse(account_data.c_str()).HasParseError() || !json.IsObject())
    crypto::chacha8(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv, &account_data[0]);

  device_type = hw::device::device_type::SOFTWARE;
  // The contents should be JSON if the wallet follows the new format.
  if (json.Parse(account_data.c_str()).HasParseError())
  {
    // old format before JSON wallet key file format
  }
  else
  {
    account_data = std::string(json["key_data"].GetString(), json["key_data"].GetString() +
      json["key_data"].GetStringLength());

    if (json.HasMember("key_on_device"))
    {
      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, key_on_device, int, Int, false, hw::device::device_type::SOFTWARE);
      device_type = static_cast<hw::device::device_type>(field_key_on_device);
    }
  }

  cryptonote::account_base account_data_check;

  r = epee::serialization::load_t_from_binary(account_data_check, account_data);
  if (!r) return false;
  return true;
}

/*!
 * \brief  Generates a wallet or restores one.
 * \param  wallet_              Name of wallet file
 * \param  password             Password of wallet file
 * \param  multisig_data        The multisig restore info and keys
 * \param  create_address_file  Whether to create an address file
 */
void CWallet::generate(const std::string& wallet_, const epee::wipeable_string& password,
  const epee::wipeable_string& multisig_data, bool create_address_file)
{
  clear();
  prepare_file_names(wallet_);

  if (!wallet_.empty())
  {
    boost::system::error_code ignored_ec;
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  m_account.generate(rct::rct2sk(rct::zero()), true, false);

  THROW_WALLET_EXCEPTION_IF(multisig_data.size() < 32, error::invalid_multisig_seed);
  size_t offset = 0;
  uint32_t threshold = *(uint32_t*)(multisig_data.data() + offset);
  offset += sizeof(uint32_t);
  uint32_t total = *(uint32_t*)(multisig_data.data() + offset);
  offset += sizeof(uint32_t);
  THROW_WALLET_EXCEPTION_IF(threshold < 2, error::invalid_multisig_seed);
  THROW_WALLET_EXCEPTION_IF(total != threshold && total != threshold + 1, error::invalid_multisig_seed);
  const size_t n_multisig_keys =  total == threshold ? 1 : threshold;
  THROW_WALLET_EXCEPTION_IF(multisig_data.size() != 8 + 32 * (4 + n_multisig_keys + total), error::invalid_multisig_seed);

  std::vector<crypto::secret_key> multisig_keys;
  std::vector<crypto::public_key> multisig_signers;
  crypto::secret_key spend_secret_key = *(crypto::secret_key*)(multisig_data.data() + offset);
  offset += sizeof(crypto::secret_key);
  crypto::public_key spend_public_key = *(crypto::public_key*)(multisig_data.data() + offset);
  offset += sizeof(crypto::public_key);
  crypto::secret_key view_secret_key = *(crypto::secret_key*)(multisig_data.data() + offset);
  offset += sizeof(crypto::secret_key);
  crypto::public_key view_public_key = *(crypto::public_key*)(multisig_data.data() + offset);
  offset += sizeof(crypto::public_key);
  for (size_t n = 0; n < n_multisig_keys; ++n)
  {
    multisig_keys.push_back(*(crypto::secret_key*)(multisig_data.data() + offset));
    offset += sizeof(crypto::secret_key);
  }
  for (size_t n = 0; n < total; ++n)
  {
    multisig_signers.push_back(*(crypto::public_key*)(multisig_data.data() + offset));
    offset += sizeof(crypto::public_key);
  }

  crypto::public_key calculated_view_public_key;
  THROW_WALLET_EXCEPTION_IF(!crypto::secret_key_to_public_key(view_secret_key, calculated_view_public_key), error::invalid_multisig_seed);
  THROW_WALLET_EXCEPTION_IF(view_public_key != calculated_view_public_key, error::invalid_multisig_seed);
  crypto::public_key local_signer;
  THROW_WALLET_EXCEPTION_IF(!crypto::secret_key_to_public_key(spend_secret_key, local_signer), error::invalid_multisig_seed);
  THROW_WALLET_EXCEPTION_IF(std::find(multisig_signers.begin(), multisig_signers.end(), local_signer) == multisig_signers.end(), error::invalid_multisig_seed);
  rct::key skey = rct::zero();
  for (const auto &msk: multisig_keys)
    sc_add(skey.bytes, skey.bytes, rct::sk2rct(msk).bytes);
  THROW_WALLET_EXCEPTION_IF(!(rct::rct2sk(skey) == spend_secret_key), error::invalid_multisig_seed);
  memwipe(&skey, sizeof(rct::key));

  m_account.make_multisig(view_secret_key, spend_secret_key, spend_public_key, multisig_keys);
  m_account.finalize_multisig(spend_public_key);

  m_account_public_address = m_account.get_keys().m_account_address;
  m_watch_only = false;
  m_multisig = true;
  m_multisig_threshold = threshold;
  m_multisig_signers = multisig_signers;
  m_key_device_type = hw::device::device_type::SOFTWARE;
  setup_keys(password);

  create_keys_file(wallet_, false, password, m_nettype != MAINNET || create_address_file);
  setup_new_blockchain();

  if (!wallet_.empty())
    store();
}

/*!
 * \brief  Generates a wallet or restores one.
 * \param  wallet_                 Name of wallet file
 * \param  password                Password of wallet file
 * \param  recovery_param          If it is a restore, the recovery key
 * \param  recover                 Whether it is a restore
 * \param  two_random              Whether it is a non-deterministic wallet
 * \param  create_address_file     Whether to create an address file
 * \return                         The secret key of the generated wallet
 */
crypto::secret_key CWallet::generate(const std::string& wallet_, const epee::wipeable_string& password,
  const crypto::secret_key& recovery_param, bool recover, bool two_random, bool create_address_file)
{
  clear();
  prepare_file_names(wallet_);

  if (!wallet_.empty())
  {
    boost::system::error_code ignored_ec;
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  crypto::secret_key retval = m_account.generate(recovery_param, recover, two_random);

  m_account_public_address = m_account.get_keys().m_account_address;
  m_watch_only = false;
  m_multisig = false;
  m_multisig_threshold = 0;
  m_multisig_signers.clear();
  m_key_device_type = hw::device::device_type::SOFTWARE;
  setup_keys(password);

  // calculate a starting refresh height
  if(m_refresh_from_block_height == 0 && !recover){
    m_refresh_from_block_height = estimate_blockchain_height();
  }

  create_keys_file(wallet_, false, password, m_nettype != MAINNET || create_address_file);

  setup_new_blockchain();

  if (!wallet_.empty())
    store();

  return retval;
}

/*!
* \brief Creates a watch only wallet from a public address and a view secret key.
* \param  wallet_                 Name of wallet file
* \param  password                Password of wallet file
* \param  account_public_address  The account's public address
* \param  viewkey                 view secret key
* \param  create_address_file     Whether to create an address file
*/
void CWallet::generate(const std::string& wallet_, const epee::wipeable_string& password,
  const cryptonote::account_public_address &account_public_address,
  const crypto::secret_key& viewkey, bool create_address_file)
{
  clear();
  prepare_file_names(wallet_);

  if (!wallet_.empty())
  {
    boost::system::error_code ignored_ec;
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  m_account.create_from_viewkey(account_public_address, viewkey);
  m_account_public_address = account_public_address;
  m_watch_only = true;
  m_multisig = false;
  m_multisig_threshold = 0;
  m_multisig_signers.clear();
  m_key_device_type = hw::device::device_type::SOFTWARE;
  setup_keys(password);

  create_keys_file(wallet_, true, password, m_nettype != MAINNET || create_address_file);

  setup_new_blockchain();

  if (!wallet_.empty())
    store();
}

/*!
* \brief Creates a wallet from a public address and a spend/view secret key pair.
* \param  wallet_                 Name of wallet file
* \param  password                Password of wallet file
* \param  account_public_address  The account's public address
* \param  spendkey                spend secret key
* \param  viewkey                 view secret key
* \param  create_address_file     Whether to create an address file
*/
void CWallet::generate(const std::string& wallet_, const epee::wipeable_string& password,
  const cryptonote::account_public_address &account_public_address,
  const crypto::secret_key& spendkey, const crypto::secret_key& viewkey, bool create_address_file)
{
  clear();
  prepare_file_names(wallet_);

  if (!wallet_.empty())
  {
    boost::system::error_code ignored_ec;
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  m_account.create_from_keys(account_public_address, spendkey, viewkey);
  m_account_public_address = account_public_address;
  m_watch_only = false;
  m_multisig = false;
  m_multisig_threshold = 0;
  m_multisig_signers.clear();
  m_key_device_type = hw::device::device_type::SOFTWARE;
  setup_keys(password);

  create_keys_file(wallet_, false, password, create_address_file);

  setup_new_blockchain();

  if (!wallet_.empty())
    store();
}

/*!
* \brief Creates a wallet from a device
* \param  wallet_        Name of wallet file
* \param  password       Password of wallet file
* \param  device_name    device string address
*/
void CWallet::restore(const std::string& wallet_, const epee::wipeable_string& password, const std::string &device_name, bool create_address_file)
{
  clear();
  prepare_file_names(wallet_);

  boost::system::error_code ignored_ec;
  if (!wallet_.empty()) {
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_wallet_file, ignored_ec), error::file_exists, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(boost::filesystem::exists(m_keys_file,   ignored_ec), error::file_exists, m_keys_file);
  }

  auto &hwdev = hw::get_device(device_name);
  hwdev.set_name(device_name);

  m_account.create_from_device(hwdev);
  m_key_device_type = m_account.get_device().get_type();
  m_account_public_address = m_account.get_keys().m_account_address;
  m_watch_only = false;
  m_multisig = false;
  m_multisig_threshold = 0;
  m_multisig_signers.clear();
  setup_keys(password);
  m_device_name = device_name;

  create_keys_file(wallet_, false, password, m_nettype != MAINNET || create_address_file);
  if (m_subaddress_lookahead_major == SUBADDRESS_LOOKAHEAD_MAJOR && m_subaddress_lookahead_minor == SUBADDRESS_LOOKAHEAD_MINOR)
  {
    // the default lookahead setting (50:200) is clearly too much for hardware wallet
    m_subaddress_lookahead_major = 5;
    m_subaddress_lookahead_minor = 20;
  }
  setup_new_blockchain();
  if (!wallet_.empty()) {
    store();
  }
}

std::string CWallet::make_multisig(const epee::wipeable_string &password,
  const std::vector<crypto::secret_key> &view_keys,
  const std::vector<crypto::public_key> &spend_keys,
  uint32_t threshold)
{
  CHECK_AND_ASSERT_THROW_MES(!view_keys.empty(), "empty view keys");
  CHECK_AND_ASSERT_THROW_MES(view_keys.size() == spend_keys.size(), "Mismatched view/spend key sizes");
  CHECK_AND_ASSERT_THROW_MES(threshold > 1 && threshold <= spend_keys.size() + 1, "Invalid threshold");

  std::string extra_multisig_info;
  std::vector<crypto::secret_key> multisig_keys;
  rct::key spend_pkey = rct::identity();
  rct::key spend_skey;
  std::vector<crypto::public_key> multisig_signers;

  // decrypt keys
  epee::misc_utils::auto_scope_leave_caller keys_reencryptor;
  if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
  {
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(password.data(), password.size(), chacha_key, m_kdf_rounds);
    m_account.encrypt_viewkey(chacha_key);
    m_account.decrypt_keys(chacha_key);
    keys_reencryptor = epee::misc_utils::create_scope_leave_handler([&, this, chacha_key]() { m_account.encrypt_keys(chacha_key); m_account.decrypt_viewkey(chacha_key); });
  }

  // In common multisig scheme there are 4 types of key exchange rounds:
  // 1. First round is exchange of view secret keys and public spend keys.
  // 2. Middle round is exchange of derivations: Ki = b * Mj, where b - spend secret key,
  //    M - public multisig key (in first round it equals to public spend key), K - new public multisig key.
  // 3. Secret spend establishment round sets your secret multisig keys as follows: kl = H(Ml), where M - is *your* public multisig key,
  //    k - secret multisig key used to sign transactions. k and M are sets of keys, of course.
  //    And secret spend key as the sum of all participant's secret multisig keys
  // 4. Last round establishes multisig wallet's public spend key. Participants exchange their public multisig keys
  //    and calculate common spend public key as sum of all unique participants' public multisig keys.
  // Note that N/N scheme has only first round. N-1/N has 2 rounds: first and last. Common M/N has all 4 rounds.

  // IMPORTANT: wallet's public spend key is not equal to secret_spend_key * G!
  // Wallet's public spend key is the sum of unique public multisig keys of all participants.
  // secret_spend_key * G = public signer key

  if (threshold == spend_keys.size() + 1)
  {
    // In N / N case we only need to do one round and calculate secret multisig keys and new secret spend key
    MINFO("Creating spend key...");

    // Calculates all multisig keys and spend key
    cryptonote::generate_multisig_N_N(get_account().get_keys(), spend_keys, multisig_keys, spend_skey, spend_pkey);

    // Our signer key is b * G, where b is secret spend key.
    multisig_signers = spend_keys;
    multisig_signers.push_back(get_multisig_signer_public_key(get_account().get_keys().m_spend_secret_key));
  }
  else
  {
    // We just got public spend keys of all participants and deriving multisig keys (set of Mi = b * Bi).
    // note that derivations are public keys as DH exchange suppose it to be
    auto derivations = cryptonote::generate_multisig_derivations(get_account().get_keys(), spend_keys);

    spend_pkey = rct::identity();
    multisig_signers = std::vector<crypto::public_key>(spend_keys.size() + 1, crypto::null_pkey);

    if (threshold == spend_keys.size())
    {
      // N - 1 / N case

      // We need an extra step, so we package all the composite public keys
      // we know about, and make a signed string out of them
      MINFO("Creating spend key...");

      // Calculating set of our secret multisig keys as follows: mi = H(Mi),
      // where mi - secret multisig key, Mi - others' participants public multisig key
      multisig_keys = cryptonote::calculate_multisig_keys(derivations);

      // calculating current participant's spend secret key as sum of all secret multisig keys for current participant.
      // IMPORTANT: participant's secret spend key is not an entire wallet's secret spend!
      //            Entire wallet's secret spend is sum of all unique secret multisig keys
      //            among all of participants and is not held by anyone!
      spend_skey = rct::sk2rct(cryptonote::calculate_multisig_signer_key(multisig_keys));

      // Preparing data for the last round to calculate common public spend key. The data contains public multisig keys.
      extra_multisig_info = pack_multisignature_keys(MULTISIG_EXTRA_INFO_MAGIC, secret_keys_to_public_keys(multisig_keys), rct::rct2sk(spend_skey));
    }
    else
    {
      // M / N case
      MINFO("Preparing keys for next exchange round...");

      // Preparing data for middle round - packing new public multisig keys to exchage with others.
      extra_multisig_info = pack_multisignature_keys(MULTISIG_EXTRA_INFO_MAGIC, derivations, m_account.get_keys().m_spend_secret_key);
      spend_skey = rct::sk2rct(m_account.get_keys().m_spend_secret_key);

      // Need to store middle keys to be able to proceed in case of wallet shutdown.
      m_multisig_derivations = derivations;
    }
  }

  clear();
  MINFO("Creating view key...");
  crypto::secret_key view_skey = cryptonote::generate_multisig_view_secret_key(get_account().get_keys().m_view_secret_key, view_keys);

  MINFO("Creating multisig address...");
  CHECK_AND_ASSERT_THROW_MES(m_account.make_multisig(view_skey, rct::rct2sk(spend_skey), rct::rct2pk(spend_pkey), multisig_keys),
      "Failed to create multisig wallet due to bad keys");
  memwipe(&spend_skey, sizeof(rct::key));

  m_account_public_address = m_account.get_keys().m_account_address;
  m_watch_only = false;
  m_multisig = true;
  m_key_device_type = hw::device::device_type::SOFTWARE;
  m_multisig_threshold = threshold;
  m_multisig_signers = multisig_signers;
  ++m_multisig_rounds_passed;

  // re-encrypt keys
  keys_reencryptor = epee::misc_utils::auto_scope_leave_caller();

  create_keys_file(m_wallet_file, false, password, boost::filesystem::exists(m_wallet_file + ".address.txt"));

  setup_new_blockchain();

  if (!m_wallet_file.empty())
    store();

  return extra_multisig_info;
}

std::string CWallet::exchange_multisig_keys(const epee::wipeable_string &password,
  const std::vector<std::string> &info)
{
  THROW_WALLET_EXCEPTION_IF(info.empty(),
    error::wallet_internal_error, "Empty multisig info");

  if (info[0].substr(0, MULTISIG_EXTRA_INFO_MAGIC.size()) != MULTISIG_EXTRA_INFO_MAGIC)
  {
    THROW_WALLET_EXCEPTION_IF(false,
      error::wallet_internal_error, "Unsupported info string");
  }

  std::vector<crypto::public_key> signers;
  std::unordered_set<crypto::public_key> pkeys;

  THROW_WALLET_EXCEPTION_IF(!unpack_extra_multisig_info(info, signers, pkeys),
    error::wallet_internal_error, "Bad extra multisig info");

  return exchange_multisig_keys(password, pkeys, signers);
}

std::string CWallet::exchange_multisig_keys(const epee::wipeable_string &password,
  std::unordered_set<crypto::public_key> derivations,
  std::vector<crypto::public_key> signers)
{
  CHECK_AND_ASSERT_THROW_MES(!derivations.empty(), "empty pkeys");
  CHECK_AND_ASSERT_THROW_MES(!signers.empty(), "empty signers");

  bool ready = false;
  CHECK_AND_ASSERT_THROW_MES(multisig(&ready), "The wallet is not multisig");
  CHECK_AND_ASSERT_THROW_MES(!ready, "Multisig wallet creation process has already been finished");

  // keys are decrypted
  epee::misc_utils::auto_scope_leave_caller keys_reencryptor;
  if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
  {
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(password.data(), password.size(), chacha_key, m_kdf_rounds);
    m_account.encrypt_viewkey(chacha_key);
    m_account.decrypt_keys(chacha_key);
    keys_reencryptor = epee::misc_utils::create_scope_leave_handler([&, this, chacha_key]() { m_account.encrypt_keys(chacha_key); m_account.decrypt_viewkey(chacha_key); });
  }

  if (m_multisig_rounds_passed == multisig_rounds_required(m_multisig_signers.size(), m_multisig_threshold) - 1)
  {
    // the last round is passed and we have to calculate spend public key
    // add ours if not included
    crypto::public_key local_signer = get_multisig_signer_public_key();

    if (std::find(signers.begin(), signers.end(), local_signer) == signers.end())
    {
        signers.push_back(local_signer);
        for (const auto &msk: get_account().get_multisig_keys())
        {
            derivations.insert(rct::rct2pk(rct::scalarmultBase(rct::sk2rct(msk))));
        }
    }

    CHECK_AND_ASSERT_THROW_MES(signers.size() == m_multisig_signers.size(), "Bad signers size");

    // Summing all of unique public multisig keys to calculate common public spend key
    crypto::public_key spend_public_key = cryptonote::generate_multisig_M_N_spend_public_key(std::vector<crypto::public_key>(derivations.begin(), derivations.end()));
    m_account_public_address.m_spend_public_key = spend_public_key;
    m_account.finalize_multisig(spend_public_key);

    m_multisig_signers = signers;
    std::sort(m_multisig_signers.begin(), m_multisig_signers.end(), [](const crypto::public_key &e0, const crypto::public_key &e1){ return memcmp(&e0, &e1, sizeof(e0)); });

    ++m_multisig_rounds_passed;
    m_multisig_derivations.clear();

    // keys are encrypted again
    keys_reencryptor = epee::misc_utils::auto_scope_leave_caller();

    if (!m_wallet_file.empty())
    {
      bool r = store_keys(m_keys_file, password, false);
      THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_keys_file);

      if (boost::filesystem::exists(m_wallet_file + ".address.txt"))
      {
        r = file_io_utils::save_string_to_file(m_wallet_file + ".address.txt", m_account.get_public_address_str(m_nettype));
        if(!r) MERROR("String with address text not saved");
      }
    }

    m_subaddresses.clear();
    m_subaddress_labels.clear();
    add_subaddress_account(tr("Primary account"));

    if (!m_wallet_file.empty())
      store();

    return {};
  }

  // Below are either middle or secret spend key establishment rounds

  for (const auto& key: m_multisig_derivations)
    derivations.erase(key);

  // Deriving multisig keys (set of Mi = b * Bi) according to DH from other participants' multisig keys.
  auto new_derivations = cryptonote::generate_multisig_derivations(get_account().get_keys(), std::vector<crypto::public_key>(derivations.begin(), derivations.end()));

  std::string extra_multisig_info;
  if (m_multisig_rounds_passed == multisig_rounds_required(m_multisig_signers.size(), m_multisig_threshold) - 2) // next round is last
  {
    // Next round is last therefore we are performing secret spend establishment round as described above.
    MINFO("Creating spend key...");

    // Calculating our secret multisig keys by hashing our public multisig keys.
    auto multisig_keys = cryptonote::calculate_multisig_keys(std::vector<crypto::public_key>(new_derivations.begin(), new_derivations.end()));
    // And summing it to get personal secret spend key
    crypto::secret_key spend_skey = cryptonote::calculate_multisig_signer_key(multisig_keys);

    m_account.make_multisig(m_account.get_keys().m_view_secret_key, spend_skey, rct::rct2pk(rct::identity()), multisig_keys);

    // Packing public multisig keys to exchange with others and calculate common public spend key in the last round
    extra_multisig_info = pack_multisignature_keys(MULTISIG_EXTRA_INFO_MAGIC, secret_keys_to_public_keys(multisig_keys), spend_skey);
  }
  else
  {
    // This is just middle round
    MINFO("Preparing keys for next exchange round...");
    extra_multisig_info = pack_multisignature_keys(MULTISIG_EXTRA_INFO_MAGIC, new_derivations, m_account.get_keys().m_spend_secret_key);
    m_multisig_derivations = new_derivations;
  }

  ++m_multisig_rounds_passed;

  create_keys_file(m_wallet_file, false, password, boost::filesystem::exists(m_wallet_file + ".address.txt"));
  return extra_multisig_info;
}

void CWallet::unpack_multisig_info(const std::vector<std::string>& info,
  std::vector<crypto::public_key> &public_keys,
  std::vector<crypto::secret_key> &secret_keys) const
{
  // parse all multisig info
  public_keys.resize(info.size());
  secret_keys.resize(info.size());
  for (size_t i = 0; i < info.size(); ++i)
  {
    THROW_WALLET_EXCEPTION_IF(!verify_multisig_info(info[i], secret_keys[i], public_keys[i]),
        error::wallet_internal_error, "Bad multisig info: " + info[i]);
  }

  // remove duplicates
  for (size_t i = 0; i < secret_keys.size(); ++i)
  {
    for (size_t j = i + 1; j < secret_keys.size(); ++j)
    {
      if (rct::sk2rct(secret_keys[i]) == rct::sk2rct(secret_keys[j]))
      {
        MDEBUG("Duplicate key found, ignoring");
        secret_keys[j] = secret_keys.back();
        public_keys[j] = public_keys.back();
        secret_keys.pop_back();
        public_keys.pop_back();
        --j;
      }
    }
  }

  // people may include their own, weed it out
  const crypto::secret_key local_skey = cryptonote::get_multisig_blinded_secret_key(get_account().get_keys().m_view_secret_key);
  const crypto::public_key local_pkey = get_multisig_signer_public_key(get_account().get_keys().m_spend_secret_key);
  for (size_t i = 0; i < secret_keys.size(); ++i)
  {
    if (secret_keys[i] == local_skey)
    {
      MDEBUG("Local key is present, ignoring");
      secret_keys[i] = secret_keys.back();
      public_keys[i] = public_keys.back();
      secret_keys.pop_back();
      public_keys.pop_back();
      --i;
    }
    else
    {
      THROW_WALLET_EXCEPTION_IF(public_keys[i] == local_pkey, error::wallet_internal_error,
          "Found local spend public key, but not local view secret key - something very weird");
    }
  }
}

std::string CWallet::make_multisig(const epee::wipeable_string &password,
  const std::vector<std::string> &info,
  uint32_t threshold)
{
  std::vector<crypto::secret_key> secret_keys(info.size());
  std::vector<crypto::public_key> public_keys(info.size());
  unpack_multisig_info(info, public_keys, secret_keys);
  return make_multisig(password, secret_keys, public_keys, threshold);
}

bool CWallet::finalize_multisig(const epee::wipeable_string &password, std::unordered_set<crypto::public_key> pkeys, std::vector<crypto::public_key> signers)
{
  exchange_multisig_keys(password, pkeys, signers);
  return true;
}

bool CWallet::unpack_extra_multisig_info(const std::vector<std::string>& info,
  std::vector<crypto::public_key> &signers,
  std::unordered_set<crypto::public_key> &pkeys) const
{
  // parse all multisig info
  signers.resize(info.size(), crypto::null_pkey);
  for (size_t i = 0; i < info.size(); ++i)
  {
      if (!verify_extra_multisig_info(info[i], pkeys, signers[i]))
      {
          return false;
      }
  }

  return true;
}

bool CWallet::finalize_multisig(const epee::wipeable_string &password, const std::vector<std::string> &info)
{
  std::unordered_set<crypto::public_key> public_keys;
  std::vector<crypto::public_key> signers;
  if (!unpack_extra_multisig_info(info, signers, public_keys))
  {
    MERROR("Bad multisig info");
    return false;
  }

  return finalize_multisig(password, public_keys, signers);
}

std::string CWallet::get_multisig_info() const
{
  // It's a signed package of private view key and public spend key
  const crypto::secret_key skey = cryptonote::get_multisig_blinded_secret_key(get_account().get_keys().m_view_secret_key);
  const crypto::public_key pkey = get_multisig_signer_public_key(get_account().get_keys().m_spend_secret_key);
  crypto::hash hash;

  std::string data;
  data += std::string((const char *)&skey, sizeof(crypto::secret_key));
  data += std::string((const char *)&pkey, sizeof(crypto::public_key));

  data.resize(data.size() + sizeof(crypto::signature));
  crypto::cn_fast_hash(data.data(), data.size() - sizeof(signature), hash);
  crypto::signature &signature = *(crypto::signature*)&data[data.size() - sizeof(crypto::signature)];
  crypto::generate_signature(hash, pkey, get_multisig_blinded_secret_key(get_account().get_keys().m_spend_secret_key), signature);

  return std::string("MultisigV1") + tools::base58::encode(data);
}

bool CWallet::verify_multisig_info(const std::string &data, crypto::secret_key &skey, crypto::public_key &pkey)
{
  const size_t header_len = strlen("MultisigV1");
  if (data.size() < header_len || data.substr(0, header_len) != "MultisigV1")
  {
    MERROR("Multisig info header check error");
    return false;
  }
  std::string decoded;
  if (!tools::base58::decode(data.substr(header_len), decoded))
  {
    MERROR("Multisig info decoding error");
    return false;
  }
  if (decoded.size() != sizeof(crypto::secret_key) + sizeof(crypto::public_key) + sizeof(crypto::signature))
  {
    MERROR("Multisig info is corrupt");
    return false;
  }

  size_t offset = 0;
  skey = *(const crypto::secret_key*)(decoded.data() + offset);
  offset += sizeof(skey);
  pkey = *(const crypto::public_key*)(decoded.data() + offset);
  offset += sizeof(pkey);
  const crypto::signature &signature = *(const crypto::signature*)(decoded.data() + offset);

  crypto::hash hash;
  crypto::cn_fast_hash(decoded.data(), decoded.size() - sizeof(signature), hash);
  if (!crypto::check_signature(hash, pkey, signature))
  {
    MERROR("Multisig info signature is invalid");
    return false;
  }

  return true;
}

bool CWallet::verify_extra_multisig_info(const std::string &data, std::unordered_set<crypto::public_key> &pkeys, crypto::public_key &signer)
{
  if (data.size() < MULTISIG_EXTRA_INFO_MAGIC.size() || data.substr(0, MULTISIG_EXTRA_INFO_MAGIC.size()) != MULTISIG_EXTRA_INFO_MAGIC)
  {
    MERROR("Multisig info header check error");
    return false;
  }
  std::string decoded;
  if (!tools::base58::decode(data.substr(MULTISIG_EXTRA_INFO_MAGIC.size()), decoded))
  {
    MERROR("Multisig info decoding error");
    return false;
  }
  if (decoded.size() < sizeof(crypto::public_key) + sizeof(crypto::signature))
  {
    MERROR("Multisig info is corrupt");
    return false;
  }
  if ((decoded.size() - (sizeof(crypto::public_key) + sizeof(crypto::signature))) % sizeof(crypto::public_key))
  {
    MERROR("Multisig info is corrupt");
    return false;
  }

  const size_t n_keys = (decoded.size() - (sizeof(crypto::public_key) + sizeof(crypto::signature))) / sizeof(crypto::public_key);
  size_t offset = 0;
  signer = *(const crypto::public_key*)(decoded.data() + offset);
  offset += sizeof(signer);
  const crypto::signature &signature = *(const crypto::signature*)(decoded.data() + offset + n_keys * sizeof(crypto::public_key));

  crypto::hash hash;
  crypto::cn_fast_hash(decoded.data(), decoded.size() - sizeof(signature), hash);
  if (!crypto::check_signature(hash, signer, signature))
  {
    MERROR("Multisig info signature is invalid");
    return false;
  }

  for (size_t n = 0; n < n_keys; ++n)
  {
    crypto::public_key mspk = *(const crypto::public_key*)(decoded.data() + offset);
    pkeys.insert(mspk);
    offset += sizeof(mspk);
  }

  return true;
}

bool CWallet::multisig(bool *ready, uint32_t *threshold, uint32_t *total) const
{
  if (!m_multisig)
    return false;
  if (threshold)
    *threshold = m_multisig_threshold;
  if (total)
    *total = m_multisig_signers.size();
  if (ready)
    *ready = !(get_account().get_keys().m_account_address.m_spend_public_key == rct::rct2pk(rct::identity()));
  return true;
}

bool CWallet::has_multisig_partial_key_images() const
{
  if (!m_multisig)
    return false;
  for (const auto &td: m_transfers)
    if (td.m_key_image_partial)
      return true;
  return false;
}

bool CWallet::has_unknown_key_images() const
{
  for (const auto &td: m_transfers)
    if (!td.m_key_image_known)
      return true;
  return false;
}

/*!
 * \brief Rewrites to the wallet file for wallet upgrade (doesn't generate key, assumes it's already there)
 * \param wallet_name Name of wallet file (should exist)
 * \param password    Password for wallet file
 */
void CWallet::rewrite(const std::string& wallet_name, const epee::wipeable_string& password)
{
  if (wallet_name.empty())
    return;
  prepare_file_names(wallet_name);
  boost::system::error_code ignored_ec;
  THROW_WALLET_EXCEPTION_IF(!boost::filesystem::exists(m_keys_file, ignored_ec), error::file_not_found, m_keys_file);
  bool r = store_keys(m_keys_file, password, m_watch_only);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_keys_file);
}
/*!
 * \brief Writes to a file named based on the normal wallet (doesn't generate key, assumes it's already there)
 * \param wallet_name       Base name of wallet file
 * \param password          Password for wallet file
 * \param new_keys_filename [OUT] Name of new keys file
 */
void CWallet::write_watch_only_wallet(const std::string& wallet_name, const epee::wipeable_string& password, std::string &new_keys_filename)
{
  prepare_file_names(wallet_name);
  boost::system::error_code ignored_ec;
  new_keys_filename = m_wallet_file + "-watchonly.keys";
  bool watch_only_keys_file_exists = boost::filesystem::exists(new_keys_filename, ignored_ec);
  THROW_WALLET_EXCEPTION_IF(watch_only_keys_file_exists, error::file_save_error, new_keys_filename);
  bool r = store_keys(new_keys_filename, password, true);
  THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, new_keys_filename);
}
//----------------------------------------------------------------------------------------------------
void CWallet::wallet_exists(const std::string& file_path, bool& keys_file_exists, bool& wallet_file_exists)
{
  std::string keys_file, wallet_file;
  do_prepare_file_names(file_path, keys_file, wallet_file);

  boost::system::error_code ignore;
  keys_file_exists = boost::filesystem::exists(keys_file, ignore);
  wallet_file_exists = boost::filesystem::exists(wallet_file, ignore);
}
//----------------------------------------------------------------------------------------------------
bool CWallet::wallet_valid_path_format(const std::string& file_path)
{
  return !file_path.empty();
}

bool CWallet::prepare_file_names(const std::string& file_path)
{
  do_prepare_file_names(file_path, m_keys_file, m_wallet_file);
  return true;
}

bool CWallet::generate_chacha_key_from_secret_keys(crypto::chacha_key &key) const
{
  hw::device &hwdev =  m_account.get_device();
  return hwdev.generate_chacha_key(m_account.get_keys(), key, m_kdf_rounds);
}
//----------------------------------------------------------------------------------------------------
void CWallet::generate_chacha_key_from_password(const epee::wipeable_string &pass, crypto::chacha_key &key) const
{
  crypto::generate_chacha_key(pass.data(), pass.size(), key, m_kdf_rounds);
}
//----------------------------------------------------------------------------------------------------
void CWallet::load(const std::string& wallet_, const epee::wipeable_string& password)
{
  clear();
  prepare_file_names(wallet_);

  boost::system::error_code e;
  bool exists = boost::filesystem::exists(m_keys_file, e);
  THROW_WALLET_EXCEPTION_IF(e || !exists, error::file_not_found, m_keys_file);
  lock_keys_file();
  THROW_WALLET_EXCEPTION_IF(!is_keys_file_locked(), error::wallet_internal_error, "internal error: \"" + m_keys_file + "\" is opened by another wallet program");

  // this temporary unlocking is necessary for Windows (otherwise the file couldn't be loaded).
  unlock_keys_file();
  if (!load_keys(m_keys_file, password))
  {
    THROW_WALLET_EXCEPTION_IF(true, error::file_read_error, m_keys_file);
  }
  LOG_PRINT_L0("Loaded wallet keys file, with public address: " << m_account.get_public_address_str(m_nettype));
  lock_keys_file();

  wallet_keys_unlocker unlocker(*this, m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only, password);

  //keys loaded ok!
  //try to load wallet file. but even if we failed, it is not big problem
  if(!boost::filesystem::exists(m_wallet_file, e) || e)
  {
    LOG_PRINT_L0("file not found: " << m_wallet_file << ", starting with empty blockchain");
    m_account_public_address = m_account.get_keys().m_account_address;
  }
  else
  {
    CWallet::cache_file_data cache_file_data;
    std::string buf;
    bool r = epee::file_io_utils::load_file_to_string(m_wallet_file, buf, std::numeric_limits<size_t>::max());
    THROW_WALLET_EXCEPTION_IF(!r, error::file_read_error, m_wallet_file);

    // try to read it as an encrypted cache
    try
    {
      LOG_PRINT_L1("Trying to decrypt cache data");

      r = ::serialization::parse_binary(buf, cache_file_data);
      THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "internal error: failed to deserialize \"" + m_wallet_file + '\"');
      std::string cache_data;
      cache_data.resize(cache_file_data.cache_data.size());
      crypto::chacha20(cache_file_data.cache_data.data(), cache_file_data.cache_data.size(), m_cache_key, cache_file_data.iv, &cache_data[0]);

      try {
        std::stringstream iss;
        iss << cache_data;
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> *this;
      }
      catch(...)
      {
        // try with previous scheme: direct from keys
        crypto::chacha_key key;
        generate_chacha_key_from_secret_keys(key);
        crypto::chacha20(cache_file_data.cache_data.data(), cache_file_data.cache_data.size(), key, cache_file_data.iv, &cache_data[0]);
        try {
          std::stringstream iss;
          iss << cache_data;
          boost::archive::portable_binary_iarchive ar(iss);
          ar >> *this;
        }
        catch (...)
        {
          crypto::chacha8(cache_file_data.cache_data.data(), cache_file_data.cache_data.size(), key, cache_file_data.iv, &cache_data[0]);
          try
          {
            std::stringstream iss;
            iss << cache_data;
            boost::archive::portable_binary_iarchive ar(iss);
            ar >> *this;
          }
          catch (...)
          {
            LOG_PRINT_L0("Failed to open portable binary, trying unportable");
            boost::filesystem::copy_file(m_wallet_file, m_wallet_file + ".unportable", boost::filesystem::copy_option::overwrite_if_exists);
            std::stringstream iss;
            iss.str("");
            iss << cache_data;
            boost::archive::binary_iarchive ar(iss);
            ar >> *this;
          }
        }
      }
    }
    catch (...)
    {
      LOG_PRINT_L1("Failed to load encrypted cache, trying unencrypted");
      try {
        std::stringstream iss;
        iss << buf;
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> *this;
      }
      catch (...)
      {
        LOG_PRINT_L0("Failed to open portable binary, trying unportable");
        boost::filesystem::copy_file(m_wallet_file, m_wallet_file + ".unportable", boost::filesystem::copy_option::overwrite_if_exists);
        std::stringstream iss;
        iss.str("");
        iss << buf;
        boost::archive::binary_iarchive ar(iss);
        ar >> *this;
      }
    }
    THROW_WALLET_EXCEPTION_IF(
      m_account_public_address.m_spend_public_key != m_account.get_keys().m_account_address.m_spend_public_key ||
      m_account_public_address.m_view_public_key  != m_account.get_keys().m_account_address.m_view_public_key,
      error::wallet_files_doesnt_correspond, m_keys_file, m_wallet_file);
  }

  cryptonote::block genesis;
  generate_genesis(genesis);
  crypto::hash genesis_hash = get_block_hash(genesis);

  if (m_blockchain.empty())
  {
    m_blockchain.push_back(genesis_hash);
    m_last_block_reward = cryptonote::get_outs_money_amount(genesis.miner_tx);
  }
  else
  {
    check_genesis(genesis_hash);
  }

  trim_hashchain();

  if (get_num_subaddress_accounts() == 0)
    add_subaddress_account(tr("Primary account"));

  try
  {
    find_and_save_rings(false);
  }
  catch (const std::exception &e)
  {
    MERROR("Failed to save rings, will try again next time");
  }
}

std::string CWallet::path() const
{
  return m_wallet_file;
}
//----------------------------------------------------------------------------------------------------
void CWallet::store()
{
  store_to("", epee::wipeable_string());
}
//----------------------------------------------------------------------------------------------------
void CWallet::store_to(const std::string &path, const epee::wipeable_string &password)
{
  trim_hashchain();

  // if file is the same, we do:
  // 1. save wallet to the *.new file
  // 2. remove old wallet file
  // 3. rename *.new to wallet_name

  // handle if we want just store wallet state to current files (ex store() replacement);
  bool same_file = true;
  if (!path.empty())
  {
    std::string canonical_path = boost::filesystem::canonical(m_wallet_file).string();
    size_t pos = canonical_path.find(path);
    same_file = pos != std::string::npos;
  }


  if (!same_file)
  {
    // check if we want to store to directory which doesn't exists yet
    boost::filesystem::path parent_path = boost::filesystem::path(path).parent_path();

    // if path is not exists, try to create it
    if (!parent_path.empty() &&  !boost::filesystem::exists(parent_path))
    {
      boost::system::error_code ec;
      if (!boost::filesystem::create_directories(parent_path, ec))
      {
        throw std::logic_error(ec.message());
      }
    }
  }
  // preparing wallet data
  std::stringstream oss;
  boost::archive::portable_binary_oarchive ar(oss);
  ar << *this;

  CWallet::cache_file_data cache_file_data = boost::value_initialized<CWallet::cache_file_data>();
  cache_file_data.cache_data = oss.str();
  std::string cipher;
  cipher.resize(cache_file_data.cache_data.size());
  cache_file_data.iv = crypto::rand<crypto::chacha_iv>();
  crypto::chacha20(cache_file_data.cache_data.data(), cache_file_data.cache_data.size(), m_cache_key, cache_file_data.iv, &cipher[0]);
  cache_file_data.cache_data = cipher;

  const std::string new_file = same_file ? m_wallet_file + ".new" : path;
  const std::string old_file = m_wallet_file;
  const std::string old_keys_file = m_keys_file;
  const std::string old_address_file = m_wallet_file + ".address.txt";

  // save keys to the new file
  // if we here, main wallet file is saved and we only need to save keys and address files
  if (!same_file) {
    prepare_file_names(path);
    bool r = store_keys(m_keys_file, password, false);
    THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_keys_file);
    if (boost::filesystem::exists(old_address_file))
    {
      // save address to the new file
      const std::string address_file = m_wallet_file + ".address.txt";
      r = file_io_utils::save_string_to_file(address_file, m_account.get_public_address_str(m_nettype));
      THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_wallet_file);
    }
    // remove old wallet file
    r = boost::filesystem::remove(old_file);
    if (!r) {
      LOG_ERROR("error removing file: " << old_file);
    }
    // remove old keys file
    r = boost::filesystem::remove(old_keys_file);
    if (!r) {
      LOG_ERROR("error removing file: " << old_keys_file);
    }
    // remove old address file
    r = boost::filesystem::remove(old_address_file);
    if (!r) {
      LOG_ERROR("error removing file: " << old_address_file);
    }
  } else {
    // save to new file
#ifdef WIN32
    // On Windows avoid using std::ofstream which does not work with UTF-8 filenames
    // The price to pay is temporary higher memory consumption for string stream + binary archive
    std::ostringstream oss;
    binary_archive<true> oar(oss);
    bool success = ::serialization::serialize(oar, cache_file_data);
    if (success) {
        success = epee::file_io_utils::save_string_to_file(new_file, oss.str());
    }
    THROW_WALLET_EXCEPTION_IF(!success, error::file_save_error, new_file);
#else
    std::ofstream ostr;
    ostr.open(new_file, std::ios_base::binary | std::ios_base::out | std::ios_base::trunc);
    binary_archive<true> oar(ostr);
    bool success = ::serialization::serialize(oar, cache_file_data);
    ostr.close();
    THROW_WALLET_EXCEPTION_IF(!success || !ostr.good(), error::file_save_error, new_file);
#endif

    // here we have "*.new" file, we need to rename it to be without ".new"
    std::error_code e = tools::replace_file(new_file, m_wallet_file);
    THROW_WALLET_EXCEPTION_IF(e, error::file_save_error, m_wallet_file, e);
  }
}

namespace
{
  template<typename T>
  T pop_index(std::vector<T>& vec, size_t idx)
  {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
    CHECK_AND_ASSERT_MES(idx < vec.size(), T(), "idx out of bounds");

    T res = vec[idx];
    if (idx + 1 != vec.size())
    {
      vec[idx] = vec.back();
    }
    vec.resize(vec.size() - 1);

    return res;
  }

  template<typename T>
  T pop_random_value(std::vector<T>& vec)
  {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");

    size_t idx = crypto::rand<size_t>() % vec.size();
    return pop_index (vec, idx);
  }

  template<typename T>
  T pop_back(std::vector<T>& vec)
  {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");

    T res = vec.back();
    vec.pop_back();
    return res;
  }

  template<typename T>
  void pop_if_present(std::vector<T>& vec, T e)
  {
    for (size_t i = 0; i < vec.size(); ++i)
    {
      if (e == vec[i])
      {
        pop_index (vec, i);
        return;
      }
    }
  }
}

bool CWallet::set_ring_database(const std::string &filename)
{
  m_ring_database = filename;
  MINFO("ringdb path set to " << filename);
  m_ringdb.reset();
  if (!m_ring_database.empty())
  {
    try
    {
      cryptonote::block b;
      generate_genesis(b);
      m_ringdb.reset(new tools::ringdb(m_ring_database, epee::string_tools::pod_to_hex(get_block_hash(b))));
    }
    catch (const std::exception &e)
    {
      MERROR("Failed to initialize ringdb: " << e.what());
      m_ring_database = "";
      return false;
    }
  }
  return true;
}

crypto::chacha_key CWallet::get_ringdb_key()
{
  if (!m_ringdb_key)
  {
    MINFO("caching ringdb key");
    crypto::chacha_key key;
    generate_chacha_key_from_secret_keys(key);
    m_ringdb_key = key;
  }
  return *m_ringdb_key;
}

bool CWallet::blackball_output(const std::pair<uint64_t, uint64_t> &output)
{
  if (!m_ringdb)
    return false;
  try { return m_ringdb->blackball(output); }
  catch (const std::exception &e) { return false; }
}

bool CWallet::set_blackballed_outputs(const std::vector<std::pair<uint64_t, uint64_t>> &outputs, bool add)
{
  if (!m_ringdb)
    return false;
  try
  {
    bool ret = true;
    if (!add)
      ret &= m_ringdb->clear_blackballs();
    ret &= m_ringdb->blackball(outputs);
    return ret;
  }
  catch (const std::exception &e) { return false; }
}

bool CWallet::unblackball_output(const std::pair<uint64_t, uint64_t> &output)
{
  if (!m_ringdb)
    return false;
  try { return m_ringdb->unblackball(output); }
  catch (const std::exception &e) { return false; }
}

bool CWallet::is_output_blackballed(const std::pair<uint64_t, uint64_t> &output) const
{
  if (!m_ringdb)
    return false;
  try { return m_ringdb->blackballed(output); }
  catch (const std::exception &e) { return false; }
}

bool CWallet::lock_keys_file()
{
  if (m_keys_file_locker)
  {
    MDEBUG(m_keys_file << " is already locked.");
    return false;
  }
  m_keys_file_locker.reset(new tools::file_locker(m_keys_file));
  return true;
}

bool CWallet::unlock_keys_file()
{
  if (!m_keys_file_locker)
  {
    MDEBUG(m_keys_file << " is already unlocked.");
    return false;
  }
  m_keys_file_locker.reset();
  return true;
}

bool CWallet::is_keys_file_locked() const
{
  return m_keys_file_locker->locked();
}

void CWallet::light_wallet_get_outs(std::vector<std::vector<CWallet::get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count) {
  
  MDEBUG("LIGHTWALLET - Getting random outs");
      
  cryptonote::COMMAND_RPC_GET_RANDOM_OUTS::request oreq;
  cryptonote::COMMAND_RPC_GET_RANDOM_OUTS::response ores;
  
  size_t light_wallet_requested_outputs_count = (size_t)((fake_outputs_count + 1) * 1.5 + 1);
  
  // Amounts to ask for
  // MyMonero api handle amounts and fees as strings
  for(size_t idx: selected_transfers) {
    const uint64_t ask_amount = m_transfers[idx].is_rct() ? 0 : m_transfers[idx].amount();
    std::ostringstream amount_ss;
    amount_ss << ask_amount;
    oreq.amounts.push_back(amount_ss.str());
  }
  
  oreq.count = light_wallet_requested_outputs_count;
  m_daemon_rpc_mutex.lock();
  bool r = epee::net_utils::invoke_http_json("/get_random_outs", oreq, ores, m_http_client, rpc_timeout, "POST");
  m_daemon_rpc_mutex.unlock();
  THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_random_outs");
  THROW_WALLET_EXCEPTION_IF(ores.amount_outs.empty() , error::wallet_internal_error, "No outputs received from light wallet node. Error: " + ores.Error);
  
  // Check if we got enough outputs for each amount
  for(auto& out: ores.amount_outs) {
    const uint64_t out_amount = boost::lexical_cast<uint64_t>(out.amount);
    THROW_WALLET_EXCEPTION_IF(out.outputs.size() < light_wallet_requested_outputs_count , error::wallet_internal_error, "Not enough outputs for amount: " + boost::lexical_cast<std::string>(out.amount));
    MDEBUG(out.outputs.size() << " outputs for amount "+ boost::lexical_cast<std::string>(out.amount) + " received from light wallet node");
  }

  MDEBUG("selected transfers size: " << selected_transfers.size());

  for(size_t idx: selected_transfers)
  { 
    // Create new index
    outs.push_back(std::vector<get_outs_entry>());
    outs.back().reserve(fake_outputs_count + 1);
    
    // add real output first
    const transfer_details &td = m_transfers[idx];
    const uint64_t amount = td.is_rct() ? 0 : td.amount();
    outs.back().push_back(std::make_tuple(td.m_global_output_index, td.get_public_key(), rct::commit(td.amount(), td.m_mask)));
    MDEBUG("added real output " << string_tools::pod_to_hex(td.get_public_key()));
    
    // Even if the lightwallet server returns random outputs, we pick them randomly.
    std::vector<size_t> order;
    order.resize(light_wallet_requested_outputs_count);
    for (size_t n = 0; n < order.size(); ++n)
      order[n] = n;
    std::shuffle(order.begin(), order.end(), std::default_random_engine(crypto::rand<unsigned>()));
    
    
    LOG_PRINT_L2("Looking for " << (fake_outputs_count+1) << " outputs with amounts " << print_money(td.is_rct() ? 0 : td.amount()));
    MDEBUG("OUTS SIZE: " << outs.back().size());
    for (size_t o = 0; o < light_wallet_requested_outputs_count && outs.back().size() < fake_outputs_count + 1; ++o)
    {
      // Random pick
      size_t i = order[o];
             
      // Find which random output key to use
      bool found_amount = false;
      size_t amount_key;
      for(amount_key = 0; amount_key < ores.amount_outs.size(); ++amount_key)
      {
        if(boost::lexical_cast<uint64_t>(ores.amount_outs[amount_key].amount) == amount) {
          found_amount = true;
          break;
        }
      }
      THROW_WALLET_EXCEPTION_IF(!found_amount , error::wallet_internal_error, "Outputs for amount " + boost::lexical_cast<std::string>(ores.amount_outs[amount_key].amount) + " not found" );

      LOG_PRINT_L2("Index " << i << "/" << light_wallet_requested_outputs_count << ": idx " << ores.amount_outs[amount_key].outputs[i].global_index << " (real " << td.m_global_output_index << "), unlocked " << "(always in light)" << ", key " << ores.amount_outs[0].outputs[i].public_key);
      
      // Convert light wallet string data to proper data structures
      crypto::public_key tx_public_key;
      rct::key mask = AUTO_VAL_INIT(mask); // decrypted mask - not used here
      rct::key rct_commit = AUTO_VAL_INIT(rct_commit);
      THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, ores.amount_outs[amount_key].outputs[i].public_key), error::wallet_internal_error, "Invalid public_key");
      string_tools::hex_to_pod(ores.amount_outs[amount_key].outputs[i].public_key, tx_public_key);
      const uint64_t global_index = ores.amount_outs[amount_key].outputs[i].global_index;
      if(!light_wallet_parse_rct_str(ores.amount_outs[amount_key].outputs[i].rct, tx_public_key, 0, mask, rct_commit, false))
        rct_commit = rct::zeroCommit(td.amount());
      
      if (tx_add_fake_output(outs, global_index, tx_public_key, rct_commit, td.m_global_output_index, true)) {
        MDEBUG("added fake output " << ores.amount_outs[amount_key].outputs[i].public_key);
        MDEBUG("index " << global_index);
      }
    }

    THROW_WALLET_EXCEPTION_IF(outs.back().size() < fake_outputs_count + 1 , error::wallet_internal_error, "Not enough fake outputs found" );
    
    // Real output is the first. Shuffle outputs
    MTRACE(outs.back().size() << " outputs added. Sorting outputs by index:");
    std::sort(outs.back().begin(), outs.back().end(), [](const get_outs_entry &a, const get_outs_entry &b) { return std::get<0>(a) < std::get<0>(b); });

    // Print output order
    for(auto added_out: outs.back())
      MTRACE(std::get<0>(added_out));

  }
}

std::string CWallet::get_wallet_file() const
{
  return m_wallet_file;
}

std::string CWallet::get_keys_file() const
{
  return m_keys_file;
}

std::string CWallet::get_daemon_address() const
{
  return m_daemon_address;
}

void CWallet::set_attribute(const std::string &key, const std::string &value)
{
  m_attributes[key] = value;
}

std::string CWallet::get_attribute(const std::string &key) const
{
  std::unordered_map<std::string, std::string>::const_iterator i = m_attributes.find(key);
  if (i == m_attributes.end())
    return std::string();
  return i->second;
}

void CWallet::set_description(const std::string &description)
{
  set_attribute(ATTRIBUTE_DESCRIPTION, description);
}

std::string CWallet::get_description() const
{
  return get_attribute(ATTRIBUTE_DESCRIPTION);
}

const std::pair<std::map<std::string, std::string>, std::vector<std::string>>& CWallet::get_account_tags()
{
  // ensure consistency
  if (m_account_tags.second.size() != get_num_subaddress_accounts())
    m_account_tags.second.resize(get_num_subaddress_accounts(), "");
  for (const std::string& tag : m_account_tags.second)
  {
    if (!tag.empty() && m_account_tags.first.count(tag) == 0)
      m_account_tags.first.insert({tag, ""});
  }
  for (auto i = m_account_tags.first.begin(); i != m_account_tags.first.end(); )
  {
    if (std::find(m_account_tags.second.begin(), m_account_tags.second.end(), i->first) == m_account_tags.second.end())
      i = m_account_tags.first.erase(i);
    else
      ++i;
  }
  return m_account_tags;
}

void CWallet::set_account_tag(const std::set<uint32_t> account_indices, const std::string& tag)
{
  for (uint32_t account_index : account_indices)
  {
    THROW_WALLET_EXCEPTION_IF(account_index >= get_num_subaddress_accounts(), error::wallet_internal_error, "Account index out of bound");
    if (m_account_tags.second[account_index] == tag)
      MDEBUG("This tag is already assigned to this account");
    else
      m_account_tags.second[account_index] = tag;
  }
  get_account_tags();
}

void CWallet::set_account_tag_description(const std::string& tag, const std::string& description)
{
  THROW_WALLET_EXCEPTION_IF(tag.empty(), error::wallet_internal_error, "Tag must not be empty");
  THROW_WALLET_EXCEPTION_IF(m_account_tags.first.count(tag) == 0, error::wallet_internal_error, "Tag is unregistered");
  m_account_tags.first[tag] = description;
}

std::string CWallet::sign(const std::string &data) const
{
  crypto::hash hash;
  crypto::cn_fast_hash(data.data(), data.size(), hash);
  const cryptonote::account_keys &keys = m_account.get_keys();
  crypto::signature signature;
  crypto::generate_signature(hash, keys.m_account_address.m_spend_public_key, keys.m_spend_secret_key, signature);
  return std::string("SigV1") + tools::base58::encode(std::string((const char *)&signature, sizeof(signature)));
}

bool CWallet::verify(const std::string &data, const cryptonote::account_public_address &address, const std::string &signature) const
{
  const size_t header_len = strlen("SigV1");
  if (signature.size() < header_len || signature.substr(0, header_len) != "SigV1") {
    LOG_PRINT_L0("Signature header check error");
    return false;
  }
  crypto::hash hash;
  crypto::cn_fast_hash(data.data(), data.size(), hash);
  std::string decoded;
  if (!tools::base58::decode(signature.substr(header_len), decoded)) {
    LOG_PRINT_L0("Signature decoding error");
    return false;
  }
  crypto::signature s;
  if (sizeof(s) != decoded.size()) {
    LOG_PRINT_L0("Signature decoding error");
    return false;
  }
  memcpy(&s, decoded.data(), sizeof(s));
  return crypto::check_signature(hash, address.m_spend_public_key, s);
}

bool CWallet::verify_with_public_key(const std::string &data, const crypto::public_key &public_key, const std::string &signature) const
{
  if (signature.size() < MULTISIG_SIGNATURE_MAGIC.size() || signature.substr(0, MULTISIG_SIGNATURE_MAGIC.size()) != MULTISIG_SIGNATURE_MAGIC) {
    MERROR("Signature header check error");
    return false;
  }
  crypto::hash hash;
  crypto::cn_fast_hash(data.data(), data.size(), hash);
  std::string decoded;
  if (!tools::base58::decode(signature.substr(MULTISIG_SIGNATURE_MAGIC.size()), decoded)) {
    MERROR("Signature decoding error");
    return false;
  }
  crypto::signature s;
  if (sizeof(s) != decoded.size()) {
    MERROR("Signature decoding error");
    return false;
  }
  memcpy(&s, decoded.data(), sizeof(s));
  return crypto::check_signature(hash, public_key, s);
}

std::string CWallet::encrypt(const char *plaintext, size_t len, const crypto::secret_key &skey, bool authenticated) const
{
  crypto::chacha_key key;
  crypto::generate_chacha_key(&skey, sizeof(skey), key, m_kdf_rounds);
  std::string ciphertext;
  crypto::chacha_iv iv = crypto::rand<crypto::chacha_iv>();
  ciphertext.resize(len + sizeof(iv) + (authenticated ? sizeof(crypto::signature) : 0));
  crypto::chacha20(plaintext, len, key, iv, &ciphertext[sizeof(iv)]);
  memcpy(&ciphertext[0], &iv, sizeof(iv));
  if (authenticated)
  {
    crypto::hash hash;
    crypto::cn_fast_hash(ciphertext.data(), ciphertext.size() - sizeof(signature), hash);
    crypto::public_key pkey;
    crypto::secret_key_to_public_key(skey, pkey);
    crypto::signature &signature = *(crypto::signature*)&ciphertext[ciphertext.size() - sizeof(crypto::signature)];
    crypto::generate_signature(hash, pkey, skey, signature);
  }
  return ciphertext;
}
//----------------------------------------------------------------------------------------------------
std::string CWallet::encrypt(const epee::span<char> &plaintext, const crypto::secret_key &skey, bool authenticated) const
{
  return encrypt(plaintext.data(), plaintext.size(), skey, authenticated);
}
//----------------------------------------------------------------------------------------------------
std::string CWallet::encrypt(const std::string &plaintext, const crypto::secret_key &skey, bool authenticated) const
{
  return encrypt(plaintext.data(), plaintext.size(), skey, authenticated);
}
//----------------------------------------------------------------------------------------------------
std::string CWallet::encrypt(const epee::wipeable_string &plaintext, const crypto::secret_key &skey, bool authenticated) const
{
  return encrypt(plaintext.data(), plaintext.size(), skey, authenticated);
}
//----------------------------------------------------------------------------------------------------
std::string CWallet::encrypt_with_view_secret_key(const std::string &plaintext, bool authenticated) const
{
  return encrypt(plaintext, get_account().get_keys().m_view_secret_key, authenticated);
}
//----------------------------------------------------------------------------------------------------
template<typename T>
T CWallet::decrypt(const std::string &ciphertext, const crypto::secret_key &skey, bool authenticated) const
{
  const size_t prefix_size = sizeof(chacha_iv) + (authenticated ? sizeof(crypto::signature) : 0);
  THROW_WALLET_EXCEPTION_IF(ciphertext.size() < prefix_size,
    error::wallet_internal_error, "Unexpected ciphertext size");

  crypto::chacha_key key;
  crypto::generate_chacha_key(&skey, sizeof(skey), key, m_kdf_rounds);
  const crypto::chacha_iv &iv = *(const crypto::chacha_iv*)&ciphertext[0];
  if (authenticated)
  {
    crypto::hash hash;
    crypto::cn_fast_hash(ciphertext.data(), ciphertext.size() - sizeof(signature), hash);
    crypto::public_key pkey;
    crypto::secret_key_to_public_key(skey, pkey);
    const crypto::signature &signature = *(const crypto::signature*)&ciphertext[ciphertext.size() - sizeof(crypto::signature)];
    THROW_WALLET_EXCEPTION_IF(!crypto::check_signature(hash, pkey, signature),
      error::wallet_internal_error, "Failed to authenticate ciphertext");
  }
  std::unique_ptr<char[]> buffer{new char[ciphertext.size() - prefix_size]};
  auto wiper = epee::misc_utils::create_scope_leave_handler([&]() { memwipe(buffer.get(), ciphertext.size() - prefix_size); });
  crypto::chacha20(ciphertext.data() + sizeof(iv), ciphertext.size() - prefix_size, key, iv, buffer.get());
  return T(buffer.get(), ciphertext.size() - prefix_size);
}
//----------------------------------------------------------------------------------------------------
template epee::wipeable_string CWallet::decrypt(const std::string &ciphertext, const crypto::secret_key &skey, bool authenticated) const;
//----------------------------------------------------------------------------------------------------
std::string CWallet::decrypt_with_view_secret_key(const std::string &ciphertext, bool authenticated) const
{
  return decrypt(ciphertext, gget_blockchain_height_by_dateet_account().get_keys().m_view_secret_key, authenticated);
}
//----------------------------------------------------------------------------------------------------
std::string CWallet::make_uri(const std::string &address, const std::string &payment_id, uint64_t amount, const std::string &tx_description, const std::string &recipient_name, std::string &error) const
{
  cryptonote::address_parse_info info;
  if(!get_account_address_from_str(info, nettype(), address))
  {
    error = std::string("wrong address: ") + address;
    return std::string();
  }

  // we want only one payment id
  if (info.has_payment_id && !payment_id.empty())
  {
    error = "A single payment id is allowed";
    return std::string();
  }

  if (!payment_id.empty())
  {
    crypto::hash pid32;
    crypto::hash8 pid8;
    if (!CWallet::parse_long_payment_id(payment_id, pid32) && !CWallet::parse_short_payment_id(payment_id, pid8))
    {
      error = "Invalid payment id";
      return std::string();
    }
  }

  std::string uri = "monero:" + address;
  unsigned int n_fields = 0;

  if (!payment_id.empty())
  {
    uri += (n_fields++ ? "&" : "?") + std::string("tx_payment_id=") + payment_id;
  }

  if (amount > 0)
  {
    // URI encoded amount is in decimal units, not atomic units
    uri += (n_fields++ ? "&" : "?") + std::string("tx_amount=") + cryptonote::print_money(amount);
  }

  if (!recipient_name.empty())
  {
    uri += (n_fields++ ? "&" : "?") + std::string("recipient_name=") + epee::net_utils::conver_to_url_format(recipient_name);
  }

  if (!tx_description.empty())
  {
    uri += (n_fields++ ? "&" : "?") + std::string("tx_description=") + epee::net_utils::conver_to_url_format(tx_description);
  }

  return uri;
}
//----------------------------------------------------------------------------------------------------
bool CWallet::parse_uri(const std::string &uri, std::string &address, std::string &payment_id, uint64_t &amount, std::string &tx_description, std::string &recipient_name, std::vector<std::string> &unknown_parameters, std::string &error)
{
  if (uri.substr(0, 7) != "monero:")
  {
    error = std::string("URI has wrong scheme (expected \"monero:\"): ") + uri;
    return false;
  }

  std::string remainder = uri.substr(7);
  const char *ptr = strchr(remainder.c_str(), '?');
  address = ptr ? remainder.substr(0, ptr-remainder.c_str()) : remainder;

  cryptonote::address_parse_info info;
  if(!get_account_address_from_str(info, nettype(), address))
  {
    error = std::string("URI has wrong address: ") + address;
    return false;
  }
  if (!strchr(remainder.c_str(), '?'))
    return true;

  std::vector<std::string> arguments;
  std::string body = remainder.substr(address.size() + 1);
  if (body.empty())
    return true;
  boost::split(arguments, body, boost::is_any_of("&"));
  std::set<std::string> have_arg;
  for (const auto &arg: arguments)
  {
    std::vector<std::string> kv;
    boost::split(kv, arg, boost::is_any_of("="));
    if (kv.size() != 2)
    {
      error = std::string("URI has wrong parameter: ") + arg;
      return false;
    }
    if (have_arg.find(kv[0]) != have_arg.end())
    {
      error = std::string("URI has more than one instance of " + kv[0]);
      return false;
    }
    have_arg.insert(kv[0]);

    if (kv[0] == "tx_amount")
    {
      amount = 0;
      if (!cryptonote::parse_amount(amount, kv[1]))
      {
        error = std::string("URI has invalid amount: ") + kv[1];
        return false;
      }
    }
    else if (kv[0] == "tx_payment_id")
    {
      if (info.has_payment_id)
      {
        error = "Separate payment id given with an integrated address";
        return false;
      }
      crypto::hash hash;
      crypto::hash8 hash8;
      if (!CWallet::parse_long_payment_id(kv[1], hash) && !CWallet::parse_short_payment_id(kv[1], hash8))
      {
        error = "Invalid payment id: " + kv[1];
        return false;
      }
      payment_id = kv[1];
    }
    else if (kv[0] == "recipient_name")
    {
      recipient_name = epee::net_utils::convert_from_url_format(kv[1]);
    }
    else if (kv[0] == "tx_description")
    {
      tx_description = epee::net_utils::convert_from_url_format(kv[1]);
    }
    else
    {
      unknown_parameters.push_back(arg);
    }
  }
  return true;
}

uint64_t CWallet::get_segregation_fork_height() const
{
  if (m_nettype == TESTNET)
    return TESTNET_SEGREGATION_FORK_HEIGHT;
  if (m_nettype == STAGENET)
    return STAGENET_SEGREGATION_FORK_HEIGHT;
  THROW_WALLET_EXCEPTION_IF(m_nettype != MAINNET, tools::error::wallet_internal_error, "Invalid network type");

  if (m_segregation_height > 0)
    return m_segregation_height;

  static const bool use_dns = true;
  if (use_dns)
  {
    // All four MoneroPulse domains have DNSSEC on and valid
    static const std::vector<std::string> dns_urls = {
        "segheights.moneropulse.org",
        "segheights.moneropulse.net",
        "segheights.moneropulse.co",
        "segheights.moneropulse.se"
    };

    const uint64_t current_height = get_blockchain_current_height();
    uint64_t best_diff = std::numeric_limits<uint64_t>::max(), best_height = 0;
    std::vector<std::string> records;
    if (tools::dns_utils::load_txt_records_from_dns(records, dns_urls))
    {
      for (const auto& record : records)
      {
        std::vector<std::string> fields;
        boost::split(fields, record, boost::is_any_of(":"));
        if (fields.size() != 2)
          continue;
        uint64_t height;
        if (!string_tools::get_xtype_from_string(height, fields[1]))
          continue;

        MINFO("Found segregation height via DNS: " << fields[0] << " fork height at " << height);
        uint64_t diff = height > current_height ? height - current_height : current_height - height;
        if (diff < best_diff)
        {
          best_diff = diff;
          best_height = height;
        }
      }
      if (best_height)
        return best_height;
    }
  }
  return SEGREGATION_FORK_HEIGHT;
}
}
