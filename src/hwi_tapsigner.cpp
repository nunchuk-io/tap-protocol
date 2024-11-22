#include <algorithm>
#include <cctype>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <psbt.h>
#include <primitives/transaction.h>
#include <util/strencodings.h>
#include <script/sign.h>
#include <serialize.h>
#include <base58.h>
#include <pubkey.h>
#include <span.h>
#include <crypto/aes.h>
#include "tap_protocol/hash_utils.h"
#include "tap_protocol/hwi_tapsigner.h"
#include "tap_protocol/tap_protocol.h"
#include "tap_protocol/utils.h"

namespace tap_protocol {
using namespace bc_core;
using uchar = unsigned char;

// Require to call CPubKey::IsFullyValid() when parse psbt
static const ECCVerifyHandle verify_handle;

static constexpr unsigned char BASE58_MAINNET_PUBKEY_PREFIX[] = {0x04, 0x88,
                                                                 0xB2, 0x1E};
static constexpr unsigned char BASE58_TESTNET_PUBKEY_PREFIX[] = {0x04, 0x35,
                                                                 0x87, 0xCF};

static constexpr auto &GetBase58Prefix(HWITapsigner::Chain chain) {
  const auto &prefix = chain == HWITapsigner::Chain::MAIN
                           ? BASE58_MAINNET_PUBKEY_PREFIX
                           : BASE58_TESTNET_PUBKEY_PREFIX;
  return prefix;
}

static CExtPubKey DecodeExtPubKey(HWITapsigner::Chain chain,
                                  const std::string &str) {
  CExtPubKey key;
  std::vector<unsigned char> data;
  if (DecodeBase58Check(str, data, 78)) {
    const auto &prefix = GetBase58Prefix(chain);
#ifdef SKIP_BASE58_PREFIX_CHECK
    key.Decode(data.data() + std::size(prefix));
    return key;
#else
    if (data.size() == BIP32_EXTKEY_SIZE + std::size(prefix) &&
        std::equal(std::begin(prefix), std::end(prefix), data.begin())) {
      key.Decode(data.data() + std::size(prefix));
      return key;
    }
    throw TapProtoException(TapProtoException::INVALID_PUBKEY,
                            "Invalid pubkey prefix");
#endif
  }
  throw TapProtoException(TapProtoException::INVALID_PUBKEY,
                          "Invalid pubkey decode base58");
}

static std::string EncodeExtPubKey(HWITapsigner::Chain chain,
                                   const CExtPubKey &key) {
  const auto &prefix = GetBase58Prefix(chain);
  Bytes data{std::begin(prefix), std::end(prefix)};

  const size_t size = data.size();
  data.resize(size + BIP32_EXTKEY_SIZE);
  key.Encode(data.data() + size);
  std::string ret = EncodeBase58Check(data);
  return ret;
}

static int get_bip44_purpose(HWITapsigner::AddressType address_type) {
  switch (address_type) {
    case HWITapsigner::AddressType::LEGACY:
      return 44;
    case HWITapsigner::AddressType::SH_WIT:
      return 49;
    case HWITapsigner::AddressType::WIT:
      return 84;
    case HWITapsigner::AddressType::TAP:
      return 86;
  }
  throw TapProtoException(TapProtoException::INVALID_ADDRESS_TYPE,
                          "Invalid address type");
}

static bool is_p2pkh(const CScript &script) {
  return script.size() == 25 && script[0] == 0x76 && script[1] == 0xa9 &&
         script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac;
}

static bool is_p2pk(const CScript &script) {
  return (script.size() == 35 || script.size() == 67) &&
         (script[0] == 0x21 || script[0] == 0x41) && script.back() == 0xac;
}

static std::tuple<bool, int, std::vector<unsigned char>> is_p2wpkh(
    const CScript &script) {
  int version;
  std::vector<unsigned char> program;
  bool is_wit = script.IsWitnessProgram(version, program);
  return {is_wit, version, program};
}

static Bytes ser_sig_der(Bytes r, Bytes s) {
  const auto remove_leading_zero = [](Bytes bytes) {
    for (auto it = std::begin(bytes); it != std::end(bytes); ++it) {
      if (*it == 0x0) {
        continue;
      }
      bytes.erase(std::begin(bytes), it);
      break;
    }
    return bytes;
  };

  CDataStream sig(SER_NETWORK, PROTOCOL_VERSION);
  sig << uchar(0x30);

  r = remove_leading_zero(r);
  s = remove_leading_zero(s);

  auto first = r[0];
  if (first & (1 << 7)) {
    r.insert(std::begin(r), 0x00);
  }

  first = s[0];
  if (first & (1 << 7)) {
    s.insert(std::begin(s), 0x00);
  }

  auto total_len = uchar(r.size() + s.size() + 4);
  sig << total_len;

  sig << uchar(0x02) << uchar(r.size()) << MakeUCharSpan(r);
  sig << uchar(0x02) << uchar(s.size()) << MakeUCharSpan(s);
  sig << uchar(0x01);
  return {std::begin(sig), std::end(sig)};
}

static CMutableTransaction &get_unsigned_tx(PartiallySignedTransaction &psbt) {
  if (psbt.tx) {
    return *psbt.tx;
  }
  // TODO:
  // https://github.com/bitcoin-core/HWI/blob/a2d1245d01dfac7820ea5197a8e1990507948ee9/hwilib/psbt.py#L1015
  throw TapProtoException(TapProtoException::PSBT_INVALID, "Empty transaction");
}

static bool is_hardened(int64_t component) { return component >= HARDENED; }

static void check_bip32_path(const std::vector<uint32_t> &path) {
  bool found_non_hardened = false;

  if (std::find_if(std::begin(path), std::end(path), [&](uint32_t component) {
        bool current_hardened = is_hardened(component);
        if (found_non_hardened && current_hardened) {
          return true;
        }
        found_non_hardened |= !current_hardened;
        return false;
      }) != std::end(path)) {
    throw TapProtoException(TapProtoException::MALFORMED_BIP32_PATH,
                            "Hardened path component after non-hardened");
  }
}

static auto split_bip32_path(const std::vector<uint32_t> &path) {
  check_bip32_path(path);
  auto last_hardened_iter =
      std::find_if_not(std::begin(path), std::end(path), is_hardened);

  std::vector<uint32_t> hardened(std::begin(path), last_hardened_iter);
  std::vector<uint32_t> non_hardened(last_hardened_iter, std::end(path));

  return std::make_pair(hardened, non_hardened);
}

static PartiallySignedTransaction DecodePsbt(const std::string &base64_psbt) {
  PartiallySignedTransaction psbtx;
  std::string error;
  if (!DecodeBase64PSBT(psbtx, base64_psbt, error)) {
    throw TapProtoException(TapProtoException::PSBT_PARSE_ERROR,
                            "Parse psbt error " + error);
  }
  return psbtx;
}

static std::string EncodePsbt(const PartiallySignedTransaction &psbtx) {
  CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
  ssTx << psbtx;
  return EncodeBase64(MakeUCharSpan(ssTx));
}

static constexpr int AES_BLOCK_SIZE = 16;
static Bytes AES128CTRDecrypt(const Bytes &cipher, const Bytes &key,
                              Bytes counter = Bytes(AES_BLOCK_SIZE, 0)) {
  auto increment_counter = [&]() {
    for (int i = AES_BLOCK_SIZE - 1; i > 0; --i) {
      if (++counter[i]) {
        break;
      }
    }
  };

  AES128_ctx ctx;
  AES128_init(&ctx, key.data());

  Bytes plain = cipher;
  auto *pos = plain.data();

  int left = cipher.size();
  unsigned char buf[AES_BLOCK_SIZE];
  while (left > 0) {
    AES128_encrypt(&ctx, 1, buf, counter.data());
    const int len = (left < AES_BLOCK_SIZE) ? left : AES_BLOCK_SIZE;
    for (int j = 0; j < len; j++) {
      pos[j] ^= buf[j];
    }
    pos += len;
    left -= len;
    increment_counter();
  }
  return plain;
}

CExtPubKey HWITapsignerImpl::GetXpubAtPathInternal(
    const std::string &derivation_path) {
  auto [hardened, non_hardened] = split_bip32_path(Str2Path(derivation_path));

  if (non_hardened.empty()) {
    DeriveDevice(derivation_path);
    auto xp = device_->Xpub(cvc_, false);
    return DecodeExtPubKey(chain_, xp);
  }

  DeriveDevice(Path2Str(hardened));
  auto xp = device_->Xpub(cvc_, false);
  auto pub = DecodeExtPubKey(chain_, xp);
  for (uint32_t path : non_hardened) {
    pub.Derive(pub, path);
  }

  return pub;
}

std::string HWITapsignerImpl::SignTx(const std::string &base64_psbt) {
  auto tx = DecodePsbt(base64_psbt);
  auto &blank_tx = get_unsigned_tx(tx);
  Bytes master_fp = GetMasterFingerprintBytes();

  using SigHashTuple = std::tuple<Bytes, std::vector<uint32_t>, int, CPubKey>;
  std::vector<SigHashTuple> sighash_tuples;

  for (size_t i = 0; i < blank_tx.vin.size(); ++i) {
    auto &txin = blank_tx.vin[i];
    auto &psbt_in = tx.inputs[i];
    CTxOut utxo;
    if (!psbt_in.witness_utxo.IsNull()) {
      utxo = psbt_in.witness_utxo;
    }
    if (psbt_in.non_witness_utxo && !psbt_in.non_witness_utxo->IsNull()) {
      if (txin.prevout.hash != psbt_in.non_witness_utxo->GetHash()) {
        throw TapProtoException(
            TapProtoException::PSBT_INVALID,
            "Input has a non_witness_utxo with the wrong hash");
      }
      utxo = psbt_in.non_witness_utxo->vout[txin.prevout.n];
    }
    if (utxo.IsNull()) {
      continue;
    }
    auto scriptcode = utxo.scriptPubKey;
    bool p2sh = false;
    if (scriptcode.IsPayToScriptHash()) {
      if (psbt_in.redeem_script.empty()) {
        continue;
      }
      scriptcode = psbt_in.redeem_script;
      p2sh = true;
    }
    const auto [is_wit, _ver, _prog] = is_p2wpkh(scriptcode);
    if (scriptcode.IsPayToWitnessScriptHash()) {
      if (psbt_in.witness_script.empty()) {
        continue;
      }
      scriptcode = psbt_in.witness_script;
    }

    Bytes sighash;

    if (!is_wit) {
      if (p2sh || is_p2pkh(scriptcode) || is_p2pk(scriptcode)) {
        txin.scriptSig = scriptcode;
      } else {
        continue;
      }
      CDataStream ss_tx(SER_NETWORK, PROTOCOL_VERSION);
      ss_tx << blank_tx;
      ss_tx << MakeUCharSpan(std::array<uchar, 4>{0x01, 0x00, 0x00, 0x00});
      sighash = SHA256d({std::begin(ss_tx), std::end(ss_tx)});
      txin.scriptSig.clear();
    } else {
      if (psbt_in.witness_utxo.IsNull()) {
        throw TapProtoException(TapProtoException::PSBT_INVALID, "Psbt error");
      }
      CDataStream prevouts_preimage(SER_NETWORK, PROTOCOL_VERSION);
      CDataStream sequence_preimage(SER_NETWORK, PROTOCOL_VERSION);
      for (auto &&inputs : blank_tx.vin) {
        prevouts_preimage << inputs.prevout;
        sequence_preimage << inputs.nSequence;
      }
      auto hashPrevouts =
          SHA256d({std::begin(prevouts_preimage), std::end(prevouts_preimage)});
      auto hashSequence =
          SHA256d({std::begin(sequence_preimage), std::end(sequence_preimage)});

      CDataStream outputs_preimage(SER_NETWORK, PROTOCOL_VERSION);
      for (auto &&output : blank_tx.vout) {
        outputs_preimage << output;
      }

      auto hashOutputs =
          SHA256d({std::begin(outputs_preimage), std::end(outputs_preimage)});

      if (auto [is_witness, ver, prog] = is_p2wpkh(scriptcode); is_witness) {
        scriptcode.clear();
        scriptcode.push_back(0x76);
        scriptcode.push_back(0xa9);
        scriptcode.push_back(0x14);
        scriptcode.insert(std::end(scriptcode), std::begin(prog),
                          std::end(prog));
        scriptcode.push_back(0x88);
        scriptcode.push_back(0xac);
      }

      CDataStream preimage(SER_NETWORK, PROTOCOL_VERSION);
      preimage << blank_tx.nVersion;
      preimage << MakeUCharSpan(hashPrevouts);
      preimage << MakeUCharSpan(hashSequence);
      preimage << txin.prevout;
      preimage << scriptcode;
      preimage << psbt_in.witness_utxo.nValue;
      preimage << txin.nSequence;
      preimage << MakeUCharSpan(hashOutputs);
      preimage << blank_tx.nLockTime;
      preimage << MakeUCharSpan(std::array<uchar, 4>{0x01, 0x00, 0x00, 0x00});

      sighash = SHA256d({std::begin(preimage), std::end(preimage)});
    }

    for (auto &&[pubkey, keypath] : psbt_in.hd_keypaths) {
      if (std::equal(std::begin(master_fp), std::end(master_fp),
                     std::begin(keypath.fingerprint),
                     std::end(keypath.fingerprint))) {
        sighash_tuples.emplace_back(sighash, keypath.path, i, pubkey);
      }
    }
  }

  if (sighash_tuples.empty()) {
    return base64_psbt;
  }

  for (auto &&[sighash, int_path, i_num, pubkey] : sighash_tuples) {
    auto [hardened, non_hardened] = split_bip32_path(int_path);
    DeriveDevice(Path2Str(hardened));
    auto rec_sig = device_->Sign(sighash, cvc_, 0, Path2Str(non_hardened));
    assert(rec_sig.size() == 65);
    Bytes r(std::begin(rec_sig) + 1, std::begin(rec_sig) + 33);
    Bytes s(std::begin(rec_sig) + 33, std::begin(rec_sig) + 65);
    tx.inputs[i_num].partial_sigs[pubkey.GetID()] =
        SigPair{pubkey, ser_sig_der(r, s)};
  }
  return EncodePsbt(tx);
}

std::string HWITapsignerImpl::GetXpubAtPath(
    const std::string &derivation_path) {
  auto pubkey = GetXpubAtPathInternal(derivation_path);
  CDataStream packed(SER_NETWORK, PROTOCOL_VERSION);

  Bytes pubkey_encoded(BIP32_EXTKEY_SIZE);
  pubkey.Encode(pubkey_encoded.data());

  packed << MakeUCharSpan(GetBase58Prefix(chain_))
         << MakeUCharSpan(pubkey_encoded);

  return EncodeBase58Check(packed);
}

std::string HWITapsignerImpl::GetChaincodeAtPath(
    const std::string &derivation_path) {
  if (derivation_path.empty() || derivation_path == "m") {
    auto xp = device_->Xpub(cvc_, true);
    auto pubkey = DecodeExtPubKey(chain_, xp);
    return Bytes2Hex(
        {std::begin(pubkey.chaincode), std::end(pubkey.chaincode)});
  }
  auto pubkey = GetXpubAtPathInternal(derivation_path);
  return Bytes2Hex({std::begin(pubkey.chaincode), std::end(pubkey.chaincode)});
}

void HWITapsignerImpl::DeriveDevice(const std::string &derivation_path) {
  if (device_->GetDerivationPath() != derivation_path) {
    device_->Derive(derivation_path, cvc_);
  }
}
Bytes HWITapsignerImpl::GetMasterFingerprintBytes() {
  auto pubkey = GetXpubAtPathInternal("m");
  auto hashed = Hash160(pubkey.pubkey);
  return {std::begin(hashed), std::begin(hashed) + 4};
}
std::string HWITapsignerImpl::GetMasterFingerprint() {
  return Bytes2Hex(GetMasterFingerprintBytes());
}

std::string HWITapsignerImpl::GetMasterXpub(AddressType address_type,
                                            int account) {
  int bip44_pupose = get_bip44_purpose(address_type);
  int bip44_chain = chain_;
  std::ostringstream path;
  path << "m/" << bip44_pupose << "h/" << bip44_chain << "h/" << account << "h";
  auto pubkey = GetXpubAtPathInternal(path.str());
  return EncodeExtPubKey(chain_, pubkey);
}

std::string HWITapsignerImpl::SignMessage(const std::string &message,
                                          const std::string &derivation_path) {
  auto [hardened, non_hardened] = split_bip32_path(Str2Path(derivation_path));

  CDataStream xmsg(SER_NETWORK, PROTOCOL_VERSION);

  constexpr std::string_view MAGIC_STRING =
      "\x18"
      "Bitcoin Signed Message:\n";

  xmsg << MakeUCharSpan(MAGIC_STRING) << message;
  const Bytes md = SHA256d({std::begin(xmsg), std::end(xmsg)});

  Bytes rec_sig;
  if (non_hardened.empty()) {
    DeriveDevice(derivation_path);
    rec_sig = device_->Sign(md, cvc_, 0);
  } else {
    if (non_hardened.size() > 2) {
      throw TapProtoException(
          TapProtoException::INVALID_PATH_LENGTH,
          "Only 2 non-hardened derivation components allowed");
    }
    DeriveDevice(Path2Str(hardened));
    rec_sig = device_->Sign(md, cvc_, 0, Path2Str(non_hardened));
  }

  auto sig = EncodeBase64(rec_sig);
  sig.erase(std::remove(std::begin(sig), std::end(sig), '\n'), std::end(sig));
  return sig;
}

void HWITapsignerImpl::SetChain(Chain chain) { chain_ = chain; }

void HWITapsignerImpl::SetDevice(Tapsigner *device) { device_ = device; }

void HWITapsignerImpl::SetDevice(Tapsigner *device, const std::string &cvc) {
  device_ = device;
  cvc_ = cvc;
}

void HWITapsignerImpl::SetupDevice(const std::string &chain_code) {
  if (!chain_code.empty() && chain_code.size() != 64) {
    throw TapProtoException(
        TapProtoException::BAD_ARGUMENTS,
        "Invalid hex chain code size = " + std::to_string(chain_code.size()));
  }
  auto use_chain_code =
      chain_code.empty() ? RandomChainCode() : Hex2Bytes(chain_code);

  if (use_chain_code.size() != 32) {
    throw TapProtoException(
        TapProtoException::BAD_ARGUMENTS,
        "Invalid chain code size = " + std::to_string(chain_code.size()));
  }
  device_->New(use_chain_code, cvc_);
}

Bytes HWITapsignerImpl::BackupDevice() {
  auto resp = device_->Backup(cvc_);
  return resp.data;
}

std::string HWITapsignerImpl::DecryptBackup(const Bytes &encrypted_data,
                                            const std::string &backup_key) {
  static constexpr unsigned char xprv[] = {'x', 'p', 'r', 'v'};
  static constexpr unsigned char tprv[] = {'t', 'p', 'r', 'v'};

  const auto backup_key_bytes = ParseHex(backup_key);
  if (backup_key_bytes.size() != 16) {
    throw TapProtoException(TapProtoException::INVALID_BACKUP_KEY,
                            "Invalid backup key");
  }
  Bytes decrypted = AES128CTRDecrypt(encrypted_data, backup_key_bytes);

  if (decrypted.size() < std::size(xprv)) {
    throw TapProtoException(TapProtoException::INVALID_BACKUP_KEY,
                            "Invalid backup key");
  }

  if (std::equal(std::begin(xprv), std::end(xprv), std::begin(decrypted)) ||
      std::equal(std::begin(tprv), std::end(tprv), std::begin(decrypted))) {
    return {std::begin(decrypted), std::end(decrypted)};
  }
  throw TapProtoException(TapProtoException::INVALID_BACKUP_KEY,
                          "Invalid backup key");
}

HWITapsignerImpl::HWITapsignerImpl(Tapsigner *device, const std::string &cvc)
    : device_(device), cvc_(cvc) {}

std::unique_ptr<HWITapsigner> MakeHWITapsigner(HWITapsigner::Chain chain) {
  auto hwi = std::make_unique<HWITapsignerImpl>();
  hwi->SetChain(chain);
  return hwi;
}

std::unique_ptr<HWITapsigner> MakeHWITapsigner(Tapsigner *device,
                                               const std::string &cvc) {
  return std::make_unique<HWITapsignerImpl>(device, cvc);
}

}  // namespace tap_protocol
