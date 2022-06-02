#include <algorithm>
#include <iterator>
#include <memory>
#include <string>
#include <vector>
#include <psbt.h>
#include <primitives/transaction.h>
#include <util/strencodings.h>
#include <script/sign.h>
#include <serialize.h>
#include <base58.h>
#include <wally_bip32.h>
#include "span.h"
#include "tap_protocol/hash_utils.h"
#include "tap_protocol/hwi_tapsigner.h"
#include "tap_protocol/utils.h"

namespace tap_protocol {

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
  throw HWITapsigerException(HWITapsigerException::UNKNOW_ERROR,
                             "Unknown address type");
}

static constexpr uint32_t HARDENED_FLAG = 1 << 31;

static bool is_p2pkh(const CScript &script) {
  return script.size() == 25 && script[0] == 0x76 and script[1] == 0xa9 and
         script[2] == 0x14 and script[23] == 0x88 and script[24] == 0xac;
}

static bool is_p2pk(const CScript &script) {
  return (script.size() == 35 || script.size() == 67) &&
         (script[0] == 0x21 or script[0] == 0x41) && script.back() == 0xac;
}

static std::tuple<bool, int, std::vector<unsigned char>> is_p2wpkh(
    const CScript &script) {
  int version;
  std::vector<unsigned char> program;
  bool is_wit = script.IsWitnessProgram(version, program);
  return {is_wit, version, program};
}

static Bytes ser_sig_der(Bytes r, Bytes s) {
  auto remove_leading_zero = [](Bytes bytes) {
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
  using uchar = unsigned char;
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
  throw HWITapsigerException(HWITapsigerException::PSBT_INVALID,
                             "Empty transaction");
}

static bool is_hardened(int64_t component) {
  return component >= HARDENED_FLAG;
}

static void check_bip32_path(const std::vector<uint32_t> &path) {
  bool found_non_hardened = false;
  for (auto component : path) {
    bool curr_hardened = is_hardened(component);
    bool curr_non_hardened = !curr_hardened;
    if (curr_hardened && found_non_hardened) {
      throw HWITapsigerException(HWITapsigerException::MALFORMED_BIP32_PATH,
                                 "Hardened path component after non-hardened");
    }
    found_non_hardened = curr_non_hardened;
  }
}

static std::pair<std::vector<uint32_t>, std::vector<uint32_t>> split_bip32_path(
    const std::vector<uint32_t> &path) {
  std::vector<uint32_t> hardened, non_hardened;
  for (auto component : path) {
    if (is_hardened(component)) {
      hardened.push_back(component);
    } else {
      non_hardened.push_back(component);
    }
  }
  return {hardened, non_hardened};
}

static ext_key xpub2extkey(const std::string &xpub) {
  //    std::vector<unsigned char> data;
  //    if (!DecodeBase58({std::begin(xpub), std::end(xpub)}, data, 100)) {
  //      throw HWITapsigerException(HWITapsigerException::UNKNOW_ERROR,
  //                                 "Decode base58 fail");
  //    }
  //    data.resize(data.size() - 4);
  //    auto hdata = Bytes2Str(data);
  //  if (int code =
  //        bip32_key_unserialize(data.data(), BIP32_SERIALIZED_LEN, &extKey);
  //      code != WALLY_OK) {
  //    assert(0);
  //  }
  ext_key extKey;
  if (int code = bip32_key_from_base58_n(xpub.data(), xpub.size(), &extKey);
      code != WALLY_OK) {
    throw HWITapsigerException(HWITapsigerException::UNKNOW_ERROR,
                               "bip32_key_from_base58 error");
  }
  return extKey;
}

inline PartiallySignedTransaction DecodePsbt(const std::string &base64_psbt) {
  PartiallySignedTransaction psbtx;
  std::string error;
  if (!DecodeBase64PSBT(psbtx, base64_psbt, error)) {
    throw HWITapsigerException(HWITapsigerException::PSBT_PARSE_ERROR,
                               "Parse psbt error " + error);
  }
  return psbtx;
}

inline std::string EncodePsbt(const PartiallySignedTransaction &psbtx) {
  CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
  ssTx << psbtx;
  return EncodeBase64(MakeUCharSpan(ssTx));
}

ext_key HWITapsignerImpl::GetPubkeyAtPath(const std::string &bip32_path) {
  cvc_ = pin_callback_();

  auto int_path = Str2Path(bip32_path);
  check_bip32_path(int_path);
  auto [hardened, non_hardened] = split_bip32_path(int_path);

  if (!non_hardened.empty()) {
    tap_signer_->Derive(bip32_path, cvc_);
    auto xp = tap_signer_->Xpub(cvc_, false);
    auto extkey = xpub2extkey(xp);
    return extkey;
  } else {
    auto str_path = Path2Str(hardened);
    tap_signer_->Derive(str_path, cvc_);
    auto xp = tap_signer_->Xpub(cvc_, false);
    auto extkey = xpub2extkey(xp);

    if (!non_hardened.empty()) {
      ext_key derived_key;
      if (int code = bip32_key_from_parent_path(
              &extkey, non_hardened.data(), non_hardened.size(),
              BIP32_FLAG_KEY_PUBLIC, &derived_key);
          code != WALLY_OK) {
        throw HWITapsigerException(HWITapsigerException::UNKNOW_ERROR,
                                   "Derive key error " + std::to_string(code));
      }
      return derived_key;
    }

    return extkey;
  }
}

void HWITapsignerImpl::SetPromptPinCallback(PromptPinCallback func) {
  pin_callback_ = std::move(func);
}

std::string HWITapsignerImpl::SignTx(const std::string &base64_psbt) {
  auto tx = DecodePsbt(base64_psbt);
  auto &blank_tx = get_unsigned_tx(tx);
  auto master_fp = GetMasterFingerprint();
  cvc_ = pin_callback_();

  using SigHashTuple = std::tuple<Bytes, std::vector<uint32_t>, int, CPubKey>;
  std::vector<SigHashTuple> sighash_tuples;

  for (int i = 0; i < blank_tx.vin.size(); ++i) {
    auto &txin = blank_tx.vin[i];
    auto &psbt_in = tx.inputs[i];
    CTxOut utxo;
    if (!psbt_in.witness_utxo.IsNull()) {
      utxo = psbt_in.witness_utxo;
    }
    if (psbt_in.non_witness_utxo && !psbt_in.non_witness_utxo->IsNull()) {
      if (txin.prevout.hash != psbt_in.non_witness_utxo->GetHash()) {
        throw HWITapsigerException(
            HWITapsigerException::PSBT_INVALID,
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
    int version_;
    std::vector<unsigned char> program_;
    bool is_wit = scriptcode.IsWitnessProgram(version_, program_);
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
      blank_tx.Serialize(ss_tx);
      ss_tx << 0x01 << 0x00 << 0x00 << 0x00;
      std::string ser_tx_str = ss_tx.str();
      sighash = SHA256d({std::begin(ser_tx_str), std::end(ser_tx_str)});
      txin.scriptSig.clear();
    } else {
      if (psbt_in.witness_utxo.IsNull()) {
        throw HWITapsigerException(HWITapsigerException::PSBT_INVALID,
                                   "Psbt error");
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
      preimage << MakeUCharSpan(Bytes{0x01, 0x00, 0x00, 0x00});

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
    check_bip32_path(int_path);
    auto [hardened, non_hardened] = split_bip32_path(int_path);
    tap_signer_->Derive(Path2Str(hardened), cvc_);
    auto rec_sig = tap_signer_->Sign(sighash, cvc_, 0, Path2Str(non_hardened));
    assert(rec_sig.size() == 65);
    Bytes r(std::begin(rec_sig) + 1, std::begin(rec_sig) + 33);
    Bytes s(std::begin(rec_sig) + 33, std::begin(rec_sig) + 65);
    auto der_sig = ser_sig_der(r, s);
    SigPair sig_pair{pubkey, der_sig};
    tx.inputs[i_num].partial_sigs[pubkey.GetID()] = sig_pair;
  }
  return EncodePsbt(tx);
}

Bytes HWITapsignerImpl::GetMasterFingerprint() {
  auto extended_key_m = GetPubkeyAtPath("m");
  auto fingerprint = Hash160(
      {std::begin(extended_key_m.pub_key), std::end(extended_key_m.pub_key)});
  return {std::begin(fingerprint), std::begin(fingerprint) + 4};
}

std::string HWITapsignerImpl::GetMasterXpub(AddressType address_type,
                                            int account) {
  int bip44_pupose = get_bip44_purpose(address_type);
  int bip44_chain = 0;
  std::ostringstream path;
  path << "m/" << bip44_pupose << "h/" << bip44_chain << "h/" << account << "h";
  auto pubkey = GetPubkeyAtPath(path.str());

  Bytes master_xpub(BIP32_SERIALIZED_LEN);
  if (int code = bip32_key_serialize(&pubkey, BIP32_FLAG_KEY_PUBLIC,
                                     master_xpub.data(), master_xpub.size());
      code != WALLY_OK) {
    throw HWITapsigerException(HWITapsigerException::UNKNOW_ERROR,
                               "BIP32 serialize error");
  }
  Bytes double_hash_xpub = SHA256d(master_xpub);
  master_xpub.insert(std::end(master_xpub), std::begin(double_hash_xpub),
                     std::begin(double_hash_xpub) + 4);
  return EncodeBase58({master_xpub.data(), master_xpub.size()});
}

HWITapsignerImpl::HWITapsignerImpl(std::unique_ptr<Tapsigner> tap_signer)
    : tap_signer_(std::move(tap_signer)) {}

std::unique_ptr<HWITapsigner> MakeHWITapsigner(
    std::unique_ptr<Tapsigner> tap_signer) {
  return std::make_unique<HWITapsignerImpl>(std::move(tap_signer));
}
}  // namespace tap_protocol
