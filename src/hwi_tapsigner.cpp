#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <psbt.h>
#include <primitives/transaction.h>
#include <util/strencodings.h>
#include <pubkey.h>
#include <script/sign.h>
#include <serialize.h>
#include "tap_protocol/hash_utils.h"
#include "tap_protocol/hwi_tapsigner.h"

namespace tap_protocol {

static bool is_p2pkh(const CScript &script) {
  return script.size() == 25 && script[0] == 0x76 and script[1] == 0xa9 and
         script[2] == 0x14 and script[23] == 0x88 and script[24] == 0xac;
}

static bool is_p2pk(const CScript &script) {
  return (script.size() == 35 || script.size() == 67) &&
         (script[0] == 0x21 or script[0] == 0x41) && script.back() == 0xac;
}

static std::pair<bool, std::vector<unsigned char>> is_p2wpkh(
    const CScript &script) {
  int version_;
  std::vector<unsigned char> program_;
  bool is_wit = script.IsWitnessProgram(version_, program_);
  if (!is_wit) {
    return {false, {}};
  }
  if (version_ != 0) {
    return {false, {}};
  }
  return {program_.size() == 20, program_};
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
  sig << 0x30;

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

  auto total_len = r.size() + s.size() + 4;
  sig << total_len;

  sig << 0x02 << r.size() << r;
  sig << 0x02 << s.size() << s;
  sig << 0x01;
  return {std::begin(sig), std::end(sig)};
}

static CMutableTransaction get_unsigned_tx(
    const PartiallySignedTransaction &psbt) {
  if (psbt.tx) {
    return *psbt.tx;
  }
  // TODO:
  // https://github.com/bitcoin-core/HWI/blob/a2d1245d01dfac7820ea5197a8e1990507948ee9/hwilib/psbt.py#L1015
  throw HWITapsigerException(HWITapsigerException::PSBT_INVALID,
                             "Empty transaction");
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

class HWITapSigerImpl : public HWITapSiger {
 public:
  using HWITapSiger::HWITapSiger;
  std::string SignTx(const std::string &psbt) override;
  std::string GetMasterFingerprint() override;

 private:
  std::unique_ptr<TapSigner> tap_signer_;
  std::string cvc_;
};

std::string HWITapSigerImpl::SignTx(const std::string &base64_psbt) {
  auto tx = DecodePsbt(base64_psbt);
  auto blank_tx = get_unsigned_tx(tx);
  auto master_fp = GetMasterFingerprint();

  using SigHashTuple = std::tuple<Bytes, std::vector<uint32_t>, int, CPubKey>;
  std::vector<SigHashTuple> sighash_tuples;

  for (int i = 0; i < blank_tx.vin.size(); ++i) {
    auto txin = blank_tx.vin[i];
    auto psbt_in = tx.inputs[i];
    CTxOut utxo;
    if (!psbt_in.witness_utxo.IsNull()) {
      utxo = psbt_in.witness_utxo;
    }
    if (psbt_in.non_witness_utxo && !psbt_in.non_witness_utxo->IsNull()) {
      if (txin.prevout.hash != psbt_in.non_witness_utxo->GetHash()) {
        throw HWITapsigerException(
            HWITapsigerException::PSBT_INVALID,
            "'Input has a non_witness_utxo with the wrong hash");
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
      if (auto [is_p2wpkh_script, prog] = is_p2wpkh(scriptcode);
          is_p2wpkh_script) {
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
      preimage << hashPrevouts;
      preimage << hashSequence;
      preimage << txin.prevout;
      WriteCompactSize(preimage, scriptcode.size());
      preimage << scriptcode;
      preimage << psbt_in.witness_utxo.nValue;
      preimage << txin.nSequence;
      preimage << hashOutputs;
      preimage << blank_tx.nLockTime;
      preimage << 0x01 << 0x00 << 0x00 << 0x00;

      sighash = SHA256d({std::begin(preimage), std::end(preimage)});
    }

    for (auto &&[pubkey, keypath] : psbt_in.hd_keypaths) {
      if (master_fp == std::string(std::begin(keypath.fingerprint),
                                   std::end(keypath.fingerprint))) {
        sighash_tuples.emplace_back(sighash, keypath.path, i, pubkey);
      }
    }
  }

  if (sighash_tuples.empty()) {
    return base64_psbt;
  }

  for (auto &&[sighash, int_path, i_num, pubkey] : sighash_tuples) {
    // TODO:
    //   check_bip32_path(int_path)  # raises ValueError if hardened after
    //   non-hardened
    // hardened, non_hardened = split_bip32_path(int_path)
    // self.device.set_derivation(path2str(hardened), self.password)
    auto rec_sig = tap_signer_->Sign(sighash, cvc_);
    assert(rec_sig.size() == 65);
    Bytes r(std::begin(rec_sig) + 1, std::begin(rec_sig) + 33);
    Bytes s(std::begin(rec_sig) + 33, std::begin(rec_sig) + 65);
    auto der_sig = ser_sig_der(r, s);
    SigPair sig_pair{pubkey, der_sig};
    tx.inputs[i_num].partial_sigs[pubkey.GetID()] = sig_pair;
  }
  return EncodePsbt(tx);
}

std::string HWITapSigerImpl::GetMasterFingerprint() { return {}; }

std::unique_ptr<HWITapSiger> MakeHWITapSigner() {
  return std::make_unique<HWITapSigerImpl>();
}
}  // namespace tap_protocol
