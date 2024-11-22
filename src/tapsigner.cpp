#include <base58.h>
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/hash_utils.h"
#include "tap_protocol/utils.h"

namespace tap_protocol {
using namespace bc_core;
void to_json(json& j, const Tapsigner::DeriveResponse& t) {
  j = {
      {"sig", t.sig},
      {"chain_code", t.chain_code},
      {"master_pubkey", t.master_pubkey},
      {"pubkey", t.pubkey},
      {"card_nonce", t.card_nonce},
  };
}

void from_json(const json& j, Tapsigner::DeriveResponse& t) {
  t.sig = j.value("sig", t.sig);
  t.chain_code = j.value("chain_code", t.chain_code);
  t.master_pubkey = j.value("master_pubkey", t.master_pubkey);
  t.pubkey = j.value("pubkey", t.pubkey);
  t.card_nonce = j.value("card_nonce", t.card_nonce);
}

void to_json(nlohmann::json& j, const Tapsigner::NewResponse& t) {
  j = {
      {"slot", t.slot},
      {"card_nonce", t.card_nonce},
  };
}

void from_json(const nlohmann::json& j, Tapsigner::NewResponse& t) {
  t.slot = j.value("slot", t.slot);
  t.card_nonce = j.value("card_nonce", t.card_nonce);
}

void to_json(nlohmann::json& j, const Tapsigner::ChangeResponse& t) {
  j = {
      {"success", t.success},
      {"card_nonce", t.card_nonce},
  };
}
void from_json(const nlohmann::json& j, Tapsigner::ChangeResponse& t) {
  t.success = j.value("success", t.success);
  t.card_nonce = j.value("card_nonce", t.card_nonce);
}

void to_json(nlohmann::json& j, const Tapsigner::BackupResponse& t) {
  j = {
      {"data", t.data},
      {"card_nonce", t.card_nonce},
  };
}
void from_json(const nlohmann::json& j, Tapsigner::BackupResponse& t) {
  t.data = j.value("data", t.data);
  t.card_nonce = j.value("card_nonce", t.card_nonce);
}

Tapsigner::Tapsigner(std::unique_ptr<Transport> transport)
    : CKTapCard(std::move(transport), false) {
  auto st = FirstLook();
  if (!st.tapsigner) {
    throw TapProtoException(
        TapProtoException::INVALID_DEVICE,
        "Incorrect device type detected. Please try again.");
  }
  CertificateCheck();
}

int Tapsigner::GetNumberOfBackups() const noexcept { return number_of_backup_; }
std::optional<std::string> Tapsigner::GetDerivationPath() const noexcept {
  return derivation_path_;
}

Tapsigner::DeriveResponse Tapsigner::Derive(const std::string& path,
                                            const std::string& cvc) {
  static constexpr int DERIVE_MAX_BIP32_PATH_DEPTH = 8;
  const std::vector<uint32_t> path_value = Str2Path(path);

  if (path_value.size() > DERIVE_MAX_BIP32_PATH_DEPTH) {
    throw TapProtoException(TapProtoException::INVALID_PATH_LENGTH,
                            "No more than 8 path components allowed.");
  }

  const json request = {
      {"cmd", "derive"},
      {"nonce", json::binary_t(PickNonce())},
      {"path", path_value},
  };

  const auto [_, resp] = SendAuth(request, {std::begin(cvc), std::end(cvc)});
  if (derivation_path_ != path) {
    derivation_path_ = Path2Str(path_value);
  }
  return resp;
}

std::string Tapsigner::GetXFP(const std::string& cvc) {
  const auto [_, resp] = SendAuth(
      {
          {"cmd", "xpub"},
          {"master", true},
      },
      {std::begin(cvc), std::end(cvc)});
  json::binary_t xpub = resp["xpub"];
  xpub.erase(std::begin(xpub), std::end(xpub) - 33);

  Bytes xpub_hash = Hash160(xpub);
  xpub_hash.resize(4);
  return ToUpper(Bytes2Hex(xpub_hash));
}

std::string Tapsigner::Xpub(const std::string& cvc, bool master) {
  const auto [_, resp] = SendAuth(
      {
          {"cmd", "xpub"},
          {"master", master},
      },
      {std::begin(cvc), std::end(cvc)});
  const Bytes xpub = resp["xpub"].get<json::binary_t>();
  return EncodeBase58Check(xpub);
}

std::string Tapsigner::Pubkey(const std::string& cvc) {
  auto recover_pubkey = [](const json& status, const json& read,
                           const Bytes& nonce, const Bytes& session_key) {
    const json::binary_t card_nonce = status["card_nonce"];

    Bytes msg;
    msg.reserve(std::size(OPENDIME) + card_nonce.size() + nonce.size());
    msg.insert(std::end(msg), std::begin(OPENDIME), std::end(OPENDIME));
    msg.insert(std::end(msg), std::begin(card_nonce), std::end(card_nonce));
    msg.insert(std::end(msg), std::begin(nonce), std::end(nonce));
    msg.push_back(0x00);

    if (msg.size() != 8 + CARD_NONCE_SIZE + USER_NONCE_SIZE + 1) {
      throw TapProtoException(TapProtoException::INVALID_PUBKEY_LENGTH,
                              "Invalid length " + std::to_string(msg.size()));
    }

    const json::binary_t pubkey = read["pubkey"];
    auto pubkey_tmp =
        XORBytes({std::begin(pubkey) + 1, std::end(pubkey)}, session_key);
    pubkey_tmp.insert(std::begin(pubkey_tmp), pubkey.front());

    const Bytes msg_sha256 = SHA256(msg);
    const json::binary_t sig = read["sig"];

    if (!CT_sig_verify(pubkey_tmp, msg_sha256, sig)) {
      throw TapProtoException(TapProtoException::SIG_VERIFY_ERROR,
                              "Bad sig in recover_pubkey");
    }

    return pubkey_tmp;
  };

  const Bytes nonce = PickNonce();
  const json status = Status();
  const auto [session_key, read] = SendAuth(
      {
          {"cmd", "read"},
          {"nonce", json::binary_t(nonce)},
      },
      {std::begin(cvc), std::end(cvc)});
  const auto ret = recover_pubkey(status, read, nonce, session_key);
  return Bytes2Hex(ret);
}

Tapsigner::ChangeResponse Tapsigner::Change(const std::string& new_cvc,
                                            const std::string& cvc) {
  if (new_cvc.size() < 6 || new_cvc.size() > 32) {
    throw TapProtoException(TapProtoException::INVALID_CVC_LENGTH,
                            "Invalid cvc length");
  }
  const auto [_, resp] = SendAuth(
      {
          {"cmd", "change"},
          {"data", Bytes(std::begin(new_cvc), std::end(new_cvc))},
      },
      {std::begin(cvc), std::end(cvc)});
  return resp;
}

Tapsigner::BackupResponse Tapsigner::Backup(const std::string& cvc) {
  const auto [_, resp] =
      SendAuth({{"cmd", "backup"}}, {std::begin(cvc), std::end(cvc)});
  return resp;
}

void Tapsigner::Update(const CKTapCard::StatusResponse& status) {
  CKTapCard::Update(status);
  number_of_backup_ = status.num_backups;
  if (status.path) {
    derivation_path_ = Path2Str(*status.path);
  }
}

bool Tapsigner::NeedSetup() const noexcept {
  return !derivation_path_.has_value();
}
}  // namespace tap_protocol
