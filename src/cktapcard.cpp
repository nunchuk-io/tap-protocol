#include <algorithm>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <base58.h>
#include <util/strencodings.h>
#include "serialize.h"
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/hash_utils.h"
#include "tap_protocol/utils.h"

namespace tap_protocol {

static constexpr std::array<char, 8> opendime = {'O', 'P', 'E', 'N',
                                                 'D', 'I', 'M', 'E'};
static constexpr int CARD_NONCE_SIZE = 16;
static constexpr int USER_NONCE_SIZE = 16;
static constexpr std::array<unsigned char, 33> FACTORY_ROOT_KEY = {
    0x03, 0x02, 0x8a, 0x0e, 0x89, 0xe7, 0x0d, 0x0e, 0xc0, 0xd9, 0x32,
    0x05, 0x3a, 0x89, 0xab, 0x1d, 0xa7, 0xd9, 0x18, 0x2b, 0xdc, 0x6d,
    0x2f, 0x03, 0xe7, 0x06, 0xee, 0x99, 0x51, 0x7d, 0x05, 0xd9, 0xe1,
};

static std::string CardPubkeyToIdent(const Bytes& card_pubkey) {
  if (card_pubkey.size() != 33) {
    throw TapProtoException(TapProtoException::INVALID_PUBKEY_LENGTH,
                            "Expecting compressed pubkey");
  }

  Bytes pubkey_sha = SHA256(card_pubkey);
  pubkey_sha.erase(std::begin(pubkey_sha), std::begin(pubkey_sha) + 8);

  auto md = ToUpper(EncodeBase32(pubkey_sha));

  static constexpr int IDENT_SIZE = 23;

  std::string ident(IDENT_SIZE, '\0');
  for (int i = 0, j = 0; i < 20; ++i) {
    if ((j + 1) % 6 == 0) {
      ident[j++] = '-';
    }
    ident[j++] = md[i];
  }
  return ident;
}

CKTapCard::CKTapCard(std::unique_ptr<Transport> transport)
    : transport_(std::move(transport)) {
  FirstLook();
}

CKTapCard::StatusResponse CKTapCard::FirstLook() {
  auto status = Status();
  if (status.proto != 1) {
    throw TapProtoException(TapProtoException::UNKNOW_PROTO_VERSION,
                            "Unknown card protocol version");
  }
  // TODO: tampered
  card_pubkey_ = status.pubkey;
  card_ident_ = CardPubkeyToIdent(card_pubkey_);
  applet_version_ = status.ver;
  birth_height_ = status.birth;
  is_testnet_ = status.testnet;
  auth_delay_ = status.auth_delay;
  is_tapsigner_ = status.tapsigner;
  return status;
}

json CKTapCard::Send(const json& msg) {
  auto resp = transport_->Send(msg);
  if (resp.contains("card_nonce")) {
    card_nonce_ = resp["card_nonce"];
  }

  if (resp.contains("auth_delay")) {
    auth_delay_ = resp["auth_delay"];
  }

  if (resp.contains("error")) {
    throw TapProtoException(
        resp.value("code", TapProtoException::DEFAULT_ERROR), resp["error"]);
  }
  return resp;
}

std::pair<Bytes, json> CKTapCard::SendAuth(const json& msg, const Bytes& cvc) {
  json send_msg = msg;
  const std::string cmd = send_msg.value("cmd", std::string{});

  Bytes session_key;
  if (!cvc.empty()) {
    XCVC xcvc = CalcXCVC({std::begin(cmd), std::end(cmd)}, card_nonce_,
                         card_pubkey_, cvc);
    session_key = std::move(xcvc.session_key);
    send_msg.merge_patch(xcvc);
  }

  if (cmd == "sign") {
    send_msg["digest"] =
        json::binary_t(XORBytes(send_msg["digest"], session_key));
  } else if (cmd == "change") {
    session_key.resize(send_msg["data"].size());
    send_msg["data"] = json::binary_t(XORBytes(send_msg["data"], session_key));
  }
  return {session_key, Send(send_msg)};
}

CKTapCard::StatusResponse CKTapCard::Status() {
  return Send({{"cmd", "status"}});
}

std::string CKTapCard::NFC() {
  const auto resp = Send({{"cmd", "nfc"}});
  if (resp.contains("url")) {
    return resp["url"];
  }
  throw TapProtoException(TapProtoException::MISSING_KEY, "No url found");
}

std::string CKTapCard::CertificateCheck() {
  auto verify_certs = [](const json& status_resp, const json& check_resp,
                         const json& certs_resp, const Bytes& my_nonce) {
    const std::vector<json::binary_t> signatures = certs_resp["cert_chain"];
    const json::binary_t card_nonce = status_resp["card_nonce"];
    assert(signatures.size() >= 2);

    Bytes msg;
    msg.insert(std::end(msg), std::begin(opendime), std::end(opendime));
    msg.insert(std::end(msg), std::begin(card_nonce), std::end(card_nonce));
    msg.insert(std::end(msg), std::begin(my_nonce), std::end(my_nonce));

    if (msg.size() != opendime.size() + CARD_NONCE_SIZE + USER_NONCE_SIZE) {
      throw TapProtoException(TapProtoException::INVALID_CARD,
                              "Invalid msg size " + std::to_string(msg.size()));
    }

    const Bytes msg_sha256 = SHA256(msg);
    const json::binary_t auth_sig = check_resp["auth_sig"];
    Bytes pubkey = status_resp["pubkey"].get<json::binary_t>();

    if (!CT_sig_verify(pubkey, msg_sha256, auth_sig)) {
      throw TapProtoException(TapProtoException::SIG_VERIFY_ERROR,
                              "Bad sig in verify_certs");
    }

    for (const auto& sig : signatures) {
      pubkey = CT_sig_to_pubkey(SHA256(pubkey), sig);
    }

    if (std::equal(std::begin(pubkey), std::end(pubkey),
                   std::begin(FACTORY_ROOT_KEY), std::end(FACTORY_ROOT_KEY))) {
      return "Root Factory Certificate";
    }

    throw TapProtoException(
        TapProtoException::INVALID_CARD,
        "Root cert is not from Coinkite. Card is counterfeit.");
  };

  const json st = Status();
  const json certs = Send({{"cmd", "certs"}});

  const auto nonce = PickNonce();
  const json check = Send({{"cmd", "check"}, {"nonce", json::binary_t(nonce)}});
  // TODO: assign self._certs_checked = True

  return verify_certs(st, check, certs, nonce);
}

CKTapCard::WaitResponse CKTapCard::Wait() { return Send({{"cmd", "wait"}}); }

CKTapCard::NewResponse CKTapCard::New(const Bytes& chain_code,
                                      const std::string& cvc, int slot) {
  const auto [_, resp] = SendAuth({{"cmd", "new"},
                                   {"slot", slot},
                                   {"chain_code", json::binary_t(chain_code)}},
                                  {std::begin(cvc), std::end(cvc)});
  return resp;
}

Bytes CKTapCard::Sign(const Bytes& digest, const std::string& cvc, int slot,
                      const std::string& subpath) {
  const auto make_recoverable_sig = [](const Bytes& digest, const Bytes& sig,
                                       const Bytes& expected_pubkey) {
    assert(digest.size() == 32);
    assert(sig.size() == 64);

    for (int rec_id = 0; rec_id < 4; ++rec_id) {
      Bytes rec_sig, pubkey;
      rec_sig.reserve(1 + sig.size());
      try {
        rec_sig.push_back(39 + rec_id);
        rec_sig.insert(std::end(rec_sig), std::begin(sig), std::end(sig));
        pubkey = CT_sig_to_pubkey(digest, rec_sig);
      } catch (TapProtoException& te) {
        if (rec_id >= 2) {
          continue;
        }
      }
      if (!expected_pubkey.empty()) {
        if (expected_pubkey != pubkey) {
          continue;
        }
      }
      return rec_sig;
    }
    throw TapProtoException(TapProtoException::SIGN_ERROR,
                            "Sig may not be created by that address/pubkey??");
  };

  if (digest.size() != 32) {
    throw TapProtoException(TapProtoException::INVALID_DIGEST_LENGTH,
                            "Digest must be exactly 32 bytes");
  }

  const std::vector<uint32_t> subpath_int =
      !subpath.empty() ? Str2Path(subpath) : std::vector<uint32_t>();

  if (subpath_int.size() > 2) {
    throw TapProtoException(TapProtoException::INVALID_PATH_LENGTH,
                            "Length of path is greater than 2");
  }

  const auto none_hardened = [](const std::vector<uint32_t>& path) {
    return !std::any_of(std::begin(path), std::end(path),
                        [](uint32_t i) { return i & HARDENED; });
  };

  if (!none_hardened(subpath_int)) {
    throw TapProtoException(TapProtoException::MALFORMED_BIP32_PATH,
                            "Subpath contains hardened components");
  }

  for (int retry = 0; retry < 5; ++retry) {
    try {
      const json request = {
          {"cmd", "sign"},
          {"slot", slot},
          {"digest", digest},
          {"subpath", subpath_int},
      };
      const auto [_, resp] =
          SendAuth(request, {std::begin(cvc), std::end(cvc)});

      const Bytes expect_pub = resp["pubkey"].get<json::binary_t>();
      const Bytes sig = resp["sig"].get<json::binary_t>();

      if (!CT_sig_verify(expect_pub, digest, sig)) {
        continue;
      }
      auto rec_sig = make_recoverable_sig(digest, sig, expect_pub);
      return rec_sig;
    } catch (TapProtoException& te) {
      if (te.code() == 205) {
        Status();
        continue;
      }
      throw;
    }
  }
  throw TapProtoException(TapProtoException::EXCEEDED_RETRY,
                          "Failed to sign digest after 5 retries. Try again.");
}

std::string CKTapCard::GetIdent() const noexcept {
  return {std::begin(card_ident_), std::end(card_ident_)};
}

std::string CKTapCard::GetAppletVersion() const noexcept {
  return applet_version_;
}
int CKTapCard::GetBirthHeight() const noexcept { return birth_height_; }
bool CKTapCard::IsTestnet() const noexcept { return is_testnet_; }
int CKTapCard::GetAuthDelay() const noexcept { return auth_delay_; }
bool CKTapCard::IsTapsigner() const noexcept { return is_tapsigner_; }

void to_json(json& j, const CKTapCard::StatusResponse& t) {
  j = {
      {"proto", t.proto},           {"ver", t.ver},
      {"birth", t.birth},           {"slots", t.slots},
      {"address", t.address},       {"pubkey", t.pubkey},
      {"card_nonce", t.card_nonce}, {"tapsigner", t.tapsigner},
      {"testnet", t.testnet},       {"num_backups", t.num_backups},
      {"auth_delay", t.auth_delay},
  };
  if (t.path) {
    j["path"] = *t.path;
  }
}

void from_json(const json& j, CKTapCard::StatusResponse& t) {
  t.proto = j.value("proto", t.proto);
  t.ver = j.value("ver", t.ver);
  t.birth = j.value("birth", t.birth);
  t.slots = j.value("slots", t.slots);
  t.address = j.value("address", t.address);
  t.pubkey = j.value("pubkey", t.pubkey);
  t.card_nonce = j.value("card_nonce", t.card_nonce);
  t.tapsigner = j.value("tapsigner", t.tapsigner);
  t.testnet = j.value("testnet", t.testnet);
  t.num_backups = j.value("num_backups", t.num_backups);
  t.auth_delay = j.value("auth_delay", t.auth_delay);
  if (j.contains("path")) {
    t.path = j["path"];
  }
}

// Tapsigner

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

Tapsigner::Tapsigner(std::unique_ptr<Transport> transport) {
  transport_ = std::move(transport);
  auto st = FirstLook();
  number_of_backup_ = st.num_backups;
  if (st.path) {
    derivation_path_ = Path2Str(*st.path);
  }
}

Tapsigner::StatusResponse Tapsigner::Status() {
  auto st = CKTapCard::Status();
  number_of_backup_ = st.num_backups;
  if (st.path) {
    derivation_path_ = Path2Str(*st.path);
  }
  return st;
}

int Tapsigner::GetNumberOfBackups() const noexcept { return number_of_backup_; }
std::optional<std::string> Tapsigner::GetDerivationPath() const noexcept {
  return derivation_path_;
}

std::string Tapsigner::GetDerivation() {
  const auto status = Status();
  if (!status.path) {
    throw TapProtoException(TapProtoException::NO_PRIVATE_KEY_PICKED,
                            "No private key picked yet.");
  }
  return Path2Str(*status.path);
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
  return resp;
}

std::string Tapsigner::GetXFP(const std::string& cvc) {
  const auto [_, resp] = SendAuth({{"cmd", "xpub"}, {"master", true}},
                                  {std::begin(cvc), std::end(cvc)});
  json::binary_t xpub = resp["xpub"];
  xpub.erase(std::begin(xpub), std::end(xpub) - 33);

  Bytes xpub_hash = Hash160(xpub);
  xpub_hash.resize(4);
  return ToUpper(Bytes2Hex(xpub_hash));
}

std::string Tapsigner::Xpub(const std::string& cvc, bool master) {
  const auto [_, resp] = SendAuth({{"cmd", "xpub"}, {"master", master}},
                                  {std::begin(cvc), std::end(cvc)});
  Bytes xpub = resp["xpub"].get<json::binary_t>();

  Bytes double_hash_xpub = SHA256d(xpub);
  xpub.insert(std::end(xpub), std::begin(double_hash_xpub),
              std::begin(double_hash_xpub) + 4);
  return EncodeBase58({xpub.data(), xpub.size()});
}

std::string Tapsigner::Pubkey(const std::string& cvc) {
  auto recover_pubkey = [](const json& status, const json& read,
                           const Bytes& nonce, const Bytes& session_key) {
    const json::binary_t card_nonce = status["card_nonce"];

    Bytes msg;
    msg.insert(std::end(msg), std::begin(opendime), std::end(opendime));
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
  const auto [session_key, read] =
      SendAuth({{"cmd", "read"}, {"nonce", json::binary_t(nonce)}},
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
  const auto [_, resp] =
      SendAuth({{"cmd", "change"},
                {"data", Bytes(std::begin(new_cvc), std::end(new_cvc))}},
               {std::begin(cvc), std::end(cvc)});
  return resp;
}

Tapsigner::BackupResponse Tapsigner::Backup(const std::string& cvc) {
  const auto [_, resp] =
      SendAuth({{"cmd", "backup"}}, {std::begin(cvc), std::end(cvc)});
  return resp;
}

// SatsCard

}  // namespace tap_protocol
