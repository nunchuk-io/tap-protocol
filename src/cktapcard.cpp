#include <algorithm>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <util/strencodings.h>
#include "serialize.h"
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/hash_utils.h"
#include "tap_protocol/utils.h"

namespace tap_protocol {
using namespace bc_core;
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

CKTapCard::CKTapCard(std::unique_ptr<Transport> transport, bool first_look)
    : transport_(std::move(transport)) {
  if (first_look) {
    FirstLook();
  }
}

std::unique_ptr<Tapsigner> ToTapsigner(CKTapCard&& cktapcard) {
  if (cktapcard.IsTapsigner()) {
    return std::make_unique<Tapsigner>(std::move(cktapcard.transport_));
  }
  throw TapProtoException(TapProtoException::INVALID_DEVICE,
                          "Incorrect device type detected. Please try again.");
}

std::unique_ptr<Satscard> ToSatscard(CKTapCard&& cktapcard) {
  if (!cktapcard.IsTapsigner()) {
    return std::make_unique<Satscard>(std::move(cktapcard.transport_));
  }
  throw TapProtoException(TapProtoException::INVALID_DEVICE,
                          "Incorrect device type detected. Please try again.");
}

CKTapCard::StatusResponse CKTapCard::FirstLook() {
  auto status = Status();
  if (status.proto != 1) {
    throw TapProtoException(TapProtoException::UNKNOW_PROTO_VERSION,
                            "Unknown card protocol version");
  }
  card_pubkey_ = status.pubkey;
  card_ident_ = CardPubkeyToIdent(card_pubkey_);
  applet_version_ = status.ver;
  birth_height_ = status.birth;
  is_testnet_ = status.testnet;
  is_tapsigner_ = status.tapsigner;
  tampered_ = status.tampered;
  return status;
}

json CKTapCard::Send(const json& msg) {
  if (transport_ == nullptr) {
    throw TapProtoException(TapProtoException::DEFAULT_ERROR,
                            "Invalid transport");
  }
  auto resp = transport_->Send(msg);
  if (auto card_nonce = resp.find("card_nonce"); card_nonce != std::end(resp)) {
    card_nonce_ = *card_nonce;
  }

  if (auto auth_delay = resp.find("auth_delay"); auth_delay != std::end(resp)) {
    auth_delay_ = *auth_delay;
  }

  if (auto error = resp.find("error"); error != std::end(resp)) {
    throw TapProtoException(
        resp.value("code", TapProtoException::DEFAULT_ERROR), *error);
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

void CKTapCard::Update(const CKTapCard::StatusResponse& status) {
  auth_delay_ = status.auth_delay;
}

CKTapCard::StatusResponse CKTapCard::Status() {
  auto st = Send({{"cmd", "status"}});
  Update(st);
  return st;
}

std::string CKTapCard::NFC() {
  const auto resp = Send({{"cmd", "nfc"}});
  if (auto url = resp.find("url"); url != std::end(resp)) {
    return *url;
  }
  throw TapProtoException(TapProtoException::MISSING_KEY, "No url found");
}

void CKTapCard::CertificateCheck(const Bytes& pubkey) {
#ifdef SKIP_CERTIFICATE_CHECK
  return;
#endif
  if (certs_checked_) {
    return;
  }
  const json st = Status();
  const json certs = Send({{"cmd", "certs"}});

  const auto nonce = json::binary_t(PickNonce());
  const json check = Send({
      {"cmd", "check"},
      {"nonce", nonce},
  });

  VerifyCerts(st["card_nonce"], st["pubkey"], nonce, certs["cert_chain"],
              check["auth_sig"], pubkey);
  certs_checked_ = true;
}

CKTapCard::WaitResponse CKTapCard::Wait() {
  WaitResponse wait = Send({{"cmd", "wait"}});
  auth_delay_ = wait.auth_delay;
  return wait;
}

CKTapCard::NewResponse CKTapCard::New(const Bytes& chain_code,
                                      const std::string& cvc, int slot) {
  const auto [_, resp] = SendAuth(
      {
          {"cmd", "new"},
          {"slot", slot},
          {"chain_code", json::binary_t(chain_code)},
      },
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
  json request = {
      {"cmd", "sign"},
      {"slot", slot},
      {"digest", digest},
  };

  if (!subpath_int.empty()) {
    request["subpath"] = subpath_int;
  }

  for (int retry = 0; retry < 5; ++retry) {
    try {
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
      if (te.code() == TapProtoException::UNLUCKY_NUMBER) {
        if (GetAppletVersion() == "0.9.0") {
          Status();
        }
        continue;
      }
      throw;
    }
  }
  throw TapProtoException(TapProtoException::EXCEEDED_RETRY,
                          "Failed to sign digest after 5 retries. Try again.");
}

std::string CKTapCard::GetIdent() const noexcept { return card_ident_; }
std::string CKTapCard::GetAppletVersion() const noexcept {
  return applet_version_;
}
int CKTapCard::GetBirthHeight() const noexcept { return birth_height_; }
bool CKTapCard::IsTestnet() const noexcept { return is_testnet_; }
int CKTapCard::GetAuthDelay() const noexcept { return auth_delay_; }
bool CKTapCard::IsTampered() const noexcept { return tampered_; }
bool CKTapCard::IsCertsChecked() const noexcept { return certs_checked_; }
bool CKTapCard::IsTapsigner() const noexcept { return is_tapsigner_; }

void to_json(json& j, const CKTapCard::StatusResponse& t) {
  j = {
      {"proto", t.proto},
      {"ver", t.ver},
      {"birth", t.birth},
      {"slots", t.slots},
      {"addr", t.addr},
      {"pubkey", t.pubkey},
      {"card_nonce", t.card_nonce},
      {"tapsigner", t.tapsigner},
      {"testnet", t.testnet},
      {"num_backups", t.num_backups},
      {"auth_delay", t.auth_delay},
      {"tampered", t.tampered},
  };
  if (t.path) {
    j["path"] = *t.path;
  }
}

void from_json(const json& j, CKTapCard::StatusResponse& t) {
  t.proto = j.value("proto", t.proto);
  t.ver = j.value("ver", t.ver);
  t.birth = j.value("birth", t.birth);
  t.slots = j.value("slots", std::vector<int>{0, 1});
  t.addr = j.value("addr", t.addr);
  t.pubkey = j.value("pubkey", t.pubkey);
  t.card_nonce = j.value("card_nonce", t.card_nonce);
  t.tapsigner = j.value("tapsigner", t.tapsigner);
  t.testnet = j.value("testnet", t.testnet);
  t.num_backups = j.value("num_backups", t.num_backups);
  t.auth_delay = j.value("auth_delay", t.auth_delay);
  t.tampered = j.value("tampered", t.tampered);
  if (auto path = j.find("path"); path != std::end(j)) {
    t.path.emplace(path->get<std::vector<uint32_t>>());
  }
}

void to_json(nlohmann::json& j, const CKTapCard::WaitResponse& t) {
  j = {
      {"auth_delay", t.auth_delay},
      {"success", t.success},
  };
}

void from_json(const nlohmann::json& j, CKTapCard::WaitResponse& t) {
  t.auth_delay = j.value("auth_delay", t.auth_delay);
  t.success = j.value("success", t.success);
}

}  // namespace tap_protocol
