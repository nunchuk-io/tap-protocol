#include "tap_protocol/cktapcard.h"
#include "bitcoin/base58.h"
#include <wally_core.h>
#include <wally_crypto.h>
#include <memory>
#include <iostream>
#include <string>
#include "nlohmann/json.hpp"
#include "tap_protocol/utils.h"

namespace tap_protocol {
CKTapCard::CKTapCard(std::unique_ptr<Transport> transport)
    : transport_(std::move(transport)) {
  FirstLook();
}

void CKTapCard::FirstLook() {
  auto status = Status();
  if (status.proto != 1) {
    throw TapProtoException(TapProtoException::UNKNOW_PROTO_VERSION,
                            "Unknown card protocol version");
  }
  // TODO: tampered
  card_pubkey_ = status.pubkey;
  card_ident_ = CardPubkeyToIdent(card_pubkey_);
}

nlohmann::json CKTapCard::Send(const nlohmann::json& msg) {
  auto resp = transport_->Send(msg);
  if (resp.contains("card_nonce")) {
    card_nonce_ = resp["card_nonce"];
  }
  return resp;
}

std::pair<Bytes, nlohmann::json> CKTapCard::SendAuth(const nlohmann::json& msg,
                                                     const Bytes& cvc) {
  nlohmann::json send_msg = msg;
  std::string cmd = send_msg.value("cmd", std::string{});

  Bytes session_key;
  if (!cvc.empty()) {
    XCVC xcvc = CalcXCVC({cmd.data(), cmd.data() + cmd.size()}, card_nonce_,
                         card_pubkey_, cvc);
    session_key = std::move(xcvc.session_key);
    send_msg.merge_patch(xcvc);
  }

  if (cmd == "send") {
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
  auto resp = Send({{"cmd", "nfc"}});
  if (resp.contains("url")) {
    return resp["url"];
  }
  throw TapProtoException(TapProtoException::MISSING_KEY, "No url found");
}

Bytes CKTapCard::GetIdent() const noexcept { return card_ident_; }

void to_json(json& j, const CKTapCard::StatusResponse& t) {
  j = {{"proto", t.proto},
       {"ver", t.ver},
       {"birth", t.birth},
       {"slots", t.slots},
       {"address", t.address},
       {"pubkey", t.pubkey},
       {"card_nonce", t.card_nonce},
       {"tapsigner", t.tapsigner},
       {"path", t.path},
       {"testnet", t.testnet}};
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
  t.path = j.value("path", t.path);
  t.testnet = j.value("testnet", t.testnet);
}

// Tapsigner

void to_json(nlohmann::json& j, const TapSigner::DeriveResponse& t) {
  j = {{"sig", t.sig},
       {"chain_code", t.chain_code},
       {"master_pubkey", t.master_pubkey},
       {"pubkey", t.pubkey},
       {"card_nonce", t.card_nonce}};
}

void from_json(const nlohmann::json& j, TapSigner::DeriveResponse& t) {
  t.sig = j.value("sig", t.sig);
  t.chain_code = j.value("chain_code", t.chain_code);
  t.master_pubkey = j.value("master_pubkey", t.master_pubkey);
  t.pubkey = j.value("pubkey", t.pubkey);
  t.card_nonce = j.value("card_nonce", t.card_nonce);
}

std::string TapSigner::GetDerivation() {
  auto status = Status();
  if (status.path.empty()) {
    throw TapProtoException(TapProtoException::NO_PRIVATE_KEY_PICKED,
                            "No private key picked yet.");
  }
  return Path2Str(status.path);
}

TapSigner::DeriveResponse TapSigner::Derive(const std::string& path,
                                            const std::string& cvc) {
  // TODO: convert path to path_value
  std::vector<int64_t> path_value = Str2Path(path);

  const json request = {{"cmd", "derive"},
                        {"nonce", json::binary_t(PickNonce())},
                        {"path", path_value}};

  const Bytes cvc_bytes(std::begin(cvc), std::end(cvc));
  const auto [_session_key, resp] = SendAuth(request, cvc_bytes);
  return resp;
}

std::string TapSigner::GetXFP(const std::string& cvc) {
  auto [session, resp] = SendAuth({{"cmd", "xpub"}, {"master", true}},
                                  {cvc.data(), cvc.data() + cvc.size()});
  json::binary_t xpub = resp["xpub"];
  xpub.erase(std::begin(xpub), std::end(xpub) - 33);

  Bytes xpub_hash(HASH160_LEN);
  if (int code = wally_hash160(xpub.data(), xpub.size(), xpub_hash.data(),
                               HASH160_LEN);
      code != WALLY_OK) {
    throw TapProtoException(TapProtoException::INVALID_HASH_LENGTH,
                            "Invalid hash160 length");
  }
  xpub_hash.resize(4);
  return ToUpper(Bytes2Str(xpub_hash));
}

std::string TapSigner::Xpub(const std::string& cvc, bool master) {
  auto [session, resp] = SendAuth({{"cmd", "xpub"}, {"master", master}},
                                  {cvc.data(), cvc.data() + cvc.size()});
  Bytes xpub = resp["xpub"].get<json::binary_t>();

  std::cout << "xpub raw: " << Bytes2Str(xpub) << "\n";
  Bytes double_hash_xpub(SHA256_LEN);
  if (int code = wally_sha256d(xpub.data(), xpub.size(),
                               double_hash_xpub.data(), SHA256_LEN);
      code != WALLY_OK) {
    throw TapProtoException(TapProtoException::INVALID_HASH_LENGTH,
                            "Invalid sha256 length");
  }
  xpub.insert(std::end(xpub), std::begin(double_hash_xpub),
              std::begin(double_hash_xpub) + 4);
  return EncodeBase58({xpub.data(), xpub.size()});
}

std::string TapSigner::Pubkey(const std::string& cvc) {
  auto recover_pubkey = [](const json& status, const json& read,
                           const Bytes& nonce, const Bytes& session_key) {
    static constexpr std::array<char, 8> opendime = {'O', 'P', 'E', 'N',
                                                     'D', 'I', 'M', 'E'};
    static constexpr int CARD_NONCE_SIZE = 16;
    static constexpr int USER_NONCE_SIZE = 16;

    json::binary_t card_nonce = status["card_nonce"];

    Bytes msg;
    msg.insert(std::end(msg), std::begin(opendime), std::end(opendime));
    msg.insert(std::end(msg), std::begin(card_nonce), std::end(card_nonce));
    msg.insert(std::end(msg), std::begin(nonce), std::end(nonce));
    msg.push_back(0x00);

    if (msg.size() != 8 + CARD_NONCE_SIZE + USER_NONCE_SIZE + 1) {
      throw TapProtoException(TapProtoException::UNKNOW_ERROR,
                              "Invalid size " + std::to_string(msg.size()));
    }

    json::binary_t pubkey = read["pubkey"];
    auto pubkey_tmp = XORBytes(
        {pubkey.data() + 1, pubkey.data() + pubkey.size()}, session_key);
    pubkey_tmp.insert(std::begin(pubkey_tmp), pubkey.front());

    Bytes msg_sha256(SHA256_LEN);

    if (int code =
            wally_sha256(msg.data(), msg.size(), msg_sha256.data(), SHA256_LEN);
        code != WALLY_OK) {
      throw TapProtoException(TapProtoException::INVALID_HASH_LENGTH,
                              "Invalid sha256 length");
    }

    json::binary_t sig = read["sig"];

    if (int code = wally_ec_sig_verify(pubkey_tmp.data(), pubkey_tmp.size(),
                                       msg_sha256.data(), msg_sha256.size(),
                                       EC_FLAG_ECDSA, sig.data(), sig.size());
        code != WALLY_OK) {
      throw TapProtoException(TapProtoException::SIG_VERIFY_ERROR,
                              "Sig verify error " + std::to_string(code));
    }
    return pubkey_tmp;
  };

  Bytes nonce = PickNonce();
  json status = Status();
  auto [session_key, read] =
      SendAuth({{"cmd", "read"}, {"nonce", json::binary_t(nonce)}},
               {cvc.data(), cvc.data() + cvc.size()});
  auto ret = recover_pubkey(status, read, nonce, session_key);
  return Bytes2Str(ret);
}

}  // namespace tap_protocol
