#include "tap_protocol/cktapcard.h"
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
std::string TapSigner::GetDerivation() {
  auto status = Status();
  if (status.path.empty()) {
    throw TapProtoException(TapProtoException::NO_PRIVATE_KEY_PICKED,
                            "No private key picked yet.");
  }
  return Path2Str(status.path);
}

json TapSigner::Derive(const std::string& path, const std::string& cvc) {
  // TODO: convert path to path_value
  std::vector<int64_t> path_value{
      2147483732,
      2147483648,
      2147483648,
  };

  const json request = {{"cmd", "derive"},
                        {"nonce", json::binary_t(PickNonce())},
                        {"path", path_value}};

  const Bytes cvc_bytes(std::begin(cvc), std::end(cvc));
  const auto [_session_key, resp] = SendAuth(request, cvc_bytes);
  return resp;
}

}  // namespace tap_protocol
