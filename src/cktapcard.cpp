#include "tap_protocol/cktapcard.h"
//#include "secp256k1.h"

namespace tap_protocol {
CKTapCard::CKTapCard(std::unique_ptr<Transport> transport)
    : transport_(std::move(transport)) {}

nlohmann::json CKTapCard::Send(const nlohmann::json& msg) {
  auto resp = transport_->Send(msg);
  if (resp.contains("card_nonce")) {
    card_nonce_ = resp["card_nonce"];
  }
  return resp;
}

nlohmann::json CKTapCard::SendAuth(const nlohmann::json& msg,
                                   const std::string& cvc) {
  //    secp256k1_context* ctx =
  //    secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  //    secp256k1_context_destroy(ctx);
  return {};
}

TapSigner::StatusResponse TapSigner::Status() {
  return Send({{"cmd", "status"}});
}

std::string TapSigner::NFC() {
  auto resp = Send({{"cmd", "nfc"}});
  if (resp.contains("url")) {
    return resp["url"];
  }
  throw TapProtoException(TapProtoException::MISSING_KEY, "No url found");
}

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
}  // namespace tap_protocol
