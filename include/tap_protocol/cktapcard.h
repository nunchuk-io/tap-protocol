#ifndef CKTAPCARD_H
#define CKTAPCARD_H

#include <memory>
#include "transport.h"

// NFCISO7816Tag for iOS
// NfcA for Android

namespace tap_protocol {

class CKTapCard {
 public:
  explicit CKTapCard(Transport* transport);

  struct StatusResponse {
    int proto{};
    std::string ver;
    int birth{};
    std::array<int, 2> slots{};
    std::string address;
    nlohmann::json::binary_t pubkey;
    nlohmann::json::binary_t card_nonce;
    bool tapsigner{};
    std::array<int64_t, 3> path{};

    friend void to_json(nlohmann::json& j, const StatusResponse& t) {
      j = {{"proto", t.proto},
           {"ver", t.ver},
           {"birth", t.birth},
           {"slots", t.slots},
           {"address", t.address},
           {"pubkey", t.pubkey},
           {"card_nonce", t.card_nonce},
           {"tapsigner", t.tapsigner},
           {"path", t.path}};
    }
    friend void from_json(const nlohmann::json& j, StatusResponse& t) {
      t.proto = j.value("proto", t.proto);
      t.ver = j.value("ver", t.ver);
      t.birth = j.value("birth", t.birth);
      t.slots = j.value("slots", t.slots);
      t.address = j.value("address", t.address);
      t.pubkey = j.value("pubkey", t.pubkey);
      t.card_nonce = j.value("card_nonce", t.card_nonce);
      t.tapsigner = j.value("tapsigner", t.tapsigner);
      t.path = j.value("path", t.path);
    }
  };

  virtual StatusResponse Status() = 0;

 protected:
  Transport* transport_;
};

class TapSigner : public CKTapCard {
  using CKTapCard::CKTapCard;

 public:
  StatusResponse Status() override;
};

}  // namespace tap_protocol
#endif  // CKTAPCARD_H
