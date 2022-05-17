#ifndef CKTAPCARD_H
#define CKTAPCARD_H

#include <memory>
#include "transport.h"

// NFCISO7816Tag for iOS
// NfcA for Android

namespace tap_protocol {

class CKTapCard {
 public:
  explicit CKTapCard(std::unique_ptr<Transport> transport);

  struct StatusResponse {
    int proto;
    std::string ver;
    int birth;
    std::array<int, 2> slots;
    std::string address;
    std::string pubkey;
    std::string card_nonce;
    bool tapsigner;
    std::string path;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(StatusResponse, proto, ver, birth, slots,
                                   address, pubkey, card_nonce, tapsigner, path)
  };

  virtual StatusResponse Status() = 0;

 protected:
  std::unique_ptr<Transport> transport_;
};

class TapSigner : public CKTapCard {
  using CKTapCard::CKTapCard;

 public:
  StatusResponse Status() override;
};

}  // namespace tap_protocol
#endif  // CKTAPCARD_H
