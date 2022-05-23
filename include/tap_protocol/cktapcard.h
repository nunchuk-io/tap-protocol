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
    int proto{};
    std::string ver;
    int birth{};
    std::array<int, 2> slots{0, 1};
    std::string address;
    nlohmann::json::binary_t pubkey;
    nlohmann::json::binary_t card_nonce;
    bool tapsigner{};
    std::array<int64_t, 3> path{};
    bool testnet{};

    friend void to_json(nlohmann::json& j, const StatusResponse& t);
    friend void from_json(const nlohmann::json& j, StatusResponse& t);
  };

  nlohmann::json Send(const nlohmann::json& msg);
  std::pair<Bytes, nlohmann::json> SendAuth(const nlohmann::json& msg,
                                            const Bytes& cvc = {});

  virtual StatusResponse Status() = 0;
  virtual std::string NFC() = 0;

 protected:
  void FirstLook();
  std::unique_ptr<Transport> transport_;
  nlohmann::json::binary_t card_nonce_;
  nlohmann::json::binary_t card_pubkey_;
  nlohmann::json::binary_t card_ident_;
};

class TapSigner : public CKTapCard {
  using CKTapCard::CKTapCard;

 public:
  StatusResponse Status() override;
  std::string NFC() override;
};

}  // namespace tap_protocol
#endif  // CKTAPCARD_H
