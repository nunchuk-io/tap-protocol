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
    std::vector<int> slots;
    std::string address;
    nlohmann::json::binary_t pubkey;
    nlohmann::json::binary_t card_nonce;
    bool tapsigner{};
    std::vector<int64_t> path;
    bool testnet{};

    friend void to_json(nlohmann::json& j, const StatusResponse& t);
    friend void from_json(const nlohmann::json& j, StatusResponse& t);
  };

  nlohmann::json Send(const nlohmann::json& msg);
  std::pair<Bytes, nlohmann::json> SendAuth(const nlohmann::json& msg,
                                            const Bytes& cvc = {});
  Bytes GetIdent() const noexcept;

  virtual StatusResponse Status();
  virtual std::string NFC();

 protected:
  void FirstLook();

 protected:
  std::unique_ptr<Transport> transport_;
  nlohmann::json::binary_t card_nonce_;
  nlohmann::json::binary_t card_pubkey_;
  nlohmann::json::binary_t card_ident_;
};

class TapSigner : public CKTapCard {
  using CKTapCard::CKTapCard;

 public:
  json Derive(const std::string& path, const std::string& cvc);
  std::string GetDerivation();
};

}  // namespace tap_protocol
#endif  // CKTAPCARD_H
