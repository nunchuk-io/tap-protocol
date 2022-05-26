#ifndef CKTAPCARD_H
#define CKTAPCARD_H

#include <memory>
#include "nlohmann/json.hpp"
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
  struct DeriveResponse {
    nlohmann::json::binary_t sig;
    nlohmann::json::binary_t chain_code;
    nlohmann::json::binary_t master_pubkey;
    nlohmann::json::binary_t pubkey;
    nlohmann::json::binary_t card_nonce;

    friend void to_json(nlohmann::json& j, const DeriveResponse& t);
    friend void from_json(const nlohmann::json& j, DeriveResponse& t);
  };

  DeriveResponse Derive(const std::string& path, const std::string& cvc);
  std::string GetXFP(const std::string& cvc);
  std::string Xpub(const std::string& cvc, bool master);
  std::string Pubkey(const std::string& cvc);
  std::string GetDerivation();
};

}  // namespace tap_protocol
#endif  // CKTAPCARD_H
