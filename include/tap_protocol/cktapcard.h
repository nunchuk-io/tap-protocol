#ifndef CKTAPCARD_H
#define CKTAPCARD_H

#include <memory>
#include "nlohmann/json.hpp"
#include "transport.h"

// NFCISO7816Tag for iOS
// IsoDep for Android

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
    std::vector<uint32_t> path;
    int num_backups{};
    bool testnet{};

    friend void to_json(nlohmann::json& j, const StatusResponse& t);
    friend void from_json(const nlohmann::json& j, StatusResponse& t);
  };

  struct NewResponse {
    int slot{};
    nlohmann::json::binary_t card_nonce;

    friend void to_json(nlohmann::json& j, const NewResponse& t);
    friend void from_json(const nlohmann::json& j, NewResponse& t);
  };

  nlohmann::json Send(const nlohmann::json& msg);
  std::pair<Bytes, nlohmann::json> SendAuth(const nlohmann::json& msg,
                                            const Bytes& cvc = {});
  std::string GetIdent() const noexcept;

  virtual StatusResponse Status();
  virtual std::string NFC();
  virtual NewResponse New(const Bytes& chain_code, const std::string& cvc,
                          int slot = 0) = 0;
  virtual std::string CertificateCheck();
  virtual Bytes Sign(const Bytes& digest, const std::string& cvc, int slot = 0,
                     const std::string& subpath = {}) = 0;

 protected:
  void FirstLook();

 protected:
  std::unique_ptr<Transport> transport_;
  nlohmann::json::binary_t card_nonce_;
  nlohmann::json::binary_t card_pubkey_;
  nlohmann::json::binary_t card_ident_;
};

class Tapsigner : public CKTapCard {
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

  struct ChangeResponse {
    bool success{};
    nlohmann::json::binary_t card_nonce;

    friend void to_json(nlohmann::json& j, const ChangeResponse& t);
    friend void from_json(const nlohmann::json& j, ChangeResponse& t);
  };

  struct BackupResponse {
    nlohmann::json::binary_t data;
    nlohmann::json::binary_t card_nonce;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(BackupResponse, data, card_nonce);
  };

  DeriveResponse Derive(const std::string& path, const std::string& cvc);
  std::string GetXFP(const std::string& cvc);
  std::string Xpub(const std::string& cvc, bool master);
  std::string Pubkey(const std::string& cvc);
  std::string GetDerivation();
  ChangeResponse Change(const std::string& new_cvc, const std::string& cvc);
  BackupResponse Backup(const std::string& cvc);
  NewResponse New(const Bytes& chain_code, const std::string& cvc,
                  int slot = 0) override;
  Bytes Sign(const Bytes& digest, const std::string& cvc, int slot = 0,
             const std::string& subpath = {}) override;
};

}  // namespace tap_protocol
#endif  // CKTAPCARD_H
