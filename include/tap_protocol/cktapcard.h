#ifndef CKTAPCARD_H
#define CKTAPCARD_H

#include <memory>
#include <optional>
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
    std::vector<int> slots{0, 1};
    std::string address;
    nlohmann::json::binary_t pubkey;
    nlohmann::json::binary_t card_nonce;
    bool tapsigner{};
    std::optional<std::vector<uint32_t>> path;
    int num_backups{};
    bool testnet{};
    int auth_delay{};
    bool tampered{};

    friend void to_json(nlohmann::json& j, const StatusResponse& t);
    friend void from_json(const nlohmann::json& j, StatusResponse& t);
  };

  struct NewResponse {
    int slot{};
    nlohmann::json::binary_t card_nonce;

    friend void to_json(nlohmann::json& j, const NewResponse& t);
    friend void from_json(const nlohmann::json& j, NewResponse& t);
  };

  struct WaitResponse {
    bool success{};
    int auth_delay{};

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(WaitResponse, success, auth_delay);
  };

  nlohmann::json Send(const nlohmann::json& msg);
  std::pair<Bytes, nlohmann::json> SendAuth(const nlohmann::json& msg,
                                            const Bytes& cvc = {});
  std::string GetIdent() const noexcept;
  std::string GetAppletVersion() const noexcept;
  int GetBirthHeight() const noexcept;
  bool IsTestnet() const noexcept;
  int GetAuthDelay() const noexcept;
  bool IsTampered() const noexcept;

  StatusResponse Status();
  std::string NFC();
  std::string CertificateCheck();
  WaitResponse Wait();
  NewResponse New(const Bytes& chain_code, const std::string& cvc,
                  int slot = 0);
  Bytes Sign(const Bytes& digest, const std::string& cvc, int slot = 0,
             const std::string& subpath = {});

 protected:
  CKTapCard() = default;
  StatusResponse FirstLook();
  virtual void Update(const StatusResponse& status);
  std::unique_ptr<Transport> transport_;

 private:
  nlohmann::json::binary_t card_nonce_;
  nlohmann::json::binary_t card_pubkey_;
  std::string card_ident_;
  std::string applet_version_;
  int birth_height_{};
  bool is_testnet_{};
  int auth_delay_{};
  bool tampered_{};
};

class Tapsigner : public CKTapCard {
  using CKTapCard::CKTapCard;

 public:
  explicit Tapsigner(std::unique_ptr<Transport> transport);

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

  int GetNumberOfBackups() const noexcept;
  std::optional<std::string> GetDerivationPath() const noexcept;

 protected:
  void Update(const StatusResponse& status) override;

 private:
  bool is_tapsigner_{};
  int number_of_backup_{};
  std::optional<std::string> derivation_path_;
};

class Satscard : public CKTapCard {
  using CKTapCard::CKTapCard;

 public:
  explicit Satscard(std::unique_ptr<Transport> transport);

  struct UnsealResponse {
    int slot{};
    json::binary_t privkey;
    json::binary_t pubkey;
    json::binary_t master_pk;
    json::binary_t chain_code;
    json::binary_t card_nonce;

    friend void to_json(nlohmann::json& j, const UnsealResponse& t);
    friend void from_json(const nlohmann::json& j, UnsealResponse& t);
  };

  UnsealResponse Unseal(const std::string& cvc);
  NewResponse New(const Bytes& chain_code, const std::string& cvc);

 protected:
  void Update(const StatusResponse& status) override;

 private:
  int active_slot_ = 0;
  int num_slots_ = 1;
};

}  // namespace tap_protocol
#endif  // CKTAPCARD_H
