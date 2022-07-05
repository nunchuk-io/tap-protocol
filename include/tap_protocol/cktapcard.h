#ifndef CKTAPCARD_H
#define CKTAPCARD_H

#include <memory>
#include <optional>
#include "nlohmann/json.hpp"
#include "transport.h"

// NFCISO7816Tag for iOS
// IsoDep for Android

namespace tap_protocol {

class Tapsigner;
class Satscard;
class CKTapCard;

std::unique_ptr<Tapsigner> ToTapsigner(CKTapCard&& cktapcard);
std::unique_ptr<Satscard> ToSatscard(CKTapCard&& cktapcard);

class CKTapCard {
 public:
  explicit CKTapCard(std::unique_ptr<Transport> transport,
                     bool first_look = true);

  friend std::unique_ptr<Tapsigner> ToTapsigner(CKTapCard&& cktapcard);
  friend std::unique_ptr<Satscard> ToSatscard(CKTapCard&& cktapcard);

  struct StatusResponse {
    int proto{};
    std::string ver;
    int birth{};
    std::vector<int> slots;
    std::string addr;
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
  bool IsCertsChecked() const noexcept;
  bool IsTapsigner() const noexcept;
  virtual bool NeedSetup() const noexcept { return false; };

  StatusResponse Status();
  std::string NFC();
  std::string CertificateCheck();
  WaitResponse Wait();
  NewResponse New(const Bytes& chain_code, const std::string& cvc,
                  int slot = 0);
  Bytes Sign(const Bytes& digest, const std::string& cvc, int slot = 0,
             const std::string& subpath = {});

 protected:
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
  bool is_tapsigner_{};
  int auth_delay_{};
  bool tampered_{};
  bool certs_checked_{};
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
  ChangeResponse Change(const std::string& new_cvc, const std::string& cvc);
  BackupResponse Backup(const std::string& cvc);

  bool NeedSetup() const noexcept override;
  int GetNumberOfBackups() const noexcept;
  std::optional<std::string> GetDerivationPath() const noexcept;

 protected:
  void Update(const StatusResponse& status) override;

 private:
  int number_of_backup_{};
  std::optional<std::string> derivation_path_;
};

class Satscard : public CKTapCard {
  using CKTapCard::CKTapCard;

 public:
  explicit Satscard(std::unique_ptr<Transport> transport);

  enum class SlotStatus {
    UNUSED,
    SEALED,
    UNSEALED,
  };

  struct Slot {
    int index{};
    SlotStatus status;
    std::string address{};

    // cvc provide && unsealed slot
    json::binary_t privkey{};
    json::binary_t pubkey{};
    json::binary_t master_pk{};
    json::binary_t chain_code{};

    // WIF format if privkey is present
    std::string to_wif(bool testnet = false) const;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(Slot, index, status, address, privkey,
                                   pubkey, master_pk, chain_code);

    bool operator==(const Slot& other) const {
      return index == other.index && status == other.status &&
             address == other.address && privkey == other.privkey &&
             pubkey == other.pubkey && master_pk == other.pubkey &&
             chain_code == other.chain_code;
    }
  };

  Slot Unseal(const std::string& cvc);
  Slot New(const Bytes& chain_code, const std::string& cvc);

  Slot GetSlot(int slot, const std::string& cvc = {});
  std::vector<Slot> ListSlots(const std::string& cvc = {}, size_t limit = 10);

  Slot GetActiveSlot() const;
  int GetActiveSlotIndex() const noexcept;
  int GetNumSlots() const noexcept;
  bool NeedSetup() const noexcept override;
  bool HasUnusedSlots() const noexcept;
  bool IsUsedUp() const noexcept;

 protected:
  void Update(const StatusResponse& status) override;

 private:
  void RenderActiveSlotAddress(const StatusResponse& status);
  SlotStatus GetActiveSlotStatus() const noexcept;

  int active_slot_ = 0;
  int num_slots_ = 1;
  // address_ : return `addr` from status cmd
  std::string address_;
  // render_address_ : active slot full address
  std::string render_address_;
};

}  // namespace tap_protocol
#endif  // CKTAPCARD_H
