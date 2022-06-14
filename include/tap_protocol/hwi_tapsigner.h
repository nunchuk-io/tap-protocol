#ifndef HWI_TAPSIGNER_H
#define HWI_TAPSIGNER_H

#include <memory>
#include <optional>
#include <string>
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/tap_protocol.h"

struct CExtPubKey;

namespace tap_protocol {

using PromptCVCCallback =
    std::function<std::optional<std::string>(const std::string &message)>;

class HWITapsigner {
 protected:
  HWITapsigner() = default;

 public:
  enum AddressType {
    LEGACY = 1,  // Legacy address type. P2PKH for single sig, P2SH for scripts.
    WIT = 2,     // Native segwit v0 address type. P2WPKH for single sig, P2WPSH
                 // for scripts.
    SH_WIT = 3,  // Nested segwit v0 address type. P2SH-P2WPKH for single sig,
                 // P2SH-P2WPSH for scripts.
    TAP = 4,     // Segwit v1 Taproot address type. P2TR always.
  };

  enum Chain : int {
    MAIN = 0,
    TESTNET = 1,
    SIGNET = TESTNET,
  };

  virtual void SetChain(Chain chain) = 0;
  virtual void SetDevice(Tapsigner *device) = 0;
  virtual void SetDevice(Tapsigner *device, const std::string &cvc) = 0;
  virtual std::string SignTx(const std::string &base64_psbt) = 0;
  virtual std::string SignMessage(const std::string &message,
                                  const std::string &derivation_path) = 0;
  virtual std::string GetMasterFingerprint() = 0;
  virtual std::string GetMasterXpub(AddressType address_type = WIT,
                                    int account = 0) = 0;
  virtual std::string GetXpubAtPath(const std::string &derivation_path) = 0;
  virtual bool SetupDevice() = 0;
  virtual Bytes BackupDevice() = 0;
  virtual Bytes DecryptBackup(const Bytes &encrypted_data,
                              const std::string &backup_key) = 0;
  virtual void SetPromptCVCCallback(PromptCVCCallback func) = 0;
  virtual ~HWITapsigner() = default;
};

class HWITapsignerImpl : public HWITapsigner {
 public:
  HWITapsignerImpl() = default;
  HWITapsignerImpl(Tapsigner *device, const std::string &cvc);
  HWITapsignerImpl(Tapsigner *device, PromptCVCCallback cvc_callback);
  void SetChain(Chain chain) override;
  void SetDevice(Tapsigner *device) override;
  void SetDevice(Tapsigner *device, const std::string &cvc) override;
  std::string SignTx(const std::string &base64_psbt) override;
  std::string SignMessage(const std::string &message,
                          const std::string &derivation_path) override;
  std::string GetMasterFingerprint() override;
  std::string GetMasterXpub(AddressType address_type = WIT,
                            int account = 0) override;
  std::string GetXpubAtPath(const std::string &path) override;
  bool SetupDevice() override;
  Bytes BackupDevice() override;
  Bytes DecryptBackup(const Bytes &encrypted_data,
                      const std::string &backup_key) override;
  void SetPromptCVCCallback(PromptCVCCallback func) override;
  ~HWITapsignerImpl() override = default;

 private:
  Bytes GetMasterFingerprintBytes();
  CExtPubKey GetPubkeyAtPath(const std::string &derivation_path);
  void GetCVC(const std::string &message = "Please provide CVC:");

 private:
  Chain chain_ = MAIN;
  PromptCVCCallback cvc_callback_;
  Tapsigner *device_;
  std::string cvc_;
};

std::unique_ptr<HWITapsigner> MakeHWITapsigner(HWITapsigner::Chain chain);

std::unique_ptr<HWITapsigner> MakeHWITapsigner(Tapsigner *device,
                                               const std::string &cvc);
std::unique_ptr<HWITapsigner> MakeHWITapsigner(Tapsigner *device,
                                               PromptCVCCallback cvc_callback);

}  // namespace tap_protocol

#endif
