#ifndef HWI_TAPSIGNER_H
#define HWI_TAPSIGNER_H

#include <memory>
#include <optional>
#include <string>
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/tap_protocol.h"

struct CExtPubKey;

namespace tap_protocol {

class HWITapsigerException : public TapProtoException {
 public:
  using TapProtoException::TapProtoException;

  static const int PSBT_PARSE_ERROR = -2001;
  static const int PSBT_INVALID = -2002;
  static const int MALFORMED_BIP32_PATH = -2003;

  static const int UNKNOW_ERROR = -2999;
};

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
    TEST = 1,
    SIG = TEST,
  };

  virtual void SetChain(Chain chain) = 0;
  virtual std::string SignTx(const std::string &base64_psbt) = 0;
  virtual std::string SignMessage(const std::string &message,
                                  const std::string &derivation_path) = 0;
  virtual Bytes GetMasterFingerprint() = 0;
  virtual std::string GetMasterXpub(AddressType address_type = WIT,
                                    int account = 0) = 0;
  virtual std::string GetXpubAtPath(const std::string &derivation_path) = 0;
  virtual bool SetupDevice() = 0;
  virtual Bytes BackupDevice() = 0;
  virtual bool RestoreDevice() = 0;
  virtual void SetPromptCVCCallback(PromptCVCCallback func) = 0;
  virtual ~HWITapsigner() = default;
};

class HWITapsignerImpl : public HWITapsigner {
 public:
  HWITapsignerImpl(std::unique_ptr<Tapsigner> tap_signer,
                   PromptCVCCallback cvc_callback);
  void SetChain(Chain chain) override;
  std::string SignTx(const std::string &base64_psbt) override;
  std::string SignMessage(const std::string &message,
                          const std::string &derivation_path) override;
  Bytes GetMasterFingerprint() override;
  std::string GetMasterXpub(AddressType address_type = WIT,
                            int account = 0) override;
  std::string GetXpubAtPath(const std::string &path) override;
  bool SetupDevice() override;
  Bytes BackupDevice() override;
  bool RestoreDevice() override;
  void SetPromptCVCCallback(PromptCVCCallback func) override;
  ~HWITapsignerImpl() override = default;

 private:
  CExtPubKey GetPubkeyAtPath(const std::string &derivation_path);
  void GetCVC(const std::string &message = "Please provide CVC:");

 private:
  Chain chain_ = MAIN;
  PromptCVCCallback cvc_callback_;
  std::unique_ptr<Tapsigner> device_;
  std::string cvc_;
};

std::unique_ptr<HWITapsigner> MakeHWITapsigner(
    std::unique_ptr<Tapsigner> tap_signer, PromptCVCCallback cvc_callback);

}  // namespace tap_protocol

#endif
