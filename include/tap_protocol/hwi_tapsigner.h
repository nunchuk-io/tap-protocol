#ifndef HWI_TAPSIGNER_H
#define HWI_TAPSIGNER_H

#include <memory>
#include <optional>
#include <string>
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/tap_protocol.h"

struct ext_key;

namespace tap_protocol {

class HWITapsigerException : public TapProtoException {
 public:
  using TapProtoException::TapProtoException;

  static const int PSBT_PARSE_ERROR = -2001;
  static const int PSBT_INVALID = -2002;
  static const int MALFORMED_BIP32_PATH = -2003;

  static const int UNKNOW_ERROR = -2999;
};

using PromptCVCCallback = std::function<std::optional<std::string>()>;

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

  virtual std::string SignTx(const std::string &base64_psbt) = 0;
  virtual Bytes GetMasterFingerprint() = 0;
  virtual std::string GetMasterXpub(AddressType address_type = WIT,
                                    int account = 0) = 0;
  virtual void SetPromptCVCCallback(PromptCVCCallback func) = 0;

  virtual ~HWITapsigner() = default;
};

class HWITapsignerImpl : public HWITapsigner {
 public:
  HWITapsignerImpl() = default;
  HWITapsignerImpl(std::unique_ptr<Tapsigner> tap_signer,
                   PromptCVCCallback cvc_callback);

  std::string SignTx(const std::string &psbt) override;
  Bytes GetMasterFingerprint() override;
  void SetPromptCVCCallback(PromptCVCCallback func) override;
  std::string GetMasterXpub(AddressType address_type = WIT,
                            int account = 0) override;

  ~HWITapsignerImpl() = default;

 private:
  ext_key GetPubkeyAtPath(const std::string &bip32_path);
  void GetCVC();

 private:
  // TODO: set chain
  int chain = 0;  // 0 MAIN, 1 TEST
  PromptCVCCallback cvc_callback_;
  std::unique_ptr<Tapsigner> tap_signer_;
  std::string cvc_;
};

std::unique_ptr<HWITapsigner> MakeHWITapsigner(
    std::unique_ptr<Tapsigner> tap_signer, PromptCVCCallback cvc_callback);

}  // namespace tap_protocol

#endif
