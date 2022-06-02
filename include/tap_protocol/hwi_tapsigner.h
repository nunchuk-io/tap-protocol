#ifndef HWI_TAPSIGNER_H
#define HWI_TAPSIGNER_H

#include <memory>
#include <string>
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/tap_protocol.h"

namespace tap_protocol {

class HWITapsigerException : public TapProtoException {
 public:
  using TapProtoException::TapProtoException;

  static const int PSBT_PARSE_ERROR = -1000;
  static const int PSBT_INVALID = -1001;
  static const int MALFORMED_BIP32_PATH = -1002;
};

using PromptPinCallback = std::function<std::string()>;

class HWITapsigner {
 protected:
  HWITapsigner() = default;

 public:
  virtual std::string SignTx(const std::string &base64_psbt) = 0;
  virtual Bytes GetPubkeyAtPath(const std::string &bip32_path) = 0;
  virtual Bytes GetMasterFingerprint() = 0;
  virtual void SetPromptPinCallback(PromptPinCallback func) = 0;

  virtual ~HWITapsigner() = default;
};

class HWITapsignerImpl : public HWITapsigner {
 public:
  HWITapsignerImpl() = default;
  HWITapsignerImpl(std::unique_ptr<Tapsigner> tap_signer);

  std::string SignTx(const std::string &psbt) override;
  Bytes GetPubkeyAtPath(const std::string &bip32_path) override;
  Bytes GetMasterFingerprint() override;
  void SetPromptPinCallback(PromptPinCallback func) override;

  ~HWITapsignerImpl() = default;

 private:
  PromptPinCallback pin_callback_;
  std::unique_ptr<Tapsigner> tap_signer_;
  std::string cvc_;
};

std::unique_ptr<HWITapsigner> MakeHWITapsigner(
    std::unique_ptr<Tapsigner> tap_signer);

}  // namespace tap_protocol

#endif
