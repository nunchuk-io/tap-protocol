#ifndef HWI_TAPSIGNER_H
#define HWI_TAPSIGNER_H

#include <memory>
#include <string>
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/tap_protocol.h"

struct ext_key;

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
  virtual void SetPromptPinCallback(PromptPinCallback func) = 0;

  virtual ~HWITapsigner() = default;
};

class HWITapsignerImpl : public HWITapsigner {
 public:
  HWITapsignerImpl() = default;
  HWITapsignerImpl(std::unique_ptr<Tapsigner> tap_signer);

  std::string SignTx(const std::string &psbt) override;
  Bytes GetMasterFingerprint() override;
  void SetPromptPinCallback(PromptPinCallback func) override;
  std::string GetMasterXpub(AddressType address_type = WIT,
                            int account = 0) override;

  ~HWITapsignerImpl() = default;

 private:
  ext_key GetPubkeyAtPath(const std::string &bip32_path);

 private:
  int chain = 0;  // 0 MAIN, 1 TEST
  PromptPinCallback pin_callback_;
  std::unique_ptr<Tapsigner> tap_signer_;
  std::string cvc_;
};

std::unique_ptr<HWITapsigner> MakeHWITapsigner(
    std::unique_ptr<Tapsigner> tap_signer);

}  // namespace tap_protocol

#endif
