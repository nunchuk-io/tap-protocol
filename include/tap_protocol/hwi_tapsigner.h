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
};

class HWITapSiger {
 public:
  HWITapSiger() = default;

  virtual std::string SignTx(const std::string &base64_psbt) = 0;
  virtual std::string GetMasterFingerprint() = 0;

};

std::unique_ptr<HWITapSiger> MakeHWITapSigner();

}  // namespace tap_protocol

#endif
