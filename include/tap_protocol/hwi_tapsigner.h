#ifndef HWI_TAPSIGNER_H
#define HWI_TAPSIGNER_H

#include <memory>
#include <string>
#include "tap_protocol/tap_protocol.h"

namespace tap_protocol {

class HWITapsigerException : public TapProtoException {
 public:
  using TapProtoException::TapProtoException;

  static const int PSBT_PARSE_ERROR = -1000;
};

class HWITapsiger {
 public:
  HWITapsiger() = default;

  virtual std::string SignTx(const std::string &psbt) = 0;
};

std::unique_ptr<HWITapsiger> MakeHWITapsigner();

}  // namespace tap_protocol

#endif
