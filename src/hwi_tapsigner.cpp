#include "tap_protocol/hwi_tapsigner.h"
#include <wally_psbt.h>
#include <iostream>
#include <memory>

namespace tap_protocol {

class HWITapsigerImpl : public HWITapsiger {
 public:
  using HWITapsiger::HWITapsiger;
  std::string SignTx(const std::string &psbt);
};

std::string HWITapsigerImpl::SignTx(const std::string &base64_psbt) {
  wally_psbt *w_psbt;
  auto deleter = [](wally_psbt *ptr) { wally_psbt_free(ptr); };
  auto auto_deleter =
      std::unique_ptr<wally_psbt, decltype(deleter)>(w_psbt, deleter);

  if (int code = wally_psbt_from_base64(base64_psbt.data(), &w_psbt);
      code != WALLY_OK) {
    throw HWITapsigerException(HWITapsigerException::PSBT_PARSE_ERROR,
                               "Parse psbt error");
  }

  return {};
}

std::unique_ptr<HWITapsiger> MakeHWITapsigner() {
  return std::make_unique<HWITapsigerImpl>();
}
}  // namespace tap_protocol
