#include "tap_protocol/cktapcard.h"

namespace tap_protocol {
CKTapCard::CKTapCard(std::unique_ptr<Transport> transport)
    : transport_(std::move(transport)) {}

TapSigner::StatusResponse TapSigner::Status() {
  return transport_->Send({{"cmd", "status"}});
}
}  // namespace tap_protocol
