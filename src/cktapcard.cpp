#include "tap_protocol/cktapcard.h"

namespace tap_protocol {
CKTapCard::CKTapCard(Transport* transport) : transport_(transport) {}

TapSigner::StatusResponse TapSigner::Status() {
  return transport_->Send({{"cmd", "status"}});
}
}  // namespace tap_protocol
