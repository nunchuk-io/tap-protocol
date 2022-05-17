#include "tap_protocol/tap_protocol.h"

tap_protocol::TapProtoException::TapProtoException(int code,
                                                   std::string message)
    : code_(code), message_(std::move(message)) {}

const char* tap_protocol::TapProtoException::what() const noexcept {
  return message_.c_str();
}
int tap_protocol::TapProtoException::code() const noexcept { return code_; }
