#ifndef TAPPROTOCOL_H
#define TAPPROTOCOL_H

#include <functional>
#include <vector>
#include <cstddef>
#include <string>

namespace tap_protocol {
using Bytes = std::vector<unsigned char>;

using SendReceiveFunction = std::function<Bytes(const Bytes &msg)>;

class TapProtoException : public std::exception {
 public:
  static const int SERIALIZE_ERROR = -1;
  static const int MESSAGE_TOO_LONG = -2;
  static const int MISSING_KEY = -3;
  static const int ISO_APP_SELECT_FAILED = -4;
  static const int SW_FAIL = -5;

 public:
  TapProtoException(int code, std::string message);
  const char *what() const noexcept override;
  int code() const noexcept;

 private:
  std::string message_;
  int code_;
};

}  // namespace tap_protocol

#endif  // TAPPROTOCOL_H
