#ifndef TAPPROTOCOL_H
#define TAPPROTOCOL_H

#include <functional>
#include <vector>
#include <cstddef>
#include <string>

namespace tap_protocol {
using NdefMessage = std::vector<unsigned char>;

using SendReceiveFunction =
    std::function<NdefMessage(const NdefMessage &msg)>;

class TapProtoException : public std::exception {
 public:
  static const int SERIALIZE_ERROR = -1;

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
