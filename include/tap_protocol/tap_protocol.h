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
  static const int INVALID_CVC_LENGTH = -6;
  static const int PICK_KEY_PAIR_FAIL = -7;
  static const int ECDH_FAIL = -8;
  static const int XCVC_FAIL = -9;
  static const int UNKNOW_PROTO_VERSION = -10;
  static const int INVALID_PUBKEY_COMPRESS_LENGTH = -11;
  static const int NO_PRIVATE_KEY_PICKED = -12;
  static const int MALFORMED_BIP32_PATH = -13;
  static const int INVALID_HASH_LENGTH = -14;
  static const int SIG_VERIFY_ERROR = -15;
  static const int INVALID_DIGEST_LENGTH = -16;
  static const int INVALID_PATH_LENGTH = -17;

  static const int UNKNOW_ERROR = -100;

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
