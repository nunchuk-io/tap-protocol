#ifndef TAPPROTOCOL_H
#define TAPPROTOCOL_H

#include <functional>
#include <vector>
#include <cstddef>
#include <string>

namespace tap_protocol {
using Bytes = std::vector<unsigned char>;

using SendReceiveFunction = std::function<Bytes(const Bytes &msg)>;

// Convenient for iOS
struct APDURequest {
  unsigned char cla, ins, p1, p2;
  Bytes data;
};

struct APDUResponse {
  Bytes data;
  unsigned char sw1, sw2;
};
using SendReceiveFunctionIOS =
    std::function<APDUResponse(const APDURequest &req)>;

class TapProtoException : public std::exception {
 public:
  static const int MESSAGE_TOO_LONG = -1001;
  static const int MISSING_KEY = -1002;
  static const int ISO_APP_SELECT_FAILED = -1003;
  static const int SW_FAIL = -1004;
  static const int INVALID_CVC_LENGTH = -1005;
  static const int PICK_KEY_PAIR_FAIL = -1006;
  static const int ECDH_FAIL = -1007;
  static const int XCVC_FAIL = -1008;
  static const int UNKNOW_PROTO_VERSION = -1009;
  static const int INVALID_PUBKEY_COMPRESS_LENGTH = -1010;
  static const int NO_PRIVATE_KEY_PICKED = -1011;
  static const int MALFORMED_BIP32_PATH = -1012;
  static const int INVALID_HASH_LENGTH = -1013;
  static const int SIG_VERIFY_ERROR = -1014;
  static const int INVALID_DIGEST_LENGTH = -1015;
  static const int INVALID_PATH_LENGTH = -1016;
  static const int SERIALIZE_ERROR = -1017;
  static const int EXCEEDED_RETRY = -1018;
  static const int INVALID_CARD = -1019;

  static const int UNKNOW_ERROR = -1999;

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
