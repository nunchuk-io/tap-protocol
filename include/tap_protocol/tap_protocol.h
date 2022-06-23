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
  static constexpr int DEFAULT_ERROR = 500;
  static constexpr int MESSAGE_TOO_LONG = 601;
  static constexpr int MISSING_KEY = 602;
  static constexpr int ISO_SELECT_FAIL = 603;
  static constexpr int SW_FAIL = 604;
  static constexpr int INVALID_CVC_LENGTH = 605;
  static constexpr int PICK_KEY_PAIR_FAIL = 606;
  static constexpr int ECDH_FAIL = 607;
  static constexpr int XCVC_FAIL = 608;
  static constexpr int UNKNOW_PROTO_VERSION = 609;
  static constexpr int INVALID_PUBKEY_LENGTH = 610;
  static constexpr int NO_PRIVATE_KEY_PICKED = 611;
  static constexpr int MALFORMED_BIP32_PATH = 612;
  static constexpr int INVALID_HASH_LENGTH = 613;
  static constexpr int SIG_VERIFY_ERROR = 614;
  static constexpr int INVALID_DIGEST_LENGTH = 615;
  static constexpr int INVALID_PATH_LENGTH = 616;
  static constexpr int SERIALIZE_ERROR = 617;
  static constexpr int EXCEEDED_RETRY = 618;
  static constexpr int INVALID_CARD = 619;
  static constexpr int SIGN_ERROR = 620;
  static constexpr int SIG_TO_PUBKEY_FAIL = 621;
  static constexpr int PSBT_PARSE_ERROR = 622;
  static constexpr int PSBT_INVALID = 623;
  static constexpr int INVALID_ADDRESS_TYPE = 624;
  static constexpr int INVALID_BACKUP_KEY = 625;
  static constexpr int INVALID_PUBKEY = 626;

 public:
  explicit TapProtoException(int code, std::string message)
      : code_(code), message_(std::move(message)) {}
  const char *what() const noexcept override { return message_.c_str(); }
  int code() const noexcept { return code_; }
  ~TapProtoException() = default;

 private:
  int code_;
  std::string message_;
};

}  // namespace tap_protocol

#endif  // TAPPROTOCOL_H
