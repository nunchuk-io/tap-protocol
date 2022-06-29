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
  static constexpr int UNLUCKY_NUMBER = 205;
  static constexpr int BAD_ARGUMENTS = 400;
  static constexpr int BAD_AUTH = 401;
  static constexpr int NEED_AUTH = 403;
  static constexpr int UNKNOW_COMMAND = 404;
  static constexpr int INVALID_COMMAND = 405;
  static constexpr int INVALID_STATE = 406;
  static constexpr int WEAK_NONCE = 417;
  static constexpr int BAD_CBOR = 422;
  static constexpr int BACKUP_FIRST = 425;
  static constexpr int RATE_LIMIT = 429;
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

static constexpr char OPENDIME[] = {'O', 'P', 'E', 'N', 'D', 'I', 'M', 'E'};

static constexpr unsigned char FACTORY_ROOT_KEY[] = {
    0x03, 0x02, 0x8a, 0x0e, 0x89, 0xe7, 0x0d, 0x0e, 0xc0, 0xd9, 0x32,
    0x05, 0x3a, 0x89, 0xab, 0x1d, 0xa7, 0xd9, 0x18, 0x2b, 0xdc, 0x6d,
    0x2f, 0x03, 0xe7, 0x06, 0xee, 0x99, 0x51, 0x7d, 0x05, 0xd9, 0xe1,
};

static constexpr int CARD_NONCE_SIZE = 16;
static constexpr int USER_NONCE_SIZE = 16;
static constexpr uint32_t HARDENED = 0x80000000;

}  // namespace tap_protocol

#endif  // TAPPROTOCOL_H
