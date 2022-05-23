#ifndef UTILS_H
#define UTILS_H

#include <wally_crypto.h>
#include "tap_protocol/tap_protocol.h"
#include "tap_protocol/secp256k1_utils.h"
#include "nlohmann/json.hpp"

namespace tap_protocol {

std::string Bytes2Str(const Bytes &msg);

Bytes XORBytes(const Bytes &a, const Bytes &b);

struct XCVC {
  Bytes session_key;
  Bytes epubkey;
  Bytes xcvc;

  NLOHMANN_DEFINE_TYPE_INTRUSIVE(XCVC, epubkey, xcvc);
};

XCVC CalcXCVC(const nlohmann::json::binary_t &card_nonce,
              const nlohmann::json::binary_t &his_pubkey, const Bytes &cvc);

}  // namespace tap_protocol

#endif  // UTILS_H
