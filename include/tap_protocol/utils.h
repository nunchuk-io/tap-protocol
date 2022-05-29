#ifndef UTILS_H
#define UTILS_H

#include "tap_protocol/tap_protocol.h"
#include "tap_protocol/secp256k1_utils.h"
#include "nlohmann/json.hpp"

namespace tap_protocol {

static constexpr int64_t HARDENED = 0x80000000;

std::string Bytes2Str(const Bytes &msg);
std::string ToUpper(std::string str);

Bytes XORBytes(const Bytes &a, const Bytes &b);
Bytes operator^(const Bytes &a, const Bytes &b);

struct XCVC {
  nlohmann::json::binary_t session_key;
  nlohmann::json::binary_t epubkey;
  nlohmann::json::binary_t xcvc;

  NLOHMANN_DEFINE_TYPE_INTRUSIVE(XCVC, epubkey, xcvc);
};

XCVC CalcXCVC(const Bytes &cmd, const nlohmann::json::binary_t &card_nonce,
              const nlohmann::json::binary_t &his_pubkey, const Bytes &cvc);

Bytes CardPubkeyToIdent(const Bytes &card_pubkey);
std::string Path2Str(const std::vector<int64_t> &path);
std::vector<int64_t> Str2Path(std::string path);
Bytes PickNonce();

}  // namespace tap_protocol

#endif  // UTILS_H
