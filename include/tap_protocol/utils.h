#ifndef UTILS_H
#define UTILS_H

#include "tap_protocol/tap_protocol.h"
#include "tap_protocol/secp256k1_utils.h"
#include "nlohmann/json.hpp"

#ifdef LIB_TAPPROTOCOL_USE_BITCOIN_RANDOM
void GetStrongRandBytes(unsigned char *buf, int num) noexcept;
void GetRandBytes(unsigned char *buf, int num) noexcept;
#endif

namespace tap_protocol {

std::string Bytes2Hex(const Bytes &msg);
Bytes Hex2Bytes(const std::string &hex);
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

std::string Path2Str(const std::vector<uint32_t> &path);
std::vector<uint32_t> Str2Path(const std::string &path);

Bytes RandomBytes(size_t size);
Bytes RandomChainCode();
Bytes PickNonce();

void VerifyCerts(const nlohmann::json::binary_t &card_nonce,
                 const nlohmann::json::binary_t &card_pubkey,
                 const nlohmann::json::binary_t &my_nonce,
                 const std::vector<nlohmann::json::binary_t> &cert_chain,
                 const nlohmann::json::binary_t &signature,
                 const nlohmann::json::binary_t &slot_pubkey);

}  // namespace tap_protocol

#endif  // UTILS_H
