#include "tap_protocol/utils.h"

namespace tap_protocol {
std::string Bytes2Str(const Bytes &msg) {
  std::ostringstream result;
  for (auto &&c : msg) {
    result << std::hex << std::setw(2) << std::setfill('0') << int(c);
  }
  return result.str();
}

Bytes XORBytes(const Bytes &a, const Bytes &b) {
  assert(a.size() == b.size());
  Bytes result(a.size());
  for (size_t i = 0; i < a.size(); ++i) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

XCVC CalcXCVC(const nlohmann::json::binary_t &card_nonce,
              const nlohmann::json::binary_t &his_pubkey, const Bytes &cvc) {
  if (cvc.size() < 6 || cvc.size() > 32) {
    throw TapProtoException(TapProtoException::INVALID_CVC_LENGTH,
                            "Invalid cvc length");
  }

  auto [my_privkey, my_pubkey] = CT_pick_keypair();

  Bytes session_key = CT_ecdh(his_pubkey, my_privkey);

  Bytes md(SHA256_LEN);
  if (int code = wally_sha256(card_nonce.data(), card_nonce.size(), md.data(),
                              md.size());
      code != WALLY_OK) {
    throw TapProtoException(TapProtoException::XCVC_FAIL,
                            "Calculate XCVC fail");
  }

  Bytes mask = XORBytes(session_key, md);
  mask.resize(cvc.size());

  Bytes xcvc = XORBytes(cvc, mask);
  return XCVC{.session_key = session_key, .epubkey = my_pubkey, .xcvc = xcvc};
}

}  // namespace tap_protocol
