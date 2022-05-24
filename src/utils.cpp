#include "tap_protocol/utils.h"
#include <climits>
#include <cppcodec/base32_rfc4648.hpp>
#include <random>

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

Bytes operator^(const Bytes &a, const Bytes &b) { return XORBytes(a, b); }

XCVC CalcXCVC(const Bytes &cmd, const nlohmann::json::binary_t &card_nonce,
              const nlohmann::json::binary_t &his_pubkey, const Bytes &cvc) {
  if (cvc.size() < 6 || cvc.size() > 32) {
    throw TapProtoException(TapProtoException::INVALID_CVC_LENGTH,
                            "Invalid cvc length");
  }

  auto [my_privkey, my_pubkey] = CT_pick_keypair();

  Bytes session_key = CT_ecdh(his_pubkey, my_privkey);

  Bytes md(SHA256_LEN);

  Bytes to_be_hashed(card_nonce);
  to_be_hashed.insert(std::end(to_be_hashed), std::begin(cmd), std::end(cmd));

  if (int code = wally_sha256(to_be_hashed.data(), to_be_hashed.size(),
                              md.data(), md.size());
      code != WALLY_OK) {
    throw TapProtoException(TapProtoException::XCVC_FAIL,
                            "Calculate XCVC fail");
  }

  Bytes mask = XORBytes(session_key, md);
  mask.resize(cvc.size());

  Bytes xcvc = XORBytes(cvc, mask);
  return XCVC{.session_key = session_key, .epubkey = my_pubkey, .xcvc = xcvc};
}

Bytes CardPubkeyToIdent(const Bytes &card_pubkey) {
  if (card_pubkey.size() != 33) {
    throw TapProtoException(TapProtoException::INVALID_PUBKEY_COMPRESS_LENGTH,
                            "Expecting compressed pubkey");
  }

  Bytes pubkey_sha(SHA256_LEN);
  if (int code = wally_sha256(card_pubkey.data(), card_pubkey.size(),
                              pubkey_sha.data(), SHA256_LEN);
      code != WALLY_OK) {
    throw TapProtoException(TapProtoException::UNKNOW_ERROR,
                            "SHA error wally_code = " + std::to_string(code));
  }

  pubkey_sha.erase(std::begin(pubkey_sha), std::begin(pubkey_sha) + 8);

  using base32 = cppcodec::base32_rfc4648;
  auto md = base32::encode(pubkey_sha);

  static constexpr int IDENT_SIZE = 23;

  Bytes ident(IDENT_SIZE);
  for (int i = 0, j = 0; i < 20; ++i) {
    if ((j + 1) % 6 == 0) {
      ident[j++] = '-';
    }
    ident[j++] = md[i];
  }
  return ident;
}

std::string Path2Str(const std::vector<int64_t> &path) {
  static constexpr int64_t HARDENED = 0x80000000;
  std::string result = "m";
  for (auto it = std::begin(path); it != std::end(path); ++it) {
    int32_t c = (*it & ~HARDENED);
    result += std::to_string(c);
    if (*it & HARDENED) {
      result += 'h';
    }
    if (std::next(it) != std::end(path)) {
      result += '/';
    }
  }
  return result;
}

Bytes PickNonce() {
  using random_bytes_engine =
      std::independent_bits_engine<std::default_random_engine, CHAR_BIT,
                                   unsigned char>;
  static random_bytes_engine rbe(std::random_device{}());
  static constexpr int USER_NONCE_SIZE = 16;
  Bytes nonce(USER_NONCE_SIZE);
  std::generate(std::begin(nonce), std::end(nonce), rbe);
  return nonce;
}

}  // namespace tap_protocol
