#include <algorithm>
#include <cctype>
#include <climits>
#include <random>
#include <string>
#include <vector>
#include "tap_protocol/utils.h"
#include "tap_protocol/hash_utils.h"
#include "util/strencodings.h"

#ifdef LIB_TAPPROTOCOL_USE_BITCOIN_RANDOM
void GetRandBytes(Span<unsigned char> bytes) noexcept;
void GetStrongRandBytes(Span<unsigned char> bytes) noexcept;
#endif

namespace tap_protocol {
using namespace bc_core;
std::string Bytes2Hex(const Bytes &msg) { return HexStr(msg); }

Bytes Hex2Bytes(const std::string &hex) { return ParseHex(hex); }

std::string ToUpper(std::string str) {
  std::transform(std::begin(str), std::end(str), std::begin(str),
                 [](char c) { return std::toupper(c); });
  return str;
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

  const auto [my_privkey, my_pubkey] = CT_pick_keypair();

  const Bytes session_key = CT_ecdh(his_pubkey, my_privkey);

  Bytes card_nonce_hashed(card_nonce);
  card_nonce_hashed.insert(std::end(card_nonce_hashed), std::begin(cmd),
                           std::end(cmd));

  const Bytes md = SHA256(card_nonce_hashed);
  Bytes mask = XORBytes(session_key, md);
  mask.resize(cvc.size());

  const Bytes xcvc = XORBytes(cvc, mask);
  return XCVC{session_key, my_pubkey, xcvc};
}

std::string Path2Str(const std::vector<uint32_t> &path) {
  if (path.empty()) {
    return "m";
  }
  std::string result{"m/"};
  for (auto it = std::begin(path); it != std::end(path); ++it) {
    uint32_t c = (*it & ~HARDENED);
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

inline std::vector<std::string> split(const std::string &s, char delim) {
  std::vector<std::string> result;
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    result.push_back(item);
  }
  return result;
}

std::vector<uint32_t> Str2Path(const std::string &path) {
  auto path_component_in_range = [](uint32_t path) {
    return 0 <= path && path < HARDENED;
  };

  std::vector<uint32_t> result;

  auto splits = split(path, '/');
  for (auto &str : splits) {
    if (str.empty() || str == "m") {
      continue;
    }
    uint32_t num{}, here{};
    if (char last = std::toupper(str.back());
        last == 'P' || last == 'H' || last == '\'') {
      if (str.size() < 2) {
        throw TapProtoException(TapProtoException::MALFORMED_BIP32_PATH,
                                "Malformed bip32 path component");
      }
      str.pop_back();
      try {
        num = std::stoul(str);
      } catch (std::exception &e) {
      }
      if (!path_component_in_range(num)) {
        throw TapProtoException(TapProtoException::MALFORMED_BIP32_PATH,
                                "Hardened path component out of range");
      }
      here = num | HARDENED;
    } else {
      try {
        here = std::stoul(str);
      } catch (std::exception &e) {
      }
      if (!path_component_in_range(here)) {
        throw TapProtoException(TapProtoException::MALFORMED_BIP32_PATH,
                                "Non-Hardened path component out of range");
      }
    }
    result.push_back(here);
  }
  return result;
}

Bytes PickNonce() { return RandomBytes(USER_NONCE_SIZE); }

#ifdef LIB_TAPPROTOCOL_USE_BITCOIN_RANDOM
Bytes RandomBytes(size_t size) {
  Bytes result(size);
  auto *pos = result.data();
  // bitcoin can only generates up to 32 bytes
  for (int left = size; left > 0;) {
    int len = left >= 32 ? 32 : left;
    // TODO (giahuy): consider using GetStrongRandBytes
    ::GetRandBytes(Span<unsigned char>(pos, len));
    pos += len;
    left -= len;
  }
  return result;
}
#else
using random_bytes_engine =
    std::independent_bits_engine<std::default_random_engine, CHAR_BIT,
                                 unsigned char>;
static random_bytes_engine rbe(std::random_device{}());

Bytes RandomBytes(size_t size) {
  Bytes result(size);
  std::generate(std::begin(result), std::end(result), std::ref(rbe));
  return result;
}
#endif

Bytes RandomChainCode() { return SHA256d(RandomBytes(128)); }

void VerifyCerts(const nlohmann::json::binary_t &card_nonce,
                 const nlohmann::json::binary_t &card_pubkey,
                 const nlohmann::json::binary_t &my_nonce,
                 const std::vector<nlohmann::json::binary_t> &cert_chain,
                 const nlohmann::json::binary_t &signature,
                 const nlohmann::json::binary_t &slot_pubkey) {
  assert(cert_chain.size() >= 2);

  Bytes msg;
  msg.reserve(std::size(OPENDIME) + card_nonce.size() + my_nonce.size() +
              slot_pubkey.size());
  msg.insert(std::end(msg), std::begin(OPENDIME), std::end(OPENDIME));
  msg.insert(std::end(msg), std::begin(card_nonce), std::end(card_nonce));
  msg.insert(std::end(msg), std::begin(my_nonce), std::end(my_nonce));

  if (msg.size() != std::size(OPENDIME) + CARD_NONCE_SIZE + USER_NONCE_SIZE) {
    throw TapProtoException(TapProtoException::INVALID_CARD,
                            "Invalid msg size " + std::to_string(msg.size()));
  }

  if (!slot_pubkey.empty()) {
    assert(slot_pubkey.size() == 33);
    msg.insert(std::end(msg), std::begin(slot_pubkey), std::end(slot_pubkey));
  }

  const Bytes msg_sha256 = SHA256(msg);

  if (!CT_sig_verify(card_pubkey, msg_sha256, signature)) {
    throw TapProtoException(TapProtoException::SIG_VERIFY_ERROR,
                            "Bad sig in verify_certs");
  }

  auto pubkey = card_pubkey;
  for (const auto &sig : cert_chain) {
    pubkey = CT_sig_to_pubkey(SHA256(pubkey), sig);
  }

  if (std::equal(std::begin(pubkey), std::end(pubkey),
                 std::begin(FACTORY_ROOT_KEY), std::end(FACTORY_ROOT_KEY))) {
    //"Root Factory Certificate";
    return;
  }

  throw TapProtoException(
      TapProtoException::INVALID_CARD,
      "Root cert is not from Coinkite. Card is counterfeit.");
}

}  // namespace tap_protocol
