#include <algorithm>
#include <cctype>
#include <climits>
#include <random>
#include <string>
#include <vector>
#include "tap_protocol/utils.h"
#include "tap_protocol/hash_utils.h"
#include "util/strencodings.h"

namespace tap_protocol {

std::string Bytes2Str(const Bytes &msg) {
  std::string rv(msg.size() * 2, '\0');
  static constexpr char hexmap[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  auto it = rv.begin();
  for (auto v : msg) {
    *it++ = hexmap[v >> 4];
    *it++ = hexmap[v & 15];
  }
  assert(it == rv.end());
  return rv;
}

Bytes Hex2Bytes(const std::string &hex) {
  return ParseHex(hex);
}

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

  auto [my_privkey, my_pubkey] = CT_pick_keypair();

  Bytes session_key = CT_ecdh(his_pubkey, my_privkey);

  Bytes to_be_hashed(card_nonce);
  to_be_hashed.insert(std::end(to_be_hashed), std::begin(cmd), std::end(cmd));

  const Bytes md = SHA256(to_be_hashed);
  Bytes mask = XORBytes(session_key, md);
  mask.resize(cvc.size());

  const Bytes xcvc = XORBytes(cvc, mask);
  return XCVC{.session_key = session_key, .epubkey = my_pubkey, .xcvc = xcvc};
}

std::string Path2Str(const std::vector<uint32_t> &path) {
  std::string result = path.empty() ? "" : "m/";
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

std::vector<uint32_t> Str2Path(std::string path) {
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

// TODO: secure rand?
using random_bytes_engine =
    std::independent_bits_engine<std::default_random_engine, CHAR_BIT,
                                 unsigned char>;
static random_bytes_engine rbe(std::random_device{}());

Bytes RandomBytes(size_t size) {
  Bytes result(size);
  std::generate(std::begin(result), std::end(result), rbe);
  return result;
}

Bytes PickNonce() {
  static constexpr int USER_NONCE_SIZE = 16;
  return RandomBytes(USER_NONCE_SIZE);
}

}  // namespace tap_protocol
