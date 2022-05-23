#include <algorithm>
#include <cassert>
#include <climits>
#include <random>
#include <wally_crypto.h>
#include "tap_protocol/secp256k1_utils.h"

namespace tap_protocol {

using random_bytes_engine =
    std::independent_bits_engine<std::default_random_engine, CHAR_BIT,
                                 unsigned char>;
static std::mt19937 mt{std::random_device{}()};
static random_bytes_engine rbe(mt());

std::pair<Bytes, Bytes> CT_pick_keypair() {
  Bytes priv(32), pub(EC_PUBLIC_KEY_LEN);
  std::generate(std::begin(priv), std::end(priv), rbe);
  if (int code = wally_ec_public_key_from_private_key(
          priv.data(), priv.size(), pub.data(), EC_PUBLIC_KEY_LEN);
      code != WALLY_OK) {
    throw TapProtoException(TapProtoException::PICK_KEY_PAIR_FAIL,
                            "CT_pick_keypair fail");
  }
  return {priv, pub};
}

Bytes CT_ecdh(const Bytes& pubkey, const Bytes& privkey) {
  Bytes result(SHA256_LEN);
  if (int code = wally_ecdh(pubkey.data(), pubkey.size(), privkey.data(),
                            privkey.size(), result.data(), SHA256_LEN);
      code != WALLY_OK) {
    throw TapProtoException(TapProtoException::ECDH_FAIL, "CT_ecdh fail");
  }
  return result;
}

}  // namespace tap_protocol
