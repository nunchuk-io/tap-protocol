#include <algorithm>
#include <cassert>
#include <climits>
#include <memory>
#include <random>
#include <iostream>
#include <wally_crypto.h>
#include "tap_protocol/secp256k1_utils.h"
#include "tap_protocol/utils.h"

namespace tap_protocol {

std::pair<Bytes, Bytes> CT_pick_keypair() {
  Bytes priv = RandomBytes(32), pub(EC_PUBLIC_KEY_LEN);
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

Bytes CT_sig_to_pubkey(const Bytes& pubkey, const Bytes& sig) {
  Bytes result(EC_PUBLIC_KEY_LEN);
  assert(sig.size() == EC_SIGNATURE_RECOVERABLE_LEN);

  if (int code =
          wally_ec_sig_to_public_key(pubkey.data(), pubkey.size(), sig.data(),
                                     sig.size(), result.data(), result.size());
      code != WALLY_OK) {
    throw TapProtoException(TapProtoException::UNKNOW_ERROR,
                            "CT_sig_to_pubkey fail");
  };
  return result;
}

bool CT_sig_verify(const Bytes& pubkey, const Bytes& msg, const Bytes& sig) {
  assert(sig.size() == EC_SIGNATURE_LEN);
  if (int code = wally_ec_sig_verify(pubkey.data(), pubkey.size(), msg.data(),
                                     msg.size(), EC_FLAG_ECDSA, sig.data(),
                                     sig.size());
      code != WALLY_OK) {
    return false;
  }
  return true;
}

}  // namespace tap_protocol
