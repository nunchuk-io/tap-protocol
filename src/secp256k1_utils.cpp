#include <algorithm>
#include <cassert>
#include <climits>
#include <memory>
#include <random>
#include <secp256k1.h>
#include <iostream>
#include <wally_crypto.h>
#include "tap_protocol/secp256k1_utils.h"

namespace tap_protocol {

using random_bytes_engine =
    std::independent_bits_engine<std::default_random_engine, CHAR_BIT,
                                 unsigned char>;
static std::mt19937 mt{std::random_device{}()};
static random_bytes_engine rbe(mt());

Bytes RandomBytes(size_t size) {
  Bytes result(size);
  std::generate(std::begin(result), std::end(result), rbe);
  return result;
}

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
  // secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
  // |
  //                                                   SECP256K1_CONTEXT_SIGN);
  //
  // auto deleter = [](secp256k1_context* ptr) { secp256k1_context_destroy(ptr);
  // }; std::unique_ptr<secp256k1_context, decltype(deleter)> auto_delete(ctx,
  //                                                                   deleter);
  //
  // secp256k1_ecdsa_signature secp_sig;
  // if (int code =
  //         secp256k1_ecdsa_signature_parse_compact(ctx, &secp_sig,
  //         sig.data());
  //     code != 1) {
  //   return false;
  // }
  //
  // secp256k1_pubkey secp_pub;
  // if (int code = secp256k1_ec_pubkey_parse(ctx, &secp_pub, pubkey.data(),
  //                                          pubkey.size());
  //     code != 1) {
  //   return false;
  // }
  //
  // if (int code = secp256k1_ecdsa_verify(ctx, &secp_sig, msg.data(),
  // &secp_pub);
  //     code != 1) {
  //   return false;
  // }
  // return true;

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
