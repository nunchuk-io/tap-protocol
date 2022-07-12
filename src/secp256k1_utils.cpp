#include <algorithm>
#include <cassert>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_recovery.h>
#include "pubkey.h"
#include "tap_protocol/secp256k1_utils.h"
#include "tap_protocol/utils.h"

namespace tap_protocol {

static constexpr int EC_PRIVATE_KEY_LEN = 32;
static constexpr int EC_PUBLIC_KEY_LEN = 33;
static constexpr int SHA256_LEN = 32;
static constexpr int EC_SIGNATURE_RECOVERABLE_LEN = 65;
static constexpr int EC_SIGNATURE_LEN = 64;

static secp256k1_context* get_secp256k1_context() {
  struct ContextHolder {
    secp256k1_context* ctx;
    ContextHolder()
        : ctx(secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                       SECP256K1_CONTEXT_VERIFY)) {
#ifdef LIB_TAPPROTOCOL_USE_BITCOIN_RANDOM
      Bytes random_bytes(32);
      GetStrongRandBytes(random_bytes.data(), random_bytes.size());
      assert(secp256k1_context_randomize(ctx, random_bytes.data()));
#else
      Bytes random_bytes = RandomBytes(32);
      assert(secp256k1_context_randomize(ctx, random_bytes.data()));
#endif
    }
    ContextHolder(const ContextHolder&) = delete;
    ContextHolder& operator=(const ContextHolder&) = delete;
    ~ContextHolder() { secp256k1_context_destroy(ctx); }
  };
  static ContextHolder context_holder;
  return context_holder.ctx;
}

std::pair<Bytes, Bytes> CT_pick_keypair() {
  Bytes priv = RandomBytes(EC_PRIVATE_KEY_LEN), pub(EC_PUBLIC_KEY_LEN);
  secp256k1_pubkey ecpub;

  if (!secp256k1_ec_pubkey_create(get_secp256k1_context(), &ecpub,
                                  priv.data())) {
    throw TapProtoException(TapProtoException::PICK_KEY_PAIR_FAIL,
                            "CT_pick_keypair fail pubkey create");
  }

  size_t output_len = pub.size();
  if (!secp256k1_ec_pubkey_serialize(get_secp256k1_context(), pub.data(),
                                     &output_len, &ecpub,
                                     SECP256K1_EC_COMPRESSED)) {
    throw TapProtoException(TapProtoException::PICK_KEY_PAIR_FAIL,
                            "CT_pick_keypair fail pubkey serialize");
  }

  return {priv, pub};
}

Bytes CT_ecdh(const Bytes& pubkey, const Bytes& privkey) {
  Bytes result(SHA256_LEN);
  secp256k1_pubkey ecpub;

  if (!secp256k1_ec_pubkey_parse(get_secp256k1_context(), &ecpub, pubkey.data(),
                                 pubkey.size())) {
    throw TapProtoException(TapProtoException::ECDH_FAIL,
                            "CT_ecdh fail pubkey parse");
  }

  if (!secp256k1_ecdh(get_secp256k1_context(), result.data(), &ecpub,
                      privkey.data(), nullptr, nullptr)) {
    throw TapProtoException(TapProtoException::ECDH_FAIL, "CT_ecdh fail ecdh");
  }

  return result;
}

Bytes CT_sig_to_pubkey(const Bytes& pubkey, const Bytes& sig) {
  assert(sig.size() == EC_SIGNATURE_RECOVERABLE_LEN);
  Bytes result(EC_PUBLIC_KEY_LEN);

  const auto rec_id_from_header = [](int header) -> int {
    int header_num = header & 0xff;
    if (header_num >= 39) {
      header_num -= 12;
    } else if (header_num >= 35) {
      header_num -= 8;
    } else if (header_num >= 31) {
      header_num -= 4;
    }
    int rec_id = header_num - 27;
    return rec_id;
  };

  int rec_id = rec_id_from_header(sig[0]);
  secp256k1_ecdsa_recoverable_signature ecsig;

  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
          get_secp256k1_context(), &ecsig, sig.data() + 1, rec_id)) {
    throw TapProtoException(
        TapProtoException::SIG_TO_PUBKEY_FAIL,
        "CT_sig_to_pubkey fail ecdsa recoverable signature");
  }

  secp256k1_pubkey ecpub;
  if (!secp256k1_ecdsa_recover(get_secp256k1_context(), &ecpub, &ecsig,
                               pubkey.data())) {
    throw TapProtoException(TapProtoException::SIG_TO_PUBKEY_FAIL,
                            "CT_sig_to_pubkey fail ecdsa recover");
  }

  size_t output_len = result.size();
  if (!secp256k1_ec_pubkey_serialize(get_secp256k1_context(), result.data(),
                                     &output_len, &ecpub,
                                     SECP256K1_EC_COMPRESSED)) {
    throw TapProtoException(TapProtoException::SIG_TO_PUBKEY_FAIL,
                            "CT_sig_to_pubkey ec pubkey serialize");
  }

  return result;
}

bool CT_sig_verify(const Bytes& pubkey, const Bytes& msg, const Bytes& sig) {
  assert(sig.size() == EC_SIGNATURE_LEN);

  secp256k1_ecdsa_signature ecsig;
  if (!secp256k1_ecdsa_signature_parse_compact(get_secp256k1_context(), &ecsig,
                                               sig.data())) {
    return false;
  }
  secp256k1_pubkey ecpub;
  if (!secp256k1_ec_pubkey_parse(get_secp256k1_context(), &ecpub, pubkey.data(),
                                 pubkey.size())) {
    return false;
  }

  if (!secp256k1_ecdsa_verify(get_secp256k1_context(), &ecsig, msg.data(),
                              &ecpub)) {
    return false;
  }
  return true;
}

Bytes CT_priv_to_pubkey(const Bytes& privkey) {
  secp256k1_pubkey ecpub;
  if (!secp256k1_ec_pubkey_create(get_secp256k1_context(), &ecpub,
                                  privkey.data())) {
    throw TapProtoException(TapProtoException::DEFAULT_ERROR,
                            "CT_priv_to_pubkey fail pubkey create");
  }
  Bytes output(EC_PUBLIC_KEY_LEN);
  size_t output_len = output.size();
  if (!secp256k1_ec_pubkey_serialize(get_secp256k1_context(), output.data(),
                                     &output_len, &ecpub,
                                     SECP256K1_EC_COMPRESSED)) {
    throw TapProtoException(TapProtoException::DEFAULT_ERROR,
                            "CT_priv_to_pubkey fail pubkey serialize");
  }
  return output;
}

Bytes CT_bip32_derive(const Bytes& chain_code, const Bytes& master_pub,
                      const std::vector<uint32_t>& path) {
  if (master_pub.size() == 32) {
    throw TapProtoException(TapProtoException::INVALID_PUBKEY,
                            "Expect pubkey but got privkey");
  }
  CExtPubKey ckey;
  std::copy(std::begin(chain_code), std::end(chain_code),
            std::begin(ckey.chaincode));
  ckey.pubkey.Set(std::begin(master_pub), std::end(master_pub));
  for (auto p : path) {
    ckey.Derive(ckey, p);
  }
  return {std::begin(ckey.pubkey), std::end(ckey.pubkey)};
}

}  // namespace tap_protocol
