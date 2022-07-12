#ifndef SECP256K1_UTILS_H
#define SECP256K1_UTILS_H

#include "tap_protocol/tap_protocol.h"

namespace tap_protocol {
std::pair<Bytes, Bytes> CT_pick_keypair();

Bytes CT_ecdh(const Bytes& pubkey, const Bytes& privkey);

Bytes CT_sig_to_pubkey(const Bytes& pubkey, const Bytes& sig);

bool CT_sig_verify(const Bytes& pubkey, const Bytes& msg, const Bytes& sig);

Bytes CT_priv_to_pubkey(const Bytes& privkey);

Bytes CT_bip32_derive(const Bytes& chain_code, const Bytes& master_pub,
                      const std::vector<uint32_t>& path);

}  // namespace tap_protocol

#endif  // SECP256K1_UTILS_H
