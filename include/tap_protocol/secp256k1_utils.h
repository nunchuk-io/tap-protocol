#ifndef SECP256K1_UTILS_H
#define SECP256K1_UTILS_H

#include "tap_protocol/tap_protocol.h"

namespace tap_protocol {
std::pair<Bytes, Bytes> CT_pick_keypair();

Bytes CT_ecdh(const Bytes& pubkey, const Bytes& privkey);
}  // namespace tap_protocol

#endif  // SECP256K1_UTILS_H
