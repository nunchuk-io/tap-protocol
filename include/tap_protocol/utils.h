#ifndef UTILS_H
#define UTILS_H

#include "nlohmann/json.hpp"

namespace tap_protocol {

// def calc_xcvc(cmd, card_nonce, his_pubkey, cvc):
//     # Calcuate session key and xcvc value need for auth'ed commands
//     # - also picks an arbitrary keypair for my side of the ECDH?
//     # - requires pubkey from card and proposed CVC value
//     assert 6 <= len(cvc) <= 32
//
//     cvc = force_bytes(cvc)
//
//     # fresh new ephemeral key for our side of connection
//     my_privkey, my_pubkey = CT_pick_keypair()
//
//     # standard ECDH
//     # - result is sha256s(compressed shared point (33 bytes))
//     session_key = CT_ecdh(his_pubkey, my_privkey)
//
//     md = sha256s(card_nonce + cmd.encode('ascii'))
//     mask = xor_bytes(session_key, md)[0:len(cvc)]
//     xcvc = xor_bytes(cvc, mask)
//
//     return session_key, dict(epubkey=my_pubkey, xcvc=xcvc)
//

struct XCVC {};

static XCVC CalcXCVC(const nlohmann::json::binary_t &card_nonce,
                     const nlohmann::json::binary_t &his_pubkey,
                     const std::string &cvc) {}

}  // namespace tap_protocol

#endif  // UTILS_H
