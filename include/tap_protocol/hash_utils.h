#ifndef HASH_UTILS_H
#define HASH_UTILS_H

#include "tap_protocol/tap_protocol.h"

namespace tap_protocol {

Bytes SHA256(const Bytes &data);
Bytes SHA256d(const Bytes &data);
Bytes Hash160(const Bytes &data);

}  // namespace tap_protocol

#endif
