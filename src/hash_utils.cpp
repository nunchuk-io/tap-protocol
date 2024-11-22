#include "tap_protocol/hash_utils.h"
#include <crypto/sha256.h>
#include <hash.h>

namespace tap_protocol {
using namespace bc_core;
static constexpr int SHA256_LEN = 32;
static constexpr int HASH160_LEN = 20;

Bytes SHA256(const Bytes &data) {
  Bytes result(SHA256_LEN);
  CSHA256().Write(data.data(), data.size()).Finalize(result.data());
  return result;
}

Bytes SHA256d(const Bytes &data) {
  Bytes result(SHA256_LEN);
  CHash256().Write(data).Finalize(result);
  return result;
}

Bytes Hash160(const Bytes &data) {
  Bytes result(HASH160_LEN);
  CHash160().Write(data).Finalize(result);
  return result;
}

}  // namespace tap_protocol
