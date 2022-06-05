#include "tap_protocol/hash_utils.h"
#include <crypto/sha256.h>
#include <hash.h>

namespace tap_protocol {

static constexpr int SHA256_LEN_ = 32;
static constexpr int HASH160_LEN_ = 20;

Bytes SHA256(const Bytes &data) {
  Bytes result(SHA256_LEN_);
  CSHA256 hasher;
  hasher.Write(data.data(), data.size());
  hasher.Finalize(result.data());
  return result;
}

Bytes SHA256d(const Bytes &data) {
  Bytes result(SHA256_LEN_);
  CHash256 hasher;
  hasher.Write(data);
  hasher.Finalize(result);
  return result;
}

Bytes Hash160(const Bytes &data) {
  Bytes result(HASH160_LEN_);
  CHash160 hasher;
  hasher.Write(data);
  hasher.Finalize(result);
  return result;
}

}  // namespace tap_protocol
