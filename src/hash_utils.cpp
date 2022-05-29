#include "tap_protocol/hash_utils.h"
#include <wally_core.h>
#include <wally_crypto.h>

namespace tap_protocol {

Bytes SHA256(const Bytes &data) {
  Bytes data_hash(SHA256_LEN);
  if (int code =
          wally_sha256(data.data(), data.size(), data_hash.data(), SHA256_LEN);
      code != WALLY_OK) {
    throw TapProtoException(TapProtoException::INVALID_HASH_LENGTH,
                            "Invalid sha256 length");
  }
  return data_hash;
}

Bytes SHA256d(const Bytes &data) {
  Bytes data_double_hash(SHA256_LEN);
  if (int code = wally_sha256d(data.data(), data.size(),
                               data_double_hash.data(), SHA256_LEN);
      code != WALLY_OK) {
    throw TapProtoException(TapProtoException::INVALID_HASH_LENGTH,
                            "Invalid sha256 length");
  }
  return data_double_hash;
}

Bytes Hash160(const Bytes &data) {
  Bytes data_hash(HASH160_LEN);
  if (int code = wally_hash160(data.data(), data.size(), data_hash.data(),
                               HASH160_LEN);
      code != WALLY_OK) {
    throw TapProtoException(TapProtoException::INVALID_HASH_LENGTH,
                            "Invalid hash160 length");
  }
  return data_hash;
}

}  // namespace tap_protocol
