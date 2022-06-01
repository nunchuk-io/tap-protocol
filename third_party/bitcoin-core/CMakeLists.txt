cmake_minimum_required(VERSION 3.16)

project(bitcoin-core LANGUAGES CXX)
#set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(${PROJECT_NAME} STATIC
  src/amount.h
  src/streams.h
  src/psbt.h
  src/psbt.cpp
  src/uint256.h
  src/uint256.cpp
  src/attributes.h
  src/compat/endian.h
  src/compat/byteswap.h
  src/prevector.h
  src/span.h

  src/support/allocators/zeroafterfree.h
  src/support/cleanse.h
  src/support/cleanse.cpp

  src/util/strencodings.h
  src/util/strencodings.cpp
  src/util/string.h
  src/util/string.cpp

  src/tinyformat.h

  src/prevector.h
  src/serialize.h

  src/crypto/common.h
  src/crypto/sha256.h
  src/crypto/sha256.cpp
  src/crypto/sha512.h
  src/crypto/sha512.cpp
  src/crypto/ripemd160.h
  src/crypto/ripemd160.cpp

  src/script/keyorigin.h
  src/script/script.h
  src/script/script.cpp

  src/hash.h
  src/hash.cpp

  src/version.h
  src/crypto/hmac_sha512.h
  src/crypto/hmac_sha512.cpp
  src/crypto/hmac_sha256.h
  src/crypto/hmac_sha256.cpp

  src/primitives/transaction.h
  src/primitives/transaction.cpp
  src/pubkey.h
  src/pubkey.cpp
  src/script/sign.h
  src/script/sign.cpp
  src/script/standard.h
  src/script/standard.cpp

  #src/coins.h
  #src/coins.cpp
  #src/compressor.h
  #src/compressor.cpp
  #src/core_memusage.h
  #src/memusage.h
  #src/indirectmap.h
  #
  #src/util/hasher.h
  #src/util/hasher.cpp
  #src/crypto/siphash.h
  #src/crypto/siphash.cpp
  src/script/interpreter.h
  src/script/interpreter.cpp
  src/script/script_error.h
  src/script/script_error.cpp
  src/util/hash_type.h
  src/crypto/sha1.h
  src/crypto/sha1.cpp
  src/base58.h
  src/base58.cpp
  #src/key.h
  #src/key.cpp
  #src/support/allocators/secure.h
  #src/support/lockedpool.h
  #src/support/lockedpool.cpp
  #src/policy/policy.h
  #src/policy/policy.cpp
  #src/consensus/consensus.h
  #src/policy/feerate.h
  #src/policy/feerate.cpp
  #src/script/signingprovider.h
  #src/script/signingprovider.cpp
  #src/sync.h
  #src/sync.cpp
  #src/threadsafety.h
  #src/util/macros.h
  #src/util/vector.h
  #src/logging.h
  #src/logging.cpp
  #src/fs.h
  #src/fs.cpp
  #src/random.h
  #src/random.cpp
  #src/crypto/chacha20.h
  #src/crypto/chacha20.cpp
  #src/consensus/validation.h
  #src/util/system.h
  #src/util/system.cpp
  #src/compat.h
  #src/compat/assumptions.h
  #src/util/settings.h
  #src/util/settings.cpp
  #src/util/time.h
  #src/util/time.cpp
  #src/util/threadnames.h
  #src/util/threadnames.cpp
  #src/randomenv.h
  #src/randomenv.cpp
  #src/chainparamsbase.h
  #src/chainparamsbase.cpp
  #src/util/check.h
  #src/util/getuniquepath.h
  #src/util/getuniquepath.cpp
  #src/util/translation.h

)

target_include_directories(${PROJECT_NAME}
  PUBLIC src
)
