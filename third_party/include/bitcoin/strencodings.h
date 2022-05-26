// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Utilities for converting data from/to strings.
 */
#ifndef BITCOIN_UTIL_STRENCODINGS_H
#define BITCOIN_UTIL_STRENCODINGS_H

#include <vector>
#include <string>

/** Convert from one power-of-2 number base to another. */
template <int frombits, int tobits, bool pad, typename O, typename I>
bool ConvertBits(const O& outfn, I it, I end) {
  size_t acc = 0;
  size_t bits = 0;
  constexpr size_t maxv = (1 << tobits) - 1;
  constexpr size_t max_acc = (1 << (frombits + tobits - 1)) - 1;
  while (it != end) {
    acc = ((acc << frombits) | *it) & max_acc;
    bits += frombits;
    while (bits >= tobits) {
      bits -= tobits;
      outfn((acc >> bits) & maxv);
    }
    ++it;
  }
  if (pad) {
    if (bits) outfn((acc << (tobits - bits)) & maxv);
  } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
    return false;
  }
  return true;
}

inline std::string EncodeBase32(const std::vector<unsigned char>& input,
                                bool pad = true) {
  static const char* pbase32 = "abcdefghijklmnopqrstuvwxyz234567";

  std::string str;
  str.reserve(((input.size() + 4) / 5) * 8);
  ConvertBits<8, 5, true>([&](int v) { str += pbase32[v]; }, input.begin(),
                          input.end());
  if (pad) {
    while (str.size() % 8) {
      str += '=';
    }
  }
  return str;
}

#endif  // BITCOIN_UTIL_STRENCODINGS_H
