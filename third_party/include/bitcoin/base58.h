// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Why base-58 instead of standard base-64 encoding?
 * - Don't want 0OIl characters that look the same in some fonts and
 *      could be used to create visually identical looking data.
 * - A string with non-alphanumeric characters is not as easily accepted as
 * input.
 * - E-mail usually won't line-break if there's no punctuation to break at.
 * - Double-clicking selects the whole string as one word if it's all
 * alphanumeric.
 */
#ifndef BITCOIN_BASE58_H
#define BITCOIN_BASE58_H

#include <string>
#include <assert.h>
#include <vector>
#include <string_view>

/** All alphanumeric characters except for "0", "I", "O", and "l" */
static const char* pszBase58 =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Encode a byte span as a base58-encoded string
 */
inline std::string EncodeBase58(std::basic_string_view<unsigned char> input) {
  // Skip & count leading zeroes.
  int zeroes = 0;
  int length = 0;
  while (input.size() > 0 && input[0] == 0) {
    input = input.substr(1);
    zeroes++;
  }
  // Allocate enough space in big-endian base58 representation.
  int size = input.size() * 138 / 100 + 1;  // log(256) / log(58), rounded up.
  std::vector<unsigned char> b58(size);
  // Process the bytes.
  while (input.size() > 0) {
    int carry = input[0];
    int i = 0;
    // Apply "b58 = b58 * 256 + ch".
    for (auto it = b58.rbegin();
         (carry != 0 || i < length) && (it != b58.rend()); it++, i++) {
      carry += 256 * (*it);
      *it = carry % 58;
      carry /= 58;
    }

    assert(carry == 0);
    length = i;
    input = input.substr(1);
  }
  // Skip leading zeroes in base58 result.
  std::vector<unsigned char>::iterator it = b58.begin() + (size - length);
  while (it != b58.end() && *it == 0) it++;
  // Translate the result into a string.
  std::string str;
  str.reserve(zeroes + (b58.end() - it));
  str.assign(zeroes, '1');
  while (it != b58.end()) str += pszBase58[*(it++)];
  return str;
}

#endif  // BITCOIN_BASE58_H
