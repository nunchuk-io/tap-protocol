#include <doctest.h>
#include <iostream>
#include "tap_protocol/utils.h"
#include "tap_protocol/secp256k1_utils.h"

TEST_CASE("CT_pick_keypair") {
  auto [priv, pub] = tap_protocol::CT_pick_keypair();

  auto privStr = tap_protocol::Bytes2Hex(priv);
  auto pubStr = tap_protocol::Bytes2Hex(pub);

  CAPTURE(privStr);
  CAPTURE(pubStr);

  CHECK(privStr.size() != 0);
  CHECK(pubStr.size() != 0);
}

TEST_CASE("CT_ecdh") {
  auto [priv, pub] = tap_protocol::CT_pick_keypair();

  auto privStr = tap_protocol::Bytes2Hex(priv);
  auto pubStr = tap_protocol::Bytes2Hex(pub);

  auto sessionKey = tap_protocol::CT_ecdh(pub, priv);
  CHECK(!sessionKey.empty());
}

TEST_CASE("random bytes") {
  auto r1 = tap_protocol::RandomBytes(32);
  auto r2 = tap_protocol::RandomBytes(128);
  auto r3 = tap_protocol::RandomBytes(123);

  CHECK(r1.size() == 32);
  CHECK(r2.size() == 128);
  CHECK(r3.size() == 123);
  CHECK(!(r1 == r2));
  CHECK(!(r2 == r3));
}
