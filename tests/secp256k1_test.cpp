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

  MESSAGE("done CT_pick_keypair");
}

TEST_CASE("CT_ecdh") {
  auto [priv, pub] = tap_protocol::CT_pick_keypair();

  auto privStr = tap_protocol::Bytes2Hex(priv);
  auto pubStr = tap_protocol::Bytes2Hex(pub);

  auto sessionKey = tap_protocol::CT_ecdh(pub, priv);
  CHECK(!sessionKey.empty());

  MESSAGE("done CT_ecdh");
}
