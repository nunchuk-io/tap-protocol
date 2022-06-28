#include "doctest.h"
#include "emulator.h"
#include "stringification.h"
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/hash_utils.h"
#include "tap_protocol/utils.h"

TEST_CASE("satscard status") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Satscard satcard(std::move(tp));

  auto st = satcard.Status();
  CHECK(st.slots.size() == 2);
  CHECK(st.slots.back() == 10);

  MESSAGE("satscard status: ", json(st).dump(2));
}

TEST_CASE("satscard unseal slot") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Satscard satcard(std::move(tp));

  auto us = satcard.Unseal("123456");

  MESSAGE("satscard unseal: ", json(us).dump(2));
}

TEST_CASE("new slot") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Satscard satcard(std::move(tp));

  auto newResponse = satcard.New(
      tap_protocol::SHA256(tap_protocol::RandomBytes(128)), "123456");
  CHECK(newResponse.slot != 0);
  MESSAGE("new:", json(newResponse).dump(2));
}
