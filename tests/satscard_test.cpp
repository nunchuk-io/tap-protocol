#include "doctest.h"
#include "emulator.h"
#include "stringification.h"
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/hash_utils.h"
#include "tap_protocol/utils.h"

TEST_SUITE_BEGIN("satcard" * doctest::skip([]() -> bool {
                   std::unique_ptr<tap_protocol::Transport> tp =
                       std::make_unique<CardEmulator>();
                   tap_protocol::CKTapCard card(std::move(tp));
                   return card.IsTapsigner();
                   ;
                 }()));

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

TEST_CASE("get address") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Satscard satcard(std::move(tp));

  std::string address = satcard.Address(true, 0);
  CHECK(!address.empty());
  MESSAGE("slot: ", 0, "address: ", address);

  for (int slot = 1; slot < 10; ++slot) {
    std::string address = satcard.Address(true, slot);
    MESSAGE("slot: ", slot, "address: ", address);
  }
}

TEST_SUITE_END();
