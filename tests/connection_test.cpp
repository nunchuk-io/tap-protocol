#include "doctest.h"
#include "emulator.h"
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/tap_protocol.h"

TEST_CASE("status emulator") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  tap_protocol::CKTapCard card(std::move(tp));

  // When call 'status'
  auto resp = card.Status();

  // Then return proto version = 1
  CHECK(resp.proto == 1);

  MESSAGE("status: ", json(resp).dump(2));
}

TEST_CASE("get nfc url") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  tap_protocol::CKTapCard card(std::move(tp));

  MESSAGE("Is tapsigner: ", card.IsTapsigner());
  if (card.IsTapsigner()) {
    auto resp = card.NFC();
    std::string tapsigner_url = "https://tapsigner.com";
    CHECK(resp.substr(0, tapsigner_url.size()) == tapsigner_url);
  } else {
    auto satscard = tap_protocol::ToSatscard(std::move(card));
    if (!satscard->IsUsedUp()) {
      auto resp = satscard->NFC();
      const std::string satscard_url = "https://getsatscard.com";
      CHECK(resp.substr(0, satscard_url.size()) == satscard_url);
    }
  }
}

TEST_CASE("type of card") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  tap_protocol::CKTapCard card(std::move(tp));
  if (card.IsTapsigner()) {
    auto tapsigner = tap_protocol::ToTapsigner(std::move(card));
    auto st = tapsigner->Status();
    CHECK(st.proto == 1);

  } else {
    auto satscard = tap_protocol::ToSatscard(std::move(card));
    auto st = satscard->Status();
    CHECK(st.proto == 1);
  }
}

TEST_CASE("invalid card") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  tap_protocol::CKTapCard card(std::move(tp));
  if (card.IsTapsigner()) {
    CHECK_THROWS_AS(
        { auto tapsigner = tap_protocol::ToSatscard(std::move(card)); },
        tap_protocol::TapProtoException);
  } else {
    CHECK_THROWS_AS(
        { auto satscard = tap_protocol::ToTapsigner(std::move(card)); },
        tap_protocol::TapProtoException);
  }
}
