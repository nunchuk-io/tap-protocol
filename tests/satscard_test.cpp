#include "doctest.h"
#include "emulator.h"
#include "stringification.h"
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/hash_utils.h"
#include "tap_protocol/utils.h"

#define CHECK_IF(CONDITION, EXPR) \
  if ((CONDITION)) {              \
    CHECK((EXPR));                \
  }

TEST_SUITE_BEGIN("satcard" * doctest::skip([]() -> bool {
                   std::unique_ptr<tap_protocol::Transport> tp =
                       std::make_unique<CardEmulator>();
                   tap_protocol::CKTapCard card(std::move(tp));
                   return card.IsTapsigner();
                   ;
                 }()));

TEST_CASE("list slot infos with cvc first time") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Satscard satscard(std::move(tp));

  auto infos = satscard.ListSlots("123456");
  CHECK(infos.size() == satscard.GetNumSlots());

  for (auto &info : infos) {
    CHECK_IF(info.status == tap_protocol::Satscard::SlotStatus::UNSEALED,
             !info.address.empty());
    CHECK_IF(info.status == tap_protocol::Satscard::SlotStatus::UNUSED,
             info.address.empty());
    CHECK_IF(info.status == tap_protocol::Satscard::SlotStatus::SEALED,
             !info.address.empty());
    CHECK_IF(info.status == tap_protocol::Satscard::SlotStatus::UNSEALED,
             !info.address.empty() && !info.privkey.empty());
    MESSAGE(json(info).dump(2));
  }
}

TEST_CASE("satscard status") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Satscard satscard(std::move(tp));

  auto st = satscard.Status();
  CHECK(st.slots.size() == 2);
  CHECK(st.slots.back() == 10);

  MESSAGE("satscard status: ", json(st).dump(2));
}

TEST_CASE("list slot info no cvc") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Satscard satscard(std::move(tp));

  auto infos = satscard.ListSlots();
  CHECK(infos.size() == satscard.GetNumSlots());

  for (auto &info : infos) {
    CHECK_IF(info.status == tap_protocol::Satscard::SlotStatus::UNSEALED,
             !info.address.empty());
    CHECK_IF(info.status == tap_protocol::Satscard::SlotStatus::UNUSED,
             info.address.empty());
    CHECK_IF(info.status == tap_protocol::Satscard::SlotStatus::SEALED,
             !info.address.empty());
    CHECK(info.privkey.empty());
    CHECK(info.chain_code.empty());
    CHECK(info.master_pk.empty());
    CHECK(info.pubkey.empty());
    // MESSAGE(json(info).dump(2));
  }
}

TEST_CASE("satscard unseal slot") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Satscard satscard(std::move(tp));

  if (satscard.IsUsedUp()) {
    return;
  }

  if (satscard.GetActiveSlot().status ==
      tap_protocol::Satscard::SlotStatus::SEALED) {
    int past = satscard.GetActiveSlotIndex();
    auto unseal = satscard.Unseal("123456");
    int now = satscard.GetActiveSlotIndex();

    const tap_protocol::Satscard::Slot expected_new_slot = {
        now,
        tap_protocol::Satscard::SlotStatus::UNUSED,
    };

    // new slot is unused if the card is not used up
    CHECK_IF(!satscard.IsUsedUp(),
             satscard.GetActiveSlot() == expected_new_slot);

    CHECK_IF(!satscard.IsUsedUp(), past + 1 == now);
    CHECK_IF(!satscard.IsUsedUp(), satscard.GetActiveSlot().index == now);

    MESSAGE("satscard unseal: ", json(unseal).dump(2));
  } else {
  }
}

TEST_CASE("new slot") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Satscard satscard(std::move(tp));

  if (satscard.IsUsedUp()) {
    return;
  }

  if (satscard.NeedSetup()) {
    auto newResponse = satscard.New(
        tap_protocol::SHA256(tap_protocol::RandomBytes(128)), "123456");

    CHECK(newResponse.index == satscard.GetActiveSlotIndex());
    CHECK(!satscard.GetActiveSlot().address.empty());
    CHECK(satscard.GetActiveSlot().status ==
          tap_protocol::Satscard::SlotStatus::SEALED);
    MESSAGE("new:", json(newResponse).dump(2));
  }
}

TEST_CASE("list slot infos with limit") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Satscard satscard(std::move(tp));

  auto infos = satscard.ListSlots("123456", satscard.GetActiveSlotIndex());
  // all unsealed slots has address
  for (auto &info : infos) {
    CHECK(!info.address.empty());
    CHECK(info.status == tap_protocol::Satscard::SlotStatus::UNSEALED);
    CHECK(info.index < satscard.GetActiveSlotIndex());
  }
}

TEST_CASE("return same pk for unseal slot") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Satscard satscard(std::move(tp));

  if (satscard.GetSlot(0).status ==
      tap_protocol::Satscard::SlotStatus::UNSEALED) {
    CHECK(satscard.GetSlot(0, "123456").privkey ==
          satscard.GetSlot(0, "123456").privkey);

    CHECK(satscard.GetSlot(0, "123456").master_pk ==
          satscard.GetSlot(0, "123456").master_pk);
  }
}

TEST_CASE("show wif") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Satscard satscard(std::move(tp));

  auto infos = satscard.ListSlots("123456");

  for (auto &info : infos) {
    if (info.status == tap_protocol::Satscard::SlotStatus::UNSEALED) {
      auto wif = info.to_wif(satscard.IsTestnet());
      MESSAGE("wif:", wif);
      CHECK(!wif.empty());
    }
  }
}

TEST_CASE("invalid cvc") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Satscard satscard(std::move(tp));

  try {
    satscard.GetSlot(0, "654321");
    satscard.GetSlot(0, "654321");
    satscard.GetSlot(0, "654321");
  } catch (tap_protocol::TapProtoException &te) {
    MESSAGE("invalid cvc msg: ", te.what());
    CHECK(te.code() == tap_protocol::TapProtoException::BAD_AUTH);
  }

  MESSAGE("delay: ", satscard.GetAuthDelay());
  auto info = satscard.GetSlot(0, "123456");
  MESSAGE("info: ", json(info).dump(2));
}

TEST_SUITE_END();
