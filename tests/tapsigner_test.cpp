#include <random>
#include <algorithm>
#include <string>
#include "doctest.h"
#include "emulator.h"
#include "stringification.h"
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/tap_protocol.h"
#include "tap_protocol/utils.h"
#include "tap_protocol/hash_utils.h"

// must run emulator first
// https://github.com/coinkite/coinkite-tap-proto/tree/master/emulator
// $ ./ecard.py emulate -t
// $ ./ecard.py emulate -t --no-init # fresh card

TEST_CASE("tapsigner to satscard") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Tapsigner tapsigner(std::move(tp));
  if (!tapsigner.IsTapsigner()) {
    auto satscard = tap_protocol::ToSatscard(std::move(tapsigner));
    MESSAGE("satscard active slot: ", satscard->GetActiveSlotIndex());
  }
}

TEST_SUITE_BEGIN("tapsigner" * doctest::skip([]() -> bool {
                   std::unique_ptr<tap_protocol::Transport> tp =
                       std::make_unique<CardEmulator>();
                   tap_protocol::CKTapCard card(std::move(tp));
                   return !card.IsTapsigner();
                   ;
                 }()));

TEST_CASE("set up new card") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Tapsigner tapsigner(std::move(tp));

  if (tapsigner.NeedSetup()) {
    // setup new card

    auto newResp = tapsigner.New(tap_protocol::RandomChainCode(), "123456", 0);

    MESSAGE("new resp:", json(newResp).dump(2));
    CHECK(!newResp.card_nonce.empty());

  } else {
    MESSAGE("card is already setup, and ready to use");
    // already setup
  }
}

TEST_CASE("test card identity") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  tap_protocol::Tapsigner tapsigner(std::move(tp));

  // When get ident
  auto ident = tapsigner.GetIdent();

  // Then ident must equal emulator card ident
  const std::string emulatorCardIdent = "XDXKQ-W6VW6-GEQI3-ATSC2";
  CHECK(ident == emulatorCardIdent);
}

TEST_CASE("test tapsigner derivation path") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  tap_protocol::Tapsigner tapsigner(std::move(tp));
  tapsigner.Derive("m/", "123456");

  auto d = tapsigner.GetDerivationPath();
  CHECK(d == "m");

  tapsigner.Derive("m/84h", "123456");
  d = tapsigner.GetDerivationPath();
  CHECK(d == "m/84h");

  tapsigner.Derive("m", "123456");
  d = tapsigner.GetDerivationPath();
  CHECK(d == "m");
}

TEST_CASE("string to path and reverse") {
  std::vector<uint32_t> path{
      2147483732,
      2147483648,
      2147483648,
  };

  std::string str_path = "m/84h/0h/0h";

  CHECK(tap_protocol::Str2Path(str_path) == path);
  CHECK(str_path == tap_protocol::Path2Str(path));
}

TEST_CASE("get xfp") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Tapsigner tapsigner(std::move(tp));

  // When call get xfp
  std::string xfp = tapsigner.GetXFP("123456");

  MESSAGE("xfp:", xfp);

  // Then return a valid xfp
  CHECK(xfp.size() == 8);
}

TEST_CASE("get xpub") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Tapsigner tapsigner(std::move(tp));
  // When call get xpub

  std::string xpub = tapsigner.Xpub("123456", true);

  // Then return a valid xpub
  CHECK(!xpub.empty());

  MESSAGE("xpub:", xpub);
}

TEST_CASE("get pubkey") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Tapsigner tapsigner(std::move(tp));
  // When call get pubkey

  auto pubkey = tapsigner.Pubkey("123456");

  // Then return a valid pubkey
  CHECK(!pubkey.empty());
  MESSAGE("pubkey:", pubkey);
}

TEST_CASE("backup then change cvc") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Tapsigner tapsigner(std::move(tp));

  json backupResp = tapsigner.Backup("123456");
  MESSAGE("backup:", backupResp.dump(2));
  MESSAGE("backup data:",
          tap_protocol::Bytes2Hex(backupResp["data"].get<json::binary_t>()));
  CHECK(!backupResp["data"].get<json::binary_t>().empty());

  json changeResp = tapsigner.Change("654321", "123456");
  MESSAGE("change:", changeResp.dump(2));
  CHECK(changeResp["success"] == true);

  json changeBack = tapsigner.Change("123456", "654321");
  CHECK(changeBack["success"] == true);
}

TEST_CASE("check certs") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Tapsigner tapsigner(std::move(tp));

  // emulator doesn't need certificate check
  CHECK_THROWS_AS(
      {
        std::string label = tapsigner.CertificateCheck();
        CAPTURE(label);
      },
      tap_protocol::TapProtoException);
}

TEST_CASE("sign digest") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::Tapsigner tapsigner(std::move(tp));

  auto digest = tap_protocol::RandomBytes(32);
  tap_protocol::Bytes resp =
      tapsigner.Sign({std::begin(digest), std::end(digest)}, "123456");
  CHECK(!resp.empty());
  MESSAGE("digest:", tap_protocol::Bytes2Hex(digest));
  MESSAGE("signed digest:", tap_protocol::Bytes2Hex(resp));
}

TEST_SUITE_END();
