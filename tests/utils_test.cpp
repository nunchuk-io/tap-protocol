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

TEST_CASE("set up new card") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::TapSigner tapSigner(std::move(tp));

  if (tapSigner.Status().path.empty()) {
    // setup new card

    // Random chain_code

    tap_protocol::Bytes random_chain_code = tap_protocol::RandomBytes(128);

    tap_protocol::Bytes chain_code_hash =
        tap_protocol::SHA256d(random_chain_code);

    json newResp = tapSigner.New(chain_code_hash, "123456", 0);
    MESSAGE("new resp:", newResp.dump(2));

    CHECK(!tap_protocol::CKTapCard::NewResponse(newResp).card_nonce.empty());
  } else {
    MESSAGE("card is already setup, and ready to use");
    // already setup
  }
}

TEST_CASE("test card identity") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  tap_protocol::TapSigner tapSigner(std::move(tp));

  // When get ident
  auto ident = tapSigner.GetIdent();

  // Then ident must equal emulator card ident
  const std::string emulatorCardIdent = "XDXKQ-W6VW6-GEQI3-ATSC2";
  auto identStr = std::string((const char*)ident.data(), ident.size());

  CAPTURE(emulatorCardIdent);
  CAPTURE(identStr);
  CHECK(identStr == emulatorCardIdent);
}

TEST_CASE("derive tapsigner") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  tap_protocol::TapSigner tapSigner(std::move(tp));
  // When set derivation path
  auto resp = tapSigner.Derive("84h/0h/0h", "123456");

  // Then return a pubkey to this path
  CHECK(!resp.pubkey.empty());
  MESSAGE(json(resp).dump(2));
}

TEST_CASE("test tapsigner derivation path") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  tap_protocol::TapSigner tapSigner(std::move(tp));
  // When get derivation path
  std::string d = tapSigner.GetDerivation();
  // Then return derivation path
  CHECK(!d.empty());
  MESSAGE("derivation = ", d);
}

TEST_CASE("string to path and reverse") {
  std::vector<int64_t> path{
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
  tap_protocol::TapSigner tapSigner(std::move(tp));

  // When call get xfp
  std::string xfp = tapSigner.GetXFP("123456");

  // Then return a valid xfp
  CHECK(xfp.size() == 8);
}

TEST_CASE("get xpub") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::TapSigner tapSigner(std::move(tp));
  // When call get xpub

  std::string xpub = tapSigner.Xpub("123456", true);

  // Then return a valid xpub
  CHECK(!xpub.empty());

  MESSAGE("xpub:", xpub);
}

TEST_CASE("get pubkey") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::TapSigner tapSigner(std::move(tp));
  // When call get pubkey

  auto pubkey = tapSigner.Pubkey("123456");

  // Then return a valid pubkey
  CHECK(!pubkey.empty());
  MESSAGE("pubkey:", pubkey);
}

TEST_CASE("binary string") {
  std::string str = "nunchuk is awesome";
  tap_protocol::Bytes toBytes(std::begin(str), std::end(str));
  json::binary_t bin = toBytes;
  tap_protocol::Bytes binToBytes = bin;
  std::string bytesToStr{bin.data(), bin.data() + bin.size()};

  CHECK(str == bytesToStr);
}

TEST_CASE("backup then change cvc") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::TapSigner tapSigner(std::move(tp));

  json backupResp = tapSigner.Backup("123456");
  MESSAGE("backup:", backupResp.dump(2));
  CHECK(!backupResp["data"].get<json::binary_t>().empty());

  json changeResp = tapSigner.Change("654321", "123456");
  MESSAGE("change:", changeResp.dump(2));
  CHECK(changeResp["success"] == true);

  json changeBack = tapSigner.Change("123456", "654321");
  CHECK(changeBack["success"] == true);
}

TEST_CASE("check certs") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::TapSigner tapSigner(std::move(tp));

  CHECK_THROWS_AS(
      {
        std::string label = tapSigner.CertificateCheck();
        CAPTURE(label);
      },
      tap_protocol::TapProtoException);
}

TEST_CASE("sign digest") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::TapSigner tapSigner(std::move(tp));

  std::string msg = "nunchuk!!!";
  // bd8c9c3b2285e518c6f31f0692e4395276ca141dde4fbe9dc69baf74f2a3143b
  // tap_protocol::Bytes digest =
  //     tap_protocol::SHA256d({std::begin(msg), std::end(msg)});
  tap_protocol::Bytes resp =
      tapSigner.SignMessage({std::begin(msg), std::end(msg)}, "123456");
  CHECK(!resp.empty());
  MESSAGE("signed:", tap_protocol::Bytes2Str(resp));
}

