#include "doctest.h"
#include "emulator.h"
#include "stringification.h"
#include "tap_protocol/tap_protocol.h"
#include "tap_protocol/utils.h"

TEST_CASE("test card identity") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  tap_protocol::TapSigner tapSigner(std::move(tp));

  // When get ident
  auto ident = tapSigner.GetIdent();

  // Then ident must equal emulator card ident
  constexpr std::string_view emulatorCardIdent = "XDXKQ-W6VW6-GEQI3-ATSC2";
  auto identSv = std::string_view((const char*)ident.data(), ident.size());

  CHECK(identSv == emulatorCardIdent);
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

TEST_CASE("derive tapsigner") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  tap_protocol::TapSigner tapSigner(std::move(tp));
  // When set derivation path
  json resp = tapSigner.Derive("", "123456");
  MESSAGE(resp.dump(2));
}

TEST_CASE("string to path and reverse") {
  std::vector<int64_t> path{
      2147483732,
      2147483648,
      2147483648,
  };

  std::string str_path = "m84h/0h/0h";

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
  tap_protocol::Bytes b(xfp.data(), xfp.data() + xfp.size());
  CAPTURE(xfp);
  CHECK(xfp == "B633CAB6");
}

TEST_CASE("get xpub") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::TapSigner tapSigner(std::move(tp));
  // When call get xpub

  std::string xpub = tapSigner.Xpub("123456", true);
  std::string expected_xpub =
      R"(xpub661MyMwAqRbcEZKCyeR8H1W71xtGnuwZwHd946V3GgckZmErBBkhFoisKzVNJdvrwRuiqXwP9AD6h5LPnwRKkLzofV7B9ecKo7v64G7afnx)";
  CAPTURE(xpub);
  CHECK(xpub == expected_xpub);

  MESSAGE(xpub);
}

TEST_CASE("get pubkey") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();
  tap_protocol::TapSigner tapSigner(std::move(tp));
  // When call get pubkey

  auto pubkey = tapSigner.Pubkey("123456");
  MESSAGE(pubkey);
}

TEST_CASE("binary string") {
  std::string s = "abcd";
  tap_protocol::Bytes b(std::begin(s), std::end(s));
  json::binary_t jb = b;
  tap_protocol::Bytes bback = jb;
  std::string sback{jb.data(), jb.data() + jb.size()};

  CHECK(s == sback);
}
