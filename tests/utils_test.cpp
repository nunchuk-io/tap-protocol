#include "doctest.h"
#include "emulator.h"
#include <string_view>

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
  auto resp = tapSigner.Derive("", "123456");
  MESSAGE(resp.dump(2));
}
