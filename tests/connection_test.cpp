#include "doctest.h"
#include "emulator.h"

TEST_CASE("tapsigner status emulator") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  tap_protocol::TapSigner tapSigner(std::move(tp));

  // When call 'status'
  auto resp = tapSigner.Status();

  // Then return proto version = 1
  CHECK(resp.proto == 1);

  std::cout << json(resp).dump(2) << "\n";
}

TEST_CASE("get nfc url") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  tap_protocol::TapSigner tapSigner(std::move(tp));

  // When call 'nfc'
  auto resp = tapSigner.NFC();

  // Then return url start with "https://tapsigner.com"
  const std::string url = "https://tapsigner.com";
  CHECK(url == resp.substr(0, url.size()));

  std::cout << "card nfc url: " << resp << "\n";
}
