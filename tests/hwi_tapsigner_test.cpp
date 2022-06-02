#include "doctest.h"
#include "emulator.h"
#include "tap_protocol/hash_utils.h"
#include "tap_protocol/utils.h"
#include "tap_protocol/hwi_tapsigner.h"
#include <fstream>
#include <memory>

auto cvc_callback = [] { return std::string("123456"); };

TEST_CASE("HWI Tapsigner test") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  std::unique_ptr<tap_protocol::Tapsigner> tapsigner =
      std::make_unique<tap_protocol::Tapsigner>(std::move(tp));

  auto hwi = tap_protocol::MakeHWITapsigner(std::move(tapsigner), cvc_callback);

  SUBCASE("master fingerprint") {
    auto masterFingerprint = hwi->GetMasterFingerprint();
    CHECK(!masterFingerprint.empty());
    MESSAGE("masterFingerprint:", tap_protocol::Bytes2Str(masterFingerprint));
  };

  SUBCASE("master xpub") {
    auto masterXpub = hwi->GetMasterXpub();
    CHECK(!masterXpub.empty());
    MESSAGE("master xpub:", masterXpub);
  }
}

TEST_CASE("sign psbt") {
  // std::string psbt =
  //     R"(cHNidP8BAHECAAAAAS7w4h16KqOqfJVQRcA8FG672TT1GlovnJk4mngM4bbxAAAAAAD9////AhAnAAAAAAAAFgAUvhWTAOpyTfn5ALB9Lt6k4faE05EDXwEAAAAAABYAFPUdz4DPP0p0np5QsiiM43NjU7ugAAAAAAABAHECAAAAAQZuL5e936meZwHMr+tdwhGtyL+dyS2fNx0RlSfxiIgUAQAAAAD+////AqCGAQAAAAAAFgAUkFeZwhSTizd8cC+i7im4HW31YcckXhAAAAAAABYAFE4BgIDrI24H1Cd8YtE/g1+kwl+wAAAAAAEBH6CGAQAAAAAAFgAUkFeZwhSTizd8cC+i7im4HW31YcciBgOPWy9tBwxsE9ubPsvtOZMhR7qj0OF5PwxEMXEvb+M1hRgk3z8nVAAAgAAAAIAAAACAAAAAAAAAAAAAACICAyx8huKKjc1Pca4285yHEdTrEhEZa2WtIv9CLxDZEGj4GCTfPydUAACAAAAAgAAAAIABAAAAAAAAAAA=)";
  // std::string psbt =
  //    R"(cHNidP8BAHECAAAAAS7w4h16KqOqfJVQRcA8FG672TT1GlovnJk4mngM4bbxAAAAAAD9////AhAnAAAAAAAAFgAUz+WzNKEF+dhqxdUYAhCA8vSDm78DXwEAAAAAABYAFPUdz4DPP0p0np5QsiiM43NjU7ugAAAAAAABAHECAAAAAQZuL5e936meZwHMr+tdwhGtyL+dyS2fNx0RlSfxiIgUAQAAAAD+////AqCGAQAAAAAAFgAUkFeZwhSTizd8cC+i7im4HW31YcckXhAAAAAAABYAFE4BgIDrI24H1Cd8YtE/g1+kwl+wAAAAAAEBH6CGAQAAAAAAFgAUkFeZwhSTizd8cC+i7im4HW31YcciBgOPWy9tBwxsE9ubPsvtOZMhR7qj0OF5PwxEMXEvb+M1hRiTgGJuVAAAgAAAAIAAAACAAAAAAAAAAAAAACICAyx8huKKjc1Pca4285yHEdTrEhEZa2WtIv9CLxDZEGj4GJOAYm5UAACAAAAAgAAAAIABAAAAAAAAAAA=)";
  std::string psbt =
      R"(cHNidP8BAHECAAAAAeQO+WHGMBcygfnSdJp0RMQecTH8b0uOiKe7nZFDnPHBAQAAAAD9////AqCGAQAAAAAAFgAU09lgrqrjqstuu1rWWnCWj0cKR80miJUAAAAAABYAFElZt8QO2/t4f+tE8+RZP7od4ELwAAAAAAABAHECAAAAAbz4pIynRzUSKaolRPcKnY5RfLHhpKeBV1bg0O1u+0r7AQAAAAD9////AqCGAQAAAAAAFgAUCAL5UrovoM8vygCX5BwEljhQJIdTD5cAAAAAABYAFJe/6NsVCMVnHr+LBoxQiiJsRHsBAAAAAAEBH1MPlwAAAAAAFgAUl7/o2xUIxWcev4sGjFCKImxEewEiBgMqDCr9TKp8dIYPSYh5AXJZGMpqvGGcwgoRRL2CyOVHdxiTgGJuVAAAgAAAAIAAAACAAQAAAAAAAAAAACICAlSlFPNQVFfm18C+2kLOBJa88mbUalgkWnN5ro5pyKhAGJOAYm5UAACAAAAAgAAAAIABAAAAAQAAAAA=)";

  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  std::unique_ptr<tap_protocol::Tapsigner> tapsigner =
      std::make_unique<tap_protocol::Tapsigner>(std::move(tp));

  auto hwi = tap_protocol::MakeHWITapsigner(std::move(tapsigner), cvc_callback);

  const std::string expected_signed_tx =
      R"(cHNidP8BAHECAAAAAeQO+WHGMBcygfnSdJp0RMQecTH8b0uOiKe7nZFDnPHBAQAAAAD9////AqCGAQAAAAAAFgAU09lgrqrjqstuu1rWWnCWj0cKR80miJUAAAAAABYAFElZt8QO2/t4f+tE8+RZP7od4ELwAAAAAAABAHECAAAAAbz4pIynRzUSKaolRPcKnY5RfLHhpKeBV1bg0O1u+0r7AQAAAAD9////AqCGAQAAAAAAFgAUCAL5UrovoM8vygCX5BwEljhQJIdTD5cAAAAAABYAFJe/6NsVCMVnHr+LBoxQiiJsRHsBAAAAAAEBH1MPlwAAAAAAFgAUl7/o2xUIxWcev4sGjFCKImxEewEiAgMqDCr9TKp8dIYPSYh5AXJZGMpqvGGcwgoRRL2CyOVHd0gwRQIhAI5hXfgHClL7jYxTbljOGUc8Sc1axW7HOMwkH2xFF1JUAiAoHHwoNqE2jGrnYnMo4n9ah14GPNoMzRMfiYdq1L3efQEiBgMqDCr9TKp8dIYPSYh5AXJZGMpqvGGcwgoRRL2CyOVHdxiTgGJuVAAAgAAAAIAAAACAAQAAAAAAAAAAACICAlSlFPNQVFfm18C+2kLOBJa88mbUalgkWnN5ro5pyKhAGJOAYm5UAACAAAAAgAAAAIABAAAAAQAAAAA=)";

  auto signed_tx = hwi->SignTx(psbt);

  CHECK(signed_tx == expected_signed_tx);

  SUBCASE("sign psbt 2") {
    std::string psbt2 =
        R"(cHNidP8BAHECAAAAAXrmtsvP0awn2qYs/ZkvYFpuiWVqdvLC5lsQDus+Hg1nAQAAAAD9////AhAnAAAAAAAAFgAUPyYxfgarAm+2nXG+cmkATjuEpVSJYJUAAAAAABYAFMs/gBI6mDaaW9+mcSpkzNGdGKneAAAAAAABAHECAAAAAeQO+WHGMBcygfnSdJp0RMQecTH8b0uOiKe7nZFDnPHBAQAAAAD9////AqCGAQAAAAAAFgAU09lgrqrjqstuu1rWWnCWj0cKR80miJUAAAAAABYAFElZt8QO2/t4f+tE8+RZP7od4ELwAAAAAAEBHyaIlQAAAAAAFgAUSVm3xA7b+3h/60Tz5Fk/uh3gQvAiBgJUpRTzUFRX5tfAvtpCzgSWvPJm1GpYJFpzea6OacioQBiTgGJuVAAAgAAAAIAAAACAAQAAAAEAAAAAACICA0Q5584TFoYf1zZmwx6ryEzfSI0zbvqLIp1s7sMmJ3LuGJOAYm5UAACAAAAAgAAAAIABAAAAAgAAAAA=)";
    auto sign_tx_2 = hwi->SignTx(psbt2);
    MESSAGE("sign psbt2:", sign_tx_2);
  }
}
