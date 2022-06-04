#include "doctest.h"
#include "emulator.h"
#include "tap_protocol/hash_utils.h"
#include "tap_protocol/utils.h"
#include "tap_protocol/hwi_tapsigner.h"
#include <fstream>
#include <memory>

auto cvc_callback = [](const std::string &msg) {
  return std::string("123456");
};

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
  // std::string psbt =
  //    R"(cHNidP8BAHECAAAAAeQO+WHGMBcygfnSdJp0RMQecTH8b0uOiKe7nZFDnPHBAQAAAAD9////AqCGAQAAAAAAFgAU09lgrqrjqstuu1rWWnCWj0cKR80miJUAAAAAABYAFElZt8QO2/t4f+tE8+RZP7od4ELwAAAAAAABAHECAAAAAbz4pIynRzUSKaolRPcKnY5RfLHhpKeBV1bg0O1u+0r7AQAAAAD9////AqCGAQAAAAAAFgAUCAL5UrovoM8vygCX5BwEljhQJIdTD5cAAAAAABYAFJe/6NsVCMVnHr+LBoxQiiJsRHsBAAAAAAEBH1MPlwAAAAAAFgAUl7/o2xUIxWcev4sGjFCKImxEewEiBgMqDCr9TKp8dIYPSYh5AXJZGMpqvGGcwgoRRL2CyOVHdxiTgGJuVAAAgAAAAIAAAACAAQAAAAAAAAAAACICAlSlFPNQVFfm18C+2kLOBJa88mbUalgkWnN5ro5pyKhAGJOAYm5UAACAAAAAgAAAAIABAAAAAQAAAAA=)";
  //
  // std::unique_ptr<tap_protocol::Transport> tp =
  //    std::make_unique<CardEmulator>();
  //
  // std::unique_ptr<tap_protocol::Tapsigner> tapsigner =
  //    std::make_unique<tap_protocol::Tapsigner>(std::move(tp));
  //
  // auto hwi = tap_protocol::MakeHWITapsigner(std::move(tapsigner),
  // cvc_callback);
  //
  // const std::string expected_signed_tx =
  //    R"(cHNidP8BAHECAAAAAeQO+WHGMBcygfnSdJp0RMQecTH8b0uOiKe7nZFDnPHBAQAAAAD9////AqCGAQAAAAAAFgAU09lgrqrjqstuu1rWWnCWj0cKR80miJUAAAAAABYAFElZt8QO2/t4f+tE8+RZP7od4ELwAAAAAAABAHECAAAAAbz4pIynRzUSKaolRPcKnY5RfLHhpKeBV1bg0O1u+0r7AQAAAAD9////AqCGAQAAAAAAFgAUCAL5UrovoM8vygCX5BwEljhQJIdTD5cAAAAAABYAFJe/6NsVCMVnHr+LBoxQiiJsRHsBAAAAAAEBH1MPlwAAAAAAFgAUl7/o2xUIxWcev4sGjFCKImxEewEiAgMqDCr9TKp8dIYPSYh5AXJZGMpqvGGcwgoRRL2CyOVHd0gwRQIhAI5hXfgHClL7jYxTbljOGUc8Sc1axW7HOMwkH2xFF1JUAiAoHHwoNqE2jGrnYnMo4n9ah14GPNoMzRMfiYdq1L3efQEiBgMqDCr9TKp8dIYPSYh5AXJZGMpqvGGcwgoRRL2CyOVHdxiTgGJuVAAAgAAAAIAAAACAAQAAAAAAAAAAACICAlSlFPNQVFfm18C+2kLOBJa88mbUalgkWnN5ro5pyKhAGJOAYm5UAACAAAAAgAAAAIABAAAAAQAAAAA=)";
  //
  // auto signed_tx = hwi->SignTx(psbt);
  //
  // CHECK(signed_tx == expected_signed_tx);
  //
}

TEST_CASE("sign message") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  std::unique_ptr<tap_protocol::Tapsigner> tapsigner =
      std::make_unique<tap_protocol::Tapsigner>(std::move(tp));

  auto hwi = tap_protocol::MakeHWITapsigner(std::move(tapsigner), cvc_callback);

  auto sig = hwi->SignMessage("nunchuk", "m/84h/0/0");
  std::string expected_sig =
      R"(J5+9kBB9AmkTDKrhb7Fqq1XEsIJOLTA5eQievLDS9qdLQKp8gEqdIb4FjCeeIWjyXPAjv2UutTcF3rP+b2gaBhI=)";
  CHECK(sig == expected_sig);
}

TEST_CASE("get xpub at path") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  std::unique_ptr<tap_protocol::Tapsigner> tapsigner =
      std::make_unique<tap_protocol::Tapsigner>(std::move(tp));

  auto hwi = tap_protocol::MakeHWITapsigner(std::move(tapsigner), cvc_callback);

  SUBCASE("m/84h/0/0") {
    const std::string m =
        R"(xpub6C2BDeJ4ZD1HAcj9qpKdk7ijvUVVmAZmFUKck4MMtN9m7aRG5ieYA1EEqYukDzTyQrZWh7eqxVe6ptEKkPyvFF4Rm6zajwrsCD9RKwMibEo)";
    std::string res = hwi->GetXpubAtPath("m/84h/0/0");
    MESSAGE("m/84h/0/0", res);
    CHECK(m == res);
  }

  SUBCASE("m/44h") {
    const std::string m44h =
        R"(xpub69mdgvy4vNQfiXVvwnZbkAJRYcPRyrK3jXoUnzvkw3o57Mkrr65Td7wEYWcjR2WrJmamefuPfBMaw4nQ96D7rdxXRCSfXKw4CJdeoiKQpjQ)";
    std::string res = hwi->GetXpubAtPath("m/44h");
    CHECK(m44h == res);
  }

  // TODO: Somehow path "m" bip32_key_serialize error

  // SUBCASE("m/") {
  // const std::string m =
  //     R"(xpub6C2BDeJ4ZD1HAcj9qpKdk7ijvUVVmAZmFUKck4MMtN9m7aRG5ieYA1EEqYukDzTyQrZWh7eqxVe6ptEKkPyvFF4Rm6zajwrsCD9RKwMibEo)";
  // std::string res = hwi->GetXpubAtPath("m/");
  // MESSAGE("m/84h/0/0", res);
  // CHECK(m == res);
  //}
}
