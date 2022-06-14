#include "doctest.h"
#include "emulator.h"
#include "tap_protocol/hash_utils.h"
#include "tap_protocol/tap_protocol.h"
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

  auto hwi = tap_protocol::MakeHWITapsigner(tapsigner.get(), cvc_callback);
  hwi->SetChain(tap_protocol::HWITapsigner::Chain::TESTNET);

  SUBCASE("master fingerprint") {
    auto masterFingerprint = hwi->GetMasterFingerprint();
    CHECK(!masterFingerprint.empty());
    MESSAGE("masterFingerprint:", masterFingerprint);
  };

  SUBCASE("master xpub") {
    auto masterXpub = hwi->GetMasterXpub();
    CHECK(!masterXpub.empty());
    MESSAGE("master xpub:", masterXpub);
  }
}

TEST_CASE("sign psbt multisig") {
  std::string psbt =
      R"(cHNidP8BAH0CAAAAAeSA6GdrgBRXzH415gHt6/rsSN3+CJhBgAZ7umlbVGKXAQAAAAD9////AqCGAQAAAAAAFgAUm/Qf/v63kXnRvFTERpCNxyc0m349D5cAAAAAACIAIGnLboNEdb/D/PjfprMnT9zkM1fMBUYxDhbhCW093PRzAAAAAAABAH0CAAAAAQUg33sPBYFWL9J7HpL1oiVZvhGMoDPOO5Zd8cGq850ZAAAAAAD+////Ai5A3QAAAAAAFgAUfchBSYYu84vBjIXRWSPyzhg24EOAlpgAAAAAACIAIMkqtHPQHxk3Uf2nPFA/sayW8fpSlqLnMCsd9uk/79imAAAAAAEBK4CWmAAAAAAAIgAgySq0c9AfGTdR/ac8UD+xrJbx+lKWoucwKx326T/v2KYBBUdRIQIp9t45hUGQCbweTOUuHZBTguDWqgjg0cabEnsZ/Wq/fiECsa1JSeqdw6AS3BgJ/7c7DlSysgCz02TqbJmL26FEVuhSriIGAin23jmFQZAJvB5M5S4dkFOC4NaqCODRxpsSexn9ar9+GOiVI3IwAACAAQAAgAMAAIAAAAAAAAAAACIGArGtSUnqncOgEtwYCf+3Ow5UsrIAs9Nk6myZi9uhRFboGJOAYm5UAACAAAAAgAAAAIAAAAAAAAAAAAAAAQFHUSEDA482kbc+pTLFrhLwJCgpqJAFVPqhBdIhcWhqANcUMi0hA231bB830JUNQQPjB9Dyy8f7ZWYivcKWSf1PESD249u0Uq4iAgMDjzaRtz6lMsWuEvAkKCmokAVU+qEF0iFxaGoA1xQyLRiTgGJuVAAAgAAAAIAAAACAAQAAAAAAAAAiAgNt9WwfN9CVDUED4wfQ8svH+2VmIr3Clkn9TxEg9uPbtBjolSNyMAAAgAEAAIADAACAAQAAAAAAAAAA)";
  std::unique_ptr<tap_protocol::Transport> transport =
      std::make_unique<CardEmulator>();

  std::unique_ptr<tap_protocol::Tapsigner> tapsigner =
      std::make_unique<tap_protocol::Tapsigner>(std::move(transport));

  auto hwi = tap_protocol::MakeHWITapsigner(tapsigner.get(), cvc_callback);
  hwi->SetChain(tap_protocol::HWITapsigner::Chain::TESTNET);
  // const std::string expected_signed_tx =
  //     R"(cHNidP8BAHECAAAAAbaRLv2dwhA2qDirXFYNC9kxbQi5zvIlJvhRgjlJcBdAAQAAAAD9////AhAnAAAAAAAAFgAUFXSeP6uXhBP8u1KfhTzbmWX3zqHsOJUAAAAAABYAFLvdDJXh7MI0aJDBJ/gP84Bu8GyrAAAAAAABAHECAAAAAXrmtsvP0awn2qYs/ZkvYFpuiWVqdvLC5lsQDus+Hg1nAQAAAAD9////AhAnAAAAAAAAFgAUPyYxfgarAm+2nXG+cmkATjuEpVSJYJUAAAAAABYAFMs/gBI6mDaaW9+mcSpkzNGdGKneAAAAAAEBH4lglQAAAAAAFgAUyz+AEjqYNppb36ZxKmTM0Z0Yqd4iAgNEOefOExaGH9c2ZsMeq8hM30iNM276iyKdbO7DJidy7kgwRQIhAINS7fS6dgbYiPEU+1LYH2ct8jqRrN2D3H7d/kkOfbQeAiBXgcSnBEjYljn32885LlNpu3Brkhg49o0w5BKnq0f+/QEiBgNEOefOExaGH9c2ZsMeq8hM30iNM276iyKdbO7DJidy7hiTgGJuVAAAgAAAAIAAAACAAQAAAAIAAAAAACICAnSsqeOwIu1mHItlHQM+TyK3mH+qqVxgJX3MCyzHLcQhGJOAYm5UAACAAAAAgAAAAIABAAAAAwAAAAA=)";

  auto signed_tx = hwi->SignTx(psbt);
  MESSAGE("sign psbt multisig: ", signed_tx);
}

TEST_CASE("sign psbt") {
  // std::string psbt =
  //     R"(cHNidP8BAHECAAAAAS7w4h16KqOqfJVQRcA8FG672TT1GlovnJk4mngM4bbxAAAAAAD9////AhAnAAAAAAAAFgAUvhWTAOpyTfn5ALB9Lt6k4faE05EDXwEAAAAAABYAFPUdz4DPP0p0np5QsiiM43NjU7ugAAAAAAABAHECAAAAAQZuL5e936meZwHMr+tdwhGtyL+dyS2fNx0RlSfxiIgUAQAAAAD+////AqCGAQAAAAAAFgAUkFeZwhSTizd8cC+i7im4HW31YcckXhAAAAAAABYAFE4BgIDrI24H1Cd8YtE/g1+kwl+wAAAAAAEBH6CGAQAAAAAAFgAUkFeZwhSTizd8cC+i7im4HW31YcciBgOPWy9tBwxsE9ubPsvtOZMhR7qj0OF5PwxEMXEvb+M1hRgk3z8nVAAAgAAAAIAAAACAAAAAAAAAAAAAACICAyx8huKKjc1Pca4285yHEdTrEhEZa2WtIv9CLxDZEGj4GCTfPydUAACAAAAAgAAAAIABAAAAAAAAAAA=)";
  // std::string psbt =
  //    R"(cHNidP8BAHECAAAAAS7w4h16KqOqfJVQRcA8FG672TT1GlovnJk4mngM4bbxAAAAAAD9////AhAnAAAAAAAAFgAUz+WzNKEF+dhqxdUYAhCA8vSDm78DXwEAAAAAABYAFPUdz4DPP0p0np5QsiiM43NjU7ugAAAAAAABAHECAAAAAQZuL5e936meZwHMr+tdwhGtyL+dyS2fNx0RlSfxiIgUAQAAAAD+////AqCGAQAAAAAAFgAUkFeZwhSTizd8cC+i7im4HW31YcckXhAAAAAAABYAFE4BgIDrI24H1Cd8YtE/g1+kwl+wAAAAAAEBH6CGAQAAAAAAFgAUkFeZwhSTizd8cC+i7im4HW31YcciBgOPWy9tBwxsE9ubPsvtOZMhR7qj0OF5PwxEMXEvb+M1hRiTgGJuVAAAgAAAAIAAAACAAAAAAAAAAAAAACICAyx8huKKjc1Pca4285yHEdTrEhEZa2WtIv9CLxDZEGj4GJOAYm5UAACAAAAAgAAAAIABAAAAAAAAAAA=)";
  // std::string psbt =
  //    R"(cHNidP8BAHECAAAAAeQO+WHGMBcygfnSdJp0RMQecTH8b0uOiKe7nZFDnPHBAQAAAAD9////AqCGAQAAAAAAFgAU09lgrqrjqstuu1rWWnCWj0cKR80miJUAAAAAABYAFElZt8QO2/t4f+tE8+RZP7od4ELwAAAAAAABAHECAAAAAbz4pIynRzUSKaolRPcKnY5RfLHhpKeBV1bg0O1u+0r7AQAAAAD9////AqCGAQAAAAAAFgAUCAL5UrovoM8vygCX5BwEljhQJIdTD5cAAAAAABYAFJe/6NsVCMVnHr+LBoxQiiJsRHsBAAAAAAEBH1MPlwAAAAAAFgAUl7/o2xUIxWcev4sGjFCKImxEewEiBgMqDCr9TKp8dIYPSYh5AXJZGMpqvGGcwgoRRL2CyOVHdxiTgGJuVAAAgAAAAIAAAACAAQAAAAAAAAAAACICAlSlFPNQVFfm18C+2kLOBJa88mbUalgkWnN5ro5pyKhAGJOAYm5UAACAAAAAgAAAAIABAAAAAQAAAAA=)";

  std::string psbt =
      R"(cHNidP8BAHECAAAAAbaRLv2dwhA2qDirXFYNC9kxbQi5zvIlJvhRgjlJcBdAAQAAAAD9////AhAnAAAAAAAAFgAUFXSeP6uXhBP8u1KfhTzbmWX3zqHsOJUAAAAAABYAFLvdDJXh7MI0aJDBJ/gP84Bu8GyrAAAAAAABAHECAAAAAXrmtsvP0awn2qYs/ZkvYFpuiWVqdvLC5lsQDus+Hg1nAQAAAAD9////AhAnAAAAAAAAFgAUPyYxfgarAm+2nXG+cmkATjuEpVSJYJUAAAAAABYAFMs/gBI6mDaaW9+mcSpkzNGdGKneAAAAAAEBH4lglQAAAAAAFgAUyz+AEjqYNppb36ZxKmTM0Z0Yqd4iBgNEOefOExaGH9c2ZsMeq8hM30iNM276iyKdbO7DJidy7hiTgGJuVAAAgAAAAIAAAACAAQAAAAIAAAAAACICAnSsqeOwIu1mHItlHQM+TyK3mH+qqVxgJX3MCyzHLcQhGJOAYm5UAACAAAAAgAAAAIABAAAAAwAAAAA=)";
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  std::unique_ptr<tap_protocol::Tapsigner> tapsigner =
      std::make_unique<tap_protocol::Tapsigner>(std::move(tp));

  auto hwi = tap_protocol::MakeHWITapsigner(tapsigner.get(), cvc_callback);
  hwi->SetChain(tap_protocol::HWITapsigner::Chain::TESTNET);

  auto signed_tx = hwi->SignTx(psbt);

  CHECK(!signed_tx.empty());
}

TEST_CASE("sign message") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  std::unique_ptr<tap_protocol::Tapsigner> tapsigner =
      std::make_unique<tap_protocol::Tapsigner>(std::move(tp));

  auto hwi = tap_protocol::MakeHWITapsigner(tapsigner.get(), cvc_callback);
  auto sig = hwi->SignMessage("nunchuk", "m/84h/0/0");
  CHECK(!sig.empty());
}

TEST_CASE("get xpub at path") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  std::unique_ptr<tap_protocol::Tapsigner> tapsigner =
      std::make_unique<tap_protocol::Tapsigner>(std::move(tp));

  auto hwi = tap_protocol::MakeHWITapsigner(tapsigner.get(), cvc_callback);
  hwi->SetChain(tap_protocol::HWITapsigner::Chain::TESTNET);
  SUBCASE("m/") {
    std::string res = hwi->GetXpubAtPath("m/");
    MESSAGE("path m/: ", res);
    CHECK(!res.empty());
  }

  SUBCASE("m/84h/0/0") {
    std::string res = hwi->GetXpubAtPath("m/84h/0/0");
    MESSAGE("path m/84h/0/0: ", res);
    CHECK(!res.empty());
  }

  SUBCASE("m/44h") {
    std::string res = hwi->GetXpubAtPath("m/44h");
    MESSAGE("path m/44h: ", res);
    CHECK(!res.empty());
  }
}

TEST_CASE("decrypt backup") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  std::unique_ptr<tap_protocol::Tapsigner> tapsigner =
      std::make_unique<tap_protocol::Tapsigner>(std::move(tp));

  auto hwi = tap_protocol::MakeHWITapsigner(tapsigner.get(), cvc_callback);
  hwi->SetChain(tap_protocol::HWITapsigner::Chain::TESTNET);

  auto encrypted = tap_protocol::Hex2Bytes(
      "f5a6bfb5854c9cf53ffbd2ebd0c028b9761f9a5b393cc65c859e7171db2d11b1940918d4"
      "3a3788c2a2b7b3aa95ec1b743cef462f39ac8d36d1707ee1c80663e528018484e8838127"
      "2b064efc31ad11b5c7c15c7835ef2f8eaf1db2cbf2bbf03465055997574a196fbdcd4055"
      "bb06731447eb9513a306");

  std::string backup_key = "41414141414141414141414141414141";

  auto decrypted =
      hwi->DecryptBackup({std::begin(encrypted), std::end(encrypted)},
                         {std::begin(backup_key), std::end(backup_key)});
  std::string decrypted_str(std::begin(decrypted), std::end(decrypted));
  std::string expected =
      "tprv8ZgxMBicQKsPctUGYBjd5XBMn4TzcyFiuccf88VtCKaFUZend1nCDkmqPsNmhjMMehX7"
      "5AdbvPzqkQEF2S2zjGvjnCGT8g13WBmaL3nm7op\nm/44h\n";

  // MESSAGE("decrypted: ", decrypted_str);
  CHECK(decrypted_str == expected);
}
