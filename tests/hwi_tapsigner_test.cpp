#include "doctest.h"
#include "emulator.h"
#include "tap_protocol/hash_utils.h"
#include "tap_protocol/tap_protocol.h"
#include "tap_protocol/utils.h"
#include "tap_protocol/hwi_tapsigner.h"
#include <fstream>
#include <memory>

const std::string default_cvc = "123456";

TEST_SUITE_BEGIN("tapsigner" * doctest::skip([]() -> bool {
                   std::unique_ptr<tap_protocol::Transport> tp =
                       std::make_unique<CardEmulator>();
                   tap_protocol::CKTapCard card(std::move(tp));
                   return !card.IsTapsigner();
                   ;
                 }()));

TEST_CASE("verify chaincode") {
  auto tp = std::make_unique<CardEmulator>();
  auto tapsigner = std::make_unique<tap_protocol::Tapsigner>(std::move(tp));
  if (tapsigner->NeedSetup()) {
    auto hwi = tap_protocol::MakeHWITapsigner(tapsigner.get(), default_cvc);
    auto chaincode = tap_protocol::Bytes2Hex(tap_protocol::RandomChainCode());

    hwi->SetChain(tap_protocol::HWITapsigner::Chain::TESTNET);
    hwi->SetupDevice(chaincode);
    auto device_chaincode = hwi->GetChaincodeAtPath();

    CHECK(chaincode == device_chaincode);
  }
}

TEST_CASE("HWI Tapsigner test") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  std::unique_ptr<tap_protocol::Tapsigner> tapsigner =
      std::make_unique<tap_protocol::Tapsigner>(std::move(tp));

  auto hwi = tap_protocol::MakeHWITapsigner(tapsigner.get(), default_cvc);
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

  auto hwi = tap_protocol::MakeHWITapsigner(tapsigner.get(), default_cvc);
  hwi->SetChain(tap_protocol::HWITapsigner::Chain::TESTNET);

  auto signed_tx = hwi->SignTx(psbt);
  MESSAGE("sign psbt multisig: ", signed_tx);
}

TEST_CASE("sign psbt") {
  std::string psbt =
      R"(cHNidP8BAHECAAAAAbaRLv2dwhA2qDirXFYNC9kxbQi5zvIlJvhRgjlJcBdAAQAAAAD9////AhAnAAAAAAAAFgAUFXSeP6uXhBP8u1KfhTzbmWX3zqHsOJUAAAAAABYAFLvdDJXh7MI0aJDBJ/gP84Bu8GyrAAAAAAABAHECAAAAAXrmtsvP0awn2qYs/ZkvYFpuiWVqdvLC5lsQDus+Hg1nAQAAAAD9////AhAnAAAAAAAAFgAUPyYxfgarAm+2nXG+cmkATjuEpVSJYJUAAAAAABYAFMs/gBI6mDaaW9+mcSpkzNGdGKneAAAAAAEBH4lglQAAAAAAFgAUyz+AEjqYNppb36ZxKmTM0Z0Yqd4iBgNEOefOExaGH9c2ZsMeq8hM30iNM276iyKdbO7DJidy7hiTgGJuVAAAgAAAAIAAAACAAQAAAAIAAAAAACICAnSsqeOwIu1mHItlHQM+TyK3mH+qqVxgJX3MCyzHLcQhGJOAYm5UAACAAAAAgAAAAIABAAAAAwAAAAA=)";
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  std::unique_ptr<tap_protocol::Tapsigner> tapsigner =
      std::make_unique<tap_protocol::Tapsigner>(std::move(tp));

  auto hwi = tap_protocol::MakeHWITapsigner(tapsigner.get(), default_cvc);
  hwi->SetChain(tap_protocol::HWITapsigner::Chain::TESTNET);

  auto signed_tx = hwi->SignTx(psbt);

  CHECK(!signed_tx.empty());
}

TEST_CASE("sign message") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  std::unique_ptr<tap_protocol::Tapsigner> tapsigner =
      std::make_unique<tap_protocol::Tapsigner>(std::move(tp));

  auto hwi = tap_protocol::MakeHWITapsigner(tapsigner.get(), default_cvc);
  auto sig = hwi->SignMessage("nunchuk", "m/84h/0/0");
  CHECK(!sig.empty());
}

TEST_CASE("decrypt backup") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  std::unique_ptr<tap_protocol::Tapsigner> tapsigner =
      std::make_unique<tap_protocol::Tapsigner>(std::move(tp));

  auto hwi = tap_protocol::MakeHWITapsigner(tapsigner.get(), default_cvc);
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
  std::string expected =
      "tprv8ZgxMBicQKsPctUGYBjd5XBMn4TzcyFiuccf88VtCKaFUZend1nCDkmqPsNmhjMMehX7"
      "5AdbvPzqkQEF2S2zjGvjnCGT8g13WBmaL3nm7op\nm/44h\n";

  // MESSAGE("decrypted: ", decrypted_str);
  CHECK(decrypted == expected);
}

TEST_CASE("get xpub at path") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  std::unique_ptr<tap_protocol::Tapsigner> tapsigner =
      std::make_unique<tap_protocol::Tapsigner>(std::move(tp));

  auto hwi = tap_protocol::MakeHWITapsigner(tapsigner.get(), default_cvc);
  hwi->SetChain(tap_protocol::HWITapsigner::Chain::TESTNET);

  std::vector<std::string> ok = {
      "m/84'/1'/0'",     "m/84'/0'/0'",        "m/84'/0'/0'/0/0",
      "m/84'/1'/0'/1/0", "m/84'/1'/0'/1000/0", "m/84'/1'/0'/9999/9999/999/9999",
  };

  for (const std::string &path : ok) {
    auto xpub = hwi->GetXpubAtPath(path);
    CHECK(!xpub.empty());
  }

  std::vector<std::string> invalid = {
      "m/84'/0'/0'/0/0'",
      "m/84'/1'/0'/1/2147483648",
  };

  for (const std::string &path : invalid) {
    CHECK_THROWS_AS({ auto xpub = hwi->GetXpubAtPath(path); },
                    tap_protocol::TapProtoException);
  }
}

TEST_CASE("get xpub at path") {
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  std::unique_ptr<tap_protocol::Tapsigner> tapsigner =
      std::make_unique<tap_protocol::Tapsigner>(std::move(tp));

  auto hwi = tap_protocol::MakeHWITapsigner(tapsigner.get(), default_cvc);
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

TEST_SUITE_END();
