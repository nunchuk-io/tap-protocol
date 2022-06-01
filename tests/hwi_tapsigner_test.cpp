#include "doctest.h"
#include "tap_protocol/hwi_tapsigner.h"
#include <fstream>
#include <memory>

TEST_CASE("input psbt") {
  // std::string path =
  //     "/home/giahuy/Documents/nunchuk/"
  //     "transaction_"
  //     "16f027c47873bf9b252ed9bcb5adfd84ce9a2320520d2863a269851a546fd5e9.txt";
  //
  // std::ifstream ifs(path);
  // std::string base64_psbt;
  // std::getline(ifs, base64_psbt);
  //
  // auto hwi = tap_protocol::MakeHWITapSigner();
  // auto signed_tx = hwi->SignTx(base64_psbt);
  //
  // MESSAGE("signed_tx:", signed_tx);
}
