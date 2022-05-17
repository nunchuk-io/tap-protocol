#include <doctest.h>
#include <iostream>
#include <string>
#include "tap_protocol/transport.h"

using json = nlohmann::json;

TEST_CASE("receive invalid cbor") {
  CHECK_THROWS_AS(
      {
        auto sendReceiveFunc = [](const tap_protocol::NdefMessage& msg) {
          std::cout << std::hex;
          for (auto& m : msg) {
            std::cout << std::setw(2) << std::setfill('0') << (int)m;
          }

          return tap_protocol::NdefMessage{};
        };

        auto tp = tap_protocol::MakeDefaultTransport(sendReceiveFunc);

        auto resp = tp->Send({{"cmd", "status"}});
      },
      tap_protocol::TapProtoException);
}
