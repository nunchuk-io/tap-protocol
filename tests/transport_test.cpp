#include <doctest.h>
#include <iostream>
#include <string>
#include "emulator.h"
#include "tap_protocol/tap_protocol.h"
#include "tap_protocol/transport.h"

using json = nlohmann::json;

TEST_CASE("receive invalid cbor") {
  CHECK_THROWS_AS(
      {
        auto sendReceiveFunc = [](const tap_protocol::Bytes& msg) {
          return tap_protocol::Bytes{};
        };

        auto tp = tap_protocol::MakeDefaultTransport(sendReceiveFunc);

        auto resp = tp->Send({{"cmd", "status"}});
      },
      tap_protocol::TapProtoException);
}

TEST_CASE("decode cbor ok") {
  json j = json::parse(R"(
{
  "address": "",
  "birth": 700001,
  "card_nonce": {
    "bytes": [220, 181, 216, 210, 239, 27, 50, 31, 206, 173, 55, 127, 98, 97, 229, 71],
    "subtype": null
  },
  "path": [
    2147483732,
    2147483648,
    2147483648
  ],
  "proto": 1,
  "pubkey": {
    "bytes": [3, 50, 131, 14, 50, 9, 233, 80, 149, 122, 211, 150, 76, 34, 63, 136, 248, 223, 97, 218, 210, 247, 22, 8, 127, 92, 51, 109, 166, 51, 114, 165, 110],
    "subtype": null
  },
  "tapsigner": true,
  "ver": "0.1.0"
}
)");

  auto sendReceiveFunc = [=](const tap_protocol::Bytes& msg) {
    auto res = json::to_cbor(j);
    res.push_back(0x90);
    res.push_back(0x00);
    // Two more sw bytes
    return res;
  };

  auto tp = tap_protocol::MakeDefaultTransport(sendReceiveFunc);
  auto resp = tp->Send({{"cmd", "status"}});

  CHECK(resp == j);
}

TEST_CASE("ios transport") {
  json j = json::parse(R"(
{
  "address": "",
  "birth": 700001,
  "card_nonce": {
    "bytes": [220, 181, 216, 210, 239, 27, 50, 31, 206, 173, 55, 127, 98, 97, 229, 71],
    "subtype": null
  },
  "path": [
    2147483732,
    2147483648,
    2147483648
  ],
  "proto": 1,
  "pubkey": {
    "bytes": [3, 50, 131, 14, 50, 9, 233, 80, 149, 122, 211, 150, 76, 34, 63, 136, 248, 223, 97, 218, 210, 247, 22, 8, 127, 92, 51, 109, 166, 51, 114, 165, 110],
    "subtype": null
  },
  "tapsigner": true,
  "ver": "0.1.0"
}
)");

  auto sendReceiveFuncIOS = [=](const tap_protocol::APDURequest& req) {
    MESSAGE("cla = ", int(req.cla));
    MESSAGE("ins = ", int(req.ins));
    MESSAGE("p1 = ", int(req.p1));
    MESSAGE("p2 = ", int(req.p2));
    auto data = json::to_cbor(j);
    // Two more sw bytes
    return tap_protocol::APDUResponse{.data = data, .sw1 = 0x90, .sw2 = 0x00};
  };

  auto tp = tap_protocol::MakeDefaultTransportIOS(sendReceiveFuncIOS);
  auto resp = tp->Send({{"cmd", "status"}});

  CHECK(resp == j);
}
