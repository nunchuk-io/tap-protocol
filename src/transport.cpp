#include "tap_protocol/transport.h"
#include "tap_protocol/hwi_tapsigner.h"
#include <iostream>
#include <iterator>

namespace tap_protocol {
static constexpr unsigned char SW_OKAY_1 = 0x90;
static constexpr unsigned char SW_OKAY_2 = 0x00;
static constexpr unsigned char CLA = 0x00;
static constexpr unsigned char INS = 0xcb;
static constexpr unsigned char P1 = 0x0;
static constexpr unsigned char P2 = 0x0;
static constexpr std::array<unsigned char, 15> APP_ID = {
    0xf0, 0x43, 0x6f, 0x69, 0x6e, 0x6b, 0x69, 0x74,
    0x65, 0x43, 0x41, 0x52, 0x44, 0x76, 0x31,
};

static Bytes SizeToLC(size_t size) {
  if (size < 256) {
    return {static_cast<unsigned char>(size)};
  }
  return {static_cast<unsigned char>((size & 0xff00) >> 8),
          static_cast<unsigned char>((size & 0xff))};
}

static Bytes MakeAPDURequest(const Bytes &msg, unsigned char cla = CLA,
                             unsigned char ins = INS, unsigned char p1 = P1,
                             unsigned char p2 = P2) {
  if (msg.size() > 255) {
    throw TapProtoException(TapProtoException::MESSAGE_TOO_LONG,
                            "Message too long");
  }
  const auto lc = SizeToLC(msg.size());

  Bytes apdu;
  apdu.reserve(4 + lc.size() + msg.size());
  apdu.push_back(cla);
  apdu.push_back(ins);
  apdu.push_back(p1);
  apdu.push_back(p2);
  apdu.insert(end(apdu), begin(lc), end(lc));
  apdu.insert(end(apdu), begin(msg), end(msg));
  return apdu;
}

static bool IsSWOk(const Bytes &bytes) {
  if (bytes.size() < 2) {
    return false;
  }
  const auto [sw2, sw1] = std::tie(*rbegin(bytes), *std::next(rbegin(bytes)));

  if (sw1 != SW_OKAY_1 || sw2 != SW_OKAY_2) {
    return false;
  }
  return true;
}

TransportImpl::TransportImpl(SendReceiveFunction send_receive_func)
    : send_receive_func_(std::move(send_receive_func)) {
  ISOSelect();
}

void TransportImpl::ISOSelect() {
  const auto request =
      MakeAPDURequest({std::begin(APP_ID), std::end(APP_ID)}, 0x00, 0xa4, 0x4);
  Bytes response = send_receive_func_(request);
  if (!IsSWOk(response)) {
    throw TapProtoException(TapProtoException::ISO_SELECT_FAIL,
                            "ISO select failed");
  }
}

json TransportImpl::Send(const json &msg) {
  try {
    const auto request = MakeAPDURequest(json::to_cbor(msg));
    Bytes response = send_receive_func_(request);
    if (!IsSWOk(response)) {
      throw TapProtoException(TapProtoException::SW_FAIL, "SW failed");
    }
    if (response.size() > 2) {
      response.resize(response.size() - 2);
    }
    return json::from_cbor(response, false);
  } catch (json::exception &ex) {
    throw TapProtoException(TapProtoException::SERIALIZE_ERROR, ex.what());
  }
}

std::unique_ptr<Transport> MakeDefaultTransport(SendReceiveFunction func) {
  return std::make_unique<TransportImpl>(std::move(func));
}

std::unique_ptr<Transport> MakeDefaultTransportIOS(
    SendReceiveFunctionIOS func) {
  auto conv_func = [f = std::move(func)](const Bytes &req) {
    APDUResponse resp = f(APDURequest{
        req[0],
        req[1],
        req[2],
        req[3],
        {std::begin(req) + 4, std::end(req)},
    });
    resp.data.push_back(resp.sw1);
    resp.data.push_back(resp.sw2);
    return resp.data;
  };

  return std::make_unique<TransportImpl>(conv_func);
}
}  // namespace tap_protocol
