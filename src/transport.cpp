#include "tap_protocol/transport.h"
#include <iostream>

namespace tap_protocol {
static constexpr unsigned char SW_OKAY_1 = 0x90;
static constexpr unsigned char SW_OKAY_2 = 0x00;
static constexpr unsigned char CLA = 0x00;
static constexpr unsigned char INS = 0xcb;
static constexpr unsigned char P1 = 0x0;
static constexpr unsigned char P2 = 0x0;
static const Bytes APP_ID = {0xf0, 0x43, 0x6f, 0x69, 0x6e, 0x6b, 0x69, 0x74,
                             0x65, 0x43, 0x41, 0x52, 0x44, 0x76, 0x31};

namespace detail {
static std::vector<char> SizeToLC(size_t size) {
  if (size < 256) {
    return {static_cast<char>(size)};
  }
  return {static_cast<char>((size & 0xff00) >> 8),
          static_cast<char>((size & 0xff))};
}

static std::string Hex2Str(const std::vector<uint8_t> &msg) {
  std::ostringstream result;
  for (auto &&c : msg) {
    result << std::hex << std::setw(2) << std::setfill('0') << int(c);
  }
  return result.str();
}

static Bytes MakeAPDURequest(const Bytes &msg, char cla = CLA, char ins = INS,
                             char p1 = P1, char p2 = P2) {
  if (msg.size() > 255) {
    throw TapProtoException(TapProtoException::MESSAGE_TOO_LONG,
                            "Message too long");
  }
  auto lc = detail::SizeToLC(msg.size());

  Bytes result;
  result.push_back(cla);
  result.push_back(ins);
  result.push_back(p1);
  result.push_back(p2);
  result.insert(end(result), begin(lc), end(lc));
  result.insert(end(result), begin(msg), end(msg));
  return result;
}

static bool IsSWOk(const Bytes &bytes) {
  if (bytes.size() < 2) {
    return false;
  }
  auto [sw2, sw1] = std::tie(*rbegin(bytes), *std::next(rbegin(bytes)));

  if (sw1 != SW_OKAY_1 || sw2 != SW_OKAY_2) {
    return false;
  }
  return true;
}
}  // namespace detail

TransportImpl::TransportImpl(SendReceiveFunction send_receive_func)
    : send_receive_func_(std::move(send_receive_func)) {
  const auto request = detail::MakeAPDURequest(APP_ID, 0x00, 0xa4, 0x4);
  Bytes response = send_receive_func_(request);
  if (!detail::IsSWOk(response)) {
    throw TapProtoException(TapProtoException::ISO_APP_SELECT_FAILED,
                            "ISO app select failed");
  }
}

json TransportImpl::Send(const json &msg) {
  try {
    const auto request = detail::MakeAPDURequest(json::to_cbor(msg));
    Bytes response = send_receive_func_(request);
    if (!detail::IsSWOk(response)) {
      throw TapProtoException(TapProtoException::SW_FAIL, "SW failed");
    }
    if (response.size() > 2) {
      response.resize(response.size() - 2);
    }
    return json::from_cbor(response);
  } catch (json::exception &ex) {
    throw TapProtoException(TapProtoException::SERIALIZE_ERROR, ex.what());
  }
}

std::unique_ptr<Transport> MakeDefaultTransport(SendReceiveFunction func) {
  return std::make_unique<TransportImpl>(func);
}
}  // namespace tap_protocol
