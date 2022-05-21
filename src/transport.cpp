#include "tap_protocol/transport.h"

namespace tap_protocol {

namespace detail {
std::vector<char> size_to_lc(size_t size) {
  if (size < 256) {
    return {static_cast<char>(size)};
  }
  return {static_cast<char>((size & 0xff00) >> 8),
          static_cast<char>((size & 0xff))};
}

std::string hex_str(const std::vector<uint8_t> &msg) {
  std::stringstream result;
  for (auto &&c : msg) {
    result << std::hex << std::setw(2) << std::setfill('0') << int(c);
  }
  return result.str();
}

NdefMessage make_apdu_request(const json &msg) {
  auto cborRequest = json::to_cbor(msg);
  constexpr char cla = 0x00;
  constexpr char ins = 0xcb;
  constexpr char p1 = 0;
  constexpr char p2 = 0;
  auto lc = detail::size_to_lc(cborRequest.size());

  NdefMessage result;
  result.push_back(cla);
  result.push_back(ins);
  result.push_back(p1);
  result.push_back(p2);
  result.insert(end(result), begin(lc), end(lc));
  result.insert(end(result), begin(cborRequest), end(cborRequest));
  return result;
}
}  // namespace detail

TransportImpl::TransportImpl(SendReceiveFunction send_receive_func)
    : send_receive_func_(std::move(send_receive_func)) {}

json TransportImpl::Send(const json &msg) {
  try {
    const auto request = detail::make_apdu_request(msg);
    NdefMessage response = send_receive_func_(request);
    // TODO: get sw from card
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
