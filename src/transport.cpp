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
}  // namespace detail

TransportImpl::TransportImpl(SendReceiveFunction send_receive_func)
    : send_receive_func_(std::move(send_receive_func)) {}

json TransportImpl::Send(const json &msg) {
  auto cborRequest = json::to_cbor(msg);
  try {
    char cla = 0x00;
    char ins = 0xcb;
    char p1 = 0;
    char p2 = 0;
    auto lc = detail::size_to_lc(cborRequest.size());

    NdefMessage msg;
    msg.push_back(cla);
    msg.push_back(ins);
    msg.push_back(p1);
    msg.push_back(p2);
    msg.insert(end(msg), begin(lc), end(lc));
    msg.insert(end(msg), begin(cborRequest), end(cborRequest));

    NdefMessage response = send_receive_func_(msg);
    return json::from_cbor(response);
  } catch (json::exception &ex) {
    throw TapProtoException(TapProtoException::SERIALIZE_ERROR, ex.what());
  }
}

std::unique_ptr<Transport> MakeDefaultTransport(SendReceiveFunction func) {
  return std::make_unique<TransportImpl>(func);
}
}  // namespace tap_protocol
