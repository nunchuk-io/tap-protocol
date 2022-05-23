#include "tap_protocol/transport.h"

namespace tap_protocol {

namespace detail {
static constexpr int SW_OKAY = 0x9000;

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

static Bytes MakeAPDURequest(const json &msg) {
  auto cborRequest = json::to_cbor(msg);
  if (cborRequest.size() > 255) {
    throw TapProtoException(TapProtoException::MESSAGE_TOO_LONG,
                            "Message too long");
  }
  constexpr char cla = 0x00;
  constexpr char ins = 0xcb;
  constexpr char p1 = 0;
  constexpr char p2 = 0;
  auto lc = detail::SizeToLC(cborRequest.size());

  Bytes result;
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
    const auto request = detail::MakeAPDURequest(msg);

    Bytes response = send_receive_func_(request);
    // TODO: do something with 2 sw bytes
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
