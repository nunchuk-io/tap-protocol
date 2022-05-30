#ifndef TRANSPORT_H
#define TRANSPORT_H

#include "tap_protocol.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

namespace tap_protocol {

class Transport {
 public:
  virtual ~Transport() = default;
  virtual json Send(const json &msg) = 0;
};

class TransportImpl : public Transport {
 public:
  explicit TransportImpl(SendReceiveFunction send_receive_func);
  ~TransportImpl() override = default;

  json Send(const json &msg) override;

 private:
  void ISOAppSelect();
  SendReceiveFunction send_receive_func_;
};

std::unique_ptr<Transport> MakeDefaultTransport(SendReceiveFunction func);
std::unique_ptr<Transport> MakeDefaultTransportIOS(SendReceiveFunctionIOS func);

}  // namespace tap_protocol

#endif  // TRANSPORT_H
