#include "doctest.h"

#ifdef BUILD_TEST_WITH_EMULATOR
#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <stdexcept>

#include "tap_protocol/cktapcard.h"
#include "tap_protocol/transport.h"
#include "tap_protocol/tap_protocol.h"

using boost::asio::local::stream_protocol;

std::string hex_str(const std::vector<uint8_t>& msg) {
  std::stringstream result;
  for (auto&& c : msg) {
    result << std::hex << std::setw(2) << std::setfill('0') << int(c);
  }
  return result.str();
}

struct CardEmulator : public tap_protocol::Transport {
  boost::asio::io_service io_service;
  stream_protocol::socket socket;

  CardEmulator() : socket(io_service) { reconnect(); }
  ~CardEmulator() { std::cout << "~CardEmulator() called\n"; }

  void reconnect() { socket.connect("/tmp/ecard-pipe"); }

  json Send(const json& msg) override {
    auto cborRequest = json::to_cbor(msg);
    boost::system::error_code error;
    boost::asio::write(socket, boost::asio::buffer(cborRequest), error);
    if (error) {
      throw std::runtime_error(error.message() + "|" +
                               std::to_string(error.value()));
    } else {
      // write ok
    }
    boost::asio::streambuf receive_buffer;
    auto reply_length =
        boost::asio::read_until(socket, receive_buffer, '\n', error);

    if (error && error != boost::asio::error::eof) {
      throw std::runtime_error(error.message() + "|" +
                               std::to_string(error.value()));
    } else {
      const char* data =
          boost::asio::buffer_cast<const char*>(receive_buffer.data());
      std::string_view sv(data, receive_buffer.size());

      // TODO: not official emulator
      if (sv.front() == '\n') {
        sv.remove_prefix(1);
      }
      if (sv.back() == '\n') {
        sv.remove_suffix(1);
      }
      return json::from_cbor(sv);
    }
  };
};

std::unique_ptr<tap_protocol::Transport> tp = std::make_unique<CardEmulator>();

TEST_CASE("tapsigner status") {
  tap_protocol::TapSigner tapSigner(tp.get());
  json resp = tapSigner.Status();
}

#endif
