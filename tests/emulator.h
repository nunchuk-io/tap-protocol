#ifndef EMULATOR_H
#define EMULATOR_H
#ifdef BUILD_TEST_WITH_EMULATOR
#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <stdexcept>

#include "tap_protocol/cktapcard.h"
#include "tap_protocol/transport.h"

using boost::asio::local::stream_protocol;

// CardEmulator
// https://github.com/coinkite/coinkite-tap-proto/tree/master/emulator
struct CardEmulator : public tap_protocol::Transport {
  static boost::asio::io_service io_service_;
  static stream_protocol::socket socket_;

  CardEmulator() { connect(); }

  static void connect() {
    if (!socket_.is_open()) {
      socket_.connect("/tmp/ecard-pipe");
    }
  }

  json Send(const json& msg) override {
    auto cborRequest = json::to_cbor(msg);
    boost::system::error_code error;
    boost::asio::write(socket_, boost::asio::buffer(cborRequest), error);
    if (error) {
      throw std::runtime_error(error.message() + "|" +
                               std::to_string(error.value()));
    } else {
      // write ok
    }
    boost::asio::streambuf receive_buffer;
    boost::asio::read(socket_, receive_buffer,
                      boost::asio::transfer_at_least(1), error);

    if (error && error != boost::asio::error::eof) {
      throw std::runtime_error(error.message() + "|" +
                               std::to_string(error.value()));
    } else {
      const char* data =
          boost::asio::buffer_cast<const char*>(receive_buffer.data());
      return json::from_cbor(data, data + receive_buffer.size());
    }
  };
};

inline boost::asio::io_service CardEmulator::io_service_;
inline stream_protocol::socket CardEmulator::socket_ =
    boost::asio::local::stream_protocol::socket(CardEmulator::io_service_);
#endif
#endif
