#include "doctest.h"

#ifdef BUILD_TEST_WITH_EMULATOR
#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <stdexcept>

#include "tap_protocol/cktapcard.h"
#include "tap_protocol/transport.h"

using boost::asio::local::stream_protocol;

static boost::asio::io_service io_service_;
static stream_protocol::socket socket_ =
    boost::asio::local::stream_protocol::socket(io_service_);

// CardEmulator
// https://github.com/coinkite/coinkite-tap-proto/tree/master/emulator
struct CardEmulator : public tap_protocol::Transport {
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

TEST_CASE("tapsigner status emulator") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  tap_protocol::TapSigner tapSigner(std::move(tp));

  // When call 'status'
  auto resp = tapSigner.Status();

  // Then return proto version = 1
  CHECK(resp.proto == 1);

  std::cout << json(resp).dump(2) << "\n";
}

TEST_CASE("get nfc url") {
  // Given card
  std::unique_ptr<tap_protocol::Transport> tp =
      std::make_unique<CardEmulator>();

  tap_protocol::TapSigner tapSigner(std::move(tp));

  // When call 'nfc'
  auto resp = tapSigner.NFC();

  // Then return url start with "https://tapsigner.com"
  const std::string url = "https://tapsigner.com";
  CHECK(url == resp.substr(0, url.size()));

  std::cout << "card nfc url: " << resp << "\n";
}

#endif
