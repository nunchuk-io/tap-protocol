#include "base58.h"
#include "support/cleanse.h"
#include "util/strencodings.h"
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/hash_utils.h"
#include "tap_protocol/utils.h"
#include "bech32.h"

#include <iostream>

namespace tap_protocol {

static std::string render_address(const Bytes& pubkey, bool testnet = false) {
  const Bytes witprog =
      Hash160(pubkey.size() == 32 ? CT_priv_to_pubkey(pubkey) : pubkey);
  Bytes input{0};
  input.reserve(1 + witprog.size() * 8 / 5);
  bool ret = ConvertBits<8, 5, true>([&](int v) { input.push_back(v); },
                                     std::begin(witprog), std::end(witprog));
  if (!ret) {
    throw TapProtoException(TapProtoException::DEFAULT_ERROR,
                            "Render address error");
  }

  return bech32::Encode(bech32::Encoding::BECH32, testnet ? "tb" : "bc", input);
}

static auto recover_address(const json& status, const json& read,
                            const Bytes& my_nonce) {
  int slot = status["slots"][0];
  const json::binary_t card_nonce = status["card_nonce"];
  Bytes msg;
  msg.reserve(std::size(OPENDIME) + card_nonce.size() + my_nonce.size() + 1);
  msg.insert(std::end(msg), std::begin(OPENDIME), std::end(OPENDIME));
  msg.insert(std::end(msg), std::begin(card_nonce), std::end(card_nonce));
  msg.insert(std::end(msg), std::begin(my_nonce), std::end(my_nonce));
  msg.push_back(slot);
  if (msg.size() !=
      std::size(OPENDIME) + CARD_NONCE_SIZE + USER_NONCE_SIZE + 1) {
    throw TapProtoException(TapProtoException::INVALID_CARD,
                            "Invalid msg size " + std::to_string(msg.size()));
  }

  const Bytes pubkey = read["pubkey"].get<json::binary_t>();
  if (!CT_sig_verify(pubkey, SHA256(msg), read["sig"].get<json::binary_t>())) {
    throw TapProtoException(TapProtoException::SIG_VERIFY_ERROR,
                            "Bad sig in recover_address");
  }

  const std::string expect = status["addr"];
  const std::string_view sv_expect(expect);

  const std::string_view left =
      sv_expect.substr(0, sv_expect.find_first_of('_'));
  const std::string_view right =
      sv_expect.substr(sv_expect.find_last_of('_') + 1);

  const std::string addr =
      render_address(pubkey, status.value("testnet", false));
  static constexpr int ADDR_TRIM = 12;

  if (!(left.size() == right.size() && left.size() == ADDR_TRIM &&
        addr.find(left) != std::string::npos &&
        addr.find(right) != std::string::npos)) {
    throw TapProtoException(TapProtoException::DEFAULT_ERROR,
                            "Corrupt response");
  }
  return std::make_pair(pubkey, addr);
};

static std::string EncodeSecret(const Bytes& privkey, bool is_testnet) {
  static constexpr unsigned char MAINNET_SECRET_KEY = 0x80;
  static constexpr unsigned char TESTNET_SECRET_KEY = 0xef;

  std::vector<unsigned char> data{is_testnet ? TESTNET_SECRET_KEY
                                             : MAINNET_SECRET_KEY};
  data.insert(std::end(data), std::begin(privkey), std::end(privkey));
  data.push_back(0x1);

  std::string ret = EncodeBase58Check(data);
  memory_cleanse(data.data(), data.size());
  return ret;
}

static auto verify_master_pubkey(const Bytes& pub, const Bytes& sig,
                                 const Bytes& chain_code, const Bytes& my_nonce,
                                 const Bytes& card_nonce) {
  Bytes msg;
  msg.reserve(std::size(OPENDIME) + card_nonce.size() + my_nonce.size() +
              chain_code.size());
  msg.insert(std::end(msg), std::begin(OPENDIME), std::end(OPENDIME));
  msg.insert(std::end(msg), std::begin(card_nonce), std::end(card_nonce));
  msg.insert(std::end(msg), std::begin(my_nonce), std::end(my_nonce));
  msg.insert(std::end(msg), std::begin(chain_code), std::end(chain_code));

  if (msg.size() !=
      std::size(OPENDIME) + CARD_NONCE_SIZE + USER_NONCE_SIZE + 32) {
    throw TapProtoException(TapProtoException::DEFAULT_ERROR,
                            "Invalid msg size " + std::to_string(msg.size()));
  }

  if (!CT_sig_verify(pub, SHA256(msg), sig)) {
    throw TapProtoException(TapProtoException::SIG_VERIFY_ERROR,
                            "Bad sig in verify_master_pubkey");
  }
  return pub;
};

std::string Satscard::Slot::to_wif(bool testnet) const {
  if (privkey.size() != 32) {
    throw TapProtoException(TapProtoException::INVALID_PRIVKEY,
                            "Empty or invalid privkey length");
  }
  return EncodeSecret(privkey, testnet);
}

Satscard::Satscard(std::unique_ptr<Transport> transport)
    : CKTapCard(std::move(transport), false) {
  auto st = FirstLook();
  // TODO(giahuy): Should check certs here?

  if (GetActiveSlotStatus() == SlotStatus::SEALED) {
    RenderActiveSlotAddress(st);
  }
}

void Satscard::RenderActiveSlotAddress(const StatusResponse& status) {
  if (status.addr.empty()) {
    address_.clear();
    render_address_.clear();
    return;
  }
  const auto nonce = json::binary_t(PickNonce());
  const auto read = Send({
      {"cmd", "read"},
      {"nonce", nonce},
  });
  auto [pubkey, addr] = recover_address(status, read, nonce);
  render_address_ = addr;

  return;
  // TODO(giahuy): Implement additional check
  const Bytes my_nonce = json::binary_t(PickNonce());
  const Bytes card_nonce = read["card_nonce"].get<json::binary_t>();
  const json derive = Send({
      {"cmd", "derive"},
      {"nonce", my_nonce},
  });

  const Bytes master_pub = verify_master_pubkey(
      derive["master_pubkey"].get<json::binary_t>(),
      derive["sig"].get<json::binary_t>(),
      derive["chain_code"].get<json::binary_t>(), my_nonce, card_nonce);
}

void Satscard::Update(const CKTapCard::StatusResponse& status) {
  CKTapCard::Update(status);
  active_slot_ = status.slots[0];
  num_slots_ = status.slots[1];
  address_ = status.addr;
}

Satscard::Slot Satscard::Unseal(const std::string& cvc) {
  int target = active_slot_;
  const auto dump = Send({
      {"cmd", "dump"},
      {"slot", target},
  });
  if (auto used = dump.find("used"); used != std::end(dump) && !*used) {
    throw TapProtoException(TapProtoException::BAD_ARGUMENTS,
                            "Slot has not been used yet.");
  }
  if (auto sealed = dump.find("sealed"); sealed != std::end(dump) && !*sealed) {
    throw TapProtoException(TapProtoException::BAD_ARGUMENTS,
                            "Slot has already been unsealed.");
  }

  const auto [session_key, resp] = SendAuth(
      {
          {"cmd", "unseal"},
          {"slot", target},
      },
      {std::begin(cvc), std::end(cvc)});

  auto result = Slot{
      resp["slot"],
      SlotStatus::UNSEALED,
      render_address_,
      XORBytes(resp["privkey"].get<json::binary_t>(), session_key),
      resp["pubkey"],
      XORBytes(resp["master_pk"].get<json::binary_t>(), session_key),
      resp["chain_code"],
  };

  // move to next slot 'unused' or used up
  active_slot_ = resp["slot"].get<int>() + 1;
  // also clear address
  RenderActiveSlotAddress({});

  return result;
}

Satscard::Slot Satscard::New(const Bytes& chain_code, const std::string& cvc) {
  int target = active_slot_;

  const auto dump = Send({
      {"cmd", "dump"},
      {"slot", target},
  });
  if (auto used = dump.find("used"); used != std::end(dump) && *used) {
    throw TapProtoException(
        TapProtoException::BAD_ARGUMENTS,
        "Slot has been used already. Unseal it, and move to next");
  }
  auto resp = CKTapCard::New(chain_code, cvc, target);
  RenderActiveSlotAddress(Status());
  active_slot_ = resp.slot;
  return GetActiveSlot();
}

Satscard::Slot Satscard::GetSlot(int slot, const std::string& cvc) {
  if (slot >= num_slots_) {
    throw TapProtoException(TapProtoException::BAD_ARGUMENTS, "Invalid slot");
  }

  if (slot > active_slot_) {
    return Slot{
        slot,
        SlotStatus::UNUSED,
    };
  }

  if (slot == active_slot_) {
    return GetActiveSlot();
  }

  if (cvc.empty()) {
    // all slots < active_slot are unsealed
    auto dump = Send({
        {"cmd", "dump"},
        {"slot", slot},
    });
    return Slot{
        dump["slot"],
        SlotStatus::UNSEALED,
        std::move(dump["addr"]),
    };
  }

  auto [session_key, dump] = SendAuth(
      {
          {"cmd", "dump"},
          {"slot", slot},
      },
      {std::begin(cvc), std::end(cvc)});

  return Slot{
      dump["slot"],
      SlotStatus::UNSEALED,
      render_address(dump["pubkey"].get<json::binary_t>(), IsTestnet()),
      XORBytes(dump["privkey"].get<json::binary_t>(), session_key),
      dump["pubkey"].get<json::binary_t>(),
      XORBytes(dump["master_pk"].get<json::binary_t>(), session_key),
      dump["chain_code"],
  };
}

std::vector<Satscard::Slot> Satscard::ListSlots(const std::string& cvc,
                                                size_t limit) {
  std::vector<Satscard::Slot> result;
  result.reserve(limit);

  for (size_t slot = 0; slot < limit; ++slot) {
    result.push_back(GetSlot(slot, cvc));
  }

  return result;
}

Satscard::Slot Satscard::GetActiveSlot() const {
  if (active_slot_ == num_slots_) {
    throw TapProtoException(TapProtoException::INVALID_SLOT, "Card is used up");
  }
  return Slot{
      active_slot_,
      GetActiveSlotStatus(),
      render_address_,
  };
}

int Satscard::GetNumSlots() const noexcept { return num_slots_; }
int Satscard::GetActiveSlotIndex() const noexcept { return active_slot_; }

Satscard::SlotStatus Satscard::GetActiveSlotStatus() const noexcept {
  if (active_slot_ == num_slots_) {
    return SlotStatus::UNSEALED;
  }

  if (address_.empty()) {
    return SlotStatus::UNUSED;
  }

  return SlotStatus::SEALED;
}

bool Satscard::HasUnusedSlots() const noexcept {
  return (GetActiveSlotStatus() == SlotStatus::UNUSED) ||
         (active_slot_ + 1 < num_slots_);
}

bool Satscard::IsUsedUp() const noexcept {
  return (active_slot_ == num_slots_) ||
         (active_slot_ == num_slots_ - 1 &&
          GetActiveSlotStatus() == SlotStatus::UNSEALED);
}

bool Satscard::NeedSetup() const noexcept {
  return GetActiveSlotStatus() == SlotStatus::UNUSED;
}

}  // namespace tap_protocol
