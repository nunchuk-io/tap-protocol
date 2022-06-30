#include "util/strencodings.h"
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/hash_utils.h"
#include "tap_protocol/utils.h"
#include "bech32.h"

namespace tap_protocol {
void to_json(nlohmann::json& j, const Satscard::UnsealResponse& t) {
  j = {
      {"slot", t.slot},
      {"privkey", t.privkey},
      {"pubkey", t.pubkey},
      {"master_pk", t.master_pk},
      {"chain_code", t.chain_code},
      {"card_nonce", t.card_nonce},
  };
}
void from_json(const nlohmann::json& j, Satscard::UnsealResponse& t) {
  t.slot = j.value("slot", t.slot);
  t.privkey = j.value("privkey", t.privkey);
  t.pubkey = j.value("pubkey", t.pubkey);
  t.master_pk = j.value("master_pk", t.master_pk);
  t.chain_code = j.value("chain_code", t.chain_code);
  t.card_nonce = j.value("card_nonce", t.card_nonce);
}

static std::string render_address(const Bytes& pubkey, bool testnet = false) {
  const Bytes witprog =
      Hash160(pubkey.size() == 32 ? CT_priv_to_pubkey(pubkey) : pubkey);
  Bytes input{0};
  bool ret = ConvertBits<8, 5, true>([&](int v) { input.push_back(v); },
                                     std::begin(witprog), std::end(witprog));
  assert(ret);

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

  if (!(addr.find(left) != std::string::npos &&
        addr.find(right) != std::string::npos && left.size() == right.size() &&
        left.size() == ADDR_TRIM)) {
    throw TapProtoException(TapProtoException::DEFAULT_ERROR,
                            "Corrupt response");
  }
  return std::make_pair(pubkey, addr);
};

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

Satscard::Satscard(std::unique_ptr<Transport> transport)
    : CKTapCard(std::move(transport), false) {
  FirstLook();
}

void Satscard::Update(const CKTapCard::StatusResponse& status) {
  CKTapCard::Update(status);
  active_slot_ = status.slots[0];
  num_slots_ = status.slots[1];
}

Satscard::UnsealResponse Satscard::Unseal(const std::string& cvc) {
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
  auto result = UnsealResponse(resp);
  result.privkey = XORBytes(session_key, result.privkey);
  return result;
}

Satscard::NewResponse Satscard::New(const Bytes& chain_code,
                                    const std::string& cvc) {
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
  active_slot_ = resp.slot;
  return resp;
}

std::string Satscard::Address(bool faster, int slot) {
  if (!IsCertsChecked() && !faster) {
    CertificateCheck();
  }
  const auto st = Status();
  int cur_slot = st.slots[0];
  if (st.addr.empty() && cur_slot == slot) {
    return {};
  }
  if (slot > cur_slot) {
    return {};
  }
  if (slot != cur_slot) {
    const auto dump = Send({
        {"cmd", "dump"},
        {"slot", slot},
    });
    return dump["addr"];
  }
  const auto nonce = json::binary_t(PickNonce());
  const auto read = Send({
      {"cmd", "read"},
      {"nonce", nonce},
  });

  auto [pubkey, addr] = recover_address(st, read, nonce);

  if (faster) {
    return addr;
  }

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

  return {};
}
}  // namespace tap_protocol
