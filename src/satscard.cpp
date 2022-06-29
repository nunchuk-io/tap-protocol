#include <iostream>
#include "tap_protocol/cktapcard.h"
#include "tap_protocol/utils.h"

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

Satscard::Satscard(std::unique_ptr<Transport> transport)
    : CKTapCard(std::move(transport)) {
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
  if (!certs_checked && !faster) {
    CertificateCheck();
  }
  auto st = Status();
  int cur_slot = st.slots[0];
  if (st.addr.empty() && cur_slot == slot) {
    return {};
  }
  if (slot != cur_slot) {
    auto dump = Send({
        {"cmd", "dump"},
        {"slot", slot},
    });
    return dump["addr"];
  }
  return {};
}
}  // namespace tap_protocol
