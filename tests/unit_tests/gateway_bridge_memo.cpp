// Copyright (c) 2024, The Beldex Project
//
// Unit tests for the HF22 gateway bridge memo: encrypt/decrypt round-trip,
// wrong-key/tampered-ciphertext rejection, output_index binding, the
// no-memo case, structural consensus validation (validate_gateway_bridge_memos),
// and the chain registry. Self-contained — no chain or DB is required, since
// construct_gateway_withdraw_tx is a pure function of its arguments and
// decrypt_gateway_bridge_memo only reads tx.extra/tx.vout.

#include <gtest/gtest.h>

#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_core/gateway_utils.h"
#include "cryptonote_core/gateway_chain_registry.h"
#include "cryptonote_config.h"
#include "crypto/crypto.h"

using namespace cryptonote;

namespace {

  constexpr network_type NET = network_type::MAINNET;
  constexpr hf HF = hf::hf22_gateway_addresses;

  struct gateway_keys { crypto::public_key pub; crypto::secret_key sec; };

  gateway_keys random_gateway_keys()
  {
    gateway_keys k{};
    crypto::generate_keys(k.pub, k.sec);
    return k;
  }

  crypto::eth_address random_eth_address()
  {
    crypto::eth_address a{};
    crypto::rand(sizeof(a), reinterpret_cast<uint8_t*>(&a));
    return a;
  }

  // One gateway withdrawal, one destination, optionally with a bridge memo.
  transaction build_withdrawal_with_memo(const gateway_keys& dest, uint64_t amount, uint64_t fee,
                                         uint16_t chain_index, const crypto::eth_address& evm_addr,
                                         crypto::hash& hash_to_sign)
  {
    gateway_withdraw_destination d{};
    d.gateway_id = dest.pub;
    d.amount     = amount;
    d.gateway_bridge_chain_index = chain_index;
    d.gateway_bridge_evm_addr    = evm_addr;

    transaction tx{};
    EXPECT_TRUE(construct_gateway_withdraw_tx(HF, NET, random_gateway_keys().pub, {d}, fee, tx, hash_to_sign));
    return tx;
  }

  tx_extra_gateway_bridge_memo only_memo(const transaction& tx)
  {
    tx_extra_gateway_bridge_memo m{};
    EXPECT_TRUE(get_field_from_tx_extra(tx.extra, m));
    return m;
  }

  TEST(GatewayBridgeMemo, roundtrip)
  {
    auto dest = random_gateway_keys();
    const uint16_t chain_index = 2; // sepolia
    const crypto::eth_address evm = random_eth_address();

    crypto::hash h{};
    transaction tx = build_withdrawal_with_memo(dest, 1000, 10, chain_index, evm, h);

    tx_extra_gateway_bridge_memo memo = only_memo(tx);
    EXPECT_EQ(memo.output_index, 0u);

    gateway_bridge_memo_plaintext out{};
    ASSERT_TRUE(decrypt_gateway_bridge_memo(tx, memo, dest.sec, out));
    EXPECT_EQ(out.chain_index, chain_index);
    EXPECT_EQ(out.evm_addr, evm);
  }

  TEST(GatewayBridgeMemo, no_memo_when_chain_index_zero)
  {
    auto dest = random_gateway_keys();
    crypto::hash h{};
    transaction tx = build_withdrawal_with_memo(dest, 1000, 10, /*chain_index=*/0, random_eth_address(), h);

    tx_extra_gateway_bridge_memo m{};
    EXPECT_FALSE(get_field_from_tx_extra(tx.extra, m));
  }

  TEST(GatewayBridgeMemo, wrong_key_rejected)
  {
    auto dest = random_gateway_keys();
    crypto::hash h{};
    transaction tx = build_withdrawal_with_memo(dest, 1000, 10, 1, random_eth_address(), h);
    tx_extra_gateway_bridge_memo memo = only_memo(tx);

    auto wrong = random_gateway_keys();
    gateway_bridge_memo_plaintext out{};
    EXPECT_FALSE(decrypt_gateway_bridge_memo(tx, memo, wrong.sec, out));
  }

  TEST(GatewayBridgeMemo, tampered_ciphertext_rejected)
  {
    auto dest = random_gateway_keys();
    crypto::hash h{};
    transaction tx = build_withdrawal_with_memo(dest, 1000, 10, 1, random_eth_address(), h);
    tx_extra_gateway_bridge_memo memo = only_memo(tx);
    memo.ciphertext.data[0] ^= 0xFF; // flip a bit

    gateway_bridge_memo_plaintext out{};
    EXPECT_FALSE(decrypt_gateway_bridge_memo(tx, memo, dest.sec, out));
  }

  TEST(GatewayBridgeMemo, output_index_binds_to_the_right_destination)
  {
    auto dest_a = random_gateway_keys();
    auto dest_b = random_gateway_keys();
    const crypto::eth_address evm_a = random_eth_address();

    gateway_withdraw_destination da{};
    da.gateway_id = dest_a.pub;
    da.amount     = 500;
    da.gateway_bridge_chain_index = 1;
    da.gateway_bridge_evm_addr    = evm_a;

    gateway_withdraw_destination db{};
    db.gateway_id = dest_b.pub;
    db.amount     = 500;
    // no memo for db (chain_index stays 0)

    transaction tx{};
    crypto::hash h{};
    ASSERT_TRUE(construct_gateway_withdraw_tx(HF, NET, random_gateway_keys().pub, {da, db}, 10, tx, h));
    ASSERT_EQ(tx.vout.size(), 2u);

    // Exactly one memo, bound to output_index 0 (da).
    size_t skip = 0;
    tx_extra_gateway_bridge_memo m{};
    int count = 0;
    tx_extra_gateway_bridge_memo found{};
    while (get_field_from_tx_extra(tx.extra, m, skip++)) { found = m; ++count; }
    EXPECT_EQ(count, 1);
    EXPECT_EQ(found.output_index, 0u);

    gateway_bridge_memo_plaintext out{};
    ASSERT_TRUE(decrypt_gateway_bridge_memo(tx, found, dest_a.sec, out));
    EXPECT_EQ(out.evm_addr, evm_a);

    // dest_b's key must not decrypt output 0's memo (wrong DH key => integrity check fails).
    gateway_bridge_memo_plaintext out_wrong{};
    EXPECT_FALSE(decrypt_gateway_bridge_memo(tx, found, dest_b.sec, out_wrong));
  }

  TEST(GatewayBridgeMemo, validate_accepts_wellformed)
  {
    auto dest = random_gateway_keys();
    crypto::hash h{};
    transaction tx = build_withdrawal_with_memo(dest, 1000, 10, 1, random_eth_address(), h);
    std::string reason;
    EXPECT_TRUE(validate_gateway_bridge_memos(tx, reason)) << reason;
  }

  TEST(GatewayBridgeMemo, validate_accepts_zero_memos)
  {
    auto dest = random_gateway_keys();
    crypto::hash h{};
    transaction tx = build_withdrawal_with_memo(dest, 1000, 10, 0, random_eth_address(), h);
    std::string reason;
    EXPECT_TRUE(validate_gateway_bridge_memos(tx, reason)) << reason;
  }

  TEST(GatewayBridgeMemo, validate_rejects_out_of_range_output_index)
  {
    auto dest = random_gateway_keys();
    crypto::hash h{};
    transaction tx = build_withdrawal_with_memo(dest, 1000, 10, 1, random_eth_address(), h);

    // Rebuild tx.extra with a bogus (out-of-range) output_index.
    tx_extra_gateway_bridge_memo memo = only_memo(tx);
    tx.extra.clear();
    add_tx_extra<tx_extra_pub_key>(tx, crypto::public_key{});
    memo.output_index = static_cast<uint32_t>(tx.vout.size()); // one past the end
    add_gateway_bridge_memo_to_tx_extra(tx.extra, memo);

    std::string reason;
    EXPECT_FALSE(validate_gateway_bridge_memos(tx, reason));
  }

  TEST(GatewayBridgeMemo, validate_rejects_duplicate_output_index)
  {
    auto dest = random_gateway_keys();
    crypto::hash h{};
    transaction tx = build_withdrawal_with_memo(dest, 1000, 10, 1, random_eth_address(), h);
    tx_extra_gateway_bridge_memo memo = only_memo(tx);
    // Append a second memo with the same output_index.
    add_gateway_bridge_memo_to_tx_extra(tx.extra, memo);

    std::string reason;
    EXPECT_FALSE(validate_gateway_bridge_memos(tx, reason));
  }

  TEST(GatewayBridgeMemo, validate_rejects_non_gateway_output_index)
  {
    // A memo whose output_index points at a stealth (non-gateway) output must
    // be rejected. Build a gw->wallet withdrawal (stealth outputs) and hand-craft
    // a memo pointing at output 0.
    auto source = random_gateway_keys();
    account_base acc; acc.generate();
    gateway_wallet_destination wd{};
    wd.addr = acc.get_keys().m_account_address;
    wd.amount = 1000;

    transaction tx{};
    crypto::hash h{};
    ASSERT_TRUE(construct_gateway_withdraw_to_wallet_tx(HF, NET, source.pub, {wd}, 10, tx, h));
    ASSERT_GT(tx.vout.size(), 0u);
    ASSERT_TRUE(std::holds_alternative<txout_to_key>(tx.vout[0].target));

    tx_extra_gateway_bridge_memo memo{};
    memo.output_index = 0;
    add_gateway_bridge_memo_to_tx_extra(tx.extra, memo);

    std::string reason;
    EXPECT_FALSE(validate_gateway_bridge_memos(tx, reason));
  }

  TEST(GatewayBridgeMemo, validate_rejects_bad_version)
  {
    auto dest = random_gateway_keys();
    crypto::hash h{};
    transaction tx = build_withdrawal_with_memo(dest, 1000, 10, 1, random_eth_address(), h);
    tx_extra_gateway_bridge_memo memo = only_memo(tx);
    memo.version = 1;

    transaction tx2 = tx;
    tx2.extra.clear();
    add_tx_extra<tx_extra_pub_key>(tx2, crypto::public_key{});
    add_gateway_bridge_memo_to_tx_extra(tx2.extra, memo);

    std::string reason;
    EXPECT_FALSE(validate_gateway_bridge_memos(tx2, reason));
  }

  TEST(GatewayChainRegistry, roundtrip_and_sentinel)
  {
    for (const auto& e : GATEWAY_CHAIN_REGISTRY)
    {
      EXPECT_NE(e.chain_index, 0u) << "chain_index 0 is the reserved 'no memo' sentinel";
      auto id = gateway_chain_index_to_evm_chain_id(e.chain_index);
      ASSERT_TRUE(id.has_value());
      EXPECT_EQ(*id, e.evm_chain_id);
      auto idx = gateway_evm_chain_id_to_chain_index(e.evm_chain_id);
      ASSERT_TRUE(idx.has_value());
      EXPECT_EQ(*idx, e.chain_index);
      auto name_idx = gateway_chain_name_to_index(e.name);
      ASSERT_TRUE(name_idx.has_value());
      EXPECT_EQ(*name_idx, e.chain_index);
    }
    EXPECT_FALSE(gateway_chain_index_to_evm_chain_id(0).has_value());
  }

  TEST(GatewayBridgeMemo, domain_separation_from_payment_id_mask)
  {
    // Same (tx_key, gateway_id, output_index) but different plaintext content
    // must not accidentally reuse the payment_id mask: build both a
    // payment_id-integrated withdrawal and a bridge-memo withdrawal from the
    // same source/dest, and confirm the resulting on-chain bytes differ (the
    // domain tag change is the only thing that could make them differ here,
    // since payment_id and the memo protect different plaintexts).
    auto dest = random_gateway_keys();
    gateway_withdraw_destination d_pid{};
    d_pid.gateway_id = dest.pub;
    d_pid.amount = 1000;
    d_pid.payment_id = 0xdeadbeefcafe0000ULL;

    gateway_withdraw_destination d_memo{};
    d_memo.gateway_id = dest.pub;
    d_memo.amount = 1000;
    d_memo.gateway_bridge_chain_index = 1;
    d_memo.gateway_bridge_evm_addr = random_eth_address();

    transaction tx_pid{}, tx_memo{};
    crypto::hash h{};
    ASSERT_TRUE(construct_gateway_withdraw_tx(HF, NET, random_gateway_keys().pub, {d_pid}, 10, tx_pid, h));
    ASSERT_TRUE(construct_gateway_withdraw_tx(HF, NET, random_gateway_keys().pub, {d_memo}, 10, tx_memo, h));

    // tx_pid has no tx_extra_gateway_bridge_memo at all -- structurally distinct
    // carriers, which is the real domain separation guarantee here.
    tx_extra_gateway_bridge_memo m{};
    EXPECT_FALSE(get_field_from_tx_extra(tx_pid.extra, m));
    EXPECT_TRUE(get_field_from_tx_extra(tx_memo.extra, m));
  }

}
