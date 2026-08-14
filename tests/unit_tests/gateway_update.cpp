// Copyright (c) 2024, The Beldex Project
//
// Unit tests for the HF22 gateway descriptor update (update_gateway_address):
// construction of the self-funded, output-less update tx, the two
// domain-separated signing messages, and finalize's signature checks.
// Self-contained — no chain or DB is required, because construction and
// finalization are pure functions of the transaction.

#include <gtest/gtest.h>

#include <string>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_core/gateway_utils.h"
#include "cryptonote_config.h"
#include "crypto/crypto.h"

using namespace cryptonote;

namespace {

  constexpr network_type NET = network_type::MAINNET;
  constexpr hf HF = hf::hf22_gateway_addresses;

  struct keys { crypto::public_key pub; crypto::secret_key sec; };

  keys random_keys()
  {
    keys k;
    crypto::generate_keys(k.pub, k.sec);
    return k;
  }

  // Sign `msg` with the native Schnorr owner key.
  gateway_owner_sig_v schnorr_sign(const keys& k, const crypto::hash& msg)
  {
    crypto::signature s{};
    crypto::generate_signature(msg, k.pub, k.sec, s);
    return s;
  }

  tx_extra_gateway_descriptor_operation only_op(const transaction& tx)
  {
    tx_extra_gateway_descriptor_operation op{};
    EXPECT_TRUE(get_field_from_tx_extra(tx.extra, op, 0));
    return op;
  }

  TEST(GatewayUpdate, construct_is_self_funded_and_outputless)
  {
    const auto gw = random_keys();
    const auto new_owner = random_keys();
    transaction tx{};
    crypto::hash h_in{}, h_own{};
    ASSERT_TRUE(construct_gateway_update_tx(HF, NET, gw.pub, gateway_owner_key_v{new_owner.pub},
                                            "hello", 500, tx, h_in, h_own));

    EXPECT_EQ(tx.type, txtype::update_gateway_address);
    // Self-funded: exactly one gateway input covering the burned update fee plus
    // the miner fee, and no outputs (update txs are exempt from min-2-outputs).
    ASSERT_EQ(tx.vin.size(), 1u);
    const auto* in = std::get_if<txin_gateway>(&tx.vin[0]);
    ASSERT_NE(in, nullptr);
    EXPECT_EQ(in->gateway_addr, gw.pub);
    EXPECT_EQ(in->amount, GATEWAY_ADDRESS_UPDATE_FEE + 500);
    EXPECT_EQ(in->asset_id, crypto::null_aid);
    EXPECT_TRUE(tx.vout.empty());

    // The update fee must be genuinely burned, like the registration fee.
    EXPECT_EQ(get_burned_amount_from_tx_extra(tx.extra), GATEWAY_ADDRESS_UPDATE_FEE);

    // Pure-gateway: no RCT data, and with no outputs the arithmetic balance
    // check yields the whole input (burn + miner fee). The burn is realized
    // because it never exceeds that amount.
    EXPECT_EQ(tx.rct_signatures.type, rct::RCTType::Null);
    uint64_t fee = 0;
    std::string reason;
    ASSERT_TRUE(verify_pure_gateway_balance(tx, fee, reason)) << reason;
    EXPECT_EQ(fee, GATEWAY_ADDRESS_UPDATE_FEE + 500);
    EXPECT_GE(fee, get_burned_amount_from_tx_extra(tx.extra));

    // The descriptor op carries the NEW owner key and meta.
    const auto op = only_op(tx);
    EXPECT_EQ(op.op_type, gateway_descriptor_op_type::update_address);
    EXPECT_EQ(op.address_id, gw.pub);
    EXPECT_EQ(op.descriptor.meta_info, "hello");
    const auto* stored = std::get_if<crypto::public_key>(&op.descriptor.owner_key);
    ASSERT_NE(stored, nullptr);
    EXPECT_EQ(*stored, new_owner.pub);
  }

  TEST(GatewayUpdate, the_two_signing_messages_are_distinct)
  {
    const auto gw = random_keys();
    const auto new_owner = random_keys();
    transaction tx{};
    crypto::hash h_in{}, h_own{};
    ASSERT_TRUE(construct_gateway_update_tx(HF, NET, gw.pub, gateway_owner_key_v{new_owner.pub},
                                            "", 10, tx, h_in, h_own));
    // Domain separation: signing one must never produce a signature valid for the
    // other, or a fee-spend authorization could be replayed as an owner change.
    EXPECT_NE(h_in, h_own);
    EXPECT_EQ(h_in,  gateway_input_message(NET, tx));
    EXPECT_EQ(h_own, gateway_ownership_message(NET, tx));
  }

  TEST(GatewayUpdate, finalize_attaches_canonical_proofs)
  {
    const auto gw = random_keys();
    const auto cur_owner = random_keys();
    const auto new_owner = random_keys();
    transaction tx{};
    crypto::hash h_in{}, h_own{};
    ASSERT_TRUE(construct_gateway_update_tx(HF, NET, gw.pub, gateway_owner_key_v{new_owner.pub},
                                            "m", 10, tx, h_in, h_own));

    ASSERT_TRUE(finalize_gateway_update_tx(NET, tx, gateway_owner_key_v{cur_owner.pub},
                                           schnorr_sign(cur_owner, h_in),
                                           schnorr_sign(cur_owner, h_own)));

    // Canonical layout consensus expects for a descriptor tx with one gateway
    // input: [ownership_proof][input_sig].
    ASSERT_EQ(tx.gateway_proofs.size(), 2u);
    EXPECT_NE(std::get_if<gateway_ownership_proof>(&tx.gateway_proofs[0]), nullptr);
    EXPECT_NE(std::get_if<gateway_input_sig>(&tx.gateway_proofs[1]), nullptr);

    // Filling the (prunable) proof slots must not disturb the prefix-derived
    // messages, or the signatures would no longer match what was signed.
    EXPECT_EQ(gateway_input_message(NET, tx), h_in);
    EXPECT_EQ(gateway_ownership_message(NET, tx), h_own);
  }

  TEST(GatewayUpdate, finalize_rejects_wrong_key_and_swapped_signatures)
  {
    const auto gw = random_keys();
    const auto cur_owner = random_keys();
    const auto other = random_keys();
    const auto new_owner = random_keys();

    auto fresh = [&](transaction& tx, crypto::hash& h_in, crypto::hash& h_own) {
      tx = {};
      ASSERT_TRUE(construct_gateway_update_tx(HF, NET, gw.pub, gateway_owner_key_v{new_owner.pub},
                                              "", 10, tx, h_in, h_own));
    };

    transaction tx{};
    crypto::hash h_in{}, h_own{};

    // A different key's signatures must not authorize the change.
    fresh(tx, h_in, h_own);
    EXPECT_FALSE(finalize_gateway_update_tx(NET, tx, gateway_owner_key_v{cur_owner.pub},
                                            schnorr_sign(other, h_in),
                                            schnorr_sign(other, h_own)));

    // Swapping the two signatures must fail: each is checked against its own
    // domain-separated message, so a fee-spend sig cannot stand in for an
    // ownership proof (or vice versa).
    fresh(tx, h_in, h_own);
    EXPECT_FALSE(finalize_gateway_update_tx(NET, tx, gateway_owner_key_v{cur_owner.pub},
                                            schnorr_sign(cur_owner, h_own),   // swapped
                                            schnorr_sign(cur_owner, h_in)));  // swapped
  }

  TEST(GatewayUpdate, construct_rejects_bad_inputs)
  {
    const auto gw = random_keys();
    const auto new_owner = random_keys();
    transaction tx{};
    crypto::hash h_in{}, h_own{};

    // A zero fee would leave the tx with no input amount at all.
    EXPECT_FALSE(construct_gateway_update_tx(HF, NET, gw.pub, gateway_owner_key_v{new_owner.pub},
                                             "", 0, tx, h_in, h_own));

    // Oversized meta_info is rejected up front rather than by consensus later.
    EXPECT_FALSE(construct_gateway_update_tx(HF, NET, gw.pub, gateway_owner_key_v{new_owner.pub},
                                             std::string(GATEWAY_DESCRIPTOR_MAX_META_INFO_SIZE + 1, 'x'),
                                             10, tx, h_in, h_own));

    // An owner key that is not a canonical main-subgroup point is rejected, matching
    // consensus (is_valid_gateway_owner_key).
    crypto::public_key bad{};   // all-zero is not a valid point
    EXPECT_FALSE(construct_gateway_update_tx(HF, NET, gw.pub, gateway_owner_key_v{bad},
                                             "", 10, tx, h_in, h_own));
  }

  // The proofs live in the PRUNABLE region, so the tx id must still commit to
  // them: they are the only authorization for a keyless txin_gateway, and a
  // txin_gateway has no key image, so tx-id uniqueness is the sole replay guard.
  // An update tx is RCTType::Null *and* carries proofs — the case where the
  // hashers' usual "Null ⇒ empty prunable region" short-circuit would drop them
  // out of the tx id. Pin that here rather than trust the comment in
  // cryptonote_format_utils.cpp.
  TEST(GatewayUpdate, tx_id_commits_to_the_prunable_proofs)
  {
    const auto gw = random_keys();
    const auto cur_owner = random_keys();
    const auto new_owner = random_keys();

    transaction tx{};
    crypto::hash h_in{}, h_own{};
    ASSERT_TRUE(construct_gateway_update_tx(HF, NET, gw.pub, gateway_owner_key_v{new_owner.pub},
                                            "m", 10, tx, h_in, h_own));
    ASSERT_EQ(tx.rct_signatures.type, rct::RCTType::Null); // the risky combination
    ASSERT_TRUE(finalize_gateway_update_tx(NET, tx, gateway_owner_key_v{cur_owner.pub},
                                           schnorr_sign(cur_owner, h_in),
                                           schnorr_sign(cur_owner, h_own)));
    const crypto::hash id = get_transaction_hash(tx);

    // Swapping the proof vector for different (also valid) signatures must move
    // the tx id. If it did not, the same authorization would have two encodings
    // — i.e. a replayable tx that debits the gateway twice.
    transaction other = tx;
    other.gateway_proofs.clear();
    other.gateway_proofs.emplace_back(gateway_ownership_proof{schnorr_sign(cur_owner, h_own)});
    other.gateway_proofs.emplace_back(gateway_input_sig{schnorr_sign(cur_owner, h_in)});
    other.invalidate_hashes();
    EXPECT_NE(get_transaction_hash(other), id) << "tx id does not cover gateway_proofs";

    // And the proofs must survive a serialize/deserialize round trip with the
    // tx id reproducing (the serializer's presence condition must agree with the
    // hashers' — they are separate copies of the same rule).
    const std::string blob = tx_to_blob(tx);
    transaction parsed{};
    ASSERT_TRUE(parse_and_validate_tx_from_blob(blob, parsed));
    ASSERT_EQ(parsed.gateway_proofs.size(), 2u);
    EXPECT_NE(std::get_if<gateway_ownership_proof>(&parsed.gateway_proofs[0]), nullptr);
    EXPECT_NE(std::get_if<gateway_input_sig>(&parsed.gateway_proofs[1]), nullptr);
    EXPECT_EQ(get_transaction_hash(parsed), id);
  }

  TEST(GatewayUpdate, cross_network_messages_differ)
  {
    // genesis binding: the same update must not be replayable on another network.
    const auto gw = random_keys();
    const auto new_owner = random_keys();
    transaction a{}, b{};
    crypto::hash a_in{}, a_own{}, b_in{}, b_own{};
    ASSERT_TRUE(construct_gateway_update_tx(HF, network_type::MAINNET, gw.pub,
                                            gateway_owner_key_v{new_owner.pub}, "", 10, a, a_in, a_own));
    ASSERT_TRUE(construct_gateway_update_tx(HF, network_type::TESTNET, gw.pub,
                                            gateway_owner_key_v{new_owner.pub}, "", 10, b, b_in, b_own));
    EXPECT_NE(a_in, b_in);
    EXPECT_NE(a_own, b_own);
  }

}
