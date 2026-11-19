// Copyright (c) 2026, The Beldex Project
#include "gtest/gtest.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/uptime_proof.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/token_descriptor_operation_utils.h"
#include "ringct/rctOps.h"
#include "random_path.h"

namespace cryptonote {
struct tx_pool_test_access
{
  static void validated(tx_memory_pool& pool, const crypto::hash& id)
  {
    pool.m_input_cache[id] = {true, tx_verification_context{}, 0, crypto::null_hash};
  }
  static bool duplicate(const tx_memory_pool& pool, const transaction& tx)
  {
    return pool.have_duplicated_non_standard_tx(tx, feature::PRIVACY_TOKENS);
  }
};
}
namespace {
using namespace cryptonote;
const txtype pool_types[] = {txtype::register_privacy_token, txtype::mint_token,
    txtype::update_token, txtype::burn_token};
const token_descriptor_operation_type pool_ops[] = {
    token_descriptor_operation_type::register_token, token_descriptor_operation_type::mint_token,
    token_descriptor_operation_type::update_token, token_descriptor_operation_type::burn_token};

class TokenPool : public testing::Test
{
protected:
  fs::path path = random_tmp_file();
  tx_memory_pool pool{chain};
  master_nodes::master_node_list nodes{chain};
  Blockchain chain{pool, nodes};
  BlockchainLMDB* db = nullptr; // Owned by chain after init.
  std::vector<hard_fork> saved_forks;

  void SetUp() override
  {
    saved_forks = fakechain_hardforks;
    db = new BlockchainLMDB;
    db->open(path, FAKECHAIN);
    // Seed genesis directly: these tests exercise the pool, not block admission.
    block genesis{};
    generate_genesis_block(genesis, FAKECHAIN);
    {
      db_wtxn_guard guard(db);
      db->add_block({genesis, block_to_blob(genesis)}, 1, 1, 1, 1, {});
      guard.stop();
    }
    const test_options options{{{hf::hf1, 0, 0, 0}}, 0};
    ASSERT_TRUE(chain.init(db, nullptr, FAKECHAIN, true, &options));
    ASSERT_TRUE(pool.init(0));
  }
  void TearDown() override
  {
    chain.deinit();
    fakechain_hardforks = saved_forks;
    fs::remove_all(path);
  }
  transaction tx(size_t kind, unsigned token, uint64_t nonce)
  {
    tx_extra_token_descriptor_operation registration{};
    registration.operation_type = token_descriptor_operation_type::register_token;
    registration.fields = token_field_descriptor;
    registration.descriptor.ticker = "TOKEN" + std::to_string(token);
    registration.descriptor.full_name = "Template test";
    registration.descriptor.owner = rct::rct2pk(rct::scalarmultBase(rct::d2h(7)));
    registration.descriptor.total_max_supply = 100;
    auto op = registration;
    op.operation_type = pool_ops[kind];
    if (kind)
    {
      op.fields |= token_field_token_id;
      op.token_id = get_or_calculate_token_id(registration);
    }
    transaction result{};
    result.version = txversion::v4_tx_types;
    result.type = pool_types[kind];
    result.unlock_time = nonce;
    txin_to_key input{};
    input.k_image = rct::rct2ki(rct::scalarmultBase(rct::d2h(nonce)));
    result.vin.emplace_back(input);
    if (!add_token_descriptor_operation_to_tx_extra(result.extra, op))
      throw std::runtime_error("Cannot encode pool fixture");
    return result;
  }
  // `verified` models whether the tx passed its input check when it entered
  // the pool; a tx delivered inside a block is stored even when it did not.
  crypto::hash insert(transaction tx, uint64_t received, bool verified = true, bool kept_by_block = true)
  {
    const auto id = get_transaction_hash(tx);
    txpool_tx_meta_t meta{};
    meta.fee = 10000 * beldex::COIN;
    meta.weight = 1000;
    meta.receive_time = received;
    meta.relayed = true;
    // Default models transactions restored after a detach; admission dedup is bypassed.
    meta.kept_by_block = kept_by_block;
    if (verified)
    {
      meta.max_used_block_height = 0;
      meta.max_used_block_id = db->get_block_hash_from_height(0);
    }
    db_wtxn_guard guard(db);
    db->add_txpool_tx(id, tx_to_blob(tx), meta);
    guard.stop();
    if (!pool.init(0)) throw std::runtime_error("Cannot reload test pool");
    // Only spend validation is substituted; the real template builder handles
    // parsing, fees, weights, token conflicts and the final selection.
    tx_pool_test_access::validated(pool, id);
    return id;
  }
  block block_template()
  {
    block result{};
    size_t weight;
    uint64_t fee, reward, governance;
    if (!pool.fill_block_template(result, 300000, beldex::COIN, weight, fee,
            reward, feature::PRIVACY_TOKENS, 100, governance))
      throw std::runtime_error("Cannot build test template");
    return result;
  }
  void clear()
  {
    std::vector<crypto::hash> ids;
    pool.get_transaction_hashes(ids);
    db_wtxn_guard guard(db);
    for (const auto& id : ids) db->remove_txpool_tx(id);
    guard.stop();
    ASSERT_TRUE(pool.init(0));
  }
};

// M10 regression: a pooled token operation that the new block has invalidated
// must be evicted at that block, releasing the token's pending slot, instead
// of squatting it for MEMPOOL_TX_LIVETIME (3 days). kept_by_block txs are
// exempt: they may belong to an alt chain the node could still reorg onto.
// (The fixture's proof-less ops fail re-validation, standing in for ops that
// a mined block made permanently stale.)
TEST_F(TokenPool, StaleTokenOpsAreEvictedOnNewBlockReleasingTheSlot)
{
  const auto stale = insert(tx(1, 1, 1), 1, /*verified=*/true, /*kept_by_block=*/false);
  const auto alt   = insert(tx(1, 2, 2), 2, /*verified=*/true, /*kept_by_block=*/true);
  ASSERT_EQ(pool.get_transactions_count(), 2);
  // Both tokens' slots are held before the block arrives.
  EXPECT_TRUE(tx_pool_test_access::duplicate(pool, tx(2, 1, 3)));
  EXPECT_TRUE(tx_pool_test_access::duplicate(pool, tx(2, 2, 3)));

  block blk{};
  blk.major_version = feature::PRIVACY_TOKENS;
  blk.miner_tx.vin.emplace_back(txin_gen{101});
  ASSERT_TRUE(pool.on_blockchain_inc(blk));

  // The relayed stale op is gone and token 1's slot is free again...
  EXPECT_EQ(pool.get_transactions_count(), 1);
  EXPECT_FALSE(tx_pool_test_access::duplicate(pool, tx(2, 1, 3)));
  // ...while the kept_by_block op survives and token 2's slot stays held.
  EXPECT_TRUE(tx_pool_test_access::duplicate(pool, tx(2, 2, 3)));
}

TEST_F(TokenPool, SameTokenPairsConflictExceptBurnsIncludingReorgRestores)
{
  for (size_t first = 0; first < 4; ++first)
    for (size_t second = 0; second < 4; ++second)
    {
      SCOPED_TRACE("first=" + std::to_string(first) + " second=" + std::to_string(second));
      auto a = insert(tx(first, 1, 1), 1);
      auto b = insert(tx(second, 1, 2), 2);
      auto other = insert(tx(second, 2, 3), 3);
      // M9: a burn never occupies the token's per-block slot -- it only moves
      // current_supply, which no other operation reads from its own descriptor
      // -- so any pair involving a burn coexists in one template. Otherwise a
      // dust-holder's burns could outbid the owner's mint/update every block.
      const bool has_burn = first == 3 || second == 3;
      for (size_t attempt = 0; attempt < 2; ++attempt)
      {
        auto result = block_template();
        if (has_burn)
        {
          ASSERT_EQ(result.tx_hashes.size(), 3);
          EXPECT_EQ(std::count(result.tx_hashes.begin(), result.tx_hashes.end(), a), 1);
          EXPECT_EQ(std::count(result.tx_hashes.begin(), result.tx_hashes.end(), b), 1);
          EXPECT_EQ(std::count(result.tx_hashes.begin(), result.tx_hashes.end(), other), 1);
        }
        else
        {
          ASSERT_EQ(result.tx_hashes.size(), 2);
          EXPECT_EQ(std::count(result.tx_hashes.begin(), result.tx_hashes.end(), other), 1);
          EXPECT_EQ(std::count(result.tx_hashes.begin(), result.tx_hashes.end(), a) +
                    std::count(result.tx_hashes.begin(), result.tx_hashes.end(), b), 1);
        }
      }
      // Template selection skips any loser; it must not mutate pool contents.
      EXPECT_EQ(pool.get_transactions_count(), 3);
      clear();
    }
}

TEST_F(TokenPool, MintAdmissionDedupUsesTokenId)
{
  insert(tx(1, 1, 1), 1);
  EXPECT_TRUE(tx_pool_test_access::duplicate(pool, tx(1, 1, 2)));
  EXPECT_FALSE(tx_pool_test_access::duplicate(pool, tx(1, 2, 3)));
  clear();
  EXPECT_FALSE(tx_pool_test_access::duplicate(pool, tx(1, 1, 2)));
}
// A tx that was stored without passing its input check (which is where the
// ownership proof is verified) must not hold the per-token pending slot, or
// anyone could keep the owner's own operation out of the pool.
TEST_F(TokenPool, UnverifiedOperationDoesNotHoldThePendingSlot)
{
  for (size_t kind = 0; kind < 3; ++kind) // register, mint, update
  {
    SCOPED_TRACE(kind);
    insert(tx(kind, 1, 1), 1, false /*verified*/);
    EXPECT_FALSE(tx_pool_test_access::duplicate(pool, tx(kind, 1, 2)));
    clear();
    insert(tx(kind, 1, 1), 1, true /*verified*/);
    EXPECT_TRUE(tx_pool_test_access::duplicate(pool, tx(kind, 1, 2)));
    clear();
  }
}
} // namespace
