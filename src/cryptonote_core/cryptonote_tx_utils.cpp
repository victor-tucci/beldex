// Copyright (c) 2014-2019, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <unordered_set>
#include <unordered_map>
#include <random>
#include <algorithm>
#include "epee/string_tools.h"
#include "common/apply_permutation.h"
#include "common/hex.h"
#include "cryptonote_tx_utils.h"
#include "cryptonote_config.h"
#include "blockchain.h"
#include "cryptonote_basic/miner.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_basic/asset_descriptor_operation_utils.h"
#include "cryptonote_basic/cryptonote_format_utils.h"  // zarcanum_derivation_to_scalar
#include "crypto/crypto.h"
#include "crypto/asset_proofs.h"
#include "crypto/hf21_transcript_domains.h"
#include "crypto/hash.h"
#include "ringct/rctSigs.h"
#include "multisig/multisig.h"
#include "epee/int-util.h"

using namespace crypto;

namespace cryptonote
{
  //---------------------------------------------------------------
  static void classify_addresses(const std::vector<tx_destination_entry> &destinations, const std::optional<cryptonote::tx_destination_entry>& change_addr, size_t &num_stdaddresses, size_t &num_subaddresses, account_public_address &single_dest_subaddress)
  {
    num_stdaddresses = 0;
    num_subaddresses = 0;
    std::unordered_set<cryptonote::account_public_address> unique_dst_addresses;
    bool change_found = false;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      if (change_addr && *change_addr == dst_entr && !change_found)
      {
        change_found = true;
        continue;
      }
      if (unique_dst_addresses.count(dst_entr.addr) == 0)
      {
        unique_dst_addresses.insert(dst_entr.addr);
        if (dst_entr.is_subaddress)
        {
          ++num_subaddresses;
          single_dest_subaddress = dst_entr.addr;
        }
        else
        {
          ++num_stdaddresses;
        }
      }
    }
    LOG_PRINT_L2("destinations include " << num_stdaddresses << " standard addresses and " << num_subaddresses << " subaddresses");
  }

  keypair get_deterministic_keypair_from_height(uint64_t height)
  {
    keypair k;

    ec_scalar& sec = k.sec;

    for (int i=0; i < 8; i++)
    {
      uint64_t height_byte = height & ((uint64_t)0xFF << (i*8));
      uint8_t byte = height_byte >> i*8;
      sec.data[i] = byte;
    }
    for (int i=8; i < 32; i++)
    {
      sec.data[i] = 0x00;
    }

    generate_keys(k.pub, k.sec, k.sec, true);

    return k;
  }

  bool get_deterministic_output_key(const account_public_address& address, const keypair& tx_key, size_t output_index, crypto::public_key& output_key)
  {
    crypto::key_derivation derivation{};
    bool r = crypto::generate_key_derivation(address.m_view_public_key, tx_key.sec, derivation);
    CHECK_AND_ASSERT_MES(r, false, "failed to generate_key_derivation(" << address.m_view_public_key << ", " << tx_key.sec << ")");

    r = crypto::derive_public_key(derivation, output_index, address.m_spend_public_key, output_key);
    CHECK_AND_ASSERT_MES(r, false, "failed to derive_public_key(" << derivation << ", " << output_index << ", "<< address.m_spend_public_key << ")");

    return true;
  }

  bool validate_governance_reward_key(uint64_t height, std::string_view governance_wallet_address_str, size_t output_index, const crypto::public_key& output_key, const cryptonote::network_type nettype)
  {
    keypair gov_key = get_deterministic_keypair_from_height(height);

    cryptonote::address_parse_info governance_wallet_address;
    cryptonote::get_account_address_from_str(governance_wallet_address, nettype, governance_wallet_address_str);
    crypto::public_key correct_key;

    if (!get_deterministic_output_key(governance_wallet_address.address, gov_key, output_index, correct_key))
    {
      MERROR("Failed to generate deterministic output key for governance wallet output validation");
      return false;
    }

    return correct_key == output_key;
  }

  
  const uint64_t MASTER_NODE_BASE_REWARD_PERCENTAGE = 95;

  uint64_t governance_reward_formula(uint64_t base_reward, hf hf_version)
  {
    return hf_version >= hf::hf17_POS ? beldex::FOUNDATION_REWARD_HF17 : 0;// governance planned at V17
  }
  
  uint64_t derive_governance_from_block_reward(network_type nettype, const cryptonote::block &block, hf hf_version)
  {
    if (hf_version >= hf::hf17_POS)
      return governance_reward_formula(0, hf_version);
    uint64_t result       = 0;
    uint64_t mnode_reward = 0;
    size_t vout_end     = block.miner_tx.vout.size();
    if (block_has_governance_output(nettype, block))
      --vout_end; // skip the governance output, the governance may be the batched amount. we want the original base reward

    for (size_t vout_index = 1; vout_index < vout_end; ++vout_index)
    {
      tx_out const &output = block.miner_tx.vout[vout_index];
      mnode_reward += output.amount;
    }
    uint64_t base_reward  = mnode_reward * 2; 
    uint64_t governance   = governance_reward_formula(base_reward, hf_version);
    uint64_t block_reward = base_reward - governance;

    uint64_t actual_reward = 0; // sanity check
    for (tx_out const &output : block.miner_tx.vout) actual_reward += output.amount;

    CHECK_AND_ASSERT_MES(block_reward <= actual_reward, false,
        "Rederiving the base block reward from the master node reward "
        "exceeded the actual amount paid in the block, derived block reward: "
        << block_reward << ", actual reward: " << actual_reward);

    result = governance;
    return result;  
  }  

  bool block_has_governance_output(network_type nettype, cryptonote::block const &block)
  {
    bool result = height_has_governance_output(nettype, block.major_version, get_block_height(block));
    return result;
  }

  bool height_has_governance_output(network_type nettype, hf hard_fork_version, uint64_t height)
  {
    if (hard_fork_version < hf::hf17_POS)
      return false;

    if(height == 742425)
    {
      return true;
    }
   
    if (height % cryptonote::get_config(nettype).GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS != 0)
    {
      return false;
    }
    return true;  
  }

  
  uint64_t master_node_reward_formula(uint64_t base_reward, hf hard_fork_version)
  {
    return
      hard_fork_version >= hf::hf17_POS          ? beldex::MN_REWARD_HF17_POS :
      hard_fork_version >= hf::hf11_infinite_staking ? (base_reward / 10) * (MASTER_NODE_BASE_REWARD_PERCENTAGE/10) : // 90% of base reward up until HF15's fixed payout
      0;
  }

  uint64_t get_portion_of_reward(uint64_t portions, uint64_t total_master_node_reward)
  {
    uint64_t hi, lo, rewardhi, rewardlo;
    lo = mul128(total_master_node_reward, portions, &hi);
    div128_64(hi, lo, old::STAKING_PORTIONS, &rewardhi, &rewardlo);
    return rewardlo;
  }

  std::vector<uint64_t> distribute_reward_by_portions(const std::vector<master_nodes::payout_entry>& payout, uint64_t total_reward, bool distribute_remainder)
  {
    uint64_t paid_reward = 0;
    std::vector<uint64_t> result;

    result.reserve(payout.size());
    for (auto const &entry : payout)
    {
      uint64_t reward = get_portion_of_reward(entry.portions, total_reward);
      paid_reward += reward;
      result.push_back(reward);
    }

    if (distribute_remainder && payout.size())
    {
      uint64_t remainder = total_reward - paid_reward;
      result.front() += remainder;
    }

    return result;
  }

  static uint64_t calculate_sum_of_portions(const std::vector<master_nodes::payout_entry>& payout, uint64_t total_master_node_reward)
  {
    uint64_t reward = 0;
    for (auto const &entry : payout)
      reward += get_portion_of_reward(entry.portions, total_master_node_reward);
    return reward;
  }

  enum struct reward_type
  {
    miner,
    mnode,
    governance
  };

  struct reward_payout
  {
    reward_type            type;
    account_public_address address;
    uint64_t               amount;
    bool operator==(master_nodes::payout_entry const &other) const { return address == other.address; }
  };

  bool construct_miner_tx(
      size_t height,
      size_t median_weight,
      uint64_t already_generated_coins,
      size_t current_block_weight,
      uint64_t fee,
      transaction& tx,
      const beldex_miner_tx_context &miner_tx_context,
      const blobdata& extra_nonce,
      hf hard_fork_version,
      const crypto::signature security_signature)
  {
    tx.vin.clear();
    tx.vout.clear();
    tx.extra.clear();
    tx.output_unlock_times.clear();
    tx.type    = txtype::standard;
    tx.version = transaction::get_max_version_for_hf(hard_fork_version);

    keypair const txkey{hw::get_device("default")};
    keypair const gov_key = get_deterministic_keypair_from_height(height); // NOTE: Always need since we use same key for master node

    // NOTE: TX Extra
    
      add_tx_extra<tx_extra_pub_key>(tx, txkey.pub);
      if(!extra_nonce.empty())
      {
        if(!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
          return false;
      }

      // TODO(doyle): We don't need to do this. It's a deterministic key.
      if (already_generated_coins != 0)
        add_tx_extra<tx_extra_pub_key>(tx, gov_key.pub);

      add_master_node_winner_to_tx_extra(tx.extra, miner_tx_context.block_leader.key);
    

      beldex_block_reward_context block_reward_context = {};
      block_reward_context.fee                       = fee;
      block_reward_context.height                    = height;
      block_reward_context.block_leader_payouts      = miner_tx_context.block_leader.payouts;
      block_reward_context.batched_governance        = miner_tx_context.batched_governance;

    block_reward_parts reward_parts{};
    if(!get_beldex_block_reward(median_weight, current_block_weight, already_generated_coins, hard_fork_version, reward_parts, block_reward_context))
    {
      LOG_PRINT_L0("Failed to calculate block reward");
      return false;
    }
    // TODO(doyle): Batching awards
    //
    // NOTE: Summarise rewards to payout (up to 9 payout entries/outputs)
    //
    // Miner Block
    // - 1       | Miner
    // - Up To 4 | Block Leader (Queued node at the top of the Master Node List)
    // - Up To 1 | Governance
    //
    // POS Block
    // - Up to 4 | Block Producer (0-3 for Pooled Master Node)
    // - Up To 4 | Block Leader   (Queued node at the top of the Master Node List)
    // - Up To 1 | Governance     (When a block is at the Governance payout interval)
    //
    // NOTE: POS Block Payment Details
    //
    // By default, when POS round is 0, the Block Producer is the Block
    // Leader. Coinbase and transaction fees are given to the Block Leader.
    // This is the common case, and in that instance we avoid generating
    // duplicate outputs and payment occurs in 1 output.
    //
    // On alternative rounds, transaction fees are given to the alternative
    // block producer (which is now different from the Block Leader). The
    // original block producer still receives the coinbase reward. A POS
    // round's failure is determined by the non-participation of the members of
    // the quorum, so failing a round's onus is not always on the original block
    // producer (it could be the validators colluding) hence why they still
    // receive the coinbase.
    //
    // Allocating the transaction fee to alternative block producers on
    // alternative rounds dis-incentivizes members in the quorum from
    // intentionally not participating in the quorum to try and attain a spot as
    // the subsequent alternative leader and snag a reward. The reward they
    // receive instead is just the transaction fee.
    //
    // Purposely not participating to exploit alternative round transaction fees
    // is further dis-incentivized as it is recorded on their behaviour metrics
    // (multiple non-participation marks over the monitoring period will induce
    // a decommission) by members of the quorum.

    size_t rewards_length                = 0;
    std::array<reward_payout, 9> rewards = {};

    if (hard_fork_version >= hf::hf9_master_nodes)
      CHECK_AND_ASSERT_MES(miner_tx_context.block_leader.payouts.size(), false, "Constructing a block leader reward for block but no payout entries specified");

    // NOTE: Add Block Producer Reward
    master_nodes::payout const &leader = miner_tx_context.block_leader;
    if (miner_tx_context.POS)
    {
      CHECK_AND_ASSERT_MES(miner_tx_context.POS_block_producer.payouts.size(), false, "Constructing a reward for block produced by POS but no payout entries specified");
      CHECK_AND_ASSERT_MES(miner_tx_context.POS_block_producer.key, false, "Null Key given for POS Block Producer");
      CHECK_AND_ASSERT_MES(hard_fork_version >= hf::hf17_POS , false, "POS Block Producer is not valid until HF16, current HF" << static_cast<int>(hard_fork_version));

      uint64_t leader_reward = reward_parts.master_node_total;
      if (miner_tx_context.block_leader.key == miner_tx_context.POS_block_producer.key)
      {
        leader_reward += reward_parts.miner_fee;
      }
      else if (reward_parts.miner_fee)
      {
        // Alternative Block Producer (receives just miner fee, if there is one)
        master_nodes::payout const &producer = miner_tx_context.POS_block_producer;
        std::vector<uint64_t> split_rewards   = distribute_reward_by_portions(producer.payouts, reward_parts.miner_fee, true /*distribute_remainder*/);

        for (size_t i = 0; i < producer.payouts.size(); i++)
          rewards[rewards_length++] = {reward_type::mnode, producer.payouts[i].address, split_rewards[i]};
      }

      std::vector<uint64_t> split_rewards = distribute_reward_by_portions(leader.payouts, leader_reward, true /*distribute_remainder*/);
      for (size_t i = 0; i < leader.payouts.size(); i++)
        rewards[rewards_length++] = {reward_type::mnode, leader.payouts[i].address, split_rewards[i]};
    }
    else
    {

      CHECK_AND_ASSERT_MES(miner_tx_context.POS_block_producer.payouts.empty(), false, "Constructing a reward for block produced by miner but payout entries specified");

      if (uint64_t miner_amount = reward_parts.base_miner + reward_parts.miner_fee; miner_amount)
        rewards[rewards_length++] = {reward_type::miner, miner_tx_context.miner_block_producer, miner_amount};

      if (hard_fork_version >= hf::hf9_master_nodes)
      {
        std::vector<uint64_t> split_rewards =
            distribute_reward_by_portions(leader.payouts,
                                          reward_parts.master_node_total,
                                          hard_fork_version >= hf::hf17_POS /*distribute_remainder*/);
        for (size_t i = 0; i < leader.payouts.size(); i++)
          rewards[rewards_length++] = {reward_type::mnode, leader.payouts[i].address, split_rewards[i]};
      }
    }

    // NOTE: Add Governance Payout
    if (hard_fork_version >= hf::hf17_POS && already_generated_coins != 0)
    {
      if (reward_parts.governance_paid == 0)
      {
        CHECK_AND_ASSERT_MES(hard_fork_version >= hf::hf17_POS, false, "Governance reward can NOT be 0 after hardfork 17, hard_fork_version: " << static_cast<int>(hard_fork_version));
      }
      else
      {
        const network_type nettype = miner_tx_context.nettype;
        cryptonote::address_parse_info governance_wallet_address;
        cryptonote::get_account_address_from_str(governance_wallet_address, nettype, cryptonote::get_config(nettype).governance_wallet_address(hard_fork_version));
        rewards[rewards_length++] = {reward_type::governance, governance_wallet_address.address, reward_parts.governance_paid};
      }
    }
    CHECK_AND_ASSERT_MES(rewards_length <= rewards.size(), false, "More rewards specified than supported, number of rewards: " << rewards_length << ", capacity: " << rewards.size());
    CHECK_AND_ASSERT_MES(rewards_length > 0,               false, "Zero rewards are to be payed out, there should be atleast 1");

    // NOTE: Make TX Outputs
    uint64_t summary_amounts = 0;
    for (size_t reward_index = 0; reward_index < rewards_length; reward_index++)
    {
      auto const &[type, address, amount] = rewards[reward_index];
      assert(amount > 0);

      crypto::public_key out_eph_public_key{};

      // TODO(doyle): I don't think txkey is necessary, just use the governance key?
      keypair const &derivation_pair = (type == reward_type::miner) ? txkey : gov_key;
      crypto::key_derivation derivation{};

      if (!get_deterministic_output_key(address, derivation_pair, reward_index, out_eph_public_key))
      {
        MERROR("Failed to generate output one-time public key");
        return false;
      }


      txout_to_key tk = {};
      tk.key          = out_eph_public_key;

      tx_out out = {};
      out.target = tk;
      out.amount = amount;
      tx.vout.push_back(out);
      tx.output_unlock_times.push_back(height + MINED_MONEY_UNLOCK_WINDOW);
      summary_amounts += amount;
    }

    uint64_t expected_amount = 0;
    if (hard_fork_version <= hf::hf16)
    {
      // NOTE: Use the amount actually paid out when we split the master node
      // reward (across up to 4 recipients) which may actually pay out less than
      // the total reward allocated for Master Nodes (due to remainder from
      // division). This occurred prior to HF15, after that we redistribute dust
      // properly.
      expected_amount = reward_parts.base_miner + reward_parts.miner_fee + reward_parts.governance_paid;
      for (size_t reward_index = 0; reward_index < rewards_length; reward_index++)
      {
        [[maybe_unused]] auto const &[type, address, amount] = rewards[reward_index];
        if (type == reward_type::mnode) expected_amount += amount;
      }
    }
    else
    {
      expected_amount = reward_parts.base_miner + reward_parts.miner_fee + reward_parts.governance_paid + reward_parts.master_node_total;
    }

    CHECK_AND_ASSERT_MES(summary_amounts == expected_amount, false, "Failed to construct miner tx, summary_amounts = " << summary_amounts << " not equal total block_reward = " << expected_amount);
    CHECK_AND_ASSERT_MES(tx.vout.size() == rewards_length, false, "TX output mis-match with rewards expected: " << rewards_length << ", tx outputs: " << tx.vout.size());

    //lock
    tx.unlock_time = height + MINED_MONEY_UNLOCK_WINDOW;
    tx.vin.push_back(txin_gen{height});
    tx.invalidate_hashes();

    //LOG_PRINT("MINER_TX generated ok, block_reward=" << print_money(block_reward) << "("  << print_money(block_reward - fee) << "+" << print_money(fee)
    //  << "), current_block_size=" << current_block_size << ", already_generated_coins=" << already_generated_coins << ", tx_id=" << get_transaction_hash(tx), LOG_LEVEL_2);

    if ((hard_fork_version >= hf::hf12_security_signature) && !miner_tx_context.POS) {
      add_security_signature_to_tx_extra(tx.extra, security_signature);
    }
    LOG_PRINT_L2("MINER_TX generated ok");
    return true;
  }

  bool get_beldex_block_reward(size_t median_weight, size_t current_block_weight, uint64_t already_generated_coins, hf hard_fork_version, block_reward_parts &result, const beldex_block_reward_context &beldex_context)
  {
    result = {};
    uint64_t base_reward, base_reward_unpenalized;
    if (!get_base_block_reward(median_weight, current_block_weight, already_generated_coins, base_reward, base_reward_unpenalized, hard_fork_version, beldex_context.height))
    {
      MERROR("Failed to calculate base block reward");
      return false;
    }

    if (base_reward == 0)
    {
      MERROR("Unexpected base reward of 0");
      return false;
    }

    if (already_generated_coins == 0)
    {
      result.original_base_reward = result.base_miner = base_reward;
      return true;
    }

    // We base governance fees and MN rewards based on the block reward formula.  (Prior to HF13,
    // however, they were accidentally based on the block reward formula *after* subtracting a
    // potential penalty if the block producer includes txes beyond the median size limit).
    //result.original_base_reward = hard_fork_version >= hf::hf15_flash ? base_reward_unpenalized : base_reward;
    result.original_base_reward = base_reward;

    // There is a goverance fee due every block.  Beginning in hardfork 10 this is still subtracted
    // from the block reward as if it was paid, but the actual payments get batched into rare, large
    // accumulated payments.  (Before hardfork 10 they are included in every block, unbatched).
    result.governance_due  = governance_reward_formula(result.original_base_reward, hard_fork_version);
    result.governance_paid = hard_fork_version >= hf::hf10_bulletproofs
        ? beldex_context.batched_governance
        : result.governance_due;

    uint64_t const master_node_reward = master_node_reward_formula(result.original_base_reward, hard_fork_version);
    if (hard_fork_version < hf::hf17_POS)
    {
      result.master_node_total = calculate_sum_of_portions(beldex_context.block_leader_payouts, master_node_reward);
      // The base_miner amount is everything left in the base reward after subtracting off the master
      // node and governance fee amounts (the due amount in the latter case). (Any penalty for
      // exceeding the block limit is already removed from base_reward).
      uint64_t non_miner_amounts = result.governance_due + result.master_node_total;
      result.base_miner = base_reward > non_miner_amounts ? base_reward - non_miner_amounts : 0;
      result.miner_fee = beldex_context.fee;
    }
    else
    {
      result.master_node_total = master_node_reward;

      if (beldex_context.testnet_override)
      {
        result.miner_fee = beldex_context.fee;
      }
      else
      {
        uint64_t const penalty = base_reward_unpenalized - base_reward;
        result.miner_fee = penalty >= beldex_context.fee ? 0 : beldex_context.fee - penalty;
      }

      // In HF16, the block producer changes between the Miner and Master Node
      // depending on the state of the Master Node network. The producer is no
      // longer allocated a block reward (unless they are a Master Node) but
      // always receive the transaction fees. Any penalty for exceeding the
      // block limit must now be paid from the common reward received by all
      // Block Producer's (i.e. their transaction fees for constructing the
      // block).
      uint64_t allocated = result.governance_due + result.master_node_total;
      uint64_t remainder = base_reward_unpenalized - allocated;
      if (allocated > base_reward_unpenalized || remainder != 0)
      {
        if (allocated > base_reward_unpenalized)
          MERROR("We allocated more reward " << cryptonote::print_money(allocated) << " than what was available " << cryptonote::print_money(base_reward_unpenalized));
        else
          MERROR("We allocated reward but there was still " << cryptonote::print_money(remainder) << " beldex left to distribute.");
        return false;
      }
    }

    return true;
  }

  crypto::public_key get_destination_view_key_pub(const std::vector<tx_destination_entry> &destinations, const std::optional<cryptonote::tx_destination_entry>& change_addr)
  {
    account_public_address addr = {null_pkey, null_pkey};
    size_t count = 0;
    bool found_change = false;
    for (const auto &i : destinations)
    {
      if (i.amount == 0)
        continue;
      if (change_addr && *change_addr == i && !found_change)
      {
        found_change = true;
        continue;
      }
      if (i.addr == addr)
        continue;
      if (count > 0)
        return null_pkey;
      addr = i.addr;
      ++count;
    }
    if (count == 0 && change_addr)
      return change_addr->addr.m_view_public_key;
    return addr.m_view_public_key;
  }

  static bool use_confidential_asset_path(const std::vector<tx_source_entry>& sources, const std::vector<tx_destination_entry>& destinations)
  {
    for (const auto& src : sources)
    {
      if (src.has_ca_metadata || src.asset_id != crypto::null_pkey)
        return true;
    }
    for (const auto& dst : destinations)
    {
      if (dst.asset_id != crypto::null_pkey)
        return true;
    }
    return false;
  }

  static constexpr bool ca_construction_capabilities_available()
  {
    // Phase 1 capability: tx primitives exist and constructor can enter CA-aware branching.
    // Full CA signature/proof generation is still pending and guarded later in construction.
    return true;
  }

  static std::string ca_construction_missing_capabilities_reason()
  {
    return "Confidential-asset tx construction is not available yet: missing CA tx input/output variants, "
           "CA signature generation, and tx-wide CA proof generation/verification integration";
  }

  static const crypto::key_image* get_txin_key_image_ptr(const txin_v& in)
  {
    if (const auto* tk = std::get_if<txin_to_key>(&in))
      return &tk->k_image;
    if (const auto* zc = std::get_if<txin_zc_input>(&in))
      return &zc->k_image;
    return nullptr;
  }

  static bool add_amount_or_overflow(uint64_t amount, uint64_t& total)
  {
    if (amount > std::numeric_limits<uint64_t>::max() - total)
      return false;
    total += amount;
    return true;
  }

  static bool add_amount_by_asset(
      const crypto::public_key& asset_id,
      uint64_t amount,
      std::unordered_map<crypto::public_key, uint64_t>& totals)
  {
    auto& current = totals[asset_id];
    return add_amount_or_overflow(amount, current);
  }

  [[maybe_unused]] static crypto::hash get_ca_domain_separated_rct_message_hash(
      const crypto::hash& tx_prefix_hash,
      const transaction& tx)
  {
    std::vector<uint8_t> blob;
    static constexpr char DOMAIN_TAG[] = "BLDX_CA_RCT_MSG_V1";
    blob.insert(blob.end(), DOMAIN_TAG, DOMAIN_TAG + sizeof(DOMAIN_TAG) - 1);
    const auto append_blob = [&blob](const void* ptr, size_t n) {
      const auto* p = static_cast<const uint8_t*>(ptr);
      blob.insert(blob.end(), p, p + n);
    };
    append_blob(&tx_prefix_hash, sizeof(tx_prefix_hash));

    uint64_t zc_inputs = 0;
    for (const auto& in : tx.vin)
    {
      const auto* zc = std::get_if<txin_zc_input>(&in);
      if (!zc)
        continue;
      ++zc_inputs;
      append_blob(&zc->k_image, sizeof(zc->k_image));
      append_blob(&zc->asset_id, sizeof(zc->asset_id));
      append_blob(&zc->amount_commitment, sizeof(zc->amount_commitment));
      append_blob(&zc->blinded_asset_id, sizeof(zc->blinded_asset_id));
    }

    append_blob(&zc_inputs, sizeof(zc_inputs));
    crypto::hash h = crypto::null_hash;
    crypto::cn_fast_hash(blob.data(), blob.size(), h);
    return h;
  }

  [[maybe_unused]] static bool generate_ca_tx_proofs(transaction& tx)
  {
    tx.proofs.clear();
    LOG_ERROR("CA tx proof generation is not wired yet");
    return true;
  }

  static bool append_ca_output_assets_metadata_to_extra(
      transaction& tx,
      const std::vector<tx_destination_entry>& destinations)
  {
    if (destinations.empty())
      return true;

    tx_extra_ca_output_assets assets{};
    assets.asset_ids.reserve(destinations.size());
    for (const auto& dst : destinations)
      assets.asset_ids.push_back(dst.asset_id);

    if (!remove_field_from_tx_extra<tx_extra_ca_output_assets>(tx.extra))
      return false;
    return add_ca_output_assets_to_tx_extra(tx.extra, assets);
  }

  static bool validate_construct_tx_preflight(
      const std::vector<tx_source_entry>& sources,
      const std::vector<tx_destination_entry>& destinations,
      const rct::RCTConfig& rct_config,
      const beldex_construct_tx_params& tx_params,
      const std::optional<tx_destination_entry>& change_addr,
      const std::vector<crypto::secret_key>& additional_tx_keys)
  {
    auto collect_non_native_assets = [](const auto& entries, auto get_asset_id) {
      std::unordered_set<crypto::public_key> non_native;
      for (const auto& e : entries)
      {
        const crypto::public_key aid = get_asset_id(e);
        if (aid != crypto::null_pkey)
          non_native.insert(aid);
      }
      return non_native;
    };

    if (tx_params.burn_percent)
    {
      LOG_ERROR("cannot construct tx: internal error: burn percent must be converted to fixed burn amount in the wallet");
      return false;
    }

    const bool has_any_ca_metadata = use_confidential_asset_path(sources, destinations);
    if (has_any_ca_metadata && tx_params.hf_version < hf::hf20_bulletproof_plus)
    {
      LOG_ERROR("CA tx construction is not allowed before hf20_bulletproof_plus");
      return false;
    }

    const bool ca_metadata_requested = tx_params.hf_version >= hf::hf20_bulletproof_plus && has_any_ca_metadata;
    const bool ca_deploy_mode = ca_metadata_requested && tx_params.tx_type == txtype::deploy_new_asset;
    const bool ca_transfer_mode = ca_metadata_requested && tx_params.tx_type == txtype::standard;
    if (ca_metadata_requested)
    {
      if (!ca_construction_capabilities_available())
      {
        LOG_ERROR(ca_construction_missing_capabilities_reason());
        return false;
      }
      if (!ca_deploy_mode && !ca_transfer_mode)
      {
        LOG_ERROR("CA tx construction currently supports txtype::standard and txtype::deploy_new_asset only");
        return false;
      }
    }

    if (ca_transfer_mode)
    {
      bool has_ca_input_source = false;
      bool has_legacy_input_source = false;
      for (size_t i = 0; i < sources.size(); ++i)
      {
        const bool is_ca_source = sources[i].has_ca_metadata || sources[i].asset_id != crypto::null_pkey;
        has_ca_input_source = has_ca_input_source || is_ca_source;
        has_legacy_input_source = has_legacy_input_source || !is_ca_source;
      }
      if (!has_ca_input_source)
      {
        LOG_ERROR("CA path requested without any CA input sources");
        return false;
      }
      // HF21 CA transfer still pays fee in native BDX, so mixed CA + native
      // inputs are valid/expected. Legacy non-native sources are still rejected
      // by the per-source metadata checks below.
      (void)has_legacy_input_source;

      bool has_ca_outputs = false;
      for (const auto& dst : destinations)
        has_ca_outputs = has_ca_outputs || dst.asset_id != crypto::null_pkey;
      if (has_ca_outputs && !has_ca_input_source)
      {
        LOG_ERROR("CA outputs requested without CA inputs");
        return false;
      }
    }

    if (sources.empty())
    {
      LOG_ERROR("Empty sources");
      return false;
    }

    for (size_t i = 0; i < sources.size(); ++i)
    {
      const tx_source_entry& src = sources[i];
      const bool source_ca_requested = src.has_ca_metadata || src.asset_id != crypto::null_pkey;
      if (src.outputs.empty())
      {
        LOG_ERROR("Source #" << i << " has empty outputs ring");
        return false;
      }
      if (src.real_output >= src.outputs.size())
      {
        LOG_ERROR("Source #" << i << " has invalid real_output index " << src.real_output
                  << " (ring size: " << src.outputs.size() << ")");
        return false;
      }

      uint64_t prev_abs_index = 0;
      bool have_prev_abs_index = false;
      for (size_t j = 0; j < src.outputs.size(); ++j)
      {
        const uint64_t abs_index = src.outputs[j].first;
        if (have_prev_abs_index && abs_index <= prev_abs_index)
        {
          LOG_ERROR("Source #" << i << " has non-increasing ring absolute indices at position " << j
                    << " (" << abs_index << " <= " << prev_abs_index << ")");
          return false;
        }
        prev_abs_index = abs_index;
        have_prev_abs_index = true;
      }

      // Keep output ring metadata arrays coherent for both legacy and CA paths.
      if (src.output_asset_ids.size() != src.outputs.size() ||
          src.output_asset_commitments.size() != src.outputs.size())
      {
        LOG_ERROR("Source #" << i << " has output asset metadata size mismatch: outputs=" << src.outputs.size()
                  << ", output_asset_ids=" << src.output_asset_ids.size()
                  << ", output_asset_commitments=" << src.output_asset_commitments.size());
        return false;
      }

      if (source_ca_requested)
      {
        if (!src.has_ca_metadata)
        {
          LOG_ERROR("Source #" << i << " requests CA path without has_ca_metadata");
          return false;
        }
        if (src.asset_id == crypto::null_pkey)
        {
          LOG_ERROR("Source #" << i << " CA metadata has null asset_id");
          return false;
        }
        if (src.amount_commitment == crypto::null_pkey ||
            src.asset_id_bliding_mask == crypto::null_pkey ||
            src.blinded_asset_id == crypto::null_pkey)
        {
          LOG_ERROR("Source #" << i << " CA metadata is incomplete (real output commitments/masks missing)");
          return false;
        }

        for (size_t oi = 0; oi < src.outputs.size(); ++oi)
        {
          if (src.output_asset_ids[oi] != src.asset_id)
          {
            LOG_ERROR("Source #" << i << " ring member #" << oi
                      << " has mismatched asset_id relative to source asset_id");
            return false;
          }
          if (src.output_asset_commitments[oi] == rct::zero())
          {
            LOG_ERROR("Source #" << i << " ring member #" << oi << " has missing CA asset commitment");
            return false;
          }
        }

        if (src.real_output >= src.output_asset_commitments.size())
        {
          LOG_ERROR("Source #" << i << " real_output index out of range for CA asset commitments");
          return false;
        }
        if (src.output_asset_commitments[src.real_output] != rct::pk2rct(src.blinded_asset_id))
        {
          LOG_ERROR("Source #" << i << " real output asset commitment does not match blinded_asset_id");
          return false;
        }
      }
      else
      {
        // Legacy path must not accidentally carry CA-only metadata.
        if (src.has_ca_metadata ||
            src.asset_id != crypto::null_pkey ||
            src.amount_commitment != crypto::null_pkey ||
            src.asset_id_bliding_mask != crypto::null_pkey ||
            src.blinded_asset_id != crypto::null_pkey)
        {
          LOG_ERROR("Source #" << i << " is marked legacy but contains CA metadata");
          return false;
        }
      }
    }

    if (destinations.empty())
    {
      LOG_ERROR("Empty destinations");
      return false;
    }

    bool has_non_zero_destination = false;
    size_t change_addr_matches = 0;
    for (size_t i = 0; i < destinations.size(); ++i)
    {
      const tx_destination_entry& dst = destinations[i];
      if (dst.addr.m_spend_public_key == crypto::null_pkey || dst.addr.m_view_public_key == crypto::null_pkey)
      {
        LOG_ERROR("Destination #" << i << " has null address public key(s)");
        return false;
      }
      if (dst.amount > 0)
        has_non_zero_destination = true;
      if (change_addr && dst == *change_addr)
        ++change_addr_matches;
    }
    if (!has_non_zero_destination)
    {
      LOG_ERROR("All destinations have zero amount");
      return false;
    }
    if (change_addr_matches > 1)
    {
      LOG_ERROR("Change destination appears multiple times in destinations (" << change_addr_matches << " matches)");
      return false;
    }

    const size_t max_outputs = rct_config.range_proof_type == rct::RangeProofType::PaddedBulletproof
                                 ? TX_BULLETPROOF_MAX_OUTPUTS
                                 : TX_BULLETPROOF_PLUS_MAX_OUTPUTS;
    if (destinations.size() > max_outputs)
    {
      LOG_ERROR("Too many outputs: " << destinations.size() << ", max allowed: " << max_outputs);
      return false;
    }

    // Additional tx keys are required only for mixed std/subaddress multi-destination cases.
    size_t num_stdaddresses = 0;
    size_t num_subaddresses = 0;
    account_public_address single_dest_subaddress{};
    classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);
    const bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
    if (need_additional_txkeys && destinations.size() != additional_tx_keys.size())
    {
      LOG_ERROR("Wrong amount of additional tx keys: " << additional_tx_keys.size()
                << ", expected: " << destinations.size());
      return false;
    }

    uint64_t total_input_amount = 0;
    std::unordered_map<crypto::public_key, uint64_t> input_amounts_by_asset;
    for (size_t i = 0; i < sources.size(); ++i)
    {
      const uint64_t amount = sources[i].amount;
      if (!add_amount_or_overflow(amount, total_input_amount))
      {
        LOG_ERROR("Input amount overflow while summing source #" << i);
        return false;
      }
      const crypto::public_key asset_id = sources[i].asset_id;
      if (!add_amount_by_asset(asset_id, amount, input_amounts_by_asset))
      {
        LOG_ERROR("Input per-asset amount overflow for source #" << i);
        return false;
      }
    }

    uint64_t total_output_amount = 0;
    std::unordered_map<crypto::public_key, uint64_t> output_amounts_by_asset;
    for (size_t i = 0; i < destinations.size(); ++i)
    {
      const uint64_t amount = destinations[i].amount;
      if (!add_amount_or_overflow(amount, total_output_amount))
      {
        LOG_ERROR("Output amount overflow while summing destination #" << i);
        return false;
      }
      const crypto::public_key asset_id = destinations[i].asset_id;
      if (!add_amount_by_asset(asset_id, amount, output_amounts_by_asset))
      {
        LOG_ERROR("Output per-asset amount overflow for destination #" << i);
        return false;
      }
    }

    const bool is_deploy_tx = tx_params.tx_type == txtype::deploy_new_asset;
    const uint64_t native_in_amount = input_amounts_by_asset.count(crypto::null_pkey) ? input_amounts_by_asset[crypto::null_pkey] : 0;
    const uint64_t native_out_amount = output_amounts_by_asset.count(crypto::null_pkey) ? output_amounts_by_asset[crypto::null_pkey] : 0;
    if (is_deploy_tx)
    {
      if (native_out_amount > native_in_amount)
      {
        LOG_ERROR("Deploy tx native outputs (" << native_out_amount << ") exceed native inputs (" << native_in_amount << ")");
        return false;
      }
    }
    else if (total_output_amount > total_input_amount)
    {
      LOG_ERROR("Transaction outputs money (" << total_output_amount << ") exceeds inputs money (" << total_input_amount << ")");
      return false;
    }

    // Burned amount is paid from native coin remainder (inputs - outputs), so ensure capacity here.
    const uint64_t available_native_remainder = native_in_amount - native_out_amount;
    if (tx_params.burn_fixed > available_native_remainder)
    {
      LOG_ERROR("Invalid burn amount: burn_fixed (" << tx_params.burn_fixed
                << ") exceeds available native remainder (" << available_native_remainder << ")");
      return false;
    }

    // Per-asset conservation:
    // - Non-native assets (asset_id != null_pkey): inputs must match outputs exactly.
    // - Native asset (null_pkey): inputs >= outputs; remainder is fee + optional burn.
    for (const auto& [asset_id, out_amount] : output_amounts_by_asset)
    {
      const auto it = input_amounts_by_asset.find(asset_id);
      const uint64_t in_amount = (it == input_amounts_by_asset.end()) ? 0 : it->second;
      if (asset_id != crypto::null_pkey)
      {
        if (is_deploy_tx)
          continue; // deploy mints non-native outputs; no matching non-native inputs required
        if (in_amount != out_amount)
        {
          LOG_ERROR("Non-native asset conservation failed: asset=" << asset_id << ", in=" << in_amount << ", out=" << out_amount);
          return false;
        }
      }
      else if (in_amount < out_amount)
      {
        LOG_ERROR("Native asset conservation failed: in=" << in_amount << ", out=" << out_amount);
        return false;
      }
    }
    // Disallow silent disappearance of non-native assets (i.e. input bucket not present in outputs).
    for (const auto& [asset_id, in_amount] : input_amounts_by_asset)
    {
      if (asset_id == crypto::null_pkey)
        continue;
      if (is_deploy_tx)
        continue; // deploy is allowed to have no non-native input buckets
      const auto out_it = output_amounts_by_asset.find(asset_id);
      const uint64_t out_amount = out_it == output_amounts_by_asset.end() ? 0 : out_it->second;
      if (out_amount != in_amount)
      {
        LOG_ERROR("Non-native asset conservation failed (input-only bucket): asset=" << asset_id
                  << ", in=" << in_amount << ", out=" << out_amount);
        return false;
      }
    }

    // Single-destination non-native bucket rule: one tx may have at most one non-native
    // destination asset bucket (native bucket may still exist for fee/change mechanics).
    const auto non_native_destination_assets = collect_non_native_assets(destinations, [](const tx_destination_entry& d) { return d.asset_id; });
    const auto non_native_source_assets = collect_non_native_assets(sources, [](const tx_source_entry& s) { return s.asset_id; });
    if (non_native_destination_assets.size() > 1)
    {
      LOG_ERROR("Mixed non-native destination assets in one tx are forbidden");
      return false;
    }
    if (non_native_source_assets.size() > 1)
    {
      LOG_ERROR("Mixed non-native source assets in one tx are forbidden");
      return false;
    }

    // If a non-native destination bucket exists, inputs must contain that bucket
    // for transfer txs. Deploy transactions mint this bucket and therefore do
    // not require matching non-native inputs.
    if (!non_native_destination_assets.empty() && tx_params.tx_type != txtype::deploy_new_asset)
    {
      const crypto::public_key dst_asset = *non_native_destination_assets.begin();
      if (input_amounts_by_asset.find(dst_asset) == input_amounts_by_asset.end())
      {
        LOG_ERROR("Missing matching non-native input bucket for destination asset " << dst_asset);
        return false;
      }
      if (!non_native_source_assets.empty() && *non_native_source_assets.begin() != dst_asset)
      {
        LOG_ERROR("Non-native destination asset does not match non-native source asset");
        return false;
      }
    }
    else if (!non_native_destination_assets.empty())
    {
      LOG_PRINT_L1("deploy_new_asset preflight: allowing minted non-native destination bucket without matching input bucket");
    }

    // Change entry (when provided) must stay native to avoid cross-asset ambiguity.
    if (change_addr && change_addr->asset_id != crypto::null_pkey)
    {
      LOG_ERROR("Non-native change entry is not allowed in constructor preflight");
      return false;
    }

    // In this constructor path every input must be ringct-capable.
    for (size_t i = 0; i < sources.size(); ++i)
    {
      if (!sources[i].rct)
      {
        LOG_ERROR("Unsupported non-RCT source at input #" << i);
        return false;
      }
    }

    return true;
  }

  //---------------------------------------------------------------
  bool construct_tx_with_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, std::vector<tx_destination_entry>& destinations, const std::optional<tx_destination_entry>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, const rct::RCTConfig &rct_config, rct::multisig_out *msout, bool shuffle_outs, beldex_construct_tx_params const &tx_params)
  {
    hw::device &hwdev = sender_account_keys.get_device();
    auto log_grouped_destinations = [&](const char* stage, const char* reason) {
      std::unordered_map<crypto::public_key, uint64_t> src_by_asset;
      std::unordered_map<crypto::public_key, uint64_t> dst_by_asset;
      for (const auto& s : sources)
      {
        uint64_t& b = src_by_asset[s.asset_id];
        if (b <= std::numeric_limits<uint64_t>::max() - s.amount)
          b += s.amount;
      }
      for (const auto& d : destinations)
      {
        uint64_t& b = dst_by_asset[d.asset_id];
        if (b <= std::numeric_limits<uint64_t>::max() - d.amount)
          b += d.amount;
      }
      std::ostringstream oss;
      oss << stage << " reason=" << reason
          << " tx_type=" << static_cast<int>(tx_params.tx_type)
          << " hf=" << static_cast<int>(tx_params.hf_version)
          << " src_count=" << sources.size()
          << " dst_count=" << destinations.size()
          << " src_by_asset:";
      if (src_by_asset.empty()) oss << " <none>";
      for (const auto& [aid, amt] : src_by_asset)
        oss << " [" << (aid == crypto::null_pkey ? std::string{"native"} : tools::type_to_hex(aid))
            << "=" << print_money(amt) << "]";
      oss << " dst_by_asset:";
      if (dst_by_asset.empty()) oss << " <none>";
      for (const auto& [aid, amt] : dst_by_asset)
        oss << " [" << (aid == crypto::null_pkey ? std::string{"native"} : tools::type_to_hex(aid))
            << "=" << print_money(amt) << "]";
      if (change_addr)
      {
        oss << " change=[" << (change_addr->asset_id == crypto::null_pkey ? std::string{"native"} : tools::type_to_hex(change_addr->asset_id))
            << "=" << print_money(change_addr->amount) << "]";
      }
      else
      {
        oss << " change=<none>";
      }
      MINFO(oss.str());
    };

    if (!validate_construct_tx_preflight(sources, destinations, rct_config, tx_params, change_addr, additional_tx_keys))
    {
      log_grouped_destinations("construct_tx_with_tx_key", "preflight_failed");
      return false;
    }

    if (sources.empty())
    {
      log_grouped_destinations("construct_tx_with_tx_key", "empty_sources");
      LOG_ERROR("Empty sources");
      return false;
    }

    std::vector<rct::key> amount_keys;
    tx.set_null();
    amount_keys.clear();
    if (msout)
    {
      msout->c.clear();
    }

    tx.version = transaction::get_max_version_for_hf(tx_params.hf_version);
    /*CHECK_AND_ASSERT_MES(tx.version >= txversion::v4_tx_types, false, "Cannot construct pre-v4 transactions");
    CHECK_AND_ASSERT_MES(rct_config.range_proof_type == rct::RangeProofType::PaddedBulletproof &&
            (rct_config.bp_version == 0 || rct_config.bp_version >= 3),
            false, "Cannot construct pre-CLSAG transactions");*/

    tx.type = tx_params.tx_type;
    if (tx.version <= txversion::v2_ringct)
        tx.unlock_time = unlock_time;

    tx.extra = extra;
    crypto::public_key txkey_pub;

    if (tx.type == txtype::stake) {
      crypto::secret_key tx_sk{tx_key};
      bool added = hwdev.update_staking_tx_secret_key(tx_sk);
      CHECK_AND_NO_ASSERT_MES(added, false, "Failed to add tx secret key to stake transaction");

      cryptonote::add_tx_secret_key_to_tx_extra(tx.extra, tx_sk);
    }

    // if we have a stealth payment id, find it and encrypt it with the tx key now
    std::vector<tx_extra_field> tx_extra_fields;
    if (parse_tx_extra(tx.extra, tx_extra_fields))
    {
      bool add_dummy_payment_id = true;

      tx_extra_nonce extra_nonce;
      if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
      {
        crypto::hash payment_id = null_hash;
        crypto::hash8 payment_id8 = null_hash8;
        if (get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
        {
          LOG_PRINT_L2("Encrypting payment id " << payment_id8);
          crypto::public_key view_key_pub = get_destination_view_key_pub(destinations, change_addr);
          if (view_key_pub == null_pkey)
          {
            LOG_ERROR("Destinations have to have exactly one output to support encrypted payment ids");
            return false;
          }

          if (!hwdev.encrypt_payment_id(payment_id8, view_key_pub, tx_key))
          {
            LOG_ERROR("Failed to encrypt payment id");
            return false;
          }

          std::string extra_nonce;
          set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
          remove_field_from_tx_extra<tx_extra_nonce>(tx.extra);
          if (!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
          {
            LOG_ERROR("Failed to add encrypted payment id to tx extra");
            return false;
          }
          LOG_PRINT_L1("Encrypted payment ID: " << payment_id8);
          add_dummy_payment_id = false;
        }
        else if (get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
        {
          add_dummy_payment_id = false;
        }
      }

      // we don't add one if we've got more than the usual 1 destination plus change
      if (destinations.size() > 2)
        add_dummy_payment_id = false;

      if (add_dummy_payment_id)
      {
        // if we have neither long nor short payment id, add a dummy short one,
        // this should end up being the vast majority of txes as time goes on
        std::string extra_nonce;
        crypto::hash8 payment_id8 = null_hash8;
        crypto::public_key view_key_pub = get_destination_view_key_pub(destinations, change_addr);
        if (view_key_pub == null_pkey)
        {
          LOG_ERROR("Failed to get key to encrypt dummy payment id with");
        }
        else
        {
          hwdev.encrypt_payment_id(payment_id8, view_key_pub, tx_key);
          set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
          if (!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
          {
            LOG_ERROR("Failed to add dummy encrypted payment id to tx extra");
            // continue anyway
          }
        }
      }
    }
    else
    {
      MWARNING("Failed to parse tx extra");
      tx_extra_fields.clear();
    }

    struct input_generation_context_data
    {
      keypair in_ephemeral;
    };
    std::vector<input_generation_context_data> in_contexts;
    bool has_ca_inputs = false;
    bool has_legacy_inputs = false;
    bool has_ca_outputs = false;

    //fill inputs
    auto extract_vin_offsets = [](const std::vector<txin_v>& vin) {
      std::vector<std::vector<uint64_t>> all;
      all.reserve(vin.size());
      for (const auto& in : vin)
      {
        if (const auto* tk = std::get_if<txin_to_key>(&in))
          all.push_back(tk->key_offsets);
        else if (const auto* zc = std::get_if<txin_zc_input>(&in))
          all.push_back(zc->key_offsets);
        else
          all.emplace_back();
      }
      return all;
    };
    auto extract_vin_key_images = [](const std::vector<txin_v>& vin) {
      std::vector<crypto::key_image> all;
      all.reserve(vin.size());
      for (const auto& in : vin)
      {
        if (const auto* tk = std::get_if<txin_to_key>(&in))
          all.push_back(tk->k_image);
        else if (const auto* zc = std::get_if<txin_zc_input>(&in))
          all.push_back(zc->k_image);
        else
          all.push_back(crypto::key_image{});
      }
      return all;
    };
    auto mixring_fingerprint = [](const rct::ctkeyM& ring) {
      std::vector<uint8_t> blob;
      for (const auto& row : ring)
      {
        for (const auto& member : row)
        {
          const auto* d = reinterpret_cast<const uint8_t*>(&member.dest);
          const auto* m = reinterpret_cast<const uint8_t*>(&member.mask);
          blob.insert(blob.end(), d, d + sizeof(member.dest));
          blob.insert(blob.end(), m, m + sizeof(member.mask));
        }
      }
      crypto::hash h = crypto::null_hash;
      crypto::cn_fast_hash(blob.data(), blob.size(), h);
      return h;
    };

    int idx = -1;
    for(const tx_source_entry& src_entr:  sources)
    {
      ++idx;
      if(src_entr.real_output >= src_entr.outputs.size())
      {
        log_grouped_destinations("construct_tx_with_tx_key", "real_output_out_of_range");
        LOG_ERROR("real_output index (" << src_entr.real_output << ")bigger than output_keys.size()=" << src_entr.outputs.size());
        return false;
      }
      //key_derivation recv_derivation;
      in_contexts.push_back(input_generation_context_data());
      keypair& in_ephemeral = in_contexts.back().in_ephemeral;
      crypto::key_image img;
      const auto& out_key = reinterpret_cast<const crypto::public_key&>(src_entr.outputs[src_entr.real_output].second.dest);
      if(!generate_key_image_helper(sender_account_keys, subaddresses, out_key, src_entr.real_out_tx_key, src_entr.real_out_additional_tx_keys, src_entr.real_output_in_tx_index, in_ephemeral,img, hwdev))
      {
        log_grouped_destinations("construct_tx_with_tx_key", "key_image_generation_failed");
        LOG_ERROR("Key image generation failed!");
        return false;
      }

      //check that derivated key is equal with real output key (if non multisig)
      if(!msout && !(in_ephemeral.pub == src_entr.outputs[src_entr.real_output].second.dest) )
      {
        LOG_ERROR("derived public key mismatch with output public key at index " << idx << ", real out " << src_entr.real_output << "!\nderived_key:"
          << tools::type_to_hex(in_ephemeral.pub) << "\nreal output_public_key:"
          << tools::type_to_hex(src_entr.outputs[src_entr.real_output].second.dest) );
        LOG_ERROR("amount " << src_entr.amount << ", rct " << src_entr.rct);
        LOG_ERROR("tx pubkey " << src_entr.real_out_tx_key << ", real_output_in_tx_index " << src_entr.real_output_in_tx_index);
        return false;
      }

      const bool is_ca_input = src_entr.has_ca_metadata || src_entr.asset_id != crypto::null_pkey;
      if (is_ca_input)
      {
        if (src_entr.output_asset_ids.size() != src_entr.outputs.size() ||
            src_entr.output_asset_commitments.size() != src_entr.outputs.size())
        {
          LOG_ERROR("CA input ring metadata size mismatch at source index " << idx);
          return false;
        }
        if (!src_entr.has_ca_metadata)
        {
          LOG_ERROR("CA input requested without CA metadata at source index " << idx);
          return false;
        }
        if (src_entr.asset_id == crypto::null_pkey ||
            src_entr.asset_id_bliding_mask == crypto::null_pkey ||
            src_entr.amount_commitment == crypto::null_pkey ||
            src_entr.blinded_asset_id == crypto::null_pkey)
        {
          LOG_ERROR("CA input metadata incomplete at source index " << idx);
          return false;
        }
        for (size_t oi = 0; oi < src_entr.outputs.size(); ++oi)
        {
          if (src_entr.output_asset_ids[oi] != src_entr.asset_id)
          {
            LOG_ERROR("CA ring member asset id mismatch at source index " << idx << ", ring member " << oi);
            return false;
          }
          if (src_entr.output_asset_commitments[oi] == rct::zero())
          {
            LOG_ERROR("CA ring member asset commitment missing at source index " << idx << ", ring member " << oi);
            return false;
          }
        }
        if (src_entr.real_output >= src_entr.output_asset_commitments.size())
        {
          LOG_ERROR("CA real output index out of range for asset commitments at source index " << idx);
          return false;
        }
        if (src_entr.output_asset_commitments[src_entr.real_output] != rct::pk2rct(src_entr.blinded_asset_id))
        {
          LOG_ERROR("CA real output asset commitment mismatch at source index " << idx);
          return false;
        }
        has_ca_inputs = true;
        txin_zc_input input_zc{};
        input_zc.k_image = msout ? rct::rct2ki(src_entr.multisig_kLRki.ki) : img;
        input_zc.asset_id = src_entr.asset_id;
        input_zc.amount_commitment = src_entr.amount_commitment;
        input_zc.blinded_asset_id = src_entr.blinded_asset_id;
        for (const tx_source_entry::output_entry& out_entry : src_entr.outputs)
          input_zc.key_offsets.push_back(out_entry.first);
        CHECK_AND_ASSERT_MES(std::is_sorted(input_zc.key_offsets.begin(), input_zc.key_offsets.end()), false,
                             "ZC input absolute ring offsets must be sorted before relative encoding");
        CHECK_AND_ASSERT_MES(std::adjacent_find(input_zc.key_offsets.begin(), input_zc.key_offsets.end()) == input_zc.key_offsets.end(),
                             false, "ZC input absolute ring offsets must be strictly increasing");
        input_zc.key_offsets = absolute_output_offsets_to_relative(input_zc.key_offsets);
        tx.vin.push_back(input_zc);
      }
      else
      {
        has_legacy_inputs = true;
        //put key image into tx input
        txin_to_key input_to_key;
        input_to_key.amount = src_entr.amount;
        input_to_key.k_image = msout ? rct::rct2ki(src_entr.multisig_kLRki.ki) : img;

        //fill outputs array and use relative offsets
        for(const tx_source_entry::output_entry& out_entry: src_entr.outputs)
          input_to_key.key_offsets.push_back(out_entry.first);
        CHECK_AND_ASSERT_MES(std::is_sorted(input_to_key.key_offsets.begin(), input_to_key.key_offsets.end()), false,
                             "Legacy input absolute ring offsets must be sorted before relative encoding");
        CHECK_AND_ASSERT_MES(std::adjacent_find(input_to_key.key_offsets.begin(), input_to_key.key_offsets.end()) == input_to_key.key_offsets.end(),
                             false, "Legacy input absolute ring offsets must be strictly increasing");

        input_to_key.key_offsets = absolute_output_offsets_to_relative(input_to_key.key_offsets);
        tx.vin.push_back(input_to_key);
      }
    }

    // Allow mixed CA + native inputs for HF21 standard transfers so native
    // fees can be paid while CA value conservation is proven separately.

    if (shuffle_outs)
    {
      std::shuffle(destinations.begin(), destinations.end(), crypto::random_device{});
    }

    for (const tx_destination_entry& dst_entr : destinations)
      has_ca_outputs = has_ca_outputs || dst_entr.asset_id != crypto::null_pkey;

    // sort ins by their key image (strictly descending, consensus requirement)
    std::vector<size_t> ins_order(sources.size());
    for (size_t n = 0; n < sources.size(); ++n)
      ins_order[n] = n;
    std::sort(ins_order.begin(), ins_order.end(), [&](const size_t i0, const size_t i1) {
      const crypto::key_image* ki0 = get_txin_key_image_ptr(tx.vin[i0]);
      const crypto::key_image* ki1 = get_txin_key_image_ptr(tx.vin[i1]);
      CHECK_AND_ASSERT_MES(ki0 != nullptr && ki1 != nullptr, false, "Unsupported txin type in input sort");
      return memcmp(ki0, ki1, sizeof(*ki0)) > 0;
    });
    tools::apply_permutation(ins_order, [&] (size_t i0, size_t i1) {
      std::swap(tx.vin[i0], tx.vin[i1]);
      std::swap(in_contexts[i0], in_contexts[i1]);
      std::swap(sources[i0], sources[i1]);
    });

    // Enforce strict ordering/uniqueness locally so daemon-side "unsorted inputs"
    // cannot happen after wallet construction.
    for (size_t i = 1; i < tx.vin.size(); ++i)
    {
      const crypto::key_image* prev_ki = get_txin_key_image_ptr(tx.vin[i - 1]);
      const crypto::key_image* curr_ki = get_txin_key_image_ptr(tx.vin[i]);
      CHECK_AND_ASSERT_MES(prev_ki != nullptr && curr_ki != nullptr, false, "Unsupported txin type in input order validation");
      const int cmp = memcmp(curr_ki, prev_ki, sizeof(*prev_ki));
      CHECK_AND_ASSERT_MES(cmp < 0, false,
          "Input key image order invalid (must be strictly descending): prev="
          << tools::type_to_hex(*prev_ki) << ", curr=" << tools::type_to_hex(*curr_ki));
    }

    // figure out if we need to make additional tx pubkeys
    size_t num_stdaddresses = 0;
    size_t num_subaddresses = 0;
    account_public_address single_dest_subaddress;
    classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);

    // if this is a single-destination transfer to a subaddress, we set the tx pubkey to R=s*D
    if (num_stdaddresses == 0 && num_subaddresses == 1)
    {
      txkey_pub = rct::rct2pk(hwdev.scalarmultKey(rct::pk2rct(single_dest_subaddress.m_spend_public_key), rct::sk2rct(tx_key)));
    }
    else
    {
      txkey_pub = rct::rct2pk(hwdev.scalarmultBase(rct::sk2rct(tx_key)));
    }
    remove_field_from_tx_extra<tx_extra_pub_key>(tx.extra);
    add_tx_extra<tx_extra_pub_key>(tx, txkey_pub);

    std::vector<crypto::public_key> additional_tx_public_keys;
    std::vector<rct::key> zc_output_amount_masks;
    std::vector<rct::key> zc_output_asset_blinds;

    // we don't need to include additional tx keys if:
    //   - all the destinations are standard addresses
    //   - there's only one destination which is a subaddress
    bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
    
    //fill outputs
    size_t output_index = 0;

    tx_extra_tx_key_image_proofs key_image_proofs;
    bool found_change_already = false;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      LOG_PRINT_L0("Processing amount " << dst_entr.amount << ", is_subaddress: " << dst_entr.is_subaddress << ", asset_id: " << dst_entr.asset_id);
      crypto::public_key out_eph_public_key;

      bool this_dst_is_change_addr = false;
      hwdev.generate_output_ephemeral_keys(static_cast<uint16_t>(tx.version), this_dst_is_change_addr, sender_account_keys, txkey_pub, tx_key,
                                           dst_entr, change_addr, output_index,
                                           need_additional_txkeys, additional_tx_keys,
                                           additional_tx_public_keys, amount_keys, out_eph_public_key);

      if (tx.version >= txversion::v3_per_output_unlock_times)
      {
        if (change_addr && *change_addr == dst_entr && this_dst_is_change_addr && !found_change_already)
        {
          found_change_already = true;
          tx.output_unlock_times.push_back(0); // 0 unlock time for change
        }
        else
        {
          tx.output_unlock_times.push_back(unlock_time); // for now, all non-change have same unlock time
        }
      }

      if (tx.type == txtype::stake)
      {
        CHECK_AND_ASSERT_MES(dst_entr.addr == sender_account_keys.m_account_address, false, "A staking contribution must return back to the original sendee otherwise the pre-calculated key image is incorrect");
        CHECK_AND_ASSERT_MES(dst_entr.is_subaddress == false, false, "Staking back to a subaddress is not allowed"); // TODO(beldex): Maybe one day, revisit this
        CHECK_AND_ASSERT_MES(need_additional_txkeys == false, false, "Staking TX's can not required additional TX Keys"); // TODO(beldex): Maybe one day, revisit this

        if (!(change_addr && *change_addr == dst_entr))
        {
          auto& proof = key_image_proofs.proofs.emplace_back();
          keypair ephemeral_keys{};
          if(!generate_key_image_helper(sender_account_keys, subaddresses, out_eph_public_key, txkey_pub, additional_tx_public_keys, output_index, ephemeral_keys, proof.key_image, hwdev))
          {
            LOG_ERROR("Key image generation failed for staking TX!");
            return false;
          }

          hwdev.generate_key_image_signature(proof.key_image, out_eph_public_key, ephemeral_keys.sec, proof.signature);
        }
      }

      tx_out out;

      if (dst_entr.is_zarcanum() && tx_params.hf_version >= feature::CONFIDENTIAL_ASSETS)
      {
        LOG_PRINT_L0("Constructing confidential asset output");
        // ── HF21: confidential asset output ──────────────────────────────────
        // stealth_address is already out_eph_public_key (derived above)
        tx_out_zarcanum zout;
        zout.stealth_address = out_eph_public_key;

        // Derive blinding scalars for this output index
        crypto::key_derivation derivation{};
        hwdev.generate_key_derivation(dst_entr.addr.m_view_public_key, tx_key, derivation);
        LOG_PRINT_L0("Key derivation for output done");

        // Blinded asset ID:  T = asset_id + r*X
        rct::key r = zarcanum_derivation_to_scalar(derivation, output_index, "asset_blind");
        rct::key rX = rct::scalarmultX(r);
        rct::key asset_id_rct = rct::pk2rct(dst_entr.asset_id);
        rct::key T;
        rct::addKeys(T, asset_id_rct, rX);
        zout.blinded_asset_id = rct::rct2pk(T);
        LOG_PRINT_L0("Blinded asset ID done");

        // Amount commitment:  C = amount * asset_id + mask * G
        rct::key mask = zarcanum_derivation_to_scalar(derivation, output_index, "amount_mask");
        zout.amount_commitment = rct::rct2pk(rct::commitAsset(mask, asset_id_rct, dst_entr.amount));
        LOG_PRINT_L0("Amount commitment done");
        zc_output_amount_masks.push_back(mask);
        zc_output_asset_blinds.push_back(r);

        // Encrypted amount
        rct::key enc_key = zarcanum_derivation_to_scalar(derivation, output_index, "enc_amount");
        uint64_t enc_mask_64;
        memcpy(&enc_mask_64, enc_key.bytes, sizeof(uint64_t));
        zout.encrypted_amount = dst_entr.amount ^ enc_mask_64;
        LOG_PRINT_L0("Encrypted amount done");

        zout.version  = 0;
        zout.mix_attr = 0;

        out.amount = 0;   // plaintext amount is always 0 for ZC outputs
        out.target = zout;

        // Store blinding scalars for ZC_sig (pseudo-output) construction in Phase 7
        // These are passed back via tx_params or a separate out-param in future;
        // for now they are local and will be used when we add ZC_sig generation.
        (void)mask; // used above, will be collected for balance proof in Phase 8
      }
      else
      {
        // ── Standard BDX output ───────────────────────────────────────────────
        txout_to_key tk;
        tk.key = out_eph_public_key;
        out.amount = dst_entr.amount;
        out.target = tk;
        zc_output_asset_blinds.push_back(rct::zero());
      }

      tx.vout.push_back(out);
      output_index++;
    }
    CHECK_AND_ASSERT_MES(additional_tx_public_keys.size() == additional_tx_keys.size(), false, "Internal error creating additional public keys");

    if (tx.type == txtype::stake)
    {
      CHECK_AND_ASSERT_MES(key_image_proofs.proofs.size() >= 1, false, "No key image proofs were generated for staking tx");
      add_tx_key_image_proofs_to_tx_extra(tx.extra, key_image_proofs);

      if (tx_params.hf_version <= hf::hf15_flash)
        tx.type = txtype::standard;
    }

    remove_field_from_tx_extra<tx_extra_additional_pub_keys>(tx.extra);

    LOG_PRINT_L2("tx pubkey: " << txkey_pub);
    if (need_additional_txkeys)
    {
      LOG_PRINT_L2("additional tx pubkeys: ");
      for (size_t i = 0; i < additional_tx_public_keys.size(); ++i)
        LOG_PRINT_L2(additional_tx_public_keys[i]);
      add_additional_tx_pub_keys_to_extra(tx.extra, additional_tx_public_keys);
    }

    if (has_ca_inputs || has_ca_outputs)
    {
      if (!append_ca_output_assets_metadata_to_extra(tx, destinations))
      {
        LOG_ERROR("Failed to append CA output assets metadata to tx extra");
        return false;
      }
    }

    if (!sort_tx_extra(tx.extra, tx.extra))
      return false;

    // check for watch only wallet
    bool zero_secret_key = true;
    for (size_t i = 0; i < sizeof(sender_account_keys.m_spend_secret_key); ++i)
      zero_secret_key &= (sender_account_keys.m_spend_secret_key.data[i] == 0);
    if (zero_secret_key)
    {
      MDEBUG("Null secret key, skipping signatures");
    }
    const bool ca_path_used = has_ca_inputs || has_ca_outputs;
    const bool ca_transfer_path_used = ca_path_used && tx.type == txtype::standard;
    if (ca_transfer_path_used)
    {
      if (!has_ca_inputs)
      {
        LOG_ERROR("CA constructor path requires at least one CA/ZC input");
        return false;
      }
      tx.signatures.clear();

      // CA v1 flow is unsupported. For modern tx versions, continue below into the
      // existing RingCT construction/signing path so rct_signatures are still produced.
      if (tx.version == txversion::v1)
      {
        LOG_ERROR("CA constructor path with tx version v1 is unsupported");
        return false;
      }
    }

      if (!ca_transfer_path_used && tx.version == txversion::v1)
      {
          LOG_PRINT_L2("tx.version == txversion::v1");
          //generate ring signatures
          crypto::hash tx_prefix_hash;
          get_transaction_prefix_hash(tx, tx_prefix_hash);

          std::stringstream ss_ring_s;
          size_t i = 0;
          for(const tx_source_entry& src_entr:  sources)
          {
              ss_ring_s << "pub_keys:\n";
              std::vector<const crypto::public_key*> keys_ptrs;
              std::vector<crypto::public_key> keys(src_entr.outputs.size());
              size_t ii = 0;
              for(const tx_source_entry::output_entry& o: src_entr.outputs)
              {
                  keys[ii] = rct2pk(o.second.dest);
                  keys_ptrs.push_back(&keys[ii]);
                  ss_ring_s << o.second.dest << "\n";
                  ++ii;
              }

              tx.signatures.push_back(std::vector<crypto::signature>());
              std::vector<crypto::signature>& sigs = tx.signatures.back();
              sigs.resize(src_entr.outputs.size());
              if (!zero_secret_key)
                  crypto::generate_ring_signature(tx_prefix_hash, var::get<txin_to_key>(tx.vin[i]).k_image, keys_ptrs, in_contexts[i].in_ephemeral.sec, src_entr.real_output, sigs.data());
              ss_ring_s << "signatures:\n";
              std::for_each(sigs.begin(), sigs.end(), [&](const crypto::signature& s){ss_ring_s << s << "\n";});
              ss_ring_s << "prefix_hash:" << tx_prefix_hash << "\nin_ephemeral_key: " << in_contexts[i].in_ephemeral.sec << "\nreal_output: " << src_entr.real_output << "\n";
              i++;
          }

          MCINFO("construct_tx", "transaction_created: " << get_transaction_hash(tx) << "\n" << obj_to_json_str(tx) << "\n" << ss_ring_s.str());
    }
    else
    {

        size_t n_total_outs = sources[0].outputs.size(); // only for non-simple rct

        // the non-simple version is slightly smaller, but assumes all real inputs
        // are on the same index, so can only be used if there just one ring.
        LOG_PRINT_L2("sources.size:" << sources.size());
        LOG_PRINT_L2("range_proof_type" << static_cast<int>(rct_config.range_proof_type));
        bool use_simple_rct = sources.size() > 1 || rct_config.range_proof_type != rct::RangeProofType::Borromean;
        LOG_PRINT_L2("tx.version != txversion::v1 and use_simple_rct:" << use_simple_rct);
        if (!use_simple_rct)
        {
            LOG_PRINT_L2("not using simple rct");
            // non simple ringct requires all real inputs to be at the same index for all inputs
            for(const tx_source_entry& src_entr:  sources)
            {
                if(src_entr.real_output != sources.begin()->real_output)
                {
                    LOG_ERROR("All inputs must have the same index for non-simple ringct");
                    return false;
                }
            }

            // enforce same mixin for all outputs
            for (size_t i = 1; i < sources.size(); ++i) {
                if (n_total_outs != sources[i].outputs.size()) {
                    LOG_ERROR("Non-simple ringct transaction has varying ring size");
                    return false;
                }
            }
        }

          uint64_t amount_in = 0, amount_out = 0;
          const bool deploy_native_fee_accounting = tx_params.tx_type == txtype::deploy_new_asset;
          rct::ctkeyV inSk;
          inSk.reserve(sources.size());
          rct::ctkeyV legacy_inSk;
          std::vector<uint64_t> legacy_inamounts;
          std::vector<unsigned int> legacy_index;
          rct::ctkeyM legacy_mixRing;
          std::vector<rct::multisig_kLRki> legacy_kLRki;
          std::unordered_map<size_t, size_t> vin_to_legacy_sig_index;
          // mixRing indexing is done the other way round for simple
          rct::ctkeyM mixRing(use_simple_rct ? sources.size() : n_total_outs);
          rct::keyV dest_keys;
          std::vector<uint64_t> inamounts, outamounts;
          std::vector<unsigned int> index;
          std::vector<rct::multisig_kLRki> kLRki;
          const bool has_native_input_for_fee = std::any_of(sources.begin(), sources.end(), [](const tx_source_entry& s) {
              return s.asset_id == crypto::null_pkey;
          });
          const bool native_only_ca_fee_mode = ca_transfer_path_used && has_native_input_for_fee;
          uint64_t native_in_for_fee = 0, native_out_for_fee = 0;
          for (size_t i = 0; i < sources.size(); ++i) {
              rct::ctkey ctkey;
              const bool native_input = sources[i].asset_id == crypto::null_pkey;
              const uint64_t rct_input_amount = sources[i].amount;
              if (native_input)
                native_in_for_fee += sources[i].amount;
              amount_in += rct_input_amount;
              inamounts.push_back(rct_input_amount);
              index.push_back(sources[i].real_output);
              // inSk: (secret key, mask)
              ctkey.dest = rct::sk2rct(in_contexts[i].in_ephemeral.sec);
              ctkey.mask = sources[i].mask;
              inSk.push_back(ctkey);
              if (std::holds_alternative<txin_to_key>(tx.vin[i]))
              {
                vin_to_legacy_sig_index[i] = legacy_inSk.size();
                legacy_inSk.push_back(ctkey);
                legacy_inamounts.push_back(rct_input_amount);
                legacy_index.push_back(sources[i].real_output);
                if (msout)
                  legacy_kLRki.push_back(sources[i].multisig_kLRki);
              }
              else if (std::holds_alternative<txin_zc_input>(tx.vin[i]))
              {
                CHECK_AND_ASSERT_MES(sources[i].amount_commitment != crypto::null_pkey,
                  false, "ZC input is missing real amount commitment");
              }
              memwipe(&ctkey, sizeof(rct::ctkey));
              // inPk: (public key, commitment)
              // will be done when filling in mixRing
              if (msout) {
                  kLRki.push_back(sources[i].multisig_kLRki);
              }
          }
          for (size_t i = 0; i < tx.vout.size(); ++i) {
              // tx_out_zarcanum outputs carry their own commitments and are
              // not included in the legacy RCT dest_keys / outamounts vectors.
              if (std::holds_alternative<tx_out_zarcanum>(tx.vout[i].target)){
                dest_keys.push_back(rct::pk2rct(var::get<tx_out_zarcanum>(tx.vout[i].target).stealth_address));
              }else{
                dest_keys.push_back(rct::pk2rct(var::get<txout_to_key>(tx.vout[i].target).key));
              }

              // Deploy path mints non-native outputs in this tx. Those minted
              // amounts must not be treated as native spend in RingCT fee math.
              uint64_t rct_accounted_amount = tx.vout[i].amount;
              if (ca_transfer_path_used && std::holds_alternative<tx_out_zarcanum>(tx.vout[i].target))
              {
                CHECK_AND_ASSERT_MES(i < destinations.size(), false, "ZC output index out of range for destinations");
                rct_accounted_amount = destinations[i].amount;
              }
              if (native_only_ca_fee_mode)
              {
                const crypto::public_key dst_asset_id =
                    i < destinations.size() ? destinations[i].asset_id : crypto::null_pkey;
                if (dst_asset_id != crypto::null_pkey)
                  rct_accounted_amount = 0;
                else
                  native_out_for_fee += rct_accounted_amount;
              }
              else if (deploy_native_fee_accounting)
              {
                const crypto::public_key dst_asset_id =
                    i < destinations.size() ? destinations[i].asset_id : crypto::null_pkey;
                if (dst_asset_id != crypto::null_pkey)
                  rct_accounted_amount = 0;
              }

              outamounts.push_back(rct_accounted_amount);
              amount_out += rct_accounted_amount;
          }
        if (use_simple_rct)
        {
            // mixRing indexing is done the other way round for simple
            for (size_t i = 0; i < sources.size(); ++i)
            {
                mixRing[i].resize(sources[i].outputs.size());
                for (size_t n = 0; n < sources[i].outputs.size(); ++n)
                {
                    mixRing[i][n] = sources[i].outputs[n].second;
                }
            }
            legacy_mixRing.resize(legacy_inSk.size());
            for (const auto& [vin_idx, legacy_idx] : vin_to_legacy_sig_index)
            {
              legacy_mixRing[legacy_idx].resize(sources[vin_idx].outputs.size());
              for (size_t n = 0; n < sources[vin_idx].outputs.size(); ++n)
                legacy_mixRing[legacy_idx][n] = sources[vin_idx].outputs[n].second;
            }
        }
        else {
            for (size_t i = 0; i < sources.size(); ++i) {
                mixRing[i].resize(sources[i].outputs.size());
                for (size_t n = 0; n < sources[i].outputs.size(); ++n) {
                    mixRing[i][n] = sources[i].outputs[n].second;
                }
            }
            legacy_mixRing = mixRing;
        }
        // fee
        if (!use_simple_rct && amount_in > amount_out)
            outamounts.push_back(amount_in - amount_out);

          if (tx_params.burn_fixed) {
              if (amount_in < amount_out + tx_params.burn_fixed) {
                  LOG_ERROR("invalid burn amount: tx does not have enough unspent funds available; amount_in: "
                                    << std::to_string(amount_in) << "; amount_out + tx_params.burn_fixed: "
                                    << std::to_string(amount_out) << " + " << std::to_string(tx_params.burn_fixed));
                  return false;
              }
              remove_field_from_tx_extra<tx_extra_burn>(
                      tx.extra); // doesn't have to be present (but the wallet puts a dummy here as a safety to avoid growing the tx)
              if (!add_burned_amount_to_tx_extra(tx.extra, tx_params.burn_fixed)) {
                  LOG_ERROR("failed to add burn amount to tx extra");
                  return false;
              }
          }

          // zero out all amounts to mask rct outputs, real amounts are now encrypted
          for (size_t i = 0; i < tx.vin.size(); ++i) {
              if (!sources[i].rct)
                  continue;
              if (auto* in_to_key = std::get_if<txin_to_key>(&tx.vin[i]))
                  in_to_key->amount = 0;
          }
          for (size_t i = 0; i < tx.vout.size(); ++i)
              tx.vout[i].amount = 0;

          const crypto::hash tx_prefix_hash = get_transaction_prefix_hash(tx);
          rct::ctkeyV outSk;
          if (use_simple_rct) {
              LOG_PRINT_L2("genRctSimple");
              CHECK_AND_ASSERT_MES(legacy_inSk.size() == legacy_inamounts.size(), false, "legacy signer vector size mismatch");
              CHECK_AND_ASSERT_MES(legacy_inSk.size() == legacy_index.size(), false, "legacy index vector size mismatch");
              CHECK_AND_ASSERT_MES(legacy_inSk.size() == legacy_mixRing.size(), false, "legacy mixRing vector size mismatch");
              const uint64_t txn_fee_for_rct = ca_transfer_path_used
                  ? (native_only_ca_fee_mode ? (native_in_for_fee - native_out_for_fee) : 0)
                  : (amount_in - amount_out);
              tx.rct_signatures = rct::genRctSimple(rct::hash2rct(tx_prefix_hash), legacy_inSk, dest_keys, legacy_inamounts,
                                                    outamounts,
                                                    txn_fee_for_rct, legacy_mixRing, amount_keys, msout ? &legacy_kLRki : NULL,
                                                    msout, legacy_index, outSk, rct_config, hwdev);
          }
          else {
              LOG_PRINT_L2("genRct");
              tx.rct_signatures = rct::genRct(rct::hash2rct(tx_prefix_hash), inSk, dest_keys, outamounts, mixRing,
                                              amount_keys, msout ? &kLRki[0] : NULL, msout, sources[0].real_output,
                                              outSk, rct_config, hwdev); // same index assumption

          }

          const auto vin_offsets_pre_sign = extract_vin_offsets(tx.vin);
          const auto vin_key_images_pre_sign = extract_vin_key_images(tx.vin);
          const crypto::hash mixring_fp_pre_sign = mixring_fingerprint(mixRing);

          if (ca_transfer_path_used)
          {
              tx.asset_proofs.clear();

              // Build a unique non-native input asset ring for BGE surjection proofs.
              // Mirror verifier semantics exactly: derive from tx.vin ZC inputs in vin order.
              std::vector<rct::key> input_asset_ring;
              input_asset_ring.reserve(tx.vin.size());
              for (const auto& in : tx.vin)
              {
                  if (!std::holds_alternative<txin_zc_input>(in))
                      continue;
                  const auto& zc_in = std::get<txin_zc_input>(in);
                  if (zc_in.asset_id == crypto::null_pkey)
                      continue;
                  const rct::key aid = rct::pk2rct(zc_in.asset_id);
                  const bool seen = std::any_of(input_asset_ring.begin(), input_asset_ring.end(),
                      [&](const auto& prev){ return rct::equalKeys(prev, aid); });
                  if (!seen)
                      input_asset_ring.push_back(aid);
              }
              for (const auto& in : tx.vin)
              {
                  if (!std::holds_alternative<txin_zc_input>(in))
                      continue;
                  const auto& zc_in = std::get<txin_zc_input>(in);
                  CHECK_AND_ASSERT_MES(zc_in.asset_id != crypto::null_pkey, false,
                      "ZC input is missing asset_id while building BGE input domain");
              }
              CHECK_AND_ASSERT_MES(!input_asset_ring.empty(), false, "CA transfer requires at least one non-native input asset for surjection proofs");

              // Use canonical tx prefix hash for ZC proof transcript seeding.
              const rct::key tx_prefix_rct = rct::hash2rct(tx_prefix_hash);

              // ── Per-input ZC_sig proofs ───────────────────────────────────
              for (size_t i = 0; i < tx.vin.size(); ++i)
              {
                  if (!std::holds_alternative<txin_zc_input>(tx.vin[i]))
                      continue;

                  CHECK_AND_ASSERT_MES(i < mixRing.size(), false, "ZC input index out of range for full mixRing");
                  CHECK_AND_ASSERT_MES(i < index.size(), false, "ZC input index out of range for real index");

                  rct::ctkey spend_sk{};
                  spend_sk.dest = rct::sk2rct(in_contexts[i].in_ephemeral.sec);
                  const rct::key input_mask = rct::pk2rct(sources[i].amount_blinding_mask);
                  const rct::key input_commitment = rct::pk2rct(sources[i].amount_commitment);
                  const rct::key pseudo_mask = rct::skGen();
                  spend_sk.mask = pseudo_mask;
                  rct::key z = rct::zero();
                  sc_sub(z.bytes, input_mask.bytes, pseudo_mask.bytes); // z = input_mask - pseudo_mask
                  rct::key zG = rct::scalarmultBase(z);
                  rct::key zc_pseudo_out = rct::zero();
                  rct::subKeys(zc_pseudo_out, input_commitment, zG); // C_offset = C_in - z*G
                  const rct::key clsag_msg = [&]{
                      std::string blob{cryptonote::hf21::ZC_CLSAG_V1};
                      blob.append(reinterpret_cast<const char*>(tx_prefix_rct.bytes), sizeof(tx_prefix_rct.bytes));
                      const uint64_t idx64 = i;
                      blob.append(reinterpret_cast<const char*>(&idx64), sizeof(idx64));
                      return rct::hash2rct(crypto::cn_fast_hash(blob.data(), blob.size()));
                  }();
                  MWARNING("[ZC-DBG][sign/input" << i << "] message=<" << clsag_msg
                           << "> pseudoOut/C_offset=<" << zc_pseudo_out
                           << "> ring_size=" << mixRing[i].size());
                  for (size_t ri = 0; ri < mixRing[i].size(); ++ri)
                  {
                    MWARNING("[ZC-DBG][sign/input" << i << "] ring[" << ri << "] dest=<"
                             << mixRing[i][ri].dest << "> mask=<" << mixRing[i][ri].mask << ">");
                  }
                  rct::ZC_sig zc_sig = rct::genZCSig(
                      clsag_msg,
                      mixRing[i],
                      spend_sk,
                      z,
                      zc_pseudo_out,
                      std::get<txin_zc_input>(tx.vin[i]).k_image,
                      index[i],
                      hwdev);
                  CHECK_AND_ASSERT_MES(rct::verZCSig(clsag_msg, zc_sig, mixRing[i], zc_sig.pseudo_out_commitment),
                    false, "local ZC_sig self-verification failed");
                  tx.asset_proofs.emplace_back(std::move(zc_sig));
              }

              // ── One surjection wrapper containing one BGE proof per ZC output ──
              rct::zc_asset_surjection_proof surj{};
              size_t zc_out_idx = 0;
              for (size_t out_idx = 0; out_idx < tx.vout.size(); ++out_idx)
              {
                  if (!std::holds_alternative<tx_out_zarcanum>(tx.vout[out_idx].target))
                      continue;

                  CHECK_AND_ASSERT_MES(out_idx < zc_output_asset_blinds.size(), false, "ZC output index out of range for stored asset blinds");
                  const rct::key r = zc_output_asset_blinds[out_idx];
                  CHECK_AND_ASSERT_MES(r != rct::zero(), false, "Missing stored asset blind for ZC output");

                  const auto& zout = std::get<tx_out_zarcanum>(tx.vout[out_idx].target);
                  const rct::key T = rct::pk2rct(zout.blinded_asset_id);
                  rct::key out_asset = rct::zero();
                  rct::subKeys(out_asset, T, rct::scalarmultX(r));

                  size_t real_index = 0;
                  auto it = input_asset_ring.end();
                  for (auto jt = input_asset_ring.begin(); jt != input_asset_ring.end(); ++jt)
                  {
                      if (rct::equalKeys(*jt, out_asset))
                      {
                          it = jt;
                          break;
                      }
                  }
                  CHECK_AND_ASSERT_MES(it != input_asset_ring.end(), false,
                      "CA output asset is not present in input asset domain while constructing BGE proof");
                  real_index = std::distance(input_asset_ring.begin(), it);

                  std::string bge_ctx_blob{cryptonote::hf21::CA_SURJECTION_V1};
                  bge_ctx_blob.append(reinterpret_cast<const char*>(tx_prefix_rct.bytes), sizeof(tx_prefix_rct.bytes));
                  const uint64_t bge_out_index = zc_out_idx;
                  bge_ctx_blob.append(reinterpret_cast<const char*>(&bge_out_index), sizeof(bge_out_index));
                  const rct::key ctx = rct::hash2rct(crypto::cn_fast_hash(bge_ctx_blob.data(), bge_ctx_blob.size()));

                  crypto::BGE_proof_s bge{};
                  CHECK_AND_ASSERT_MES(
                      crypto::generate_BGE_proof(ctx, input_asset_ring, T, r, real_index, bge),
                      false,
                      "Failed to generate BGE surjection proof");
                  CHECK_AND_ASSERT_MES(
                      crypto::verify_BGE_proof(ctx, input_asset_ring, T, bge),
                      false,
                      "Local BGE self-verification failed");
                  surj.bge_proofs.push_back(std::move(bge));
                  ++zc_out_idx;
              }
              tx.asset_proofs.emplace_back(std::move(surj));

              // ── Balance proof wrapper (HF21 asset_proofs path) ────────────
              rct::zc_balance_proof bal{};
              {
                  rct::key in_mask_sum = rct::zero();
                  for (const auto& src : sources)
                  {
                      if (src.asset_id == crypto::null_pkey)
                          continue;
                      sc_add(in_mask_sum.bytes, in_mask_sum.bytes, rct::pk2rct(src.amount_blinding_mask).bytes);
                  }

                  rct::key out_mask_sum = rct::zero();
                  for (const auto& m : zc_output_amount_masks)
                      sc_add(out_mask_sum.bytes, out_mask_sum.bytes, m.bytes);

                  rct::key a = rct::zero();
                  sc_sub(a.bytes, in_mask_sum.bytes, out_mask_sum.bytes);
                  const rct::key b = rct::zero();
                  bal.P = rct::scalarmultBase(a);
                  std::string bal_ctx_blob{cryptonote::hf21::CA_BALANCE_V1};
                  bal_ctx_blob.append(reinterpret_cast<const char*>(tx_prefix_rct.bytes), sizeof(tx_prefix_rct.bytes));
                  const uint64_t bal_ctx_index = 0;
                  bal_ctx_blob.append(reinterpret_cast<const char*>(&bal_ctx_index), sizeof(bal_ctx_index));
                  const rct::key bal_ctx = rct::hash2rct(crypto::cn_fast_hash(bal_ctx_blob.data(), bal_ctx_blob.size()));
                  CHECK_AND_ASSERT_MES(
                      crypto::generate_linear_composition_proof(bal_ctx, bal.P, a, b, bal.lcp),
                      false,
                      "Failed to generate ZC balance proof");
              }
              tx.asset_proofs.emplace_back(std::move(bal));
          }
          else if (tx.type == txtype::deploy_new_asset && has_ca_outputs)
          {
              // HF21 deploy path: attach ownership proof expected by verAssetProofs().
              tx.asset_proofs.clear();

              cryptonote::tx_extra_asset_descriptor_operation ownership_ado{};
              const bool has_ownership_ado = cryptonote::get_asset_descriptor_operation_from_tx_extra(tx.extra, ownership_ado);
              CHECK_AND_ASSERT_MES(has_ownership_ado, false, "deploy_new_asset is missing tx_extra asset descriptor operation");

              const crypto::public_key expected_owner = sender_account_keys.m_account_address.m_spend_public_key;
              CHECK_AND_ASSERT_MES(ownership_ado.descriptor.owner == expected_owner, false,
                                   "deploy_new_asset owner key must match wallet spend public key for ownership signing");

              std::string blob{cryptonote::hf21::CA_OWNERSHIP_V1};
              const rct::key tx_prefix_rct = rct::hash2rct(tx_prefix_hash);
              blob.append(reinterpret_cast<const char*>(tx_prefix_rct.bytes), sizeof(tx_prefix_rct.bytes));
              const auto asset_id = cryptonote::get_or_calculate_asset_id(ownership_ado);
              blob.append(reinterpret_cast<const char*>(&asset_id), sizeof(asset_id));
              const uint8_t op_type = static_cast<uint8_t>(ownership_ado.operation_type);
              blob.append(reinterpret_cast<const char*>(&op_type), sizeof(op_type));
              blob.append(reinterpret_cast<const char*>(&ownership_ado.descriptor.owner), sizeof(ownership_ado.descriptor.owner));
              const rct::key ownership_ctx = rct::hash2rct(crypto::cn_fast_hash(blob.data(), blob.size()));

              rct::asset_operation_ownership_proof ownership_proof{};
              const rct::key owner_pk = rct::pk2rct(expected_owner);
              const rct::key owner_sk = rct::sk2rct(sender_account_keys.m_spend_secret_key);
              CHECK_AND_ASSERT_MES(crypto::generate_schnorr_sig(ownership_ctx, owner_pk, owner_sk, ownership_proof.sig),
                                   false, "failed to generate deploy ownership proof");
              tx.asset_proofs.emplace_back(std::move(ownership_proof));
          }

          const auto vin_offsets_post_sign = extract_vin_offsets(tx.vin);
          const auto vin_key_images_post_sign = extract_vin_key_images(tx.vin);
          const crypto::hash mixring_fp_post_sign = mixring_fingerprint(mixRing);
          CHECK_AND_ASSERT_MES(vin_offsets_pre_sign == vin_offsets_post_sign, false,
                               "vin key_offsets mutated after signing/proof generation");
          CHECK_AND_ASSERT_MES(vin_key_images_pre_sign == vin_key_images_post_sign, false,
                               "vin key images/order mutated after signing/proof generation");
          CHECK_AND_ASSERT_MES(mixring_fp_pre_sign == mixring_fp_post_sign, false,
                               "mixRing mutated after signing/proof generation");


          memwipe(inSk.data(), inSk.size() * sizeof(rct::ctkey));

          CHECK_AND_ASSERT_MES(tx.vout.size() == outSk.size(), false, "outSk size does not match vout");

          MCINFO("construct_tx",
                 "transaction_created: " << get_transaction_hash(tx) << "\n" << obj_to_json_str(tx) << "\n");
    }
    // HF21 standard CA transfers rely on tx.asset_proofs (ZC proofs) path.
    // Keep transaction::proofs unused/empty here until tx_proof_* integration
    // is fully implemented end-to-end.
    if (ca_transfer_path_used)
      tx.proofs.clear();

    tx.invalidate_hashes();

    return true;
  }
  //---------------------------------------------------------------
  bool construct_tx_and_get_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, std::vector<tx_destination_entry>& destinations, const std::optional<cryptonote::tx_destination_entry>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys, const rct::RCTConfig &rct_config, rct::multisig_out *msout, beldex_construct_tx_params const &tx_params)
  {
    hw::device &hwdev = sender_account_keys.get_device();
    hwdev.open_tx(tx_key, transaction::get_max_version_for_hf(tx_params.hf_version), tx_params.tx_type);
    try {
      // figure out if we need to make additional tx pubkeys
      size_t num_stdaddresses = 0;
      size_t num_subaddresses = 0;
      account_public_address single_dest_subaddress;
      classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);
      bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
      if (need_additional_txkeys)
      {
        additional_tx_keys.clear();
        for (const auto &d: destinations)
          additional_tx_keys.push_back(keypair{sender_account_keys.get_device()}.sec);
      }

      bool r = construct_tx_with_tx_key(sender_account_keys, subaddresses, sources, destinations, change_addr, extra, tx, unlock_time, tx_key, additional_tx_keys, rct_config, msout, true /*shuffle_outs*/, tx_params);
      hwdev.close_tx();
      return r;
    } catch(...) {
      hwdev.close_tx();
      throw;
    }
  }
  //---------------------------------------------------------------
  bool construct_tx(const account_keys& sender_account_keys, std::vector<tx_source_entry> &sources, const std::vector<tx_destination_entry>& destinations, const std::optional<cryptonote::tx_destination_entry>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time, const beldex_construct_tx_params &tx_params)
  {
     std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
     subaddresses[sender_account_keys.m_account_address.m_spend_public_key] = {0,0};
     crypto::secret_key tx_key;
     std::vector<crypto::secret_key> additional_tx_keys;
     std::vector<tx_destination_entry> destinations_copy = destinations;

     // Always construct CLSAG transactions.  They weren't actually acceptable before HF 16, but
     // they are now for our fake networks (which we need to do because we no longer have pre-CLSAG
     // tx generation code).
     rct::RCTConfig rct_config{
              tx_params.hf_version < hf::hf10_bulletproofs ? rct::RangeProofType::Borromean : rct::RangeProofType::PaddedBulletproof,
              tx_params.hf_version >= feature::CLSAG ? 3 : tx_params.hf_version >= feature::SMALLER_BP ? 2 : 1
      };

     return construct_tx_and_get_tx_key(sender_account_keys, subaddresses, sources, destinations_copy, change_addr, extra, tx, unlock_time, tx_key, additional_tx_keys, rct_config, NULL, tx_params);
  }
  //---------------------------------------------------------------
  bool generate_genesis_block(block& bl, network_type nettype)
  {
      const auto& conf = get_config(nettype);
    //genesis block
    bl = {};

    CHECK_AND_ASSERT_MES(oxenc::is_hex(conf.GENESIS_TX), false, "failed to parse coinbase tx from hard coded blob");
    std::string tx_bl = oxenc::from_hex(conf.GENESIS_TX);
    bool r = parse_and_validate_tx_from_blob(tx_bl, bl.miner_tx);
    CHECK_AND_ASSERT_MES(r, false, "failed to parse coinbase tx from hard coded blob");
    bl.major_version = hf::hf1;
    bl.minor_version = 0;
    bl.timestamp = 0;
    bl.nonce = conf.GENESIS_NONCE;
    miner::find_nonce_for_given_block([](const cryptonote::block &b, uint64_t height, unsigned int threads, crypto::hash &hash){
      hash = cryptonote::get_block_longhash(network_type::UNDEFINED, cryptonote::randomx_longhash_context(NULL, b, height), b, height, threads);
      return true;
    }, bl, 1, 0);
    bl.invalidate_hashes();
    return true;
  }
  //---------------------------------------------------------------
  crypto::hash get_altblock_longhash(cryptonote::network_type nettype, randomx_longhash_context const &randomx_context, const block& b, uint64_t height)
  {
    crypto::hash result = {};
    if (nettype == network_type::FAKECHAIN || b.major_version < hf::hf13_checkpointing)
    {
      result = get_block_longhash(nettype, randomx_context, b, height, 0);
    }
    else
    {
      blobdata bd = get_block_hashing_blob(b);
      rx_slow_hash(randomx_context.current_blockchain_height, randomx_context.seed_height, randomx_context.seed_block_hash.data, bd.data(), bd.size(), result.data, 0, 1);
    }

    return result;
  }

  randomx_longhash_context::randomx_longhash_context(const Blockchain *pbc,
                                                     const block &b /*block to longhash*/,
                                                     const uint64_t height)
  {
    *this = {};
    if (b.major_version >= hf::hf13_checkpointing)
    {
      if (pbc) // null only happens when generating genesis block, 0 init randomx is ok
      {
        seed_height               = rx_seedheight(height);
        seed_block_hash           = pbc->get_pending_block_id_by_height(seed_height);
        current_blockchain_height = pbc->get_current_blockchain_height();
      }
    }
  }

  crypto::hash get_block_longhash(cryptonote::network_type nettype, randomx_longhash_context const &randomx_context, const block& b, uint64_t height, int miners)
  {
    crypto::hash result      = {};
    const blobdata bd        = get_block_hashing_blob(b);
    const auto hf_version = b.major_version;

#if defined(BELDEX_INTEGRATION_TESTS)
    miners = 0;
#endif

    crypto::cn_slow_hash_type cn_type = cn_slow_hash_type::heavy_v1;
    if (nettype == network_type::FAKECHAIN)
    {
      cn_type = cn_slow_hash_type::turtle_lite_v2;
    }
    else
    {
      if (hf_version >= hf::hf13_checkpointing)
      {
        rx_slow_hash(randomx_context.current_blockchain_height,
                     randomx_context.seed_height,
                     randomx_context.seed_block_hash.data,
                     bd.data(),
                     bd.size(),
                     result.data,
                     miners,
                     0);
        return result;
      }

      if (hf_version >= hf::hf11_infinite_staking)
        cn_type = cn_slow_hash_type::turtle_lite_v2;
      else if (hf_version >= hf::hf7)
        cn_type = crypto::cn_slow_hash_type::heavy_v2;
    }

    crypto::cn_slow_hash(bd.data(), bd.size(), result, cn_type);
    return result;
  }

  crypto::hash get_block_longhash_w_blockchain(cryptonote::network_type nettype, const Blockchain *pbc, const block& b, uint64_t height, int miners)
  {
    crypto::hash result = get_block_longhash(nettype,randomx_longhash_context(pbc, b, height), b, height, miners);
    return result;
  }

  void get_block_longhash_reorg(const uint64_t split_height)
  {
    rx_reorg(split_height);
  }
}
