// Copyright (c) 2026, The Beldex Project
// All rights reserved.
#pragma once

#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/tx_extra.h"
#include "serialization/string.h"

namespace cryptonote
{
struct token_consensus_state
{
  bool exists = false;
  token_descriptor_base descriptor{};
  uint64_t current_supply = 0;
  uint64_t total_max_supply = 0;

  BEGIN_SERIALIZE()
    FIELD(exists)
    FIELD(descriptor)
    FIELD(current_supply)
    FIELD(total_max_supply)
  END_SERIALIZE()
};

// v8 on-disk state. The count is also the sequence of the next history entry.
struct token_state_record
{
  token_consensus_state state{};
  uint64_t history_size = 0;

  BEGIN_SERIALIZE()
    FIELD(state)
    FIELD(history_size)
  END_SERIALIZE()
};

// One bounded entry per operation; the prior state permits constant-work undo.
struct token_history_entry
{
  tx_extra_token_descriptor_operation operation{};
  token_state_record previous{};

  BEGIN_SERIALIZE()
    FIELD(operation)
    FIELD(previous)
  END_SERIALIZE()
};

bool validate_token_descriptor_operation(const tx_extra_token_descriptor_operation& op, std::string& reason);
bool apply_token_operation_to_state(const crypto::token_id& token_id,
    const tx_extra_token_descriptor_operation& op, token_consensus_state& state, std::string& reason);
bool load_token_current_state(BlockchainDB& db, const crypto::token_id& token_id,
    token_consensus_state& state, std::string& reason);

// Caller must hold the block write transaction; failures abort the whole block.
void append_token_operations(BlockchainDB& db, const transaction& tx);
void rewind_token_operations(BlockchainDB& db, const transaction& tx);

// Bounded history reads, for queries only. Never used to reconstruct current state.
std::vector<tx_extra_token_descriptor_operation> get_token_history_page(
    BlockchainDB& db, const crypto::token_id& token_id, uint64_t start, size_t count);
} // namespace cryptonote
