// Copyright (c) 2026, The Beldex Project
// All rights reserved.
#include "token_state.h"

#include <limits>
#include <string_view>
#include "cryptonote_basic/token_descriptor.h"
#include "cryptonote_basic/token_descriptor_operation_utils.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "serialization/binary_utils.h"

namespace cryptonote
{
namespace
{
token_state_record load_record(BlockchainDB& db, const crypto::token_id& token_id)
{
  token_state_record record{};
  std::string blob;
  if (!db.get_token_state(token_id, blob))
  {
    if (db.get_token_history_entry(token_id, 0, blob))
      throw DB_ERROR("Token history exists without current state");
    return record;
  }
  serialization::parse_binary(blob, record);
  if (!record.state.exists || record.history_size == 0 ||
      record.state.current_supply != record.state.descriptor.current_supply ||
      record.state.total_max_supply != record.state.descriptor.total_max_supply ||
      record.state.current_supply > record.state.total_max_supply)
    throw DB_ERROR("Inconsistent stored token state");
  return record;
}

token_history_entry load_entry(BlockchainDB& db, const crypto::token_id& token_id, uint64_t sequence)
{
  std::string blob;
  if (!db.get_token_history_entry(token_id, sequence, blob))
    throw DB_ERROR("Missing token history entry");
  token_history_entry entry{};
  serialization::parse_binary(blob, entry);
  if (entry.previous.history_size != sequence || entry.previous.state.exists != (sequence != 0))
    throw DB_ERROR("Inconsistent token undo sequence");
  return entry;
}
} // namespace

bool load_token_current_state(BlockchainDB& db, const crypto::token_id& token_id,
    token_consensus_state& state, std::string& reason)
{
  try
  {
    db_rtxn_guard guard{db};
    state = load_record(db, token_id).state;
    return true;
  }
  catch (const std::exception& e)
  {
    reason = std::string{"Failed to load token state: "} + e.what();
    return false;
  }
}

void append_token_operations(BlockchainDB& db, const transaction& tx)
{
  size_t index = 0;
  tx_extra_token_descriptor_operation op{};
  while (get_token_descriptor_operation_from_tx_extra(tx.extra, op, index++))
  {
    std::string reason;
    if (!validate_token_descriptor_operation(op, reason))
      throw DB_ERROR("Invalid token operation: " + reason);
    const auto token_id = get_or_calculate_token_id(op);
    auto record = load_record(db, token_id);
    token_history_entry entry{op, record};
    if (record.history_size == std::numeric_limits<uint64_t>::max())
      throw DB_ERROR("Token history sequence overflow");
    if (!apply_token_operation_to_state(token_id, op, record.state, reason))
      throw DB_ERROR("Invalid token state transition: " + reason);
    db.add_token_history_entry(token_id, record.history_size++, serialization::dump_binary(entry));
    db.set_token_state(token_id, serialization::dump_binary(record));
  }
}

void rewind_token_operations(BlockchainDB& db, const transaction& tx)
{
  std::vector<tx_extra_token_descriptor_operation> operations;
  size_t index = 0;
  tx_extra_token_descriptor_operation op{};
  while (get_token_descriptor_operation_from_tx_extra(tx.extra, op, index++))
    operations.push_back(op);

  for (auto it = operations.rbegin(); it != operations.rend(); ++it)
  {
    const auto token_id = get_or_calculate_token_id(*it);
    const auto record = load_record(db, token_id);
    if (!record.state.exists)
      throw DB_ERROR("Token state missing while rewinding");
    auto entry = load_entry(db, token_id, record.history_size - 1);
    if (serialization::dump_binary(entry.operation) != serialization::dump_binary(*it))
      throw DB_ERROR("Token undo operation does not match detached transaction");
    // Check the undo snapshot before trusting it, without reading older history.
    auto restored = entry.previous.state;
    auto current = record.state;
    std::string reason;
    if (!apply_token_operation_to_state(token_id, entry.operation, restored, reason) ||
        serialization::dump_binary(restored) != serialization::dump_binary(current))
      throw DB_ERROR("Token undo snapshot does not reproduce current state");
    db.remove_token_history_entry(token_id, record.history_size - 1);
    if (entry.previous.state.exists)
      db.set_token_state(token_id, serialization::dump_binary(entry.previous));
    else if (!db.remove_token_state(token_id))
      throw DB_ERROR("Token state disappeared while rewinding registration");
  }
}

std::vector<tx_extra_token_descriptor_operation> get_token_history_page(
    BlockchainDB& db, const crypto::token_id& token_id, uint64_t start, size_t count)
{
  if (count > 1000)
    throw std::invalid_argument("Token history page exceeds 1000 entries");
  db_rtxn_guard guard{db};
  const auto record = load_record(db, token_id);
  std::vector<tx_extra_token_descriptor_operation> result;
  for (uint64_t i = start; i < record.history_size && result.size() < count; ++i)
    result.push_back(load_entry(db, token_id, i).operation);
  return result;
}

bool validate_token_descriptor_operation(const tx_extra_token_descriptor_operation& op, std::string& reason)
{
  constexpr uint8_t known_fields_mask =
      token_field_amount_commitment |
      token_field_token_id |
      token_field_descriptor |
      token_field_amount |
      token_field_token_id_salt;

  if (op.version != 1)
  {
    reason = "unsupported token descriptor operation version";
    return false;
  }

  if (op.operation_type == token_descriptor_operation_type::undefined)
  {
    reason = "token descriptor operation type is undefined";
    return false;
  }

  if ((op.fields & ~known_fields_mask) != 0)
  {
    reason = "token descriptor operation has unknown fields set";
    return false;
  }

  if (op.field_is_set(token_field_token_id) && op.token_id == crypto::null_tid)
  {
    reason = "token descriptor operation has null token_id with token_id field set";
    return false;
  }

  if (op.field_is_set(token_field_amount_commitment) && op.amount_commitment == crypto::null_pkey)
  {
    reason = "token descriptor operation has null amount_commitment with amount_commitment field set";
    return false;
  }

  switch (op.operation_type)
  {
    case token_descriptor_operation_type::register_token:
      if (!op.field_is_set(token_field_descriptor))
      {
        reason = "register_token operation requires descriptor field";
        return false;
      }
      if (op.field_is_set(token_field_token_id))
      {
        reason = "register_token must not carry an explicit token_id; it is derived from the descriptor";
        return false;
      }
      break;

    case token_descriptor_operation_type::mint_token:
    case token_descriptor_operation_type::burn_token:
      if (!op.field_is_set(token_field_amount) || op.amount == 0)
      {
        reason = "token mint/burn operation requires non-zero amount";
        return false;
      }
      break;

    case token_descriptor_operation_type::update_token:
      if (!op.field_is_set(token_field_descriptor))
      {
        reason = "update_token operation requires descriptor field";
        return false;
      }
      break;

    default:
      reason = "unsupported token descriptor operation type";
      return false;
  }

  if (get_or_calculate_token_id(op) == crypto::null_tid)
  {
    reason = "unable to derive non-null token_id from operation";
    return false;
  }

  return true;
}

bool apply_token_operation_to_state(
    const crypto::token_id& token_id,
    const tx_extra_token_descriptor_operation& op,
    token_consensus_state& state,
    std::string& reason)
{
  auto reject = [&reason](std::string_view msg) {
    reason = std::string{msg};
    return false;
  };

  if (op.field_is_set(token_field_token_id) && op.token_id != token_id)
    return reject("token_id mismatch between key and operation");

  if (op.field_is_set(token_field_amount) && op.amount == 0)
    return reject("amount field must be non-zero when set");

  switch (op.operation_type)
  {
    case token_descriptor_operation_type::register_token:
    {
      if (state.exists)
        return reject("register_token for existing token");
      if (!op.field_is_set(token_field_descriptor))
        return reject("register_token missing descriptor");
      if (op.field_is_set(token_field_token_id))
        return reject("register_token must not carry an explicit token_id; it is derived from the descriptor");

      const auto& d = op.descriptor;
      if (d.ticker.empty())
        return reject("token ticker must not be empty");
      if (d.full_name.empty())
        return reject("token full_name must not be empty");
      if (d.owner == crypto::null_pkey)
        return reject("token owner must not be null");
      if (d.current_supply > d.total_max_supply)
        return reject("current_supply exceeds total_max_supply");

      {
        std::string descriptor_error;
        if (!validate_token_descriptor_for_registration(d, descriptor_error))
          return reject("register_token descriptor rejected: " + descriptor_error);
      }

      state.exists = true;
      state.descriptor = d;
      state.current_supply = d.current_supply;
      state.total_max_supply = d.total_max_supply;
      return true;
    }

    case token_descriptor_operation_type::mint_token:
    {
      if (!state.exists)
        return reject("mint_token for unknown token");
      if (!op.field_is_set(token_field_amount))
        return reject("mint_token missing amount");
      if (state.current_supply > std::numeric_limits<uint64_t>::max() - op.amount)
        return reject("mint_token supply overflow");
      const uint64_t new_supply = state.current_supply + op.amount;
      if (new_supply > state.total_max_supply)
        return reject("mint_token exceeds max supply");
      state.current_supply = new_supply;
      state.descriptor.current_supply = new_supply;
      return true;
    }

    case token_descriptor_operation_type::burn_token:
    {
      if (!state.exists)
        return reject("burn_token for unknown token");
      if (!op.field_is_set(token_field_amount))
        return reject("burn_token missing amount");
      if (state.current_supply < op.amount)
        return reject("burn_token exceeds current supply");
      state.current_supply -= op.amount;
      state.descriptor.current_supply = state.current_supply;
      return true;
    }

    case token_descriptor_operation_type::update_token:
    {
      if (!state.exists)
        return reject("update_token for unknown token");
      if (!op.field_is_set(token_field_descriptor))
        return reject("update_token missing descriptor");

      const auto& d = op.descriptor;
      if (d.owner == crypto::null_pkey)
        return reject("updated token owner must not be null");

      if (d.total_max_supply != state.total_max_supply)
        return reject("update_token cannot modify total_max_supply");
      if (d.current_supply != state.current_supply)
        return reject("update_token cannot modify current_supply");
      if (d.ticker != state.descriptor.ticker)
        return reject("update_token cannot modify ticker");
      if (d.full_name != state.descriptor.full_name)
        return reject("update_token cannot modify full_name");
      if (d.decimal_point != state.descriptor.decimal_point)
        return reject("update_token cannot modify decimal_point");
      if (d.version != state.descriptor.version)
        return reject("update_token cannot modify descriptor version");

      {
        std::string descriptor_error;
        if (!validate_token_descriptor_for_registration(d, descriptor_error))
          return reject("update_token descriptor rejected: " + descriptor_error);
      }

      state.descriptor = d;
      return true;
    }

    default:
      return reject("unsupported token operation");
  }
}

} // namespace cryptonote
