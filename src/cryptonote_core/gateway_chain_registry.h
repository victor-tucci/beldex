// Copyright (c) 2024, The Beldex Project
//
// HF22 gateway bridge memo (see tx_extra_gateway_bridge_memo, gateway_utils.h):
// maps a compact on-chain chain_index to a real EVM chain id (EIP-155).
// Deliberately NOT a consensus table -- validate_gateway_bridge_memos never
// inspects chain_index (it lives inside the encrypted ciphertext, invisible to
// validators). Extending this table is a plain code change, not a hard fork.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace cryptonote
{
  struct gateway_chain_entry
  {
    uint16_t chain_index;
    uint64_t evm_chain_id;
    std::string_view name;
  };

  // chain_index 0 is reserved as the "no memo" sentinel (tx_destination_entry
  // ::gateway_bridge_chain_index == 0) and MUST NOT be assigned here.
  inline constexpr std::array<gateway_chain_entry, 4> GATEWAY_CHAIN_REGISTRY{{
    {1, 1,        "ethereum"},
    {2, 11155111, "sepolia"},
    {3, 17000,    "holesky"},
    {4, 56,       "bsc"},
  }};

  inline constexpr std::optional<uint64_t> gateway_chain_index_to_evm_chain_id(uint16_t chain_index)
  {
    for (const auto& e : GATEWAY_CHAIN_REGISTRY)
      if (e.chain_index == chain_index)
        return e.evm_chain_id;
    return std::nullopt;
  }

  inline constexpr std::optional<uint16_t> gateway_evm_chain_id_to_chain_index(uint64_t evm_chain_id)
  {
    for (const auto& e : GATEWAY_CHAIN_REGISTRY)
      if (e.evm_chain_id == evm_chain_id)
        return e.chain_index;
    return std::nullopt;
  }

  inline constexpr std::optional<uint16_t> gateway_chain_name_to_index(std::string_view name)
  {
    for (const auto& e : GATEWAY_CHAIN_REGISTRY)
      if (e.name == name)
        return e.chain_index;
    return std::nullopt;
  }

  inline constexpr std::optional<std::string_view> gateway_chain_index_to_name(uint16_t chain_index)
  {
    for (const auto& e : GATEWAY_CHAIN_REGISTRY)
      if (e.chain_index == chain_index)
        return e.name;
    return std::nullopt;
  }
}
