#pragma once

#include <cstdint>
#include <string_view>
#include <cassert>
#include "common/formattable.h"

namespace cryptonote {

using namespace std::literals;

enum class txversion : uint16_t {
    v0 = 0,
    v1,
    v2_ringct,
    v3_per_output_unlock_times,
    v4_tx_types,
    _count,
  };
  enum class txtype : uint16_t {
    standard,
    state_change,
    key_image_unlock,
    stake,
    beldex_name_system,
    coin_burn,
    _count
  };

  inline constexpr std::string_view to_string(txversion v) {
    switch(v)
    {
      case txversion::v1:                         return "1"sv;
      case txversion::v2_ringct:                  return "2_ringct"sv;
      case txversion::v3_per_output_unlock_times: return "3_per_output_unlock_times"sv;
      case txversion::v4_tx_types:                return "4_tx_types"sv;
      default: assert(false);                     return "xx_unhandled_version"sv;
    }
  }

  inline constexpr std::string_view to_string(txtype type)
  {
    switch(type)
    {
      case txtype::standard:                return "standard";
      case txtype::state_change:            return "state_change";
      case txtype::key_image_unlock:        return "key_image_unlock";
      case txtype::stake:                   return "stake";
      case txtype::beldex_name_system:      return "beldex_name_system";
      case txtype::coin_burn:               return "coin_burn";
      default: assert(false);               return "xx_unhandled_type";
    }
  }

}

template <> inline constexpr bool formattable::via_to_string<cryptonote::txversion> = true;
template <> inline constexpr bool formattable::via_to_string<cryptonote::txtype> = true;
