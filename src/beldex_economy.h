#pragma once
#include <cstdint>

constexpr uint64_t COIN                       = (uint64_t)1000000000; // 1 BELDEX = pow(10, 9)
constexpr uint64_t MONEY_SUPPLY               = ((uint64_t)(-1)); // MONEY_SUPPLY - total number coins to be generated
constexpr uint64_t EMISSION_LINEAR_BASE       = ((uint64_t)(1) << 58);
constexpr uint64_t EMISSION_SUPPLY_MULTIPLIER = 19;
constexpr uint64_t EMISSION_SUPPLY_DIVISOR    = 10;
constexpr uint64_t EMISSION_DIVISOR           = 2000000;

// HF15 money supply parameters:
constexpr uint64_t BLOCK_REWARD_HF16      = 2 * COIN;
constexpr uint64_t MINER_REWARD_HF16      = BLOCK_REWARD_HF16 * 10 / 100; // Only until HF16
constexpr uint64_t MN_REWARD_HF16         = BLOCK_REWARD_HF16 * 90 / 100;
constexpr uint64_t FOUNDATION_REWARD_HF16 = 0;

// HF16+ money supply parameters: same as HF16 except the miner fee goes away and is redirected to
// LF to be used exclusively for Beldex Chainflip liquidity seeding and incentives.  See
// https://github.com/beldex-project/beldex-improvement-proposals/issues/24 for more details.  This ends
// after 6 months.
constexpr uint64_t BLOCK_REWARD_HF17        = BLOCK_REWARD_HF16;
constexpr uint64_t CHAINFLIP_LIQUIDITY_HF17 = BLOCK_REWARD_HF16 * 10 / 100;

// HF17: at most 6 months after HF16.  This is tentative and will likely be replaced before the
// actual HF with a new reward schedule including Chainflip rewards, but as per the LRC linked
// above, the liquidity funds end after 6 months.  That means that until HF17 is finalized, this is
// the fallback if we hit the 6-months-after-HF16 point:
constexpr uint64_t BLOCK_REWARD_HF18      = 1'800'000'000;
constexpr uint64_t FOUNDATION_REWARD_HF18 = 0;

static_assert(MINER_REWARD_HF16        + MN_REWARD_HF16 + FOUNDATION_REWARD_HF16 == BLOCK_REWARD_HF16);
static_assert(CHAINFLIP_LIQUIDITY_HF17 + MN_REWARD_HF16 + FOUNDATION_REWARD_HF16 == BLOCK_REWARD_HF17);
static_assert(                           MN_REWARD_HF16 + FOUNDATION_REWARD_HF18 == BLOCK_REWARD_HF18);

// -------------------------------------------------------------------------------------------------
//
// Flash
//
// -------------------------------------------------------------------------------------------------
// Flash fees: in total the sender must pay (MINER_TX_FEE_PERCENT + BURN_TX_FEE_PERCENT) * [minimum tx fee] + FLASH_BURN_FIXED,
// and the miner including the tx includes MINER_TX_FEE_PERCENT * [minimum tx fee]; the rest must be left unclaimed.
constexpr uint64_t FLASH_MINER_TX_FEE_PERCENT = 100; // The flash miner tx fee (as a percentage of the minimum tx fee)
constexpr uint64_t FLASH_BURN_FIXED           = 0;  // A fixed amount (in atomic currency units) that the sender must burn
constexpr uint64_t FLASH_BURN_TX_FEE_PERCENT  = 150; // A percentage of the minimum miner tx fee that the sender must burn.  (Adds to FLASH_BURN_FIXED)

// FIXME: can remove this post-fork 15; the burned amount only matters for mempool acceptance and
// flash quorum signing, but isn't part of the blockchain concensus rules (so we don't actually have
// to keep it around in the code for syncing the chain).
constexpr uint64_t FLASH_BURN_TX_FEE_PERCENT_OLD = 200; // A percentage of the minimum miner tx fee that the sender must burn.  (Adds to FLASH_BURN_FIXED)

static_assert(FLASH_MINER_TX_FEE_PERCENT >= 100, "flash miner fee cannot be smaller than the base tx fee");
static_assert(FLASH_BURN_FIXED >= 0, "fixed flash burn amount cannot be negative");
static_assert(FLASH_BURN_TX_FEE_PERCENT_OLD >= 0, "flash burn tx percent cannot be negative");

// -------------------------------------------------------------------------------------------------
//
// BNS
//
// -------------------------------------------------------------------------------------------------
namespace bns
{
enum struct mapping_type : uint16_t
{
  session = 0,
  wallet = 1,
  beldexnet = 2, // the type value stored in the database; counts as 1-year when used in a buy tx.
  beldexnet_2years,
  beldexnet_5years,
  beldexnet_10years,
  _count,
  update_record_internal,
};

constexpr bool is_beldexnet_type(mapping_type t) { return t >= mapping_type::beldexnet && t <= mapping_type::beldexnet_10years; }

// How many days we add per "year" of BNS beldexnet registration.  We slightly extend this to the 368
// days per registration "year" to allow for some blockchain time drift + leap years.
constexpr uint64_t REGISTRATION_YEAR_DAYS = 368;

constexpr uint64_t burn_needed(uint8_t hf_version, mapping_type type)
{
  uint64_t result = 0;

  // The base amount for session/wallet/beldexnet-1year:
  const uint64_t basic_fee = (
      hf_version >= 16 ? 15*COIN :  // cryptonote::network_version_16_pulse -- but don't want to add cryptonote_config.h include
      20*COIN                       // cryptonote::network_version_15_bns
  );
  switch (type)
  {
    case mapping_type::update_record_internal:
      result = 0;
      break;

    case mapping_type::beldexnet: /* FALLTHRU */
    case mapping_type::session: /* FALLTHRU */
    case mapping_type::wallet: /* FALLTHRU */
    default:
      result = basic_fee;
      break;

    case mapping_type::beldexnet_2years: result = 2 * basic_fee; break;
    case mapping_type::beldexnet_5years: result = 4 * basic_fee; break;
    case mapping_type::beldexnet_10years: result = 6 * basic_fee; break;
  }
  return result;
}
}; // namespace bns

