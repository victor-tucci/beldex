#pragma once

// HF21 consensus transcript-domain labels.
// Keep these centralized to guarantee signer/verifier byte-for-byte symmetry.
namespace cryptonote::hf21
{
  inline constexpr const char* ZC_CLSAG_V1 = "HF21_ZC_CLSAG_V1";
  inline constexpr const char* CA_BALANCE_V1 = "HF21_CA_BALANCE_V1";
  inline constexpr const char* CA_SURJECTION_V1 = "HF21_CA_SURJECTION_V1";
  inline constexpr const char* CA_OWNERSHIP_V1 = "HF21_CA_OWNERSHIP_V1";
}

