#include "tx_extra.h"

namespace cryptonote {

tx_extra_beldex_name_system tx_extra_beldex_name_system::make_buy(
    bns::generic_owner const& owner,
    bns::generic_owner const* backup_owner,
    bns::mapping_years mapping_years,
    const crypto::hash& name_hash,
    const std::string& encrypted_bchat_value,
    const std::string& encrypted_wallet_value,
    const std::string& encrypted_belnet_value,
    const crypto::hash& prev_txid)
{
  tx_extra_beldex_name_system result{};
  result.version = 1;
  result.fields = bns::extra_field::buy;
  result.owner = owner;

  if (backup_owner)
    result.backup_owner = *backup_owner;
  else
    result.fields = bns::extra_field::buy_no_backup;

  result.mapping_years = mapping_years;
  result.name_hash = name_hash;
  
  if (encrypted_bchat_value.size())
  {
    result.fields |= bns::extra_field::encrypted_bchat_value;
    result.encrypted_bchat_value = encrypted_bchat_value;
  }
  
  if (encrypted_wallet_value.size())
  {
    result.fields |= bns::extra_field::encrypted_wallet_value;
    result.encrypted_wallet_value = encrypted_wallet_value;
  }
  
  if (encrypted_belnet_value.size())
  {
    result.fields |= bns::extra_field::encrypted_belnet_value;
    result.encrypted_belnet_value = encrypted_belnet_value;
  }

  result.prev_txid = prev_txid;
  return result;
}

tx_extra_beldex_name_system tx_extra_beldex_name_system::make_renew(
    const bns::generic_signature& signature,
    bns::mapping_years mapping_years, 
    crypto::hash const &name_hash, 
    crypto::hash const &prev_txid)
{
  assert(is_renewal_type(mapping_years) && prev_txid);

  tx_extra_beldex_name_system result{};
  result.version = 1;
  result.fields = bns::extra_field::signature;
  result.signature = signature;
  result.mapping_years=mapping_years;
  result.name_hash = name_hash;
  result.prev_txid = prev_txid;
  return result;
}

tx_extra_beldex_name_system tx_extra_beldex_name_system::make_update(
    const bns::generic_signature& signature,
    const crypto::hash& name_hash,
    std::string_view encrypted_bchat_value,
    std::string_view encrypted_wallet_value,
    std::string_view encrypted_belnet_value,
    const bns::generic_owner* owner,
    const bns::generic_owner* backup_owner,
    const crypto::hash& prev_txid)
{
  tx_extra_beldex_name_system result{};
  result.version = 1;
  result.signature = signature;
  result.name_hash = name_hash;
  result.fields |= bns::extra_field::signature;

  if (encrypted_bchat_value.size())
  {
    result.fields |= bns::extra_field::encrypted_bchat_value;
    result.encrypted_bchat_value = std::string{encrypted_bchat_value};
  }

  if (encrypted_wallet_value.size())
  {
    result.fields |= bns::extra_field::encrypted_wallet_value;
    result.encrypted_wallet_value = std::string{encrypted_wallet_value};
  }
  
  if (encrypted_belnet_value.size())
  {
    result.fields |= bns::extra_field::encrypted_belnet_value;
    result.encrypted_belnet_value = std::string{encrypted_belnet_value};
  }

  if (owner)
  {
    result.fields |= bns::extra_field::owner;
    result.owner = *owner;
  }

  if (backup_owner)
  {
    result.fields |= bns::extra_field::backup_owner;
    result.backup_owner = *backup_owner;
  }

  result.prev_txid = prev_txid;
  return result;
}

std::vector<std::string> readable_reasons(uint16_t decomm_reason) {
  std::vector<std::string> results;
  if (decomm_reason & missed_uptime_proof) results.push_back("Missed Uptime Proofs");
  if (decomm_reason & missed_checkpoints) results.push_back("Missed Checkpoints");
  if (decomm_reason & missed_POS_participations) results.push_back("Missed POS Participation");
  if (decomm_reason & storage_server_unreachable) results.push_back("Storage Server Unreachable");
  if (decomm_reason & timestamp_response_unreachable) results.push_back("Unreachable for Timestamp Check");
  if (decomm_reason & timesync_status_out_of_sync) results.push_back("Time out of sync");
  if (decomm_reason & belnet_unreachable) results.push_back("Belnet Unreachable");
  if (decomm_reason & multi_mn_accept_range_not_met) results.push_back("Multi MN accept Range Not Met");
  return results;
}

std::vector<std::string> coded_reasons(uint16_t decomm_reason) {
  std::vector<std::string> results;
  if (decomm_reason & missed_uptime_proof) results.push_back("uptime");
  if (decomm_reason & missed_checkpoints) results.push_back("checkpoints");
  if (decomm_reason & missed_POS_participations) results.push_back("POS");
  if (decomm_reason & storage_server_unreachable) results.push_back("storage");
  if (decomm_reason & timestamp_response_unreachable) results.push_back("timecheck");
  if (decomm_reason & timesync_status_out_of_sync) results.push_back("timesync");
  if (decomm_reason & belnet_unreachable) results.push_back("belnet");
  if (decomm_reason & multi_mn_accept_range_not_met) results.push_back("multi_mn_range");
  return results;
}

}
