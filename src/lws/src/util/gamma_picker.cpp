#include <algorithm>
#include <stdexcept>
#include "gamma_picker.h"
#include "crypto/crypto.h"
#include "cryptonote_config.h"
using namespace std;

bool lws::gamma_picker::is_valid() const noexcept
  {
    return CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE < rct_offsets.size();
  }

std::uint64_t lws::gamma_picker::spendable_upper_bound() const noexcept
{
    if (!is_valid())
        return 0;
    return *(rct_offsets.end() - CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE - 1);
}