#pragma once

#include <boost/optional/optional.hpp>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "common/expect.h" // monero/src
#include "crypto/crypto.h" // monero/src
#include "db/data.h"
#include "util/random_outputs.h"
#include "wire.h"

namespace lws
{
    namespace rpc
    {
        enum class safe_uint64 : std::uint64_t
        {
        };

        //! Read an array of uint64 values as JSON strings.
        struct safe_uint64_array
        {
            std::vector<std::uint64_t> values; // so this can be passed to another function without copy
        };

        struct get_random_outs_request
        {
            get_random_outs_request() = delete;
            std::uint64_t count;
            safe_uint64_array amounts;
        };
        struct get_random_outs_response
        {
            get_random_outs_response() = delete;
            std::vector<random_ring> amount_outs;
        };
        struct account_credentials
        {
            lws::db::account_address address;
            crypto::secret_key key;
        };

        struct import_response
        {
            import_response() = delete;
            safe_uint64 import_fee;
            const char *status;
            bool new_request;
            bool request_fulfilled;
        };

        struct login_request
        {
            login_request() = delete;
            account_credentials creds;
            bool create_account;
            bool generated_locally;
        };

        struct login_response
        {
            login_response() = delete;
            bool new_address;
            bool generated_locally;
        };
        struct get_unspent_outs
        {
            struct request_t
            {
                safe_uint64 amount;
                boost::optional<safe_uint64> dust_threshold;
                boost::optional<std::uint32_t> mixin;
                boost::optional<bool> use_dust;
                account_credentials creds;
            };
            // void read_bytes(wire::json_reader &, get_unspent_outs_request &);

            struct response_t
            {
                std::uint64_t per_kb_fee;
                std::uint64_t fee_mask;
                safe_uint64 amount;
                std::vector<std::pair<db::output, std::vector<crypto::key_image>>> outputs;
                crypto::secret_key user_key;
                std::uint64_t estimated_base_fee;
                uint32_t size_scale;
            };
        };
        // void write_bytes(wire::json_writer &, const get_unspent_outs_response &);
        struct transaction_spend
        {
            transaction_spend() = delete;
            lws::db::output::spend_meta_ meta;
            lws::db::spend possible_spend;
        };
        struct get_address_txs_response
        {
            get_address_txs_response() = delete;
            struct transaction
            {
                transaction() = delete;
                db::output info;
                std::vector<transaction_spend> spends;
                std::uint64_t spent;
            };

            safe_uint64 total_received;
            std::uint64_t scanned_height;
            std::uint64_t scanned_block_height;
            std::uint64_t start_height;
            std::uint64_t transaction_height;
            std::uint64_t blockchain_height;
            std::vector<transaction> transactions;
        };
    }
}