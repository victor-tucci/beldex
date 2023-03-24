#include "rest_server.h"

#include <algorithm>
#include <boost/utility/string_ref.hpp>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <cpr/cpr.h>

#include "common/error.h"                       // beldex/src
#include "common/hex.h"
#include "common/expect.h"
#include "crypto/crypto.h"                      // beldex/src
#include "cryptonote_config.h"                  // beldex/src
#include "lmdb/util.h"                          // beldex/src
#include "rpc/core_rpc_server_commands_defs.h"  // beldex/src

#include "error.h"
#include "db/data.h"
#include "db/storage.h"
#include "rpc/client.h"
#include "util/http_server.h"
#include "util/gamma_picker.h"
#include "util/random_outputs.h"
#include "util/source_location.h"
#include "rpc/light_wallet.h"
#include "wire/json.h"
namespace lws
{
  namespace
  {
    namespace http = epee::net_utils::http;

    struct context : epee::net_utils::connection_context_base
    {
      context()
        : epee::net_utils::connection_context_base()
      {}
    };

    bool is_hidden(db::account_status status) noexcept
    {
      switch (status)
      {
      case db::account_status::active:
      case db::account_status::inactive:
        return false;
      default:
      case db::account_status::hidden:
        break;
      }
      return true;
    }

    bool is_locked(std::uint64_t unlock_time, db::block_id last) noexcept
    {
      if (unlock_time > CRYPTONOTE_MAX_BLOCK_NUMBER)
        return std::chrono::seconds{unlock_time} > std::chrono::system_clock::now().time_since_epoch();
      return db::block_id(unlock_time) > last;
    }

    bool key_check(const rpc::account_credentials& creds)
    {
      crypto::public_key verify{};
      if (!crypto::secret_key_to_public_key(creds.key, verify))
        return false;
      if (verify != creds.address.view_public)
        return false;
      return true;
    }
    
    std::vector<db::output::spend_meta_>::const_iterator
    find_metadata(std::vector<db::output::spend_meta_> const& metas, db::output_id id)
    {
      struct by_output_id
      {
        bool operator()(db::output::spend_meta_ const& left, db::output_id right) const noexcept
        {
          return left.id < right;
        }
        bool operator()(db::output_id left, db::output::spend_meta_ const& right) const noexcept
        {
          return left < right.id;
        }
      };
      return std::lower_bound(metas.begin(), metas.end(), id, by_output_id{});
    }


    //! \return Account info from the DB, iff key matches address AND address is NOT hidden.
    expect<std::pair<db::account, db::storage_reader>> open_account(const rpc::account_credentials& creds, db::storage disk)
    {
      if (!key_check(creds))
        return {lws::error::bad_view_key};

      auto reader = disk.start_read();
      if (!reader)
        return reader.error();

      const auto user = reader->get_account(creds.address);
      if (!user)
        return user.error();
      if (is_hidden(user->first))
        return {lws::error::account_not_found};
      return {std::make_pair(user->second, std::move(*reader))};
    }

    struct get_address_info
    {
      using request = rpc::account_credentials;
      using response = rpc::get_address_info_response;

      static expect<response> handle(const request& req, db::storage disk)
      {
        auto user = open_account(req, std::move(disk));
        if (!user)
          return user.error();

        response resp{};

        auto outputs = user->second.get_outputs(user->first.id);
        if (!outputs)
          return outputs.error();

        auto spends = user->second.get_spends(user->first.id);
        if (!spends)
          return spends.error();

        const expect<db::block_info> last = user->second.get_last_block();
        if (!last)
          return last.error();

        resp.blockchain_height = std::uint64_t(last->id);
        resp.transaction_height = resp.blockchain_height;
        resp.scanned_height = std::uint64_t(user->first.scan_height);
        resp.scanned_block_height = resp.scanned_height;
        resp.start_height = std::uint64_t(user->first.start_height);

        std::vector<db::output::spend_meta_> metas{};
        metas.reserve(outputs->count());

        for (auto output = outputs->make_iterator(); !output.is_end(); ++output)
        {
          const db::output::spend_meta_ meta =
            output.get_value<MONERO_FIELD(db::output, spend_meta)>();

          // these outputs will usually be in correct order post ringct
          if (metas.empty() || metas.back().id < meta.id)
            metas.push_back(meta);
          else
            metas.insert(find_metadata(metas, meta.id), meta);

          resp.total_received = rpc::safe_uint64(std::uint64_t(resp.total_received) + meta.amount);
          if (is_locked(output.get_value<MONERO_FIELD(db::output, unlock_time)>(), last->id))
            resp.locked_funds = rpc::safe_uint64(std::uint64_t(resp.locked_funds) + meta.amount);
        }

        resp.spent_outputs.reserve(spends->count());
        for (auto const& spend : spends->make_range())
        {
          const auto meta = find_metadata(metas, spend.source);
          if (meta == metas.end() || meta->id != spend.source)
          {
            throw std::logic_error{
              "Serious database error, no receive for spend"
            };
          }

          resp.spent_outputs.push_back({*meta, spend});
          resp.total_sent = rpc::safe_uint64(std::uint64_t(resp.total_sent) + meta->amount);
        }

        // resp.rates = client.get_rates();
        // if (!resp.rates && !rates_error_once.test_and_set(std::memory_order_relaxed))
        //   MWARNING("Unable to retrieve exchange rates: " << resp.rates.error().message());

        return resp;
      }
    };//get_address_info

    struct get_unspent_outs
    {
      using request = rpc::get_unspent_outs_request;
      using response = rpc::get_unspent_outs_response;

      static expect<response> handle(request req, db::storage disk)
      {
        // using rpc_command = cryptonote::rpc::GET_BASE_FEE_ESTIMATE;

        auto user = open_account(req.creds, std::move(disk));
        if (!user)
          return user.error();

          // rpc_command::request req{};
        uint64_t grace_blocks = 10;
        //   epee::byte_slice msg = rpc::client::make_message("get_dynamic_fee_estimate", req);
        //   MONERO_CHECK(client->send(std::move(msg), std::chrono::seconds{10}));
          json dynamic_fee = {
            {"jsonrpc","2.0"},
            {"id","0"},
            {"method","get_fee_estimate"},
            {"params",{{"grace_blocks",grace_blocks}}}
          };

          auto fee_data = cpr::Post(cpr::Url{lws::daemon_add},
                         cpr::Body{dynamic_fee.dump()},
                         cpr::Header{ { "Content-Type", "application/json" }});

          json resp = json::parse(fee_data.text);

        if ((req.use_dust && req.use_dust) || !req.dust_threshold)
          req.dust_threshold = rpc::safe_uint64(0);

        if (!req.mixin)
          req.mixin = 0;

        auto outputs = user->second.get_outputs(user->first.id);
        if (!outputs)
          return outputs.error();
        
        std::uint64_t received = 0;
        std::vector<std::pair<db::output, std::vector<crypto::key_image>>> unspent;

        unspent.reserve(outputs->count());
        for (db::output const& out : outputs->make_range())
        {
          if (out.spend_meta.amount < std::uint64_t(*req.dust_threshold) || out.spend_meta.mixin_count < *req.mixin)
            continue;

          received += out.spend_meta.amount;
          unspent.push_back({out, {}});

          auto images = user->second.get_images(out.spend_meta.id);
          if (!images)
            return images.error();

          unspent.back().second.reserve(images->count());
          auto range = images->make_range<MONERO_FIELD(db::key_image, value)>();
          std::copy(range.begin(), range.end(), std::back_inserter(unspent.back().second));
        }
        // const auto resp = client->receive<rpc_command::Response>(std::chrono::seconds{20}, MLWS_CURRENT_LOCATION);

        if (received < std::uint64_t(req.amount))
          return {lws::error::account_not_found};

        
        // if (!resp)
          // return resp.error();

        // if (resp->size_scale == 0 || 1024 < resp->size_scale || resp->fee_mask == 0)
          // return {lws::error::bad_daemon_response};

        if(resp["status"]=="Failed")
        {
          return {lws::error::bad_daemon_response};
        }
        
        const std::uint64_t fee_per_byte = resp["result"]["fee_per_byte"];  
        const std::uint64_t fee_per_output = resp["result"]["fee_per_output"];
        const std::uint64_t flash_fee_per_byte = resp["result"]["flash_fee_per_byte"]; 
        const std::uint64_t flash_fee_per_output = resp["result"]["flash_fee_per_output"];
        const std::uint64_t flash_fee_fixed = resp["result"]["flash_fee_fixed"]; 
        const std::uint64_t quantization_mask = resp["result"]["quantization_mask"]; 

        return response{fee_per_byte, fee_per_output,flash_fee_per_byte,flash_fee_per_output,flash_fee_fixed,quantization_mask,17,rpc::safe_uint64(received), std::move(unspent), std::move(req.creds.key)};
      }
    };//get_unspent_outs

    struct get_address_txs
    {
      using request = rpc::account_credentials;
      using response = rpc::get_address_txs_response;

      static expect<response> handle(const request& req, db::storage disk)
      {
        auto user = open_account(req, std::move(disk));
        if (!user)
          return user.error();

        auto outputs = user->second.get_outputs(user->first.id);
        if (!outputs)
          return outputs.error();

        auto spends = user->second.get_spends(user->first.id);
        if (!spends)
          return spends.error();

        const expect<db::block_info> last = user->second.get_last_block();
        if (!last)
          return last.error();

        response resp{};
        resp.scanned_height = std::uint64_t(user->first.scan_height);
        resp.scanned_block_height = resp.scanned_height;
        resp.start_height = std::uint64_t(user->first.start_height);
        resp.blockchain_height = std::uint64_t(last->id);
        resp.transaction_height = resp.blockchain_height;

        // merge input and output info into a single set of txes.

        auto output = outputs->make_iterator();
        auto spend = spends->make_iterator();

        std::vector<db::output::spend_meta_> metas{};

        resp.transactions.reserve(outputs->count());
        metas.reserve(resp.transactions.capacity());

        db::transaction_link next_output{};
        db::transaction_link next_spend{};

        if (!output.is_end())
          next_output = output.get_value<MONERO_FIELD(db::output, link)>();
        if (!spend.is_end())
          next_spend = spend.get_value<MONERO_FIELD(db::spend, link)>();

        while (!output.is_end() || !spend.is_end())
        {
          if (!resp.transactions.empty())
          {
            db::transaction_link const& last = resp.transactions.back().info.link;

            if ((!output.is_end() && next_output < last) || (!spend.is_end() && next_spend < last))
            {
              throw std::logic_error{"DB has unexpected sort order"};
            }
          }

          if (spend.is_end() || (!output.is_end() && next_output <= next_spend))
          {
            std::uint64_t amount = 0;
            if (resp.transactions.empty() || resp.transactions.back().info.link.tx_hash != next_output.tx_hash)
            {
              resp.transactions.push_back({*output});
              amount = resp.transactions.back().info.spend_meta.amount;
            }
            else
            {
              amount = output.get_value<MONERO_FIELD(db::output, spend_meta.amount)>();
              resp.transactions.back().info.spend_meta.amount += amount;
            }

            const db::output::spend_meta_ meta = output.get_value<MONERO_FIELD(db::output, spend_meta)>();
            if (metas.empty() || metas.back().id < meta.id)
              metas.push_back(meta);
            else
              metas.insert(find_metadata(metas, meta.id), meta);

            resp.total_received = rpc::safe_uint64(std::uint64_t(resp.total_received) + amount);

            ++output;
            if (!output.is_end())
              next_output = output.get_value<MONERO_FIELD(db::output, link)>();
          }
          else if (output.is_end() || (next_spend < next_output))
          {
            const db::output_id source_id = spend.get_value<MONERO_FIELD(db::spend, source)>();
            const auto meta = find_metadata(metas, source_id);
            if (meta == metas.end() || meta->id != source_id)
            {
              throw std::logic_error{
                "Serious database error, no receive for spend"
              };
            }

            if (resp.transactions.empty() || resp.transactions.back().info.link.tx_hash != next_spend.tx_hash)
            {
              resp.transactions.push_back({});
              resp.transactions.back().spends.push_back({*meta, *spend});
              resp.transactions.back().info.link.height = resp.transactions.back().spends.back().possible_spend.link.height;
              resp.transactions.back().info.link.tx_hash = resp.transactions.back().spends.back().possible_spend.link.tx_hash;
              resp.transactions.back().info.spend_meta.mixin_count =
                resp.transactions.back().spends.back().possible_spend.mixin_count;
              resp.transactions.back().info.timestamp = resp.transactions.back().spends.back().possible_spend.timestamp;
              resp.transactions.back().info.unlock_time = resp.transactions.back().spends.back().possible_spend.unlock_time;
            }
            else
              resp.transactions.back().spends.push_back({*meta, *spend});

            resp.transactions.back().spent += meta->amount;

            ++spend;
            if (!spend.is_end())
              next_spend = spend.get_value<MONERO_FIELD(db::spend, link)>();
          }
        }

        return resp;
      }
    };

    struct get_random_outs
    {
      using request = rpc::get_random_outs_request;
      using response = rpc::get_random_outs_response;

      static expect<response> handle(request req, const db::storage&)
      {
        using distribution_rpc = cryptonote::rpc::GET_OUTPUT_DISTRIBUTION;
        using histogram_rpc = cryptonote::rpc::GET_OUTPUT_HISTOGRAM;
        // std::cout <<"1" << std::endl;
        std::vector<std::uint64_t> amounts = std::move(req.amounts.values);

        if (50 < req.count || 20 < amounts.size())
          return {lws::error::exceeded_rest_request_limit};

    //     // expect<rpc::client> client = gclient.clone();
    //     // if (!client)
    //     //   return client.error();
        // std::cout <<"2" << std::endl;

        const std::greater<std::uint64_t> rsort{};
        std::sort(amounts.begin(), amounts.end(), rsort);
        const std::size_t ringct_count =
          amounts.end() - std::lower_bound(amounts.begin(), amounts.end(), 0, rsort);
        // std::cout <<"3" << std::endl;

        std::vector<lws::histogram> histograms{};
        if (ringct_count < amounts.size())
        {
          // reuse allocated vector memory
          amounts.resize(amounts.size() - ringct_count);

          histogram_rpc::request histogram_req{};
          histogram_req.amounts = std::move(amounts);
          histogram_req.min_count = 0;
          histogram_req.max_count = 0;
          histogram_req.unlocked = true;
          histogram_req.recent_cutoff = 0;

          // epee::byte_slice msg = rpc::client::make_message("get_output_histogram", histogram_req);
          // MONERO_CHECK(client->send(std::move(msg), std::chrono::seconds{10}));
          json output_histogram = {
            {"jsonrpc","2.0"},
            {"id","0"},
            {"method","get_output_histogram"},
            {"params",{{"amounts",histogram_req.amounts},{"min_count",histogram_req.min_count},{"max_count",histogram_req.max_count},{"unlocked",histogram_req.unlocked},{"recent_cutoff",histogram_req.recent_cutoff}}}
          };

          // auto histogram_resp = client->receive<histogram_rpc::Response>(std::chrono::minutes{3}, MLWS_CURRENT_LOCATION);
          auto histogram_data = cpr::Post(cpr::Url{lws::daemon_add},
               cpr::Body{output_histogram.dump()},
               cpr::Header{ { "Content-Type", "application/json" }});

          json resp = json::parse(histogram_data.text);
          // if (!histogram_resp)
          //   return histogram_resp.error();
          // std::cout << "resp : " << resp << std::endl;
          for(auto it :resp["result"]["histogram"])
          {
            lws::histogram histogram_resp{};
              histogram_resp.amount = it["amount"];
              histogram_resp.total_count = it["total_instances"];
              histogram_resp.unlocked_count = it["unlocked_instances"];
              histogram_resp.recent_count = it["recent_instances"];
              histograms.push_back(histogram_resp);
          }

          if (histograms.size() != histogram_req.amounts.size())
            return {lws::error::bad_daemon_response};

          // histograms = std::move(histogram_resp->histogram);

          amounts = std::move(histogram_req.amounts);
          amounts.insert(amounts.end(), ringct_count, 0);
        }

        std::vector<std::uint64_t> distributions{};
        if (ringct_count)
        {
          // std::cout << "print the function " << ringct_count << "\n";
          distribution_rpc::request distribution_req{};
          if (ringct_count == amounts.size())
            distribution_req.amounts = std::move(amounts);

          distribution_req.amounts.resize(1);
          distribution_req.from_height = 0;
          distribution_req.to_height = 0;
          distribution_req.cumulative = true;

    //       // epee::byte_slice msg =
    //       //   rpc::client::make_message("get_output_distribution", distribution_req);
    //       // MONERO_CHECK(client->send(std::move(msg), std::chrono::seconds{10}));
          json output_distribution = {
            {"jsonrpc","2.0"},
            {"id","0"},
            {"method","get_output_distribution"},
            {"params",{{"amounts",distribution_req.amounts},{"from_height",distribution_req.from_height},{"to_height",distribution_req.to_height},{"cumulative",distribution_req.cumulative}}}
          };

          // auto distribution_resp =
          //   client->receive<distribution_rpc::Response>(std::chrono::minutes{3}, MLWS_CURRENT_LOCATION);
          auto distribution_data = cpr::Post(cpr::Url{lws::daemon_add},
               cpr::Body{output_distribution.dump()},
               cpr::Header{ { "Content-Type", "application/json" }});

          json resp = json::parse(distribution_data.text);
          // std::cout << "get_output_distribution : " << resp << std::endl;
          // if (!distribution_resp)
          //   return distribution_resp.error();
          for(auto it :resp["result"]["distributions"][0]["distribution"])
          {
              distributions.push_back(it);
          }
          if (resp["result"]["distributions"].size() != 1)
            return {lws::error::bad_daemon_response};
          if (resp["result"]["distributions"][0]["amount"] != 0)
            return {lws::error::bad_daemon_response};

          // distributions = std::move(distribution_resp->distributions[0].data.distribution);

          if (amounts.empty())
          {
            amounts = std::move(distribution_req.amounts);
            amounts.insert(amounts.end(), ringct_count - 1, 0);
          }
        }

        class zmq_fetch_keys
        {
          /* `std::function` needs a copyable functor. The functor was made
             const and copied in the function instead of using a reference to
             make the callback in `std::function` thread-safe. This shouldn't
             be a problem now, but this is just-in-case of a future refactor. */
          // rpc::client gclient;
        public:
          zmq_fetch_keys() noexcept
            // : gclient(std::move(src))
          {}

          zmq_fetch_keys(zmq_fetch_keys&&) = default;
          zmq_fetch_keys(zmq_fetch_keys const& rhs)
          {}
        //     : gclient(MONERO_UNWRAP(rhs.gclient.clone()))
        //   {}

          expect<std::vector<output_keys>> operator()(std::vector<lws::output_ref> ids) const
          {
                    // std::cout <<"operator overload" << std::endl;

            // using get_keys_rpc = cryptonote::rpc::GET_OUTPUTS;

            // get_keys_rpc::request keys_req{};
            // keys_req.outputs = std::move(ids);
            json amount_index;
            int i =0;
            for(auto it :ids)
            {
              amount_index[i]["amounts"] = it.amount;
              amount_index[i]["index"] = it.index;
              i++;
            }
            // std::cout << "amount index in get_outs : " << amount_index << std::endl;
            json out_keys = {
            {"jsonrpc","2.0"},
            {"id","0"},
            {"method","get_outs"},
            {"params",{{"outputs",amount_index},{"get_txid",false}}}
           };

            // std::cout << "ids.size() :" << ids.size() << std::endl;
            // expect<rpc::client> client = gclient.clone();
            // if (!client)
            //   return client.error();

            // epee::byte_slice msg = rpc::client::make_message("get_output_keys", keys_req);
            // MONERO_CHECK(client->send(std::move(msg), std::chrono::seconds{10}));
            auto out_keys_data = cpr::Post(cpr::Url{lws::daemon_add},
                 cpr::Body{out_keys.dump()},
                 cpr::Header{ { "Content-Type", "application/json" }});

            json resp = json::parse(out_keys_data.text);
            // std::cout << "get_outs response : " << resp << std::endl;
            using get_keys_rpc = cryptonote::rpc::output_key_mask_unlocked;
            std::vector <get_keys_rpc> keys{};
            // auto keys_resp = client->receive<get_keys_rpc::Response>(std::chrono::seconds{10}, MLWS_CURRENT_LOCATION);
            // if (!keys_resp)
            //   return keys_resp.error();
            for(auto it : resp["result"]["outs"])
            {
              get_keys_rpc key;
              std::string key_p = it["key"];
              tools::hex_to_type(key_p,key.key);
              tools::hex_to_type((std::string)it["mask"],key.mask);
              key.unlocked = it["unlocked"];
              keys.push_back(key);
            }
            return {std::move(keys)};
          }
        };
        // std::cout << "before the random_outputs\n";
        // std::cout << "req.count : " << req.count << std::endl;
        // for(auto it : amounts)
        // {
        //   std::cout <<"amounts "<< it << std::endl;
        // }
        // std::cout << "distributions.size() : " << distributions.size() << std::endl;
        // std::cout << "histograms.size() : " << histograms.size() << std::endl;
        // for(auto it :histograms)
        // {
        //       std::cout <<"amount         " << it.amount        << std::endl;
        //       std::cout <<"total_count    " << it.total_count   << std::endl;
        //       std::cout <<"unlocked_count " << it.unlocked_count<< std::endl;
        //       std::cout <<"recent_count   " << it.recent_count  << std::endl;
        // }
        lws::gamma_picker pick_rct{std::move(distributions)};
        auto rings = pick_random_outputs(
          req.count,
          epee::to_span(amounts),
          pick_rct,
          epee::to_mut_span(histograms),
          zmq_fetch_keys{/*std::move(*client)*/}
        );
        if (!rings)
          return rings.error();

        return response{std::move(*rings)};
      }
    };

    struct import_request
    {
      using request = rpc::account_credentials;
      using response = rpc::import_response;

      static expect<response> handle(request req, db::storage disk)
      {
        bool new_request = false;
        bool fulfilled = false;
        {
          auto user = open_account(req, disk.clone());
          if (!user)
            return user.error();

          if (user->first.start_height == db::block_id(0))
            fulfilled = true;
          else
          {
            const expect<db::request_info> info =
              user->second.get_request(db::request::import_scan, req.address);

            if (!info)
            {
              if (info != lmdb::error(MDB_NOTFOUND))
                return info.error();

              new_request = true;
            }
          }
        } // close reader

        if (new_request)
          MONERO_CHECK(disk.import_request(req.address, db::block_id(0)));

        const char* status = new_request ?
          "Accepted, waiting for approval" : (fulfilled ? "Approved" : "Waiting for Approval");
        return response{rpc::safe_uint64(0), status, new_request, fulfilled};
      }
    };

    struct login
    {
      using request = rpc::login_request;
      using response = rpc::login_response;

      static expect<response> handle(request req, db::storage disk)
      {
        // std::cout <<"inside the login\n";
        if (!key_check(req.creds))
          return {lws::error::bad_view_key};

        {
          auto reader = disk.start_read();
          if (!reader)
            return reader.error();

          const auto account = reader->get_account(req.creds.address);
          reader->finish_read();

          if (account)
          {
            if (is_hidden(account->first))
              return {lws::error::account_not_found};

            // Do not count a request for account creation as login
            return response{false, bool(account->second.flags & db::account_generated_locally)};
          }
          else if (!req.create_account || account != lws::error::account_not_found)
            return account.error();
        }

        const auto flags = req.generated_locally ? db::account_generated_locally : db::default_account;
        // MONERO_CHECK(disk.creation_request(req.creds.address, req.creds.key, flags));
        MONERO_UNWRAP(disk.add_account(req.creds.address, req.creds.key));
        std::cout <<"add_account called\n";
        return response{true, req.generated_locally};
      }
    };//login

    struct submit_raw_tx
    {
      using request = rpc::submit_raw_tx_request;
      using response = rpc::submit_raw_tx_response;

      static expect<response> handle(request req, const db::storage &disk)
      {
        using transaction_rpc = cryptonote::rpc::SEND_RAW_TX;

        // expect<rpc::client> client = gclient.clone();
        // if (!client)
        //   return client.error();

        transaction_rpc::request daemon_req{};
        daemon_req.do_not_relay = false;
        daemon_req.tx_as_hex = std::move(req.tx);
        if(req.fee == "5")
        {
          daemon_req.flash = true;
        }else{
          daemon_req.flash =false;
        }// Handles Flash Method from Client
        
        // epee::byte_slice message = rpc::client::make_message("send_raw_tx_hex", daemon_req);
        // MONERO_CHECK(client->send(std::move(message), std::chrono::seconds{10}));
          json message = {
            {"jsonrpc","2.0"},
            {"id","0"},
            {"method","send_raw_transaction"},
            {"params",{{"tx_as_hex",daemon_req.tx_as_hex},{"do_not_relay",daemon_req.do_not_relay},{"flash",daemon_req.flash}}}
          };
          // std::cout <<"message : " << message.dump() << std::endl;
          auto resp = cpr::Post(cpr::Url{lws::daemon_add},
                         cpr::Body{message.dump()},
                         cpr::Header{ { "Content-Type", "application/json" }});

          json daemon_resp = json::parse(resp.text);
        // std::cout <<"daemon_resp : " << daemon_resp << std::endl;
        // const auto daemon_resp = client->receive<transaction_rpc::Response>(std::chrono::seconds{20}, MLWS_CURRENT_LOCATION);
        // if (!daemon_resp)
        //   return daemon_resp.error();
        if (daemon_resp["result"]["not_relayed"] == true)
          return {lws::error::tx_relay_failed};

        if(daemon_resp["result"]["status"] == "Failed")
          return {lws::error::status_failed};

        return response{"OK"};
      }
    }; //submit_raw_tx

    template<typename E>
    expect<epee::byte_slice> call(std::string&& root, db::storage disk)
    {
      using request = typename E::request;
      using response = typename E::response;

      expect<request> req = wire::json::from_bytes<request>(std::move(root));
      if (!req)
        return req.error();

      expect<response> resp = E::handle(std::move(*req), std::move(disk));
      if (!resp)
        return resp.error();
      return wire::json::to_bytes<response>(*resp);
    }

    struct endpoint
    {
      char const* const name;
      expect<epee::byte_slice> (*const run)(std::string&&, db::storage);
      const unsigned max_size;
    };

    constexpr const endpoint endpoints[] =
    {
      {"/get_address_info",      call<get_address_info>, 2 * 1024},
      {"/get_address_txs",       call<get_address_txs>,  2 * 1024},
      {"/get_random_outs",       call<get_random_outs>,  2 * 1024},
      // {"/get_txt_records",       nullptr,                0       },
      {"/get_unspent_outs",      call<get_unspent_outs>, 2 * 1024},
      {"/import_request",        call<import_request>,   2 * 1024},
      {"/login",                 call<login>,            2 * 1024},
      {"/submit_raw_tx",         call<submit_raw_tx>,   50 * 1024}
    };

    struct by_name_
    {
      bool operator()(endpoint const& left, endpoint const& right) const noexcept
      {
        if (left.name && right.name)
          return std::strcmp(left.name, right.name) < 0;
        return false;
      }
      bool operator()(const boost::string_ref left, endpoint const& right) const noexcept
      {
        if (right.name)
          return left < right.name;
        return false;
      }
      bool operator()(endpoint const& left, const boost::string_ref right) const noexcept
      {
        if (left.name)
          return left.name < right;
        return false;
      }
    };
    constexpr const by_name_ by_name{};

  } //anonymous
    struct rest_server::internal final : public lws::http_server_impl_base<rest_server::internal, context>
    {
      db::storage disk;
    
      explicit internal(boost::asio::io_service& io_service, lws::db::storage disk)
        : lws::http_server_impl_base<rest_server::internal, context>(io_service)
        , disk(std::move(disk))
      {
        // assert(std::is_sorted(std::begin(endpoints), std::end(endpoints), by_name));
      }

      virtual bool
      handle_http_request(const http::http_request_info& query, http::http_response_info& response, context& ctx)
      override final
      {
        const auto handler = std::lower_bound(
          std::begin(endpoints), std::end(endpoints), query.m_URI, by_name
        );
        if (handler == std::end(endpoints) || handler->name != query.m_URI)
        {
          response.m_response_code = 404;
          response.m_response_comment = "Not Found";
          return true;
        }

        if (handler->run == nullptr)
        {
          response.m_response_code = 501;
          response.m_response_comment = "Not Implemented";
          return true;
        }

        if (handler->max_size < query.m_body.size())
        {
          MINFO("Client exceeded maximum body size (" << handler->max_size << " bytes)");
          response.m_response_code = 400;
          response.m_response_comment = "Bad Request";
          return true;
        }

        if (query.m_http_method != http::http_method_post)
        {
          response.m_response_code = 405;
          response.m_response_comment = "Method Not Allowed";
          return true;
        }

        // \TODO remove copy of json string here :/
        auto body = handler->run(std::string{query.m_body}, disk.clone());
        if (!body)
        {
          MINFO(body.error().message() << " from " << ctx.m_remote_address.str() << " on " << handler->name);

          if (body.error().category() == wire::error::rapidjson_category())
          {
            response.m_response_code = 400;
            response.m_response_comment = "Bad Request";
          }
          else if (body == lws::error::account_not_found || body == lws::error::duplicate_request)
          {
            response.m_response_code = 403;
            response.m_response_comment = "Forbidden";
          }
          else if (body.matches(std::errc::timed_out) || body.matches(std::errc::no_lock_available))
          {
            response.m_response_code = 503;
            response.m_response_comment = "Service Unavailable";
          }
          else
          {
            response.m_response_code = 500;
            response.m_response_comment = "Internal Server Error";
          }
          return true;
        }

        response.m_response_code = 200;
        response.m_response_comment = "OK";
        response.m_mime_tipe = "application/json";
        response.m_header_info.m_content_type = "application/json";
        response.m_body.assign(reinterpret_cast<const char*>(body->data()), body->size()); // \TODO Remove copy here too!s
        return true;
      }
    };
    rest_server::rest_server(epee::span<const std::string> addresses, db::storage disk, configuration config)
        : io_service_(), ports_()
    {
        ports_.emplace_back(io_service_, std::move(disk));

        if (addresses.empty())
            MONERO_THROW(common_error::kInvalidArgument, "REST server requires 1 or more addresses");

        const auto init_port = [](internal &port, const std::string &address, configuration config) -> bool
        {
            epee::net_utils::http::url_content url{};
            if (!epee::net_utils::parse_url(address, url))
                MONERO_THROW(lws::error::configuration, "REST Server URL/address is invalid");

            const bool https = url.schema == "https";
            if (!https && url.schema != "http")
                MONERO_THROW(lws::error::configuration, "Unsupported scheme, only http or https supported");

            if (std::numeric_limits<std::uint16_t>::max() < url.port)
                MONERO_THROW(lws::error::configuration, "Specified port for rest server is out of range");

            if (!https)
            {
                boost::system::error_code error{};
                const boost::asio::ip::address ip_host =
                    ip_host.from_string(url.host, error);
                if (error)
                    MONERO_THROW(lws::error::configuration, "Invalid IP address for REST server");
                if (!ip_host.is_loopback() && !config.allow_external)
                    MONERO_THROW(lws::error::configuration, "Binding to external interface with http - consider using https or secure tunnel (ssh, etc). Use --confirm-external-bind to override");
            }

            if (url.port == 0)
                url.port = https ? 8443 : 8080;

            epee::net_utils::ssl_options_t ssl_options = https ? epee::net_utils::ssl_support_t::e_ssl_support_enabled : epee::net_utils::ssl_support_t::e_ssl_support_disabled;
            ssl_options.verification = epee::net_utils::ssl_verification_t::none; // clients verified with view key
            ssl_options.auth = std::move(config.auth);

            if (!port.init(std::to_string(url.port), std::move(url.host), std::move(config.access_controls), std::move(ssl_options)))
                MONERO_THROW(lws::error::http_server, "REST server failed to initialize");
            return https;
        };

        bool any_ssl = false;
        for (std::size_t index = 1; index < addresses.size(); ++index)
        {
            ports_.emplace_back(io_service_, ports_.front().disk.clone());
            any_ssl |= init_port(ports_.back(), addresses[index], config);
        }

        const bool expect_ssl = !config.auth.private_key_path.empty();
        const std::size_t threads = config.threads;
        any_ssl |= init_port(ports_.front(), addresses[0], std::move(config));
        if (!any_ssl && expect_ssl)
            MONERO_THROW(lws::error::configuration, "Specified SSL key/cert without specifying https capable REST server");

        if (!ports_.front().run(threads, false))
            MONERO_THROW(lws::error::http_server, "REST server failed to run");
    }

    rest_server::~rest_server() noexcept
    {
    }
} // lws