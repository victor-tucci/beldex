#include <iostream>
#include <string>
#include <string.h>
#include <algorithm>
#include <boost/utility/string_ref.hpp>

#include "rest_server.h"
#include "common/expect.h" // beldex/src
#include "lmdb/util.h"
#include "db/fwd.h"
#include "wallet/wallet_light_rpc.h"
#include "epee/byte_slice.h"
#include "oxenmq/oxenmq.h"
#include "oxenmq/connections.h"
#include "db/storage.h"
#include "rpc/light_wallet.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "util/random_outputs.h"
#include "error.h"
#include "cryptonote_core/blockchain.h"
#include "wallet/wallet2.h"
#include "cryptonote_core/blockchain.h"
#include <nlohmann/json.hpp>
#include "wire/json.h"
#include "wire/read.h"
#include "util/http_server.h"
#include "epee/net/net_utils_base.h"
#include "epee/net/net_parse_helpers.h"
#include "epee/net/http_protocol_handler.inl"
#include "epee/net/http_protocol_handler.h"
#include "rpc/daemon_zmq.h"
using json = nlohmann::json;
using namespace oxenmq;
using namespace std;
using namespace cryptonote::rpc;
using namespace wire;

string failmsg = " its_failed ";
// json msg = " success ";

namespace connectionURL
{
    auto connect() 
    {
        using LMQ_ptr = shared_ptr<oxenmq::OxenMQ>;
        string msg = " success ";
        LMQ_ptr m_LMQ = make_shared<oxenmq::OxenMQ>();
        m_LMQ->start();
        auto connection_url = m_LMQ->connect_remote(
            "tcp://127.0.0.1:4567",
            [](ConnectionID conn)
            { cout << "Connected \n"; },
            [](ConnectionID conn, string_view f)
            {
                cout << "connect failed: \n";
            });
    }
}

namespace lws
{
    using json = nlohmann::json;
    namespace {
      namespace http = epee::net_utils::http;

    struct context : epee::net_utils::connection_context_base
    {
      context()
        : epee::net_utils::connection_context_base()
      {}
    };

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

    bool key_check(const rpc::account_credentials& creds){
        crypto::public_key verify{};
        if (!crypto::secret_key_to_public_key(creds.key, verify))
            return false;
        if (verify != creds.address.view_public)
            return false;
        return true;
        }
    

    expect<std::pair<db::account, db::storage_reader>> open_account(const lws::rpc::account_credentials& creds, db::storage disk)
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

    struct submit_raw_tx
    {
      using request = cryptonote::rpc::SEND_RAW_TX::request;
      struct response
      {
        std::string status;
        std::string error;

        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(status)
          KV_SERIALIZE(error)
        END_KV_SERIALIZE_MAP()

      };
        // using response = tools::light_rpc::SUBMIT_RAW_TX::response;

        request object_1;
        // string param = object_1.tx;
        int flash{};
        string tx_hash;
        
        static expect<response> handle(request req, const db::storage &disk)
        {
            using LMQ_ptr = shared_ptr<oxenmq::OxenMQ>;
            
            LMQ_ptr m_LMQ = make_shared<oxenmq::OxenMQ>();
            m_LMQ->start();
            auto connection_url = m_LMQ->connect_remote(
                "tcp://127.0.0.1:4567",
                [](ConnectionID conn)
                { cout << "Connected \n"; },
                [](ConnectionID conn, string_view f)
                {
                    cout << "connect failed: \n";
                });

            // using transaction_rpc = cryptonote::rpc::SendRawTxHex;
            string msg = " success ";
            json respond{};
            m_LMQ->request(
                connection_url, "rpc.send_raw_transaction", [respond,msg](bool status, auto response_data)
                {
                if (status == 1 && response_data[0] == "200") cout << " response : " << response_data[1] << "\n"; },
                "{\"tx\": \"" + string(msg) + "\"}");
                // return success();
        }

    };
    struct get_random_outs
    {
        using request = cryptonote::rpc::GET_OUTPUTS::request;
        using response = rpc::get_random_outs_response;

        static expect<response> handle(request req, const db::storage &)
        {
            using distribution_rpc = cryptonote::rpc::GET_OUTPUT_DISTRIBUTION;
            using histogram_rpc = cryptonote::rpc::GET_OUTPUT_HISTOGRAM;
            // request::request reqs;
            vector<uint64_t> amounts = move(req.values);
            const std::size_t rct_count = amounts.end() - std::lower_bound(amounts.begin(), amounts.end(), 0);
            vector<lws::histogram> histogram{};
            if (rct_count < amounts.size())
            {
                std::string msg = "success";
                histogram_rpc::request his_req{};
                his_req.amounts = std::move(amounts);
                his_req.min_count = 0;
                his_req.max_count = 0;
                his_req.unlocked = true;
                his_req.recent_cutoff = 0;

                using LMQ_ptr = shared_ptr<oxenmq::OxenMQ>;
                LMQ_ptr m_LMQ = make_shared<oxenmq::OxenMQ>();
                m_LMQ->start();
                auto connection_url = m_LMQ->connect_remote(
                    "tcp://127.0.0.1:4567",
                    [](ConnectionID conn)
                    { cout << "Connected \n"; },
                    [](ConnectionID conn, string_view f)
                    {
                        cout << "connect failed: \n";
                    });
                // using transaction_rpc = cryptonote::rpc::SendRawTxHex;
                m_LMQ->request(
                    connection_url, "rpc.get_output_histogram", [&his_req,msg](bool status, auto histogram)
                    {
                    if (status == 1 && histogram[0] == "200")cout << " response : " << histogram[1] << "\n";
                    auto res = json::parse(histogram[1]); 
                    },"{\"tx\": \"" + std::string(msg) + "\"}");

                amounts = move(his_req.amounts);
                amounts.insert(amounts.end(), rct_count, 0);

                vector<uint64_t> distributions{};
                if (rct_count){
                    distribution_rpc::request dist_req{};
                    if (rct_count == amounts.size())
                     dist_req.amounts = std::move(amounts);

                     dist_req.amounts.resize(1);
                     dist_req.from_height = 0;
                     dist_req.to_height = 0;
                     dist_req.cumulative = true;

                    m_LMQ->request(
                    connection_url, "rpc.get_output_histogram", [&dist_req,msg](bool status, auto distribution)
                    {
                    if (status == 1 && distribution[0] == "200")cout << " response : " << distribution[1] << "\n";
                    auto dist_req = json::parse(distribution[1]); 
                    },"{\"tx\": \"" + std::string(msg) + "\"}");

                    // distributions = std::move(dist_req[0]);

                    class zmq_fetch_keys{

                    };
                }
              

            }
        }
    };

    struct login
    {
      std::string msg = "error";
      using request = rpc::login_request;
      using response = rpc::login_response;

      static expect<response> handle(request req, db::storage disk)
      {
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
        // MONERO_CHECK(add_account(req.creds.address, req.creds.key))
        MONERO_CHECK(disk.creation_request(req.creds.address, req.creds.key, flags));
        return response{true, req.generated_locally};
      }
    };
    struct get_unspent_outs
    {
      using request = lws::rpc::get_unspent_outs::request_t;
      using response = lws::rpc::get_unspent_outs::response_t;
      response objectss;
      static expect<response> handle(request req, db::storage disk)
      {
        using rpc_command = lws::rpc::get_unspent_outs::request_t;

        auto user = open_account(req.creds, std::move(disk));
        if (!user)
          return user.error();

        // expect<rpc::client> client = gclient.clone();
        // if (!client)
        //   return client.error();

          using LMQ_ptr = shared_ptr<oxenmq::OxenMQ>;
                LMQ_ptr m_LMQ = make_shared<oxenmq::OxenMQ>();
                m_LMQ->start();
                auto connection_url = m_LMQ->connect_remote(
                    "tcp://127.0.0.1:4567",
                    [](ConnectionID conn)
                    { cout << "Connected \n"; },
                    [](ConnectionID conn, string_view f)
                    {
                        cout << "connect failed: \n";
                    });
          rpc_command reqst{};
         int grace_blocks = 10;
          m_LMQ->request(
                    connection_url, "rpc.get_fee_estimate", [grace_blocks](bool status, auto estimate_fee)
                    {
                    if (status == 1 && estimate_fee[0] == "200")cout << " response : " << estimate_fee[1] << "\n";
                    auto response = json::parse(estimate_fee[1]); 
                    // json res;
                    // res = response;
                    },"{\"grace_blocks\": \"" + std::to_string(grace_blocks) + "\"}");

        if ((reqst.use_dust && reqst.use_dust) || !reqst.dust_threshold)
          reqst.dust_threshold = rpc::safe_uint64(0);

        if (!reqst.mixin)
          reqst.mixin = 0;

        auto outputs = user->second.get_outputs(user->first.id);
        if (!outputs)
          return outputs.error();

        std::uint64_t received = 0;
        std::vector<std::pair<db::output, std::vector<crypto::key_image>>> unspent;

        unspent.reserve(outputs->count());
        for (db::output const& out : outputs->make_range())
        {
          if (out.spend_meta.amount < std::uint64_t(*reqst.dust_threshold) || out.spend_meta.mixin_count < *reqst.mixin)
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

        if (received < std::uint64_t(reqst.amount))
          return {lws::error::account_not_found};

        // const auto resp = client->receive<rpc_command::Response>(std::chrono::seconds{20}, MLWS_CURRENT_LOCATION);
        // if (!resp)
        //   return resp.error();
        response resp{};
        if (resp.size_scale == 0 || 1024 < resp.size_scale || resp.fee_mask == 0)
          return {lws::error::bad_daemon_response};

        const std::uint64_t per_kb_fee =
          resp.estimated_base_fee * (1024 / resp.size_scale);
        const std::uint64_t per_kb_fee_masked =
          ((per_kb_fee + (resp.fee_mask - 1)) / resp.fee_mask) * resp.fee_mask;
        
        return response{per_kb_fee_masked, resp.fee_mask, rpc::safe_uint64(received),std::move(unspent), reqst.creds.key};
      }
    };

    struct get_address_txs
    {
      using request = lws::rpc::account_credentials;
      using response = lws::rpc::get_address_txs_response;

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

template <typename E>
expect<epee::byte_slice> call(string &&root, db::storage disk)
{
    using request = typename E::request;
    using response = typename E::response;

    expect<request> req = wire::json::from_bytes<request>(move(root));
    if (!req)
        return req.error();

    expect<response> resp = E::handle(move(*req), move(disk));
    if (!resp)
        return resp.error();
    return wire::json::to_bytes<response>(*resp);
}

struct endpoint
{
    char const *const name;
    expect<epee::byte_slice> (*const run)(string &&, lws::db::storage);
    const unsigned max_size;
};

constexpr const endpoint endpoints[] = {
    {"/submit_raw_tx",      call<submit_raw_tx>,    2 * 1024},
    {"/get_random_outs",    call<get_random_outs>,  2 * 1024},
    {"/get_unspent_outs",   call<get_unspent_outs>, 2 * 1024},
    {"/get_random_outs",    call<login>,            2 * 1024},
    {"/get_address_txs",    call<get_address_txs>,  2 * 1024}

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
  } // anonymous

  struct lws::rest_server::internal final : public lws::http_server_impl_base<rest_server::internal, context>
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

  lws::rest_server::rest_server(epee::span<const std::string> addresses, db::storage disk, configuration config)
    : io_service_(), ports_()
  {
    ports_.emplace_back(io_service_, std::move(disk));

    if (addresses.empty())
      MONERO_THROW(common_error::kInvalidArgument, "REST server requires 1 or more addresses");

    const auto init_port = [] (internal& port, const std::string& address, configuration config) -> bool
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

      epee::net_utils::ssl_options_t ssl_options = https ?
        epee::net_utils::ssl_support_t::e_ssl_support_enabled :
        epee::net_utils::ssl_support_t::e_ssl_support_disabled;
      ssl_options.verification = epee::net_utils::ssl_verification_t::none; // clients verified with view key
      ssl_options.auth = std::move(config.auth);

      if (!port.init(std::to_string(url.port), std::move(url.host), std::move(config.access_controls)))
        MONERO_THROW(lws::error::http_server, "REST server failed to initialize");
      return https;
    };

    bool any_ssl = false;
    for (std::size_t index = 1; index < addresses.size(); ++index)
    {
      ports_.emplace_back(io_service_, ports_.front().disk.clone()/*, MONERO_UNWRAP(ports_.front().client.clone())*/);
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

  lws::rest_server::~rest_server() noexcept
  {}

} //namespace lws