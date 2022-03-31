// Copyright (c) 2006-2013, Andrey N. Sabelnikov, www.sabelnikov.net
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// * Neither the name of the Andrey N. Sabelnikov nor the
// names of its contributors may be used to endorse or promote products
// derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER  BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 




#ifndef _HTTP_SERVER_H_
#define _HTTP_SERVER_H_

#include <boost/optional/optional.hpp>
#include <string>
#include "net_utils_base.h"
#include "epee/to_nonconst_iterator.h"
#include "http_auth.h"
#include "http_base.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net.http"
using namespace epee;
namespace epee
{
namespace net_utils
{
	namespace http
	{


		/************************************************************************/
		/*                                                                      */
		/************************************************************************/
		struct http_server_config
		{
			std::string m_folder;
			std::vector<std::string> m_access_control_origins;
			boost::optional<login> m_user;
			// critical_section m_lock;
		};

		/************************************************************************/
		/*                                                                      */
		/************************************************************************/

//*********************************************************************************************************
	struct connection_context_base_1
	{
    const boost::uuids::uuid m_connection_id;
    const network_address m_remote_address;
    const bool     m_is_income;
    std::chrono::steady_clock::time_point m_started;
    // const bool      m_ssl;
    std::chrono::steady_clock::time_point m_last_recv;
    std::chrono::steady_clock::time_point m_last_send;
    uint64_t m_recv_cnt;
    uint64_t m_send_cnt;
    double m_current_speed_down;
    double m_current_speed_up;
    double m_max_speed_down;
    double m_max_speed_up;

    connection_context_base_1(boost::uuids::uuid connection_id,
                            const network_address &remote_address, bool is_income,
                            std::chrono::steady_clock::time_point last_recv = std::chrono::steady_clock::time_point::min(),
                            std::chrono::steady_clock::time_point last_send = std::chrono::steady_clock::time_point::min(),
                            uint64_t recv_cnt = 0, uint64_t send_cnt = 0):
                                            m_connection_id(connection_id),
                                            m_remote_address(remote_address),
                                            m_is_income(is_income),
                                            m_started(std::chrono::steady_clock::now()),
                                            m_last_recv(last_recv),
                                            m_last_send(last_send),
                                            m_recv_cnt(recv_cnt),
                                            m_send_cnt(send_cnt),
                                            m_current_speed_down(0),
                                            m_current_speed_up(0),
                                            m_max_speed_down(0),
                                            m_max_speed_up(0)
    {}

    connection_context_base_1(): m_connection_id(),
                               m_remote_address(),
                               m_is_income(false),
                               m_started(std::chrono::steady_clock::now()),
                               m_last_recv(std::chrono::steady_clock::time_point::min()),
                               m_last_send(std::chrono::steady_clock::time_point::min()),
                               m_recv_cnt(0),
                               m_send_cnt(0),
                               m_current_speed_down(0),
                               m_current_speed_up(0),
                               m_max_speed_down(0),
                               m_max_speed_up(0)
    {}

    connection_context_base_1(const connection_context_base_1& a): connection_context_base_1()
    {
      set_details(a.m_connection_id, a.m_remote_address, a.m_is_income);
    }

    connection_context_base_1& operator=(const connection_context_base_1& a)
    {
      set_details(a.m_connection_id, a.m_remote_address, a.m_is_income);
      return *this;
    }
    
  private:
    template<class t_protocol_handler>
    friend class connection;
    void set_details(boost::uuids::uuid connection_id, const network_address &remote_address, bool is_income)
    {
      this->~connection_context_base_1();
      new(this) connection_context_base_1(connection_id, remote_address, is_income);
    }

	};

//*********************************************************************************************************

		template<class t_connection_context  = connection_context_base_1>
		class simple_http_connection_handler
		{
		public:
			typedef t_connection_context connection_context;//t_connection_context net_utils::connection_context_base connection_context;
			typedef http_server_config config_type;

			simple_http_connection_handler(i_service_endpoint* psnd_hndlr, config_type& config, t_connection_context& conn_context);
			virtual ~simple_http_connection_handler(){}

			bool release_protocol()
			{
				return true;
			}

			virtual bool thread_init()
			{
				return true;
			}

			virtual bool thread_deinit()
			{
				return true;
			}
			bool after_init_connection()
			{
				return true;
			}
			virtual bool handle_recv(const void* ptr, size_t cb);
			virtual bool handle_request(const http::http_request_info& query_info, http_response_info& response);

		private:
			enum machine_state{
				http_state_retriving_comand_line,
				http_state_retriving_header,
				http_state_retriving_body,
				http_state_connection_close,
				http_state_error
			};

			enum body_transfer_type{
				http_body_transfer_chunked,
				http_body_transfer_measure,//mean "Content-Length" valid
				http_body_transfer_chunked_instead_measure, 
				http_body_transfer_connection_close,
				http_body_transfer_multipart,
				http_body_transfer_undefined
			};

			bool handle_buff_in(std::string& buf);

			bool analize_cached_request_header_and_invoke_state(size_t pos);

			bool handle_invoke_query_line();
			bool parse_cached_header(http_header_info& body_info, const std::string& m_cache_to_process, size_t pos);
			std::string::size_type match_end_of_header(const std::string& buf);
			bool get_len_from_content_lenght(const std::string& str, size_t& len);
			bool handle_retriving_query_body();
			bool handle_query_measure();
			bool set_ready_state();
			bool slash_to_back_slash(std::string& str);
			std::string get_file_mime_tipe(const std::string& path);
			std::string get_response_header(const http_response_info& response);

			//major function 
			inline bool handle_request_and_send_response(const http::http_request_info& query_info);


			std::string get_not_found_response_body(const std::string& URI);

			std::string m_root_path;
			std::string m_cache;
			machine_state m_state;
			body_transfer_type m_body_transfer_type;
			bool m_is_stop_handling;
			http::http_request_info m_query_info;
			size_t m_len_summary, m_len_remain;
			config_type& m_config;
			bool m_want_close;
			size_t m_newlines;
		protected:
			i_service_endpoint* m_psnd_hndlr; 
			t_connection_context& m_conn_context;
		};

		template<class t_connection_context>
		struct i_http_server_handler
		{
			virtual ~i_http_server_handler(){}
			virtual bool handle_http_request(const http_request_info& query_info,
																						 http_response_info& response,
																						 t_connection_context& m_conn_context) = 0;
			virtual bool init_server_thread(){return true;}
			virtual bool deinit_server_thread(){return true;}
		};

		template<class t_connection_context>
		struct custum_handler_config: public http_server_config
		{
			i_http_server_handler<t_connection_context>* m_phandler;
			std::function<void(size_t, uint8_t*)> rng;
		};

		/************************************************************************/
		/*                                                                      */
		/************************************************************************/
		
		template<class t_connection_context = connection_context_base_1>
		class http_custom_handler: public simple_http_connection_handler<t_connection_context>
		{
		public:
			typedef custum_handler_config<t_connection_context> config_type;
			
			http_custom_handler(i_service_endpoint* psnd_hndlr, config_type& config, t_connection_context& conn_context)
				: simple_http_connection_handler<t_connection_context>(psnd_hndlr, config, conn_context),
					m_config(config),
					m_auth(m_config.m_user ? http_server_auth{*m_config.m_user, config.rng} : http_server_auth{})
			{}
			inline bool handle_request(const http_request_info& query_info, http_response_info& response)
			{
				CHECK_AND_ASSERT_MES(m_config.m_phandler, false, "m_config.m_phandler is NULL!!!!");

				const auto auth_response = m_auth.get_response(query_info);
				if (auth_response)
				{
					response = std::move(*auth_response);
					return true;
				}

				//fill with default values
				response.m_mime_tipe = "text/plain";
				response.m_response_code = 200;
				response.m_response_comment = "OK";
				response.m_body.clear();

				return m_config.m_phandler->handle_http_request(query_info, response, this->m_conn_context);
			}

			virtual bool thread_init()
			{
				return m_config.m_phandler->init_server_thread();
			}
	
			virtual bool thread_deinit()
			{
				return m_config.m_phandler->deinit_server_thread();
			}
			void handle_qued_callback()
			{}
			bool after_init_connection()
			{
				return true;
			}

		private:
			//simple_http_connection_handler::config_type m_stub_config;
			config_type& m_config;
			http_server_auth m_auth;
		};
	}
}
}

// #include "http_protocol_handler.inl"

#endif //_HTTP_SERVER_H_