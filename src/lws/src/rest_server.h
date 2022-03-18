#pragma once

#include <boost/asio/io_service.hpp>
#include <cstddef>
#include <list>
#include <string>
#include <vector>

#include "epee/net/net_ssl.h" //contrib/epee/include
#include "epee/byte_slice.h"
#include "common/expect.h"
#include "db/fwd.h"

using namespace std;

namespace lws
{
    class rest_server
    {
    public:
        struct configuration
        {
            epee::net_utils::ssl_authentication_t auth;
            std::vector<std::string> access_controls;
            std::size_t threads;
            bool allow_external;
        }; // configre

    }; // rest_server
} // lws