cmake_minimum_required(VERSION 3.10)

find_package(nlohmann_json 3.7.0 REQUIRED)

add_library(beldex-lws-rpc light_wallet.h)

target_link_libraries(beldex-lws-rpc 
        PRIVATE
        beldex-lws-db
        beldex-lws-common
        beldex-lws-wire
        beldex-lws-wire-json
        beldex-lws-util
        nlohmann_json::nlohmann_json
)