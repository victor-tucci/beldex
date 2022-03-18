set(util_headers 
    gamma_picker.h
    random_outputs.h
)

set(util_sources
    gamma_picker.cpp
)
find_package(nlohmann_json 3.7.0 REQUIRED)
add_library(beldex-lws-util 
    ${util_headers}
    ${util_source}
)

target_link_libraries(beldex-lws-util
    PUBLIC
        beldex-lws-wire
        beldex-lws-wire-json
    PRIVATE
        beldex-lws-db
)
