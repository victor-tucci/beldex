#pragma once

#include <string>

#include "byte_slice.h"
#include "common/expect.h"  // beldex/src
#include "wire/json/fwd.h"

namespace wire
{
  struct json
  {
    template<typename T>
    static expect<T> from_bytes(std::string&& source);

    template<typename T>
    static epee::byte_slice to_bytes(const T& source);
  };
}

