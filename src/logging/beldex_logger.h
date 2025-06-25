#pragma once

#include <filesystem>

#include <oxen/log.hpp>
#include <oxenmq/oxenmq.h>

#define BELDEX_LOG_ENABLED(LVL) logcat->should_log(spdlog::level::LVL)

// We can't just make a global "log" namespace because it conflicts with global C log()
namespace cryptonote { namespace log = oxen::log; }
namespace crypto { namespace log = oxen::log; }
namespace tools { namespace log = oxen::log; }
namespace master_nodes { namespace log = oxen::log; }
namespace nodetool { namespace log = oxen::log; }
namespace rct { namespace log = oxen::log; }

inline auto globallogcat = oxen::log::Cat("global");

namespace beldex::logging
{
  void
  init(const std::string& log_location, oxen::log::Level log_level, bool log_to_stdout = true);
  void
  set_file_sink(const std::string& log_location);
  void
  set_additional_log_categories(const oxen::log::Level& log_level);
  void
  process_categories_string(const std::string& categories);

  std::optional<oxen::log::Level>
  parse_level(std::string_view input);
  std::optional<oxen::log::Level>
  parse_level(uint8_t input);
  std::optional<oxen::log::Level>
  parse_level(oxenmq::LogLevel input);

}  // namespace beldex::logging