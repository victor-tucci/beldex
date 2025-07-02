#include "scoped_message_writer.h"
#include "common/format.h"

#define BELDEX_INTEGRATION_TEST_HOOKS_IMPLEMENTATION
#include "common/beldex_integration_test_hooks.h"

// NOTE(beldex): This file only exists because I need a way to hook into the
// message writer for integration tests. Originally this was a header only file,
// which means it needs to know the implementation of
// beldex_integration_test_hooks.h functions which isn't possible to expose in
// just the header because of the One Definition Rule.
//   - doyle 2018-11-08

namespace tools {

static auto logcat = log::Cat("msgwriter");
  
scoped_message_writer& scoped_message_writer::flush() {
    if (!m_content.empty()) {
        if (m_color) {
            rdln::suspend_readline pause_readline;
            fmt::print(fg(*m_color), "{}{}\n", m_prefix, m_content);
        } else
            fmt::print("{}{}\n", m_prefix, m_content);

        m_content.clear();
    }
    return *this;
}
scoped_message_writer::~scoped_message_writer() {
    flush();
}

} // namespace tools
