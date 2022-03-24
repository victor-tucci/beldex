#pragma once

#include <array>
#include <boost/utility/string_ref.hpp>
#include <cstdint>
#include <limits>
#include <rapidjson/writer.h>

#include "byte_stream.h" // beldex/contrib/epee/include
#include "span.h"        // beldex/contrib/epee/include
#include "wire/field.h"
#include "wire/filters.h"
#include "wire/json/base.h"
#include "wire/traits.h"
#include "wire/write.h"

namespace wire
{
  constexpr const std::size_t uint_to_string_size =
    std::numeric_limits<std::uintmax_t>::digits10 + 2;

  //! Writes JSON tokens one-at-a-time for DOMless output.
  class json_writer : public writer
  {
    epee::byte_stream bytes_;
    rapidjson::Writer<epee::byte_stream> formatter_;
    bool needs_flush_;

    //! \return True if buffer needs to be cleared
    virtual void do_flush(epee::span<const uint8_t>);

    //! Flush written bytes to `do_flush(...)` if configured
    void check_flush();

  protected:
    json_writer(bool needs_flush)
      : writer(), bytes_(), formatter_(bytes_), needs_flush_(needs_flush)
    {}

    //! \throw std::logic_error if incomplete JSON tree
    void check_complete();

    //! \throw std::logic_error if incomplete JSON tree. \return JSON bytes
    epee::byte_slice take_json();

    //! Flush bytes in local buffer to `do_flush(...)`
    void flush()
    {
      do_flush({bytes_.data(), bytes_.size()});
      bytes_ = epee::byte_stream{}; // TODO create .clear() method in monero project
    }

  public:
    json_writer(const json_writer&) = delete;
    virtual ~json_writer() noexcept;
    json_writer& operator=(const json_writer&) = delete;

    //! \return Null-terminated buffer containing uint as decimal ascii
    static std::array<char, uint_to_string_size> to_string(std::uintmax_t) noexcept;

    void integer(int) override final;
    void integer(std::intmax_t) override final;

    void unsigned_integer(unsigned) override final;
    void unsigned_integer(std::uintmax_t) override final;

    void real(double) override final;

    void string(boost::string_ref) override final;
    void binary(epee::span<const std::uint8_t> source) override final;

    void enumeration(std::size_t index, epee::span<char const* const> enums) override final;

    void start_array(std::size_t) override final;
    void end_array() override final;

    void start_object(std::size_t) override final;
    void key(std::uintmax_t) override final;
    void key(boost::string_ref) override final;
    void key(unsigned, boost::string_ref) override final;
    void end_object() override final;
  };

  //! Buffers entire JSON message in memory
  struct json_slice_writer final : json_writer
  {
    explicit json_slice_writer()
      : json_writer(false)
    {}

    //! \throw std::logic_error if incomplete JSON tree \return JSON bytes
    epee::byte_slice take_bytes()
    {
      return json_writer::take_json();
    }
  };

  //! Periodically flushes JSON data to `std::ostream`
  class json_stream_writer final : public json_writer
  {
    std::ostream& dest;

    virtual void do_flush(epee::span<const std::uint8_t>) override final;
  public:
    explicit json_stream_writer(std::ostream& dest)
      : json_writer(true), dest(dest)
    {}

    //! Flush remaining bytes to stream \throw std::logic_error if incomplete JSON tree
    void finish()
    {
      check_complete();
      flush();
    }
  };

 template<typename T>
  epee::byte_slice json::to_bytes(const T& source)
  {
    return wire_write::to_bytes<json_slice_writer>(source);
  }


  template<typename T, typename F = identity_>
  inline void array(json_writer& dest, const T& source, F filter = F{})
  {
    // works with "lazily" computed ranges
    wire_write::array(dest, source, 0, std::move(filter));
  }
  template<typename T, typename F>
  inline void write_bytes(json_writer& dest, as_array_<T, F> source)
  {
    wire::array(dest, source.get_value(), std::move(source.filter));
  }
  template<typename T>
  inline enable_if<is_array<T>::value> write_bytes(json_writer& dest, const T& source)
  {
    wire::array(dest, source);
  }

  template<typename T, typename F = identity_, typename G = identity_>
  inline void dynamic_object(json_writer& dest, const T& source, F key_filter = F{}, G value_filter = G{})
  {
    // works with "lazily" computed ranges
    wire_write::dynamic_object(dest, source, 0, std::move(key_filter), std::move(value_filter));
  }
  template<typename T, typename F, typename G>
  inline void write_bytes(json_writer& dest, as_object_<T, F, G> source)
  {
    wire::dynamic_object(dest, source.get_map(), std::move(source.key_filter), std::move(source.value_filter));
  }

  template<typename... T>
  inline void object(json_writer& dest, T... fields)
  {
    wire_write::object(dest, std::move(fields)...);
  }
}

namespace wire_write
{
  /*! Don't add a function called `write_bytes` to this namespace, it will
      prevent ADL lookup. ADL lookup delays the function searching until the
      template is used instead of when its defined. This allows the unqualified
      calls to `write_bytes` in this namespace to "find" user functions that are
      declared after these functions. */

  template<typename W, typename T>
  inline epee::byte_slice to_bytes(const T& value)
  {
    W dest{};
    write_bytes(dest, value);
    return dest.take_bytes();
  }

  // template<typename W, typename T, typename F = wire::identity_>
  // inline void array(W& dest, const T& source, const std::size_t count, F filter = F{})
  // {
  //   using value_type = typename T::value_type;
  //   static_assert(!std::is_same<value_type, char>::value, "write array of chars as binary");
  //   static_assert(!std::is_same<value_type, std::uint8_t>::value, "write array of unsigned chars as binary");

  //   dest.start_array(count);
  //   for (const auto& elem : source)
  //     write_bytes(dest, filter(elem));
  //   dest.end_array();
  // }

  // template<typename W, typename T>
  // inline bool field(W& dest, const wire::field_<T, true> elem)
  // {
  //   dest.key(0, elem.name);
  //   write_bytes(dest, elem.get_value());
  //   return true;
  // }

  // template<typename W, typename T>
  // inline bool field(W& dest, const wire::field_<T, false> elem)
  // {
  //   if (bool(elem.get_value()))
  //   {
  //     dest.key(0, elem.name);
  //     write_bytes(dest, *elem.get_value());
  //   }
  //   return true;
  // }

  // template<typename W, typename... T>
  // inline void object(W& dest, T... fields)
  // {
  //   dest.start_object(wire::sum(std::size_t(wire::available(fields))...));
  //   const bool dummy[] = {field(dest, std::move(fields))...};
  //   dest.end_object();
  // }

  // template<typename W, typename T, typename F, typename G>
  // inline void dynamic_object(W& dest, const T& values, const std::size_t count, F key_filter, G value_filter)
  // {
  //   dest.start_object(count);
  //   for (const auto& elem : values)
  //   {
  //     dest.key(key_filter(elem.first));
  //     write_bytes(dest, value_filter(elem.second));
  //   }
  //   dest.end_object();
  // }
} // wire_write