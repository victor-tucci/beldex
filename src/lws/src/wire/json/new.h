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