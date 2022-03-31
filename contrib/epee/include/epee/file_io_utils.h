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

#ifndef _FILE_IO_UTILS_H_
#define _FILE_IO_UTILS_H_

#include <string>
#include <ctime>

namespace epee
{
namespace file_io_utils
{
    bool is_file_exist(const std::string& path);
    bool save_string_to_file(const std::string& path_to_file, const std::string& str);
    bool get_file_time(const std::string& path_to_file, time_t& ft);
    bool set_file_time(const std::string& path_to_file, const time_t& ft);
    // bool load_file_to_string(const std::string& path_to_file, std::string& target_str, size_t max_size = 1000000000);
    bool append_string_to_file(const std::string& path_to_file, const std::string& str);
    bool get_file_size(const std::string& path_to_file, uint64_t &size);

    inline
		bool load_file_to_string(const std::string& path_to_file, std::string& target_str, size_t max_size = 1000000000)
	{
#ifdef WIN32
                std::wstring wide_path;
                try { wide_path = string_tools::utf8_to_utf16(path_to_file); } catch (...) { return false; }
                HANDLE file_handle = CreateFileW(wide_path.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (file_handle == INVALID_HANDLE_VALUE)
                    return false;
                DWORD file_size = GetFileSize(file_handle, NULL);
                if ((file_size == INVALID_FILE_SIZE) || (uint64_t)file_size > (uint64_t)max_size) {
                    CloseHandle(file_handle);
                    return false;
                }
                target_str.resize(file_size);
                DWORD bytes_read;
                BOOL result = ReadFile(file_handle, &target_str[0], file_size, &bytes_read, NULL);
                CloseHandle(file_handle);
                if (bytes_read != file_size)
                    result = FALSE;
                return result;
#else
		try
		{
			std::ifstream fstream;
			fstream.exceptions(std::ifstream::failbit | std::ifstream::badbit);
			fstream.open(path_to_file, std::ios_base::binary | std::ios_base::in | std::ios::ate);

			std::ifstream::pos_type file_size = fstream.tellg();
			
			if((uint64_t)file_size > (uint64_t)max_size) // ensure a large domain for comparison, and negative -> too large
				return false;//don't go crazy
			size_t file_size_t = static_cast<size_t>(file_size);

			target_str.resize(file_size_t);

			fstream.seekg (0, std::ios::beg);
			fstream.read((char*)target_str.data(), target_str.size());
			fstream.close();
			return true;
		}

		catch(...)
		{
			return false;
		}
#endif
	}

    
}
}

#endif //_FILE_IO_UTILS_H_
