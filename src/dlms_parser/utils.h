#pragma once

#include "types.h"
#include <cstddef>
#include <cstdint>
#include <span>

namespace dlms_parser {

class NonCopyable {
protected:
  NonCopyable() = default;
  ~NonCopyable() = default;

public:
  NonCopyable(NonCopyable&&) = default;
  NonCopyable& operator=(NonCopyable&&) = default;

  NonCopyable(const NonCopyable&) = delete;
  NonCopyable& operator=(const NonCopyable&) = delete;
};

class NonCopyableAndNonMovable : NonCopyable {
protected:
  NonCopyableAndNonMovable() = default;
  ~NonCopyableAndNonMovable() = default;

public:
  NonCopyableAndNonMovable(NonCopyableAndNonMovable&&) = delete;
  NonCopyableAndNonMovable& operator=(NonCopyableAndNonMovable&&) = delete;
};

inline uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>(static_cast<unsigned>(p[0]) << 8 | p[1]); }
inline uint32_t be32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1]) << 16 |
         static_cast<uint32_t>(p[2]) << 8 | static_cast<uint32_t>(p[3]);
}
inline uint64_t be64(const uint8_t* p) {
  return static_cast<uint64_t>(p[0]) << 56 | static_cast<uint64_t>(p[1]) << 48 |
         static_cast<uint64_t>(p[2]) << 40 | static_cast<uint64_t>(p[3]) << 32 |
         static_cast<uint64_t>(p[4]) << 24 | static_cast<uint64_t>(p[5]) << 16 |
         static_cast<uint64_t>(p[6]) << 8  | static_cast<uint64_t>(p[7]);
}

float data_as_float(DlmsDataType value_type, std::span<const uint8_t> data);
bool test_if_date_time_12b(std::span<const uint8_t> p);
void datetime_to_string(std::span<const uint8_t> data, std::span<char> buffer);
void data_to_string(DlmsDataType value_type, std::span<const uint8_t> data, std::span<char> buffer);
void obis_to_string(std::span<const uint8_t> obis, std::span<char> buffer);
const char* dlms_data_type_to_string(DlmsDataType vt);

// Read a BER-encoded length from buf[pos]. Advances pos past the length bytes.
// Returns the decoded length, or 0 if the buffer is too short.
uint32_t read_ber_length(std::span<const uint8_t> buf, size_t& pos);

int get_data_type_size(DlmsDataType type);
bool is_value_data_type(DlmsDataType type);

void format_hex_pretty_to(std::span<char> out, std::span<const uint8_t> data);

}
