#pragma once

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

enum class DlmsDataType : uint8_t {
  NONE = 0,
  ARRAY = 1,
  STRUCTURE = 2,
  BOOLEAN = 3,
  BIT_STRING = 4,
  INT32 = 5,
  UINT32 = 6,
  OCTET_STRING = 9,
  STRING = 10,
  STRING_UTF8 = 12,
  BINARY_CODED_DECIMAL = 13,
  INT8 = 15,
  INT16 = 16,
  UINT8 = 17,
  UINT16 = 18,
  COMPACT_ARRAY = 19,
  INT64 = 20,
  UINT64 = 21,
  ENUM = 22,
  FLOAT32 = 23,
  FLOAT64 = 24,
  DATETIME = 25,
  DATE = 26,
  TIME = 27
};
const char* to_string(DlmsDataType vt);

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

bool test_if_date_time_12b(std::span<const uint8_t> p);
void datetime_to_string(std::span<const uint8_t> data, std::span<char> buffer);

// Read a BER-encoded length from buf[pos]. Advances pos past the length bytes.
// Returns the decoded length, or 0 if the buffer is too short.
uint32_t read_ber_length(std::span<const uint8_t> buf, size_t& pos);

int get_data_type_size(DlmsDataType type);
bool is_value_data_type(DlmsDataType type);

inline bool is_mbus_short_frame(const std::span<const uint8_t> data) {
  if (data.size() < 5 || data[0] != 0x10 || data[4] != 0x16) return false;
  return static_cast<uint8_t>(data[1] + data[2]) == data[3];
}

}
