#pragma once

#include "types.h"
#include <cstddef>
#include <cstdint>

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

inline uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>(p[0] << 8 | p[1]); }
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

float data_as_float(DlmsDataType value_type, const uint8_t* ptr, uint8_t len);
void data_to_string(DlmsDataType value_type, const uint8_t* ptr, uint8_t len, char* buffer, size_t max_len);
void obis_to_string(const uint8_t* obis, char* buffer, size_t max_len);
const char* dlms_data_type_to_string(DlmsDataType vt);

int get_data_type_size(DlmsDataType type);
bool is_value_data_type(DlmsDataType type);

// Replaces esphome::format_hex_pretty_to for standalone capability
void format_hex_pretty_to(char* out, size_t max_out, const uint8_t* data, size_t length);

}
