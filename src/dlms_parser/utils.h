#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdarg>
#include <span>
#include <functional>

namespace dlms_parser {

enum class LogLevel {
  DEBUG,
  VERY_VERBOSE,
  VERBOSE,
  INFO,
  WARNING,
  ERROR,
};

class Logger final {
public:
  static void set_log_function(std::function<void(LogLevel log_level, const char* fmt, va_list args)> func) { _log_function = std::move(func); }

#if defined(__clang__) || defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    static void log(LogLevel log_level, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    _log_function(log_level, fmt, args);
    va_end(args);
  }

private:
  Logger() = default;
  inline static std::function<void(LogLevel log_level, const char* fmt, va_list args)> _log_function = [](LogLevel, const char*, va_list) {};
};

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

}
