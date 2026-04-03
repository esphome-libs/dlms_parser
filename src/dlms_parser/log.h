#pragma once

#include <cstdarg>
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

}
