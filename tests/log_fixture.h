#pragma once

#include "dlms_parser/log.h"
#include <doctest.h>
#include <cstdio>
#include <format>
#include <string>
#include <array>
#include <iostream>

class LogFixture {
public:
  LogFixture() : doctest_context_scope([this](std::ostream* out) {
                                         for (const auto& msg : messages)
                                           *out << "\n" << msg;
                                       }) {
    dlms_parser::Logger::set_log_function([this](const dlms_parser::LogLevel log_level, const char* fmt, va_list args) {
      std::array<char, 2000> buf{};
      vsnprintf(buf.data(), buf.size(), fmt, args);

      const char* level_str;
      switch (log_level) {
      case dlms_parser::LogLevel::DEBUG:        level_str = "[DBG] "; break;
      case dlms_parser::LogLevel::VERY_VERBOSE: level_str = "[VV]  "; break;
      case dlms_parser::LogLevel::VERBOSE:      level_str = "[VRB] "; break;
      case dlms_parser::LogLevel::INFO:         level_str = "[INF] "; break;
      case dlms_parser::LogLevel::WARNING:      level_str = "[WRN] "; break;
      case dlms_parser::LogLevel::ERROR:        level_str = "[ERR] "; break;
      }

      const auto msg = std::format("{}{}", level_str, buf.data());
      messages.emplace_back(msg);
    });
  }

  ~LogFixture() {
    dlms_parser::Logger::set_log_function([](dlms_parser::LogLevel, const char*, va_list) {});
  }

  [[nodiscard]] bool contains(const std::string& substr) const {
    for (const auto& msg : messages) {
      if (msg.find(substr) != std::string::npos)
        return true;
    }
    return false;
  }

  void clear() { messages.clear(); }

  doctest::detail::ContextScope<std::function<void(std::ostream*)>> doctest_context_scope;
  std::vector<std::string> messages;
};
