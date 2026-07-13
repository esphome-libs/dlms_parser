#pragma once

#include <array>
#include <compare>
#include <cstdio>
#include <cstdint>
#include <span>
#include <string_view>
#include <algorithm>

namespace dlms_parser {

struct ObisId final {
  std::array<uint8_t, 6> v{};

  ObisId() = default;
  constexpr explicit ObisId(const uint8_t a, const uint8_t b, const uint8_t c, const uint8_t d, const uint8_t e, const uint8_t f) noexcept : v{ a, b, c, d, e, f } {}
  constexpr explicit  ObisId(const std::span<const uint8_t, 6> s) noexcept : v{ s[0], s[1], s[2], s[3], s[4], s[5] } {}

  constexpr auto operator<=>(const ObisId&) const = default;

  [[nodiscard]] bool empty() const { return v == std::array<uint8_t, 6>{}; }

  [[nodiscard]] std::string_view to_string(std::span<char> buffer) const {
    if (buffer.empty()) return {};
    const int len = snprintf(buffer.data(), buffer.size(), "%u.%u.%u.%u.%u.%u", v[0], v[1], v[2], v[3], v[4], v[5]);
    const size_t safe_len = len > 0 ? std::min<size_t>(static_cast<size_t>(len), buffer.size() - 1) : 0;
    return { buffer.data(), safe_len };
  }
};

}
