#pragma once

#include "utils.h"
#include <cstdint>
#include <functional>
#include <span>
#include <string_view>
#include <array>

namespace dlms_parser {

enum class AxdrTokenType : uint8_t {
  EXPECT_TO_BE_FIRST,
  EXPECT_TO_BE_LAST,
  EXPECT_TYPE_EXACT,
  EXPECT_TYPE_U_I_8,
  EXPECT_CLASS_ID_UNTAGGED,
  EXPECT_OBIS6_TAGGED,
  EXPECT_OBIS6_TAGGED_WRONG,
  EXPECT_OBIS6_UNTAGGED,
  EXPECT_ATTR8_UNTAGGED,
  EXPECT_VALUE_GENERIC,
  EXPECT_VALUE_DATE_TIME,
  EXPECT_VALUE_OCTET_STRING,
  EXPECT_STRUCTURE_N,
  EXPECT_SCALER_TAGGED,
  EXPECT_UNIT_ENUM_TAGGED,
  GOING_DOWN,
  GOING_UP,
  END_OF_PATTERN = 0xFF
};

struct AxdrPatternStep {
  AxdrTokenType type{};
  uint8_t param_u8_a{ 0 };
};

struct AxdrDescriptorPattern {
  const char* name{ nullptr };
  int priority{ 0 };
  AxdrPatternStep steps[32]{};
  uint16_t default_class_id{ 0 };
  bool has_default_obis{ false };
  std::array<uint8_t, 6> default_obis{};
};

struct AxdrCapture {
  uint32_t elem_idx{ 0 };
  uint16_t class_id{ 0 };
  std::span<const uint8_t> obis{};
  DlmsDataType value_type{ DlmsDataType::NONE };
  std::span<const uint8_t> value{};
  bool has_scaler_unit{ false };
  int8_t scaler{ 0 };
  uint8_t unit_enum{ 0 };
  
  std::string_view obis_as_string(std::span<char, 32> buffer) const;
  bool is_numeric() const;
  float value_as_float_with_scaler_applied() const;
  std::string_view value_as_string(std::span<char, 128> buffer) const;
private:
  float value_as_float() const;
  static float apply_scaler(const float value, const int8_t scaler);
};

using DlmsDataCallback = std::function<void(const AxdrCapture& axdrCapture)>;

struct ParseResult {
  size_t count{ 0 };          // number of matched COSEM objects
  size_t bytes_consumed{ 0 }; // how many bytes of the input buffer were processed
};

// Recursive AXDR parser with DSL-based pattern matching.
// Input must start with a DLMS type byte (STRUCTURE 0x02 or ARRAY 0x01).
// No knowledge of APDU framing or encryption.
class AxdrParser final : NonCopyableAndNonMovable {
public:
  explicit AxdrParser(DlmsDataCallback dlmsDataCallback);

  // Register a named pattern from the DSL string, e.g. "TC,TO,TS,TV".
  void register_pattern(const char* name, const char* dsl, int priority = 10);
  void register_pattern(const char* name, const char* dsl, int priority, std::span<const uint8_t, 6> default_obis);
  void clear_patterns();

  // Parse AXDR bytes. Fires cooked_cb and/or raw_cb for each pattern match.
  // Either callback may be nullptr.
  ParseResult parse(std::span<const uint8_t> axdr);

  [[nodiscard]] std::span<const AxdrDescriptorPattern> patterns() const { return { patterns_.data(), patterns_count_ }; }
  [[nodiscard]] size_t patterns_size() const { return patterns_count_; }

private:
  static constexpr size_t MAX_PATTERNS = 32;

  // Pattern registry
  std::array<AxdrDescriptorPattern, MAX_PATTERNS> patterns_;
  size_t patterns_count_{ 0 };
  AxdrDescriptorPattern& register_pattern_dsl_(const char* name, std::string_view dsl, int priority);

  // Parse-time state — reset at the start of each parse() call
  std::span<const uint8_t> buffer_{};
  size_t pos_{ 0 };
  DlmsDataCallback dlmsDataCallback_;
  size_t objects_found_{ 0 };
  uint8_t last_pattern_elements_consumed_{ 0 };

  // Primitives
  uint8_t read_byte_();
  uint16_t read_u16_();
  uint32_t read_u32_();

  // Traversal
  bool skip_data_(DlmsDataType type);
  bool parse_element_(DlmsDataType type, uint8_t depth = 0);
  bool parse_sequence_(DlmsDataType type, uint8_t depth = 0);

  // Pattern matching
  bool test_if_date_time_12b_(std::span<const uint8_t> buf = {}) const;
  bool capture_generic_value_(AxdrCapture& c);
  bool try_match_patterns_(uint8_t elem_idx, uint8_t elem_count);
  bool match_pattern_(uint8_t elem_idx, uint8_t elem_count, const AxdrDescriptorPattern& pat, uint8_t& consumed);
  static float apply_scaler(float value, int8_t scaler);
  void emit_object_(const AxdrDescriptorPattern& pat, const AxdrCapture& c);
};

}
