#pragma once

#include "utils.h"
#include "obis_id.h"
#include <array>
#include <cstdio>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string_view>

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
  SELF_DESC,
  FLAT_POSITIONAL,
  GOING_DOWN,
  GOING_UP,
  END_OF_PATTERN = 0xFF
};

struct AxdrPatternStep final {
  AxdrTokenType type{};
  uint8_t param_u8_a{ 0 };
};

struct FlatFieldSpec final {
  ObisId obis{};

  // Optional guard: if expected_prefix_len > 0, the captured value at this position must
  // start with these bytes or the whole FLAT_POSITIONAL match is rejected.
  static constexpr size_t MAX_PREFIX_BYTES = 16;
  std::array<uint8_t, MAX_PREFIX_BYTES> expected_prefix{};
  uint8_t expected_prefix_len{ 0 };

  constexpr FlatFieldSpec() = default;
  constexpr explicit FlatFieldSpec(const ObisId o) : obis(o) {}

  // Returns an empty optional if prefix has more than MAX_PREFIX_BYTES bytes.
  static std::optional<FlatFieldSpec> with_prefix(ObisId o, std::span<const uint8_t> prefix);
};

struct AxdrDescriptorPattern final {
  const char* name{ nullptr };
  int priority{ 0 };
  AxdrPatternStep steps[32]{};
  uint16_t default_class_id{ 0 };
  ObisId default_obis{};

  // Only used by FLAT_POSITIONAL patterns: one field spec per element of a fixed-size,
  // untagged STRUCTURE (vendor sends bare values, no per-element class-id/OBIS/attribute
  // metadata — position is the only thing identifying a field).
  static constexpr size_t MAX_FLAT_FIELDS = 32;
  std::array<FlatFieldSpec, MAX_FLAT_FIELDS> flat_fields{};
  uint8_t flat_field_count{ 0 };
};

struct AxdrCapture final {
  uint32_t elem_idx{ 0 };
  uint16_t class_id{ 0 };
  ObisId obis{};
  DlmsDataType value_type{ DlmsDataType::NONE };
  std::span<const uint8_t> value{};
  bool has_scaler_unit{ false };
  int8_t scaler{ 0 };
  uint8_t unit_enum{ 0 };

  [[nodiscard]] bool is_numeric() const;
  [[nodiscard]] float value_as_float_with_scaler_applied() const;
  [[nodiscard]] std::string_view value_as_string(std::span<char, 128> buffer) const;

private:
  [[nodiscard]] float value_as_float() const;
  static float apply_scaler(float value, int8_t scaler);
};

using DlmsDataCallback = std::function<void(const AxdrCapture& axdrCapture)>;

struct ParseResult final {
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
  void register_pattern(const char* name, const char* dsl, int priority, ObisId default_obis = {});

  // Register a pattern for a fixed-size STRUCTURE whose elements carry no per-element OBIS/class-id
  // tagging at all — fields[i] describes element i.
  bool register_flat_positional_pattern(const char* name, int priority, std::span<const FlatFieldSpec> fields);

  // Same, but parsed from text at runtime: comma-separated "obis" or "obis~hexbytes"
  // entries, e.g. "0.0.96.1.4.255~5A50413348414E3030323030, 0.0.1.0.0.255".
  // The "~hexbytes" suffix is optional and sets that field's expected_prefix guard.
  // Returns false (registers nothing) if field_list is malformed. The parsed OBIS codes
  // and prefix bytes are copied.
  bool register_flat_positional_pattern(const char* name, int priority, const char* field_list);

  void clear_patterns();

  // Parse AXDR bytes. Fires cooked_cb and/or raw_cb for each pattern match.
  // Either callback may be nullptr.
  ParseResult parse(std::span<const uint8_t> axdr);

  [[nodiscard]] std::span<const AxdrDescriptorPattern> patterns() const { return { patterns_.data(), patterns_count_ }; }

private:
  static constexpr size_t MAX_PATTERNS = 32;

  // Pattern registry
  std::array<AxdrDescriptorPattern, MAX_PATTERNS> patterns_;
  size_t patterns_count_{ 0 };
  AxdrDescriptorPattern& register_pattern_dsl_(const char* name, std::string_view dsl, int priority);
  AxdrDescriptorPattern& insert_pattern_(AxdrDescriptorPattern pat);

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
  bool try_match_patterns_(DlmsDataType container_type, uint8_t elem_idx, uint8_t elem_count);
  bool parse_self_describing_(DlmsDataType container_type, uint8_t elem_idx, uint8_t elem_count,
                              const AxdrDescriptorPattern& pat, uint8_t& consumed);
  bool parse_flat_positional_(DlmsDataType container_type, uint8_t elem_idx, uint8_t elem_count,
                              const AxdrDescriptorPattern& pat, uint8_t& consumed);
  bool match_pattern_(DlmsDataType container_type, uint8_t elem_idx, uint8_t elem_count,
                      const AxdrDescriptorPattern& pat, uint8_t& consumed);
  void emit_object_(const AxdrDescriptorPattern& pat, const AxdrCapture& c);
};

}
