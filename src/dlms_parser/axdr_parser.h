#pragma once

#include "pattern.h"
#include "types.h"
#include "utils.h"
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace dlms_parser {

// Callback delivering raw captured data before any conversion.
using DlmsRawCallback = std::function<void(const AxdrCaptures&, const AxdrDescriptorPattern&)>;

struct ParseResult {
  size_t count{0};         // number of matched COSEM objects
  size_t bytes_consumed{0}; // how many bytes of the input buffer were processed
};

// Recursive AXDR parser with DSL-based pattern matching.
// Input must start with a DLMS type byte (STRUCTURE 0x02 or ARRAY 0x01).
// No knowledge of APDU framing or encryption.
class AxdrParser {
 public:
  AxdrParser();

  // Register a named pattern from the DSL string, e.g. "TC,TO,TS,TV".
  void register_pattern(const std::string& name, const std::string& dsl, int priority = 10);
  void register_pattern(const std::string& name, const std::string& dsl, int priority,
                        const uint8_t default_obis[6]);
  void clear_patterns();

  // Parse AXDR bytes. Fires cooked_cb and/or raw_cb for each pattern match.
  // Either callback may be nullptr.
  ParseResult parse(const uint8_t* axdr, size_t len,
                    DlmsDataCallback cooked_cb,
                    DlmsRawCallback raw_cb = nullptr);

  const std::vector<AxdrDescriptorPattern>& patterns() const { return patterns_; }

 private:
  // Pattern registry
  std::vector<AxdrDescriptorPattern> patterns_;
  AxdrDescriptorPattern& register_pattern_dsl_(const std::string& name, const std::string& dsl, int priority);

  // Parse-time state — reset at the start of each parse() call
  const uint8_t* buffer_{nullptr};
  size_t buffer_len_{0};
  size_t pos_{0};
  DlmsDataCallback cooked_cb_;
  DlmsRawCallback raw_cb_;
  size_t objects_found_{0};
  uint8_t last_pattern_elements_consumed_{0};

  // Primitives
  uint8_t read_byte_();
  uint16_t read_u16_();
  uint32_t read_u32_();

  // Traversal
  bool skip_data_(uint8_t type);
  bool parse_element_(uint8_t type, uint8_t depth = 0);
  bool parse_sequence_(uint8_t type, uint8_t depth = 0);

  // Pattern matching
  bool test_if_date_time_12b_(const uint8_t* buf = nullptr);
  bool capture_generic_value_(AxdrCaptures& c);
  bool try_match_patterns_(uint8_t elem_idx, uint8_t elem_count);
  bool match_pattern_(uint8_t elem_idx, uint8_t elem_count, const AxdrDescriptorPattern& pat, uint8_t& consumed);
  void emit_object_(const AxdrDescriptorPattern& pat, const AxdrCaptures& c);
};

}  // namespace dlms_parser
