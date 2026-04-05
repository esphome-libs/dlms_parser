#include "axdr_parser.h"
#include "log.h"
#include "utils.h"
#include <algorithm>
#include <utility>

namespace dlms_parser {

// ---------------------------------------------------------------------------
// Construction / pattern registry
// ---------------------------------------------------------------------------

void AxdrParser::register_pattern(const char* name, const char* dsl, const int priority) {
  this->register_pattern_dsl_(name, dsl, priority);
}

void AxdrParser::register_pattern(const char* name, const char* dsl, const int priority, const std::span<const uint8_t, 6> default_obis) {
  auto& pat = this->register_pattern_dsl_(name, dsl, priority);
  pat.has_default_obis = true;
  std::ranges::copy(default_obis, pat.default_obis.begin());
}

void AxdrParser::clear_patterns() {
  patterns_count_ = 0;
}

// ---------------------------------------------------------------------------
// Public parse entry point
// ---------------------------------------------------------------------------

ParseResult AxdrParser::parse(const std::span<const uint8_t> axdr, DlmsDataCallback cooked_cb, DlmsRawCallback raw_cb) {
  if (axdr.empty()) return {};

  buffer_ = axdr;
  pos_ = 0;
  cooked_cb_ = std::move(cooked_cb);
  raw_cb_ = std::move(raw_cb);
  objects_found_ = 0;
  last_pattern_elements_consumed_ = 0;

  Logger::log(LogLevel::DEBUG, "AxdrParser: parsing %zu bytes", axdr.size());

  while (this->pos_ < this->buffer_.size()) {
    const uint8_t type = this->read_byte_();
    if (type != DLMS_DATA_TYPE_STRUCTURE && type != DLMS_DATA_TYPE_ARRAY) {
      Logger::log(LogLevel::VERBOSE, "Non-container type 0x%02X at pos %zu - stopping", type, this->pos_ - 1);
      this->pos_--;  // put it back — not consumed
      break;
    }
    if (!this->parse_element_(type, 0)) {
      Logger::log(LogLevel::VERBOSE, "Parsing stopped at pos %zu", this->pos_);
      break;
    }
  }

  Logger::log(LogLevel::DEBUG, "AxdrParser: done, %zu objects found, %zu/%zu bytes consumed",
              objects_found_, pos_, buffer_.size());
  return {objects_found_, pos_};
}

// ---------------------------------------------------------------------------
// Buffer primitives
// ---------------------------------------------------------------------------

uint8_t AxdrParser::read_byte_() {
  if (this->pos_ >= this->buffer_.size()) return 0xFF;
  return this->buffer_[this->pos_++];
}

uint16_t AxdrParser::read_u16_() {
  if (this->pos_ + 1 >= this->buffer_.size()) return 0xFFFF;
  const uint16_t val = be16(&this->buffer_[this->pos_]);
  this->pos_ += 2;
  return val;
}

uint32_t AxdrParser::read_u32_() {
  if (this->pos_ + 3 >= this->buffer_.size()) return 0xFFFFFFFF;
  const uint32_t val = be32(&this->buffer_[this->pos_]);
  this->pos_ += 4;
  return val;
}

// ---------------------------------------------------------------------------
// Traversal
// ---------------------------------------------------------------------------

bool AxdrParser::skip_data_(uint8_t type) {
  const int data_size = get_data_type_size(static_cast<DlmsDataType>(type));

  if (data_size == 0) return true;

  if (data_size > 0) {
    if (this->pos_ + static_cast<size_t>(data_size) > this->buffer_.size()) return false;
    this->pos_ += static_cast<size_t>(data_size);
  } else {
    // Variable-length: BER length encoding
    const uint8_t first_byte = this->read_byte_();
    if (first_byte == 0xFF) return false;

    uint32_t length = first_byte;
    if (first_byte > 127) {
      const uint8_t num_bytes = first_byte & 0x7F;
      length = 0;
      for (int i = 0; i < num_bytes; i++) {
        if (this->pos_ >= this->buffer_.size()) return false;
        length = length << 8 | this->read_byte_();
      }
    }

    uint32_t skip_bytes = length;
    if (type == DLMS_DATA_TYPE_BIT_STRING) {
      skip_bytes = (length + 7) / 8;
    }

    if (this->pos_ + skip_bytes > this->buffer_.size()) return false;

    Logger::log(LogLevel::VERY_VERBOSE, "Skipping %s (%u bytes) at pos %zu", dlms_data_type_to_string(static_cast<DlmsDataType>(type)), skip_bytes, this->pos_);
    this->pos_ += skip_bytes;
  }
  return true;
}

bool AxdrParser::parse_element_(const uint8_t type, const uint8_t depth) {
  if (type == DLMS_DATA_TYPE_STRUCTURE || type == DLMS_DATA_TYPE_ARRAY) {
    return this->parse_sequence_(type, depth);
  }
  return this->skip_data_(type);
}

bool AxdrParser::parse_sequence_(const uint8_t type, const uint8_t depth) {
  const uint8_t elements_count = this->read_byte_();
  if (elements_count == 0xFF) {
    Logger::log(LogLevel::VERY_VERBOSE, "Invalid sequence length at pos %zu", this->pos_ - 1);
    return false;
  }

  Logger::log(LogLevel::VERBOSE, "Parsing %s with %d elements at pos %zu (depth %d)",
              type == DLMS_DATA_TYPE_STRUCTURE ? "STRUCTURE" : "ARRAY",
              elements_count, this->pos_ - 1, depth);

  uint8_t elements_consumed = 0;
  while (elements_consumed < elements_count) {
    const size_t original_position = this->pos_;

    if (this->try_match_patterns_(elements_consumed, elements_count)) {
      elements_consumed = static_cast<uint8_t>(
          elements_consumed + (this->last_pattern_elements_consumed_ ? this->last_pattern_elements_consumed_ : 1));
      this->last_pattern_elements_consumed_ = 0;
      continue;
    }

    if (this->pos_ >= this->buffer_.size()) {
      Logger::log(LogLevel::VERBOSE, "Unexpected end while reading element %d of %s",
                  elements_consumed + 1, type == DLMS_DATA_TYPE_STRUCTURE ? "STRUCTURE" : "ARRAY");
      return false;
    }

    const uint8_t elem_type = this->read_byte_();
    if (!this->parse_element_(elem_type, depth + 1)) return false;
    elements_consumed++;

    if (this->pos_ == original_position) {
      Logger::log(LogLevel::VERBOSE, "No progress at pos %zu, aborting to avoid infinite loop",
                  original_position);
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Pattern matching
// ---------------------------------------------------------------------------

// test_if_date_time_12b_ delegates to the utils function, handling the parser buffer fallback.
bool AxdrParser::test_if_date_time_12b_(const std::span<const uint8_t> buf) const {
  if (!buf.empty()) return test_if_date_time_12b(buf);
  if (this->pos_ + 12 > this->buffer_.size()) return false;
  return test_if_date_time_12b(this->buffer_.subspan(this->pos_, 12));
}

bool AxdrParser::capture_generic_value_(AxdrCaptures& c) {
  uint8_t vt = this->read_byte_();
  if (!is_value_data_type(static_cast<DlmsDataType>(vt))) return false;

  const int ds = get_data_type_size(static_cast<DlmsDataType>(vt));
  if (ds > 0) {
    if (this->pos_ + static_cast<size_t>(ds) > this->buffer_.size()) return false;
    c.value = this->buffer_.subspan(this->pos_, static_cast<size_t>(ds));
    this->pos_ += static_cast<size_t>(ds);
  } else if (ds == 0) {
    c.value = {};
  } else {
    // Variable-length: BER length encoding
    const uint8_t first_byte = this->read_byte_();
    if (first_byte == 0xFF) return false;

    uint32_t length = first_byte;
    if (first_byte > 127) {
      const uint8_t num_bytes = first_byte & 0x7F;
      length = 0;
      for (int i = 0; i < num_bytes; i++) {
        if (this->pos_ >= this->buffer_.size()) return false;
        length = length << 8 | this->read_byte_();
      }
    }

    uint32_t data_bytes = length;
    if (vt == DLMS_DATA_TYPE_BIT_STRING) {
      data_bytes = (length + 7) / 8;
    }

    if (this->pos_ + data_bytes > this->buffer_.size()) return false;
    c.value = this->buffer_.subspan(this->pos_, data_bytes);
    this->pos_ += data_bytes;
  }

  // Auto-detect 12-byte OCTET_STRING as DATETIME
  if (vt == DLMS_DATA_TYPE_OCTET_STRING && c.value.size() == 12 &&
      this->test_if_date_time_12b_(c.value)) {
    vt = DLMS_DATA_TYPE_DATETIME;
  }

  c.value_type = static_cast<DlmsDataType>(vt);
  return true;
}

bool AxdrParser::try_match_patterns_(const uint8_t elem_idx, const uint8_t elem_count) {
  for (size_t i = 0; i < this->patterns_count_; ++i) {
    const auto& p = this->patterns_[i];
    const size_t saved_position = this->pos_;
    if (uint8_t consumed = 0; this->match_pattern_(elem_idx, elem_count, p, consumed)) {
      this->last_pattern_elements_consumed_ = consumed;
      return true;
    }
    this->pos_ = saved_position;
  }
  return false;
}

bool AxdrParser::match_pattern_(const uint8_t elem_idx, const uint8_t elem_count, const AxdrDescriptorPattern& pat,
                                uint8_t& consumed) {
  AxdrCaptures cap{};
  consumed = 0;
  uint8_t level = 0;
  auto consume_one = [&] { if (level == 0) consumed++; };
  const auto initial_position = static_cast<uint32_t>(this->pos_);

  for (const auto& [type, param_u8_a] : pat.steps) {
    switch (type) {
      case AxdrTokenType::EXPECT_TO_BE_FIRST:
        if (elem_idx != 0) return false;
        break;
      case AxdrTokenType::EXPECT_TO_BE_LAST:
        if (elem_count == 0 || elem_idx != elem_count - 1) return false;
        break;
      case AxdrTokenType::EXPECT_TYPE_EXACT:
        if (this->read_byte_() != param_u8_a) return false;
        consume_one();
        break;
      case AxdrTokenType::EXPECT_TYPE_U_I_8: {
        const uint8_t t = this->read_byte_();
        if (t != DLMS_DATA_TYPE_INT8 && t != DLMS_DATA_TYPE_UINT8) return false;
        consume_one();
        break;
      }
      case AxdrTokenType::EXPECT_CLASS_ID_UNTAGGED: {
        const uint16_t v = this->read_u16_();
        if (v > 0x00FF) return false;
        cap.class_id = v;
        break;
      }
      case AxdrTokenType::EXPECT_OBIS6_TAGGED:
        if (this->read_byte_() != DLMS_DATA_TYPE_OCTET_STRING) return false;
        if (this->read_byte_() != 6) return false;
        if (this->pos_ + 6 > this->buffer_.size()) return false;
        cap.obis = this->buffer_.subspan(this->pos_, 6);
        this->pos_ += 6;
        consume_one();
        break;
      case AxdrTokenType::EXPECT_OBIS6_TAGGED_WRONG:
        // Landis+Gyr firmware bug: sends 06 09 <obis> instead of 09 06 <obis>
        if (this->read_byte_() != 6) return false;
        if (this->read_byte_() != DLMS_DATA_TYPE_OCTET_STRING) return false;
        if (this->pos_ + 6 > this->buffer_.size()) return false;
        cap.obis = this->buffer_.subspan(this->pos_, 6);
        this->pos_ += 6;
        consume_one();
        break;
      case AxdrTokenType::EXPECT_OBIS6_UNTAGGED:
        if (this->pos_ + 6 > this->buffer_.size()) return false;
        cap.obis = this->buffer_.subspan(this->pos_, 6);
        this->pos_ += 6;
        break;
      case AxdrTokenType::EXPECT_ATTR8_UNTAGGED:
        if (this->read_byte_() == 0) return false;
        break;
      case AxdrTokenType::EXPECT_VALUE_GENERIC:
        if (!this->capture_generic_value_(cap)) return false;
        consume_one();
        break;
      case AxdrTokenType::EXPECT_VALUE_DATE_TIME: {
        // Accepts both: 0x19 (DATETIME tag) + 12 bytes, or 0x09 (OCTET_STRING) + 0x0C + 12 bytes
        const uint8_t tag = this->read_byte_();
        if (tag == DLMS_DATA_TYPE_DATETIME) {
          // Native DATETIME tag (0x19): fixed 12-byte payload, no length byte
        } else if (tag == DLMS_DATA_TYPE_OCTET_STRING) {
          if (this->read_byte_() != 12) return false;
        } else {
          return false;
        }
        if (this->pos_ + 12 > this->buffer_.size()) return false;
        cap.value = this->buffer_.subspan(this->pos_, 12);
        cap.value_type = DLMS_DATA_TYPE_DATETIME;
        this->pos_ += 12;
        consume_one();
        break;
      }
      case AxdrTokenType::EXPECT_VALUE_OCTET_STRING: {
        const uint8_t vt = this->read_byte_();
        if (vt != DLMS_DATA_TYPE_OCTET_STRING && vt != DLMS_DATA_TYPE_STRING &&
            vt != DLMS_DATA_TYPE_STRING_UTF8) return false;
        const uint8_t slen = this->read_byte_();
        if (slen == 0xFF || this->pos_ + slen > this->buffer_.size()) return false;
        cap.value_type = static_cast<DlmsDataType>(vt);
        cap.value = this->buffer_.subspan(this->pos_, slen);
        this->pos_ += slen;
        consume_one();
        break;
      }
      case AxdrTokenType::EXPECT_STRUCTURE_N:
        if (this->read_byte_() != DLMS_DATA_TYPE_STRUCTURE) return false;
        if (this->read_byte_() != param_u8_a) return false;
        consume_one();
        break;
      case AxdrTokenType::EXPECT_SCALER_TAGGED:
        if (this->read_byte_() != DLMS_DATA_TYPE_INT8) return false;
        cap.scaler = static_cast<int8_t>(this->read_byte_());
        cap.has_scaler_unit = true;
        consume_one();
        break;
      case AxdrTokenType::EXPECT_UNIT_ENUM_TAGGED:
        if (this->read_byte_() != DLMS_DATA_TYPE_ENUM) return false;
        cap.unit_enum = this->read_byte_();
        cap.has_scaler_unit = true;
        consume_one();
        break;
      case AxdrTokenType::GOING_DOWN: level++; break;
      case AxdrTokenType::GOING_UP:   level--; break;
      case AxdrTokenType::END_OF_PATTERN: break;
    }
  }

  if (consumed == 0) consumed = 1;
  cap.elem_idx = initial_position;
  this->emit_object_(pat, cap);
  return true;
}

static constexpr std::array<uint8_t, 6> ZERO_OBIS = {0, 0, 0, 0, 0, 0};

float AxdrParser::apply_scaler(const float value, const int8_t scaler) {
  if (scaler == 0) return value;

  // Lookup table for 10^0 through 10^9
  static constexpr float pow10_lut[] = {
    1e0f, 1e1f, 1e2f, 1e3f, 1e4f, 1e5f, 1e6f, 1e7f, 1e8f, 1e9f
  };

  // Fast path: use LUT for typical DLMS bounds (-9 to +9)
  if (scaler > 0 && scaler <= 9) {return value * pow10_lut[scaler];}
  if (scaler < 0 && scaler >= -9) {return value / pow10_lut[-scaler];}

  // Fallback path: loop for unusually large scalers
  float multiplier = 1.0f;
  if (scaler > 0) {
    for (int i = 0; i < scaler; ++i) multiplier *= 10.0f;
    return value * multiplier;
  }

  for (int i = 0; i < -scaler; ++i) multiplier *= 10.0f;
  return value / multiplier;
}

void AxdrParser::emit_object_(const AxdrDescriptorPattern& pat, const AxdrCaptures& c) {
  // If no OBIS was captured by the pattern, use 0.0.0.0.0.0 as a placeholder.
  // If no OBIS captured, use pattern's default_obis if set, otherwise zero placeholder.
  auto [elem_idx, class_id, obis, value_type, value, has_scaler_unit, scaler, unit_enum] = c;
  if (obis.empty()) {
    obis = pat.has_default_obis ? std::span<const uint8_t>(pat.default_obis) : std::span<const uint8_t>(ZERO_OBIS);
  }

  objects_found_++;

  // Raw callback — delivers original captures (obis may be empty)
  if (this->raw_cb_) {
    this->raw_cb_(c, pat);
  }

  if (!this->cooked_cb_) return;

  char obis_str_buf[32];
  obis_to_string(obis, obis_str_buf);

  const float raw_val_f = data_as_float(value_type, value);
  float val_f = raw_val_f;

  char val_s_buf[128];
  data_to_string(value_type, value, val_s_buf);

  const bool is_numeric = value_type != DLMS_DATA_TYPE_OCTET_STRING && value_type != DLMS_DATA_TYPE_STRING &&
                          value_type != DLMS_DATA_TYPE_STRING_UTF8  && value_type != DLMS_DATA_TYPE_DATETIME;

  if (has_scaler_unit && is_numeric) {
    val_f = apply_scaler(raw_val_f, scaler);
  }

  const uint16_t cid = class_id ? class_id : pat.default_class_id;
  Logger::log(LogLevel::VERBOSE, "Pattern '%s' matched at pos %u - class_id=%d obis=%s",
              pat.name ? pat.name : "UNKNOWN", elem_idx, cid, obis_str_buf);

  if (has_scaler_unit) {
    Logger::log(LogLevel::VERBOSE, "  type=%s len=%zu scaler=%d unit=%d",
                dlms_data_type_to_string(value_type), value.size(), scaler, unit_enum);
  } else {
    Logger::log(LogLevel::VERBOSE, "  type=%s len=%zu",
                dlms_data_type_to_string(value_type), value.size());
  }

  if (!value.empty()) {
    char hex_buf[512];
    format_hex_pretty_to(hex_buf, value);
    Logger::log(LogLevel::VERBOSE, "  hex  : %s", hex_buf);
  }
  Logger::log(LogLevel::VERBOSE, "  str  : '%s'", val_s_buf);
  Logger::log(LogLevel::VERBOSE, "  float: %f", static_cast<double>(raw_val_f));
  if (has_scaler_unit && is_numeric) {
    Logger::log(LogLevel::VERBOSE, "  scaled: %f", static_cast<double>(val_f));
  }

  this->cooked_cb_(obis_str_buf, val_f, val_s_buf, is_numeric);
}

// ---------------------------------------------------------------------------
// DSL parser (Zero-Allocation Implementation)
// ---------------------------------------------------------------------------

AxdrDescriptorPattern& AxdrParser::register_pattern_dsl_(const char* name, const std::string_view dsl, const int priority) {
  AxdrDescriptorPattern pat{};
  pat.name = name;
  pat.priority = priority;

  // Fill step array with the sentinel value since we don't track step count directly
  std::ranges::fill(pat.steps, AxdrPatternStep{AxdrTokenType::END_OF_PATTERN});
  size_t step_count = 0;

  // Helper lambda to trim string_view bounds instead of creating new substrings
  auto trim = [](const std::string_view s) -> std::string_view {
    const size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string_view::npos) return {};
    const size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
  };

  std::string_view tokens[64];
  size_t tokens_count = 0;
  size_t start = 0;
  int paren = 0;

  // Split the DSL string_view by comma, ignoring commas inside parentheses
  for (size_t i = 0; i < dsl.length(); ++i) {
    if (dsl[i] == '(') { paren++; }
    else if (dsl[i] == ')') { paren--; }
    else if (dsl[i] == ',' && paren == 0) {
      if (tokens_count < 64) tokens[tokens_count++] = trim(dsl.substr(start, i - start));
      start = i + 1;
    }
  }
  if (start < dsl.length() && tokens_count < 64) {
    tokens[tokens_count++] = trim(dsl.substr(start));
  }

  // Safely adds a step sequence tracking step counts directly
  auto add_step = [&](const AxdrTokenType type, const uint8_t param = 0) {
    if (step_count < 32) {
      pat.steps[step_count++] = {type, param};
    }
  };

  auto process_simple_token = [&](const std::string_view tok) {
    if      (tok == "F")  add_step(AxdrTokenType::EXPECT_TO_BE_FIRST);
    else if (tok == "L")  add_step(AxdrTokenType::EXPECT_TO_BE_LAST);
    else if (tok == "C")  add_step(AxdrTokenType::EXPECT_CLASS_ID_UNTAGGED);
    else if (tok == "TC") {
      add_step(AxdrTokenType::EXPECT_TYPE_EXACT, DLMS_DATA_TYPE_UINT16);
      add_step(AxdrTokenType::EXPECT_CLASS_ID_UNTAGGED);
    }
    else if (tok == "O")   add_step(AxdrTokenType::EXPECT_OBIS6_UNTAGGED);
    else if (tok == "TO")  add_step(AxdrTokenType::EXPECT_OBIS6_TAGGED);
    else if (tok == "TOW") add_step(AxdrTokenType::EXPECT_OBIS6_TAGGED_WRONG);
    else if (tok == "A")   add_step(AxdrTokenType::EXPECT_ATTR8_UNTAGGED);
    else if (tok == "TA") {
      add_step(AxdrTokenType::EXPECT_TYPE_U_I_8);
      add_step(AxdrTokenType::EXPECT_ATTR8_UNTAGGED);
    }
    else if (tok == "TS")     add_step(AxdrTokenType::EXPECT_SCALER_TAGGED);
    else if (tok == "TU")     add_step(AxdrTokenType::EXPECT_UNIT_ENUM_TAGGED);
    else if (tok == "V" || tok == "TV") add_step(AxdrTokenType::EXPECT_VALUE_GENERIC);
    else if (tok == "TDTM")   add_step(AxdrTokenType::EXPECT_VALUE_DATE_TIME);
    else if (tok == "TSTR")   add_step(AxdrTokenType::EXPECT_VALUE_OCTET_STRING);
    else if (tok == "TSU") {
      add_step(AxdrTokenType::EXPECT_STRUCTURE_N, 2);
      add_step(AxdrTokenType::GOING_DOWN);
      add_step(AxdrTokenType::EXPECT_SCALER_TAGGED);
      add_step(AxdrTokenType::EXPECT_UNIT_ENUM_TAGGED);
      add_step(AxdrTokenType::GOING_UP);
    }
    else if (tok == "ADV") {
      add_step(AxdrTokenType::EXPECT_TO_BE_FIRST);
      add_step(AxdrTokenType::EXPECT_CLASS_ID_UNTAGGED);
      add_step(AxdrTokenType::EXPECT_OBIS6_UNTAGGED);
      add_step(AxdrTokenType::EXPECT_ATTR8_UNTAGGED);
      add_step(AxdrTokenType::EXPECT_VALUE_GENERIC);
    }
    else if (tok == "DN") add_step(AxdrTokenType::GOING_DOWN);
    else if (tok == "UP") add_step(AxdrTokenType::GOING_UP);
  };

  for (size_t i = 0; i < tokens_count; i++) {
    std::string_view tok = tokens[i];
    if (tok.empty()) continue;

    if (tok.starts_with("S(")) {
      const size_t l = tok.find('(');
      const size_t r = tok.rfind(')');
      if (l != std::string_view::npos && r != std::string_view::npos && r > l + 1) {
        const std::string_view inner = tok.substr(l + 1, r - l - 1);
        std::string_view inner_tokens[16];
        size_t inner_count = 0;
        size_t in_start = 0;

        for (size_t j = 0; j < inner.length(); ++j) {
          if (inner[j] == ',') {
            std::string_view t = trim(inner.substr(in_start, j - in_start));
            if (!t.empty() && inner_count < 16) inner_tokens[inner_count++] = t;
            in_start = j + 1;
          }
        }
        if (in_start < inner.length()) {
          std::string_view t = trim(inner.substr(in_start));
          if (!t.empty() && inner_count < 16) inner_tokens[inner_count++] = t;
        }

        if (inner_count > 0) {
          add_step(AxdrTokenType::EXPECT_STRUCTURE_N, static_cast<uint8_t>(inner_count));
          add_step(AxdrTokenType::GOING_DOWN);
          // Process inner tokens sequentially onto the steps array without shifting future tokens
          for (size_t j = 0; j < inner_count; ++j) {
            process_simple_token(inner_tokens[j]);
          }
          add_step(AxdrTokenType::GOING_UP);
        }
      }
    } else {
      process_simple_token(tok);
    }
  }

  // Find sorted position for insertion into the fixed array patterns_
  size_t insert_pos = 0;
  while (insert_pos < this->patterns_count_ && this->patterns_[insert_pos].priority <= pat.priority) {
    insert_pos++;
  }

  // Shift right and insert, maintaining max array bounds bounds
  if (this->patterns_count_ < MAX_PATTERNS) {
    for (size_t j = this->patterns_count_; j > insert_pos; --j) {
      this->patterns_[j] = this->patterns_[j - 1];
    }
    this->patterns_[insert_pos] = pat;
    this->patterns_count_++;
    return this->patterns_[insert_pos];
  }

  // If full, default to end-overwrite safety, although standard usage expects patterns to fit MAX_PATTERNS
  if (insert_pos < MAX_PATTERNS) {
    for (size_t j = MAX_PATTERNS - 1; j > insert_pos; --j) {
      this->patterns_[j] = this->patterns_[j - 1];
    }
    this->patterns_[insert_pos] = pat;
    return this->patterns_[insert_pos];
  }
  return this->patterns_[MAX_PATTERNS - 1];
}

}  // namespace dlms_parser
