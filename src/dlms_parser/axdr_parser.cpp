#include "axdr_parser.h"
#include "utils.h"
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <utility>

namespace dlms_parser {

std::string_view AxdrCapture::obis_as_string(std::span<char, 32> buffer) const {
  const auto len = snprintf(buffer.data(), buffer.size(), "%u.%u.%u.%u.%u.%u", obis[0], obis[1], obis[2], obis[3], obis[4], obis[5]);
  return { buffer.data(), len > 0 ? static_cast<size_t>(len) : 0 };
}

bool AxdrCapture::is_numeric() const {
  switch (value_type) {
    case DlmsDataType::OCTET_STRING:
    case DlmsDataType::STRING:
    case DlmsDataType::STRING_UTF8:
    case DlmsDataType::DATETIME:
      return false;
    default:
      return true;
  }
}

std::string_view AxdrCapture::value_as_string(std::span<char, 128> buffer) const {
  if (value.empty()) return {};

  auto hex_of = [](const std::span<const uint8_t> input, const std::span<char> output) {
    if (output.empty()) return;
    output[0] = '\0';
    size_t pos = 0;
    for (size_t i = 0; i < input.size() && pos + 2 < output.size(); i++) {
      const int written = snprintf(output.data() + pos, output.size() - pos, "%02x", input[i]);
      if (written > 0) pos += static_cast<size_t>(written);
    }
  };

  switch (value_type) {
  case DlmsDataType::OCTET_STRING:
  case DlmsDataType::STRING:
  case DlmsDataType::STRING_UTF8: {
    const size_t copy_len = std::min(value.size(), buffer.size() - 1);
    std::memcpy(buffer.data(), value.data(), copy_len);
    buffer[copy_len] = '\0';
    break;
  }
  case DlmsDataType::DATETIME:
    datetime_to_string(value, buffer);
    break;
  case DlmsDataType::BIT_STRING:
  case DlmsDataType::BINARY_CODED_DECIMAL:
  case DlmsDataType::DATE:
  case DlmsDataType::TIME:
    hex_of(value, buffer);
    break;
  case DlmsDataType::BOOLEAN:
  case DlmsDataType::ENUM:
  case DlmsDataType::UINT8:
    snprintf(buffer.data(), buffer.size(), "%u", static_cast<unsigned>(value[0]));
    break;
  case DlmsDataType::INT8:
    snprintf(buffer.data(), buffer.size(), "%d", static_cast<int>(static_cast<int8_t>(value[0])));
    break;
  case DlmsDataType::UINT16:
    if (value.size() >= 2) snprintf(buffer.data(), buffer.size(), "%u", be16(value.data()));
    break;
  case DlmsDataType::INT16:
    if (value.size() >= 2) snprintf(buffer.data(), buffer.size(), "%d", static_cast<int16_t>(be16(value.data())));
    break;
  case DlmsDataType::UINT32:
    if (value.size() >= 4) snprintf(buffer.data(), buffer.size(), "%" PRIu32, be32(value.data()));
    break;
  case DlmsDataType::INT32:
    if (value.size() >= 4) snprintf(buffer.data(), buffer.size(), "%" PRId32, static_cast<int32_t>(be32(value.data())));
    break;
  case DlmsDataType::UINT64:
    if (value.size() >= 8) snprintf(buffer.data(), buffer.size(), "%" PRIu64, be64(value.data()));
    break;
  case DlmsDataType::INT64:
    if (value.size() >= 8) snprintf(buffer.data(), buffer.size(), "%" PRId64, static_cast<int64_t>(be64(value.data())));
    break;
  case DlmsDataType::FLOAT32:
  case DlmsDataType::FLOAT64: {
    snprintf(buffer.data(), buffer.size(), "%f", static_cast<double>(value_as_float_with_scaler_applied()));
    break;
  }
  default:
    break;
  }

  return { buffer.data(), std::strlen(buffer.data()) };
}

float AxdrCapture::value_as_float_with_scaler_applied() const {
  return apply_scaler(value_as_float(), scaler);
}

float AxdrCapture::value_as_float() const
{
  if (value.empty()) return 0.0f;
  const uint8_t* ptr = value.data();
  const auto len = value.size();

  switch (value_type) {
  case DlmsDataType::BOOLEAN:
  case DlmsDataType::ENUM:
  case DlmsDataType::UINT8: return ptr[0];
  case DlmsDataType::INT8: return static_cast<int8_t>(ptr[0]);
  case DlmsDataType::BIT_STRING: return ptr[0];
  case DlmsDataType::UINT16: return len >= 2 ? static_cast<float>(be16(ptr)) : 0.0f;
  case DlmsDataType::INT16: return len >= 2 ? static_cast<float>(static_cast<int16_t>(be16(ptr))) : 0.0f;
  case DlmsDataType::UINT32: return len >= 4 ? static_cast<float>(be32(ptr)) : 0.0f;
  case DlmsDataType::INT32: return len >= 4 ? static_cast<float>(static_cast<int32_t>(be32(ptr))) : 0.0f;
  case DlmsDataType::UINT64: return len >= 8 ? static_cast<float>(be64(ptr)) : 0.0f;
  case DlmsDataType::INT64: return len >= 8 ? static_cast<float>(static_cast<int64_t>(be64(ptr))) : 0.0f;
  case DlmsDataType::FLOAT32: {
    if (len < 4) return 0.0f;
    const uint32_t i32 = be32(ptr);
    float f;
    std::memcpy(&f, &i32, sizeof(float));
    return f;
  }
  case DlmsDataType::FLOAT64: {
    if (len < 8) return 0.0f;
    const uint64_t i64 = be64(ptr);
    double d;
    std::memcpy(&d, &i64, sizeof(double));
    return static_cast<float>(d);
  }
  default: return 0.0f;
  }
}

float AxdrCapture::apply_scaler(const float value, const int8_t scaler) {
  if (scaler == 0) return value;

  // Lookup table for 10^0 through 10^9
  static constexpr float pow10_lut[] = {
    1e0f, 1e1f, 1e2f, 1e3f, 1e4f, 1e5f, 1e6f, 1e7f, 1e8f, 1e9f
  };

  // Fast path: use LUT for typical DLMS bounds (-9 to +9)
  if (scaler > 0 && scaler <= 9) { return value * pow10_lut[scaler]; }
  if (scaler < 0 && scaler >= -9) { return value / pow10_lut[-scaler]; }

  // Fallback path: loop for unusually large scalers
  float multiplier = 1.0f;
  if (scaler > 0) {
    for (int i = 0; i < scaler; ++i) multiplier *= 10.0f;
    return value * multiplier;
  }

  for (int i = 0; i < -scaler; ++i) multiplier *= 10.0f;
  return value / multiplier;
}

// ---------------------------------------------------------------------------
// Construction / pattern registry
// ---------------------------------------------------------------------------

AxdrParser::AxdrParser(DlmsDataCallback dlmsDataCallback) : dlmsDataCallback_(std::move(dlmsDataCallback))
{}

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

ParseResult AxdrParser::parse(const std::span<const uint8_t> axdr) {
  if (axdr.empty()) return {};

  buffer_ = axdr;
  pos_ = 0;
  objects_found_ = 0;
  last_pattern_elements_consumed_ = 0;

  Logger::log(LogLevel::DEBUG, "AxdrParser: parsing %zu bytes", axdr.size());

  while (this->pos_ < this->buffer_.size()) {
    const auto type = static_cast<DlmsDataType>(this->read_byte_());
    if (type != DlmsDataType::STRUCTURE && type != DlmsDataType::ARRAY) {
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

bool AxdrParser::skip_data_(DlmsDataType type) {
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
    if (type == DlmsDataType::BIT_STRING) {
      skip_bytes = (length + 7) / 8;
    }

    if (this->pos_ + skip_bytes > this->buffer_.size()) return false;

    Logger::log(LogLevel::VERY_VERBOSE, "Skipping %s (%u bytes) at pos %zu", to_string(type), skip_bytes, this->pos_);
    this->pos_ += skip_bytes;
  }
  return true;
}

bool AxdrParser::parse_element_(const DlmsDataType type, const uint8_t depth) {
  if (type == DlmsDataType::STRUCTURE || type == DlmsDataType::ARRAY) {
    return this->parse_sequence_(type, depth);
  }
  return this->skip_data_(type);
}

bool AxdrParser::parse_sequence_(const DlmsDataType type, const uint8_t depth) {
  const uint8_t elements_count = this->read_byte_();
  if (elements_count == 0xFF) {
    Logger::log(LogLevel::VERY_VERBOSE, "Invalid sequence length at pos %zu", this->pos_ - 1);
    return false;
  }

  Logger::log(LogLevel::VERBOSE, "Parsing %s with %d elements at pos %zu (depth %d)",
              type == DlmsDataType::STRUCTURE ? "STRUCTURE" : "ARRAY",
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
      Logger::log(LogLevel::WARNING, "Unexpected end while reading element %d of %s",
                  elements_consumed + 1, type == DlmsDataType::STRUCTURE ? "STRUCTURE" : "ARRAY");
      return false;
    }

    const auto elem_type = static_cast<DlmsDataType>(this->read_byte_());
    if (!this->parse_element_(elem_type, depth + 1)) return false;
    elements_consumed++;

    if (this->pos_ == original_position) {
      Logger::log(LogLevel::WARNING, "No progress at pos %zu, aborting to avoid infinite loop",
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

bool AxdrParser::capture_generic_value_(AxdrCapture& c) {
  DlmsDataType vt = static_cast<DlmsDataType>(this->read_byte_());
  if (!is_value_data_type(vt)) return false;

  const auto ds = get_data_type_size(vt);
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
    if (vt == DlmsDataType::BIT_STRING) {
      data_bytes = (length + 7) / 8;
    }

    if (this->pos_ + data_bytes > this->buffer_.size()) return false;
    c.value = this->buffer_.subspan(this->pos_, data_bytes);
    this->pos_ += data_bytes;
  }

  // Auto-detect 12-byte OCTET_STRING as DATETIME
  if (vt == DlmsDataType::OCTET_STRING && c.value.size() == 12 &&
      this->test_if_date_time_12b_(c.value)) {
    vt = DlmsDataType::DATETIME;
  }

  c.value_type = vt;
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
  AxdrCapture cap{};
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
        const auto t = static_cast<DlmsDataType>(this->read_byte_());
        if (t != DlmsDataType::INT8 && t != DlmsDataType::UINT8) return false;
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
        if (this->read_byte_() != static_cast<uint8_t>(DlmsDataType::OCTET_STRING)) return false;
        if (this->read_byte_() != 6) return false;
        if (this->pos_ + 6 > this->buffer_.size()) return false;
        cap.obis = this->buffer_.subspan(this->pos_, 6);
        this->pos_ += 6;
        consume_one();
        break;
      case AxdrTokenType::EXPECT_OBIS6_TAGGED_WRONG:
        // Landis+Gyr firmware bug: sends 06 09 <obis> instead of 09 06 <obis>
        if (this->read_byte_() != 6) return false;
        if (this->read_byte_() != static_cast<uint8_t>(DlmsDataType::OCTET_STRING)) return false;
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
        const auto tag = static_cast<DlmsDataType>(this->read_byte_());
        if (tag == DlmsDataType::DATETIME) {
          // Native DATETIME tag (0x19): fixed 12-byte payload, no length byte
        } else if (tag == DlmsDataType::OCTET_STRING) {
          if (this->read_byte_() != 12) return false;
        } else {
          return false;
        }
        if (this->pos_ + 12 > this->buffer_.size()) return false;
        cap.value = this->buffer_.subspan(this->pos_, 12);
        cap.value_type = DlmsDataType::DATETIME;
        this->pos_ += 12;
        consume_one();
        break;
      }
      case AxdrTokenType::EXPECT_VALUE_OCTET_STRING: {
        const auto vt = static_cast<DlmsDataType>(this->read_byte_());
        if (vt != DlmsDataType::OCTET_STRING && vt != DlmsDataType::STRING &&
            vt != DlmsDataType::STRING_UTF8) return false;
        const uint8_t slen = this->read_byte_();
        if (slen == 0xFF || this->pos_ + slen > this->buffer_.size()) return false;
        cap.value_type = vt;
        cap.value = this->buffer_.subspan(this->pos_, slen);
        this->pos_ += slen;
        consume_one();
        break;
      }
      case AxdrTokenType::EXPECT_STRUCTURE_N:
        if (this->read_byte_() != static_cast<uint8_t>(DlmsDataType::STRUCTURE)) return false;
        if (this->read_byte_() != param_u8_a) return false;
        consume_one();
        break;
      case AxdrTokenType::EXPECT_SCALER_TAGGED:
        if (this->read_byte_() != static_cast<uint8_t>(DlmsDataType::INT8)) return false;
        cap.scaler = static_cast<int8_t>(this->read_byte_());
        cap.has_scaler_unit = true;
        consume_one();
        break;
      case AxdrTokenType::EXPECT_UNIT_ENUM_TAGGED:
        if (this->read_byte_() != static_cast<uint8_t>(DlmsDataType::ENUM)) return false;
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
  objects_found_++;

  if (cap.obis.empty()) {
    // If no OBIS was captured by the pattern, use 0.0.0.0.0.0 as a placeholder.
    // If no OBIS captured, use pattern's default_obis if set, otherwise zero placeholder.
    static constexpr std::array<uint8_t, 6> ZERO_OBIS = { 0, 0, 0, 0, 0, 0 };
    cap.obis = pat.has_default_obis ? std::span<const uint8_t>(pat.default_obis) : ZERO_OBIS;
  }

  Logger::log(LogLevel::VERBOSE, "Pattern '%s' matched at pos %u - class_id=%d", pat.name ? pat.name : "UNKNOWN", cap.elem_idx, cap.class_id ? cap.class_id : pat.default_class_id);
  Logger::log(LogLevel::VERBOSE, "  type=%s len=%zu scaler=%d unit=%d", to_string(cap.value_type), cap.value.size(), cap.scaler, cap.unit_enum);

  dlmsDataCallback_(cap);

  return true;
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
      add_step(AxdrTokenType::EXPECT_TYPE_EXACT, static_cast<uint8_t>(DlmsDataType::UINT16));
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
