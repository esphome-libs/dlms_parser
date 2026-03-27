#include "axdr_parser.h"
#include "log.h"
#include "utils.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <utility>

namespace dlms_parser {

// ---------------------------------------------------------------------------
// Construction / pattern registry
// ---------------------------------------------------------------------------

AxdrParser::AxdrParser() = default;

void AxdrParser::register_pattern(const std::string& name, const std::string& dsl, int priority) {
  this->register_pattern_dsl_(name, dsl, priority);
}

void AxdrParser::clear_patterns() {
  patterns_.clear();
}

// ---------------------------------------------------------------------------
// Public parse entry point
// ---------------------------------------------------------------------------

size_t AxdrParser::parse(const uint8_t* axdr, size_t len,
                         DlmsDataCallback cooked_cb,
                         DlmsRawCallback raw_cb) {
  if (axdr == nullptr || len == 0) return 0;

  buffer_ = axdr;
  buffer_len_ = len;
  pos_ = 0;
  cooked_cb_ = std::move(cooked_cb);
  raw_cb_ = std::move(raw_cb);
  objects_found_ = 0;
  last_pattern_elements_consumed_ = 0;

  Logger::log(LogLevel::DEBUG, "AxdrParser: parsing %zu bytes", len);

  const uint8_t start_type = this->read_byte_();
  if (start_type != DLMS_DATA_TYPE_STRUCTURE && start_type != DLMS_DATA_TYPE_ARRAY) {
    Logger::log(LogLevel::WARNING, "Expected STRUCTURE (0x02) or ARRAY (0x01), got 0x%02X", start_type);
    return 0;
  }

  if (!this->parse_element_(start_type, 0)) {
    Logger::log(LogLevel::VERBOSE, "Parsing finished with errors or unexpected end of buffer");
  }

  Logger::log(LogLevel::DEBUG, "AxdrParser: done, %zu objects found", objects_found_);
  return objects_found_;
}

// ---------------------------------------------------------------------------
// Buffer primitives
// ---------------------------------------------------------------------------

uint8_t AxdrParser::read_byte_() {
  if (this->pos_ >= this->buffer_len_) return 0xFF;
  return this->buffer_[this->pos_++];
}

uint16_t AxdrParser::read_u16_() {
  if (this->pos_ + 1 >= this->buffer_len_) return 0xFFFF;
  const uint16_t val = be16(&this->buffer_[this->pos_]);
  this->pos_ += 2;
  return val;
}

uint32_t AxdrParser::read_u32_() {
  if (this->pos_ + 3 >= this->buffer_len_) return 0xFFFFFFFF;
  const uint32_t val = be32(&this->buffer_[this->pos_]);
  this->pos_ += 4;
  return val;
}

// ---------------------------------------------------------------------------
// Traversal
// ---------------------------------------------------------------------------

bool AxdrParser::skip_data_(uint8_t type) {
  const int data_size = utils::get_data_type_size(static_cast<DlmsDataType>(type));

  if (data_size == 0) return true;

  if (data_size > 0) {
    if (this->pos_ + static_cast<size_t>(data_size) > this->buffer_len_) return false;
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
        const uint8_t b = this->read_byte_();
        if (b == 0xFF && this->pos_ >= this->buffer_len_) return false;
        length = length << 8 | b;
      }
    }

    uint32_t skip_bytes = length;
    if (type == DLMS_DATA_TYPE_BIT_STRING) {
      skip_bytes = (length + 7) / 8;
    }

    if (this->pos_ + skip_bytes > this->buffer_len_) return false;

    Logger::log(LogLevel::VERY_VERBOSE, "Skipping %s (%u bytes) at pos %zu",
                utils::dlms_data_type_to_string(static_cast<DlmsDataType>(type)), skip_bytes, this->pos_);
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

  Logger::log(LogLevel::DEBUG, "Parsing %s with %d elements at pos %zu (depth %d)",
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

    if (this->pos_ >= this->buffer_len_) {
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
bool AxdrParser::test_if_date_time_12b_(const uint8_t* buf) {
  if (buf) return utils::test_if_date_time_12b(buf);
  if (this->pos_ + 12 > this->buffer_len_) return false;
  return utils::test_if_date_time_12b(&this->buffer_[this->pos_]);
}

bool AxdrParser::capture_generic_value_(AxdrCaptures& c) {
  uint8_t vt = this->read_byte_();
  if (!utils::is_value_data_type(static_cast<DlmsDataType>(vt))) return false;

  const int ds = utils::get_data_type_size(static_cast<DlmsDataType>(vt));
  if (ds > 0) {
    if (this->pos_ + static_cast<size_t>(ds) > this->buffer_len_) return false;
    c.value_ptr = &this->buffer_[this->pos_];
    c.value_len = static_cast<uint8_t>(ds);
    this->pos_ += static_cast<size_t>(ds);
  } else if (ds == 0) {
    c.value_ptr = nullptr;
    c.value_len = 0;
  } else {
    // Variable-length: BER length encoding
    const uint8_t first_byte = this->read_byte_();
    if (first_byte == 0xFF) return false;

    uint32_t length = first_byte;
    if (first_byte > 127) {
      const uint8_t num_bytes = first_byte & 0x7F;
      length = 0;
      for (int i = 0; i < num_bytes; i++) {
        const uint8_t b = this->read_byte_();
        if (b == 0xFF && this->pos_ >= this->buffer_len_) return false;
        length = length << 8 | b;
      }
    }

    uint32_t data_bytes = length;
    if (vt == DLMS_DATA_TYPE_BIT_STRING) {
      data_bytes = (length + 7) / 8;
    }

    if (this->pos_ + data_bytes > this->buffer_len_) return false;
    c.value_ptr = &this->buffer_[this->pos_];
    c.value_len = static_cast<uint8_t>(data_bytes > 255 ? 255 : data_bytes);
    this->pos_ += data_bytes;
  }

  // Auto-detect 12-byte OCTET_STRING as DATETIME
  if (vt == DLMS_DATA_TYPE_OCTET_STRING && c.value_len == 12 &&
      this->test_if_date_time_12b_(c.value_ptr)) {
    vt = DLMS_DATA_TYPE_DATETIME;
  }

  c.value_type = static_cast<DlmsDataType>(vt);
  return true;
}

bool AxdrParser::try_match_patterns_(const uint8_t elem_idx, const uint8_t elem_count) {
  for (const auto& p : this->patterns_) {
    const size_t saved_position = this->pos_;
    if (uint8_t consumed = 0; this->match_pattern_(elem_idx, elem_count, p, consumed)) {
      this->last_pattern_elements_consumed_ = consumed;
      return true;
    }
    this->pos_ = saved_position;
  }
  return false;
}

bool AxdrParser::match_pattern_(const uint8_t elem_idx, const uint8_t elem_count,
                                const AxdrDescriptorPattern& pat,
                                uint8_t& elements_consumed_at_level0) {
  AxdrCaptures cap{};
  elements_consumed_at_level0 = 0;
  uint8_t level = 0;
  auto consume_one = [&] { if (level == 0) elements_consumed_at_level0++; };
  const auto initial_position = static_cast<uint32_t>(this->pos_);

  for (const auto& step : pat.steps) {
    switch (step.type) {
      case AxdrTokenType::EXPECT_TO_BE_FIRST:
        if (elem_idx != 0) return false;
        break;
      case AxdrTokenType::EXPECT_TO_BE_LAST:
        if (elem_count == 0 || elem_idx != elem_count - 1) return false;
        break;
      case AxdrTokenType::EXPECT_TYPE_EXACT:
        if (this->read_byte_() != step.param_u8_a) return false;
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
        if (this->pos_ + 6 > this->buffer_len_) return false;
        cap.obis = &this->buffer_[this->pos_];
        this->pos_ += 6;
        consume_one();
        break;
      case AxdrTokenType::EXPECT_OBIS6_TAGGED_WRONG:
        // Landis+Gyr firmware bug: sends 06 09 <obis> instead of 09 06 <obis>
        if (this->read_byte_() != 6) return false;
        if (this->read_byte_() != DLMS_DATA_TYPE_OCTET_STRING) return false;
        if (this->pos_ + 6 > this->buffer_len_) return false;
        cap.obis = &this->buffer_[this->pos_];
        this->pos_ += 6;
        consume_one();
        break;
      case AxdrTokenType::EXPECT_OBIS6_UNTAGGED:
        if (this->pos_ + 6 > this->buffer_len_) return false;
        cap.obis = &this->buffer_[this->pos_];
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
        if (this->pos_ + 12 > this->buffer_len_) return false;
        cap.value_ptr = &this->buffer_[this->pos_];
        cap.value_len = 12;
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
        if (slen == 0xFF || this->pos_ + slen > this->buffer_len_) return false;
        cap.value_type = static_cast<DlmsDataType>(vt);
        cap.value_ptr = &this->buffer_[this->pos_];
        cap.value_len = slen;
        this->pos_ += slen;
        consume_one();
        break;
      }
      case AxdrTokenType::EXPECT_STRUCTURE_N:
        if (this->read_byte_() != DLMS_DATA_TYPE_STRUCTURE) return false;
        if (this->read_byte_() != step.param_u8_a) return false;
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
    }
  }

  if (elements_consumed_at_level0 == 0) elements_consumed_at_level0 = 1;
  cap.elem_idx = initial_position;
  this->emit_object_(pat, cap);
  return true;
}

static constexpr uint8_t ZERO_OBIS[6] = {0, 0, 0, 0, 0, 0};

void AxdrParser::emit_object_(const AxdrDescriptorPattern& pat, const AxdrCaptures& c) {
  // If no OBIS was captured by the pattern, use 0.0.0.0.0.0 as a placeholder.
  const AxdrCaptures effective = c.obis ? c : [&] { auto copy = c; copy.obis = ZERO_OBIS; return copy; }();

  objects_found_++;

  // Raw callback — delivers original captures (obis may be nullptr)
  if (this->raw_cb_) {
    this->raw_cb_(c, pat);
  }

  if (!this->cooked_cb_) return;

  char obis_str_buf[32];
  utils::obis_to_string(effective.obis, obis_str_buf, sizeof(obis_str_buf));

  const float raw_val_f = utils::data_as_float(effective.value_type, effective.value_ptr, effective.value_len);
  float val_f = raw_val_f;

  char val_s_buf[128];
  utils::data_to_string(effective.value_type, effective.value_ptr, effective.value_len, val_s_buf, sizeof(val_s_buf));

  const bool is_numeric = effective.value_type != DLMS_DATA_TYPE_OCTET_STRING &&
                          effective.value_type != DLMS_DATA_TYPE_STRING &&
                          effective.value_type != DLMS_DATA_TYPE_STRING_UTF8;

  if (effective.has_scaler_unit && is_numeric) {
    val_f *= static_cast<float>(std::pow(10, effective.scaler));
  }

  const uint16_t cid = effective.class_id ? effective.class_id : pat.default_class_id;
  Logger::log(LogLevel::DEBUG, "Pattern '%s' matched at pos %u — class_id=%d obis=%s",
              pat.name.c_str(), effective.elem_idx, cid, obis_str_buf);

  if (effective.has_scaler_unit) {
    Logger::log(LogLevel::INFO, "  type=%s len=%d scaler=%d unit=%d",
                utils::dlms_data_type_to_string(effective.value_type), effective.value_len, effective.scaler, effective.unit_enum);
  } else {
    Logger::log(LogLevel::INFO, "  type=%s len=%d",
                utils::dlms_data_type_to_string(effective.value_type), effective.value_len);
  }

  if (effective.value_ptr && effective.value_len > 0) {
    char hex_buf[512];
    utils::format_hex_pretty_to(hex_buf, sizeof(hex_buf), effective.value_ptr, effective.value_len);
    Logger::log(LogLevel::INFO, "  hex  : %s", hex_buf);
  }
  Logger::log(LogLevel::INFO, "  str  : '%s'", val_s_buf);
  Logger::log(LogLevel::INFO, "  float: %f", static_cast<double>(raw_val_f));
  if (effective.has_scaler_unit && is_numeric) {
    Logger::log(LogLevel::INFO, "  scaled: %f", static_cast<double>(val_f));
  }

  this->cooked_cb_(obis_str_buf, val_f, val_s_buf, is_numeric);
}

// ---------------------------------------------------------------------------
// DSL parser
// ---------------------------------------------------------------------------

void AxdrParser::register_pattern_dsl_(const std::string& name, const std::string& dsl, const int priority) {
  AxdrDescriptorPattern pat{name, priority, {}, 0};

  auto trim = [](const std::string& s) {
    const size_t b = s.find_first_not_of(" \t\r\n");
    const size_t e = s.find_last_not_of(" \t\r\n");
    if (b == std::string::npos) return std::string();
    return s.substr(b, e - b + 1);
  };

  std::vector<std::string> tokens;
  std::string current;
  int paren = 0;
  for (const char ch : dsl) {
    if (ch == '(') { paren++; current.push_back(ch); }
    else if (ch == ')') { paren--; current.push_back(ch); }
    else if (ch == ',' && paren == 0) { tokens.push_back(trim(current)); current.clear(); }
    else { current.push_back(ch); }
  }
  if (!current.empty()) tokens.push_back(trim(current));

  for (size_t i = 0; i < tokens.size(); i++) {
    const std::string& tok = tokens[i];
    if (tok.empty()) continue;

    if      (tok == "F")  pat.steps.push_back({AxdrTokenType::EXPECT_TO_BE_FIRST});
    else if (tok == "L")  pat.steps.push_back({AxdrTokenType::EXPECT_TO_BE_LAST});
    else if (tok == "C")  pat.steps.push_back({AxdrTokenType::EXPECT_CLASS_ID_UNTAGGED});
    else if (tok == "TC") {
      pat.steps.push_back({AxdrTokenType::EXPECT_TYPE_EXACT, DLMS_DATA_TYPE_UINT16});
      pat.steps.push_back({AxdrTokenType::EXPECT_CLASS_ID_UNTAGGED});
    }
    else if (tok == "O")  pat.steps.push_back({AxdrTokenType::EXPECT_OBIS6_UNTAGGED});
    else if (tok == "TO") pat.steps.push_back({AxdrTokenType::EXPECT_OBIS6_TAGGED});
    else if (tok == "TOW") pat.steps.push_back({AxdrTokenType::EXPECT_OBIS6_TAGGED_WRONG});
    else if (tok == "A")  pat.steps.push_back({AxdrTokenType::EXPECT_ATTR8_UNTAGGED});
    else if (tok == "TA") {
      pat.steps.push_back({AxdrTokenType::EXPECT_TYPE_U_I_8});
      pat.steps.push_back({AxdrTokenType::EXPECT_ATTR8_UNTAGGED});
    }
    else if (tok == "TS")     pat.steps.push_back({AxdrTokenType::EXPECT_SCALER_TAGGED});
    else if (tok == "TU")     pat.steps.push_back({AxdrTokenType::EXPECT_UNIT_ENUM_TAGGED});
    else if (tok == "V" || tok == "TV") pat.steps.push_back({AxdrTokenType::EXPECT_VALUE_GENERIC});
    else if (tok == "TDTM") pat.steps.push_back({AxdrTokenType::EXPECT_VALUE_DATE_TIME});
    else if (tok == "TSTR")   pat.steps.push_back({AxdrTokenType::EXPECT_VALUE_OCTET_STRING});
    else if (tok == "TSU") {
      pat.steps.push_back({AxdrTokenType::EXPECT_STRUCTURE_N, 2});
      pat.steps.push_back({AxdrTokenType::GOING_DOWN});
      pat.steps.push_back({AxdrTokenType::EXPECT_SCALER_TAGGED});
      pat.steps.push_back({AxdrTokenType::EXPECT_UNIT_ENUM_TAGGED});
      pat.steps.push_back({AxdrTokenType::GOING_UP});
    }
    else if (tok.size() >= 2 && tok.substr(0, 2) == "S(") {
      const size_t l = tok.find('(');
      if (const size_t r = tok.rfind(')'); l != std::string::npos && r != std::string::npos && r > l + 1) {
        const std::string inner = tok.substr(l + 1, r - l - 1);
        std::vector<std::string> inner_tokens;
        std::string cur;
        for (const char c2 : inner) {
          if (c2 == ',') { inner_tokens.push_back(trim(cur)); cur.clear(); }
          else { cur.push_back(c2); }
        }
        if (!cur.empty()) inner_tokens.push_back(trim(cur));

        if (!inner_tokens.empty()) {
          pat.steps.push_back({AxdrTokenType::EXPECT_STRUCTURE_N, static_cast<uint8_t>(inner_tokens.size())});
          inner_tokens.insert(inner_tokens.begin(), "DN");
          inner_tokens.push_back("UP");
          tokens.insert(tokens.begin() + static_cast<std::ptrdiff_t>(i + 1),
                        inner_tokens.begin(), inner_tokens.end());
        }
      }
    }
    else if (tok == "DN") pat.steps.push_back({AxdrTokenType::GOING_DOWN});
    else if (tok == "UP") pat.steps.push_back({AxdrTokenType::GOING_UP});
  }

  const auto it = std::upper_bound(this->patterns_.begin(), this->patterns_.end(), pat,
                                   [](const AxdrDescriptorPattern& a, const AxdrDescriptorPattern& b) {
                                     return a.priority < b.priority;
                                   });
  this->patterns_.insert(it, pat);
}

}  // namespace dlms_parser
