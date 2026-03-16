#include "parser.h"
#include "utils.h"
#include "log.h"
#include <cmath>
#include <cstring>
#include <cstdio>
#include <algorithm>

namespace dlms {
namespace parser {

static const char *const TAG = "dlms_parser";

DlmsParser::DlmsParser() {
  this->load_default_patterns_();
}

void DlmsParser::load_default_patterns_() {
  this->register_pattern_dsl_("T1", "TC,TO,TS,TV", 10);
  this->register_pattern_dsl_("T2", "TO,TV,TSU", 10);
  this->register_pattern_dsl_("T3", "TV,TC,TSU,TO", 10);
  this->register_pattern_dsl_("U.ZPA", "F,C,O,A,TV", 10);
}

void DlmsParser::register_custom_pattern(const std::string &dsl) {
  this->register_pattern_dsl_("CUSTOM", dsl, 0); // Priority 0 to try this first
}

size_t DlmsParser::parse(const uint8_t *buffer, size_t length, DlmsDataCallback callback, bool show_log) {
  if (buffer == nullptr || length == 0) {
    if (show_log) DLMS_LOGV(TAG, "Buffer is null or empty");
    return 0;
  }

  this->buffer_ = buffer;
  this->buffer_len_ = length;
  this->pos_ = 0;
  this->callback_ = callback;
  this->show_log_ = show_log;
  this->objects_found_ = 0;

  if (this->show_log_) DLMS_LOGD(TAG, "Starting to parse buffer of length %zu", length);

  // Skip to notification flag 0x0F
  while (this->pos_ < this->buffer_len_) {
    if (this->read_byte_() == 0x0F) {
      if (this->show_log_) DLMS_LOGD(TAG, "Found notification flag 0x0F at position %zu", this->pos_ - 1);
      break;
    }
  }

  // Strictly skip Invoke-ID/Priority (5 bytes)
  for (int i = 0; i < 5 && this->pos_ < this->buffer_len_; i++) {
    this->pos_++;
  }

  // Check for datetime object before the data and skip it if present
  if (this->test_if_date_time_12b_()) {
    if (this->show_log_) DLMS_LOGV(TAG, "Skipping datetime object at position %zu", this->pos_);
    this->pos_ += 12;
  }

  // First byte after flag should be the data type (usually Structure or Array)
  uint8_t start_type = this->read_byte_();
  if (start_type != DLMS_DATA_TYPE_STRUCTURE && start_type != DLMS_DATA_TYPE_ARRAY) {
    if (this->show_log_) {
      DLMS_LOGW(TAG, "Expected STRUCTURE or ARRAY after header, found type %02X at position %zu",
               start_type, this->pos_ - 1);
    }
    return 0;
  }

  // Trigger recursive parsing
  bool success = this->parse_element_(start_type, 0);
  if (!success && this->show_log_) {
    DLMS_LOGV(TAG, "Some errors occurred parsing DLMS data, or unexpected end of buffer.");
  }

  if (this->show_log_) {
    DLMS_LOGD(TAG, "Parsing completed. Processed %zu bytes, found %zu objects", this->pos_, this->objects_found_);
  }

  return this->objects_found_;
}

uint8_t DlmsParser::read_byte_() {
  if (this->pos_ >= this->buffer_len_) return 0xFF;
  return this->buffer_[this->pos_++];
}

uint16_t DlmsParser::read_u16_() {
  if (this->pos_ + 1 >= this->buffer_len_) return 0xFFFF;
  uint16_t val = (this->buffer_[this->pos_] << 8) | this->buffer_[this->pos_ + 1];
  this->pos_ += 2;
  return val;
}

uint32_t DlmsParser::read_u32_() {
  if (this->pos_ + 3 >= this->buffer_len_) return 0xFFFFFFFF;
  uint32_t val = (this->buffer_[this->pos_] << 24) | (this->buffer_[this->pos_ + 1] << 16) |
                 (this->buffer_[this->pos_ + 2] << 8) | this->buffer_[this->pos_ + 3];
  this->pos_ += 4;
  return val;
}

bool DlmsParser::test_if_date_time_12b_() {
  if (this->pos_ + 12 > this->buffer_len_) return false;
  const uint8_t *buf = &this->buffer_[this->pos_];

  uint16_t year = (buf[0] << 8) | buf[1];
  if (!(year == 0x0000 || (year >= 1970 && year <= 2100))) return false;
  if (!(buf[2] == 0xFF || (buf[2] >= 1 && buf[2] <= 12))) return false;
  if (!(buf[3] == 0xFF || (buf[3] >= 1 && buf[3] <= 31))) return false;
  if (!(buf[4] == 0xFF || (buf[4] >= 1 && buf[4] <= 7))) return false;
  if (!(buf[5] == 0xFF || buf[5] <= 23)) return false;
  if (!(buf[6] == 0xFF || buf[6] <= 59)) return false;
  if (!(buf[7] == 0xFF || buf[7] <= 59)) return false;

  // Hundredths of second
  uint8_t ms = buf[8];
  if (!(ms == 0xFF || ms <= 99)) return false;

  // Deviation (timezone offset, signed, 2 bytes)
  uint16_t u_dev = (buf[9] << 8) | buf[10];
  int16_t s_dev = (int16_t) u_dev;
  if (!((s_dev == (int16_t) 0x8000 || (s_dev >= -720 && s_dev <= 720)))) return false;

  return true;
}

bool DlmsParser::skip_data_(uint8_t type) {
  int data_size = get_data_type_size_((DlmsDataType)type);

  if (data_size == 0) return true;
  if (data_size > 0) {
    if (this->pos_ + data_size > this->buffer_len_) return false;
    this->pos_ += data_size;
  } else {
    uint8_t first_byte = this->read_byte_();
    if (first_byte == 0xFF) return false;

    uint32_t length = first_byte;
    if (first_byte > 127) {
      uint8_t num_bytes = first_byte & 0x7F;
      length = 0;
      for (int i = 0; i < num_bytes; i++) {
        uint8_t b = this->read_byte_();
        if (b == 0xFF && this->pos_ >= this->buffer_len_) return false;
        length = (length << 8) | b;
      }
    }

    uint32_t skip_bytes = length;
    if (type == DLMS_DATA_TYPE_BIT_STRING) {
      skip_bytes = (length + 7) / 8;
    }

    if (this->pos_ + skip_bytes > this->buffer_len_) return false;

    if (this->show_log_) {
      DLMS_LOGVV(TAG, "Skipping variable data of type %s (bytes: %u) at position %zu",
                dlms_data_type_to_string((DlmsDataType)type), skip_bytes, this->pos_);
    }
    this->pos_ += skip_bytes;
  }
  return true;
}

bool DlmsParser::parse_element_(uint8_t type, uint8_t depth) {
  if (type == DLMS_DATA_TYPE_STRUCTURE || type == DLMS_DATA_TYPE_ARRAY) {
    return this->parse_sequence_(type, depth);
  }
  return this->skip_data_(type);
}

bool DlmsParser::parse_sequence_(uint8_t type, uint8_t depth) {
  uint8_t elements_count = this->read_byte_();
  if (elements_count == 0xFF) {
    if (this->show_log_) DLMS_LOGVV(TAG, "Invalid sequence length at position %zu", this->pos_ - 1);
    return false;
  }

  if (this->show_log_) {
    DLMS_LOGD(TAG, "Parsing %s with %d elements at position %zu (depth %d)",
             type == DLMS_DATA_TYPE_STRUCTURE ? "STRUCTURE" : "ARRAY", elements_count, this->pos_ - 1, depth);
  }

  uint8_t elements_consumed = 0;
  while (elements_consumed < elements_count) {
    size_t original_position = this->pos_;

    if (this->try_match_patterns_(elements_consumed)) {
      elements_consumed += this->last_pattern_elements_consumed_ ? this->last_pattern_elements_consumed_ : 1;
      this->last_pattern_elements_consumed_ = 0;
      continue;
    }

    if (this->pos_ >= this->buffer_len_) {
      if (this->show_log_) {
        DLMS_LOGV(TAG, "Unexpected end while reading element %d of %s", elements_consumed + 1,
                 type == DLMS_DATA_TYPE_STRUCTURE ? "STRUCTURE" : "ARRAY");
      }
      return false;
    }

    uint8_t elem_type = this->read_byte_();
    if (!this->parse_element_(elem_type, depth + 1)) return false;
    elements_consumed++;

    if (this->pos_ == original_position) {
      if (this->show_log_) {
        DLMS_LOGV(TAG, "No progress parsing element %d at position %zu, aborting to avoid infinite loop",
                 elements_consumed, original_position);
      }
      return false;
    }
  }
  return true;
}

bool DlmsParser::capture_generic_value_(AxdrCaptures &c) {
  uint8_t vt = this->read_byte_();
  if (!is_value_data_type((DlmsDataType)vt)) return false;

  int ds = get_data_type_size((DlmsDataType)vt);
  if (ds > 0) {
    if (this->pos_ + ds > this->buffer_len_) return false;
    c.value_ptr = &this->buffer_[this->pos_];
    c.value_len = ds;
    this->pos_ += ds;
  } else if (ds == 0) {
    c.value_ptr = nullptr;
    c.value_len = 0;
  } else {
    uint8_t first_byte = this->read_byte_();
    if (first_byte == 0xFF) return false;

    uint32_t length = first_byte;
    if (first_byte > 127) {
      uint8_t num_bytes = first_byte & 0x7F;
      length = 0;
      for (int i = 0; i < num_bytes; i++) {
        uint8_t b = this->read_byte_();
        if (b == 0xFF && this->pos_ >= this->buffer_len_) return false;
        length = (length << 8) | b;
      }
    }

    uint32_t data_bytes = length;
    if (vt == DLMS_DATA_TYPE_BIT_STRING) {
      data_bytes = (length + 7) / 8;
    }

    if (this->pos_ + data_bytes > this->buffer_len_) return false;
    c.value_ptr = &this->buffer_[this->pos_];
    c.value_len = data_bytes > 255 ? 255 : data_bytes;
    this->pos_ += data_bytes;
  }
  c.value_type = (DlmsDataType)vt;
  return true;
}

bool DlmsParser::try_match_patterns_(uint8_t elem_idx) {
  for (const auto &p : this->patterns_) {
    uint8_t consumed = 0;
    size_t saved_position = this->pos_;
    if (this->match_pattern_(elem_idx, p, consumed)) {
      this->last_pattern_elements_consumed_ = consumed;
      return true;
    }
    this->pos_ = saved_position; // Backtrack
  }
  return false;
}

bool DlmsParser::match_pattern_(uint8_t elem_idx, const AxdrDescriptorPattern &pat,
                                uint8_t &elements_consumed_at_level0) {
  AxdrCaptures cap{};
  elements_consumed_at_level0 = 0;
  uint8_t level = 0;
  auto consume_one = [&]() { if (level == 0) elements_consumed_at_level0++; };
  size_t initial_position = this->pos_;

  for (const auto &step : pat.steps) {
    switch (step.type) {
      case AxdrTokenType::EXPECT_TO_BE_FIRST:
        if (elem_idx != 0) return false;
        break;
      case AxdrTokenType::EXPECT_TYPE_EXACT:
        if (this->read_byte_() != step.param_u8_a) return false;
        consume_one();
        break;
      case AxdrTokenType::EXPECT_TYPE_U_I_8: {
        uint8_t t = this->read_byte_();
        if (t != DLMS_DATA_TYPE_INT8 && t != DLMS_DATA_TYPE_UINT8) return false;
        consume_one();
        break;
      }
      case AxdrTokenType::EXPECT_CLASS_ID_UNTAGGED: {
        uint16_t v = this->read_u16_();
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
      case AxdrTokenType::EXPECT_STRUCTURE_N:
        if (this->read_byte_() != DLMS_DATA_TYPE_STRUCTURE) return false;
        if (this->read_byte_() != step.param_u8_a) return false;
        consume_one();
        break;
      case AxdrTokenType::EXPECT_SCALER_TAGGED:
        if (this->read_byte_() != DLMS_DATA_TYPE_INT8) return false;
        cap.scaler = (int8_t)this->read_byte_();
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
      case AxdrTokenType::GOING_UP: level--; break;
    }
  }

  if (elements_consumed_at_level0 == 0) elements_consumed_at_level0 = 1;
  cap.elem_idx = initial_position;
  this->emit_object_(pat, cap);
  return true;
}

void DlmsParser::emit_object_(const AxdrDescriptorPattern &pat, const AxdrCaptures &c) {
  if (!c.obis || !this->callback_) return;

  char obis_str_buf[32];
  obis_to_string(c.obis, obis_str_buf, sizeof(obis_str_buf));

  float raw_val_f = data_as_float(c.value_type, c.value_ptr, c.value_len);
  float val_f = raw_val_f;

  char val_s_buf[128];
  data_to_string(c.value_type, c.value_ptr, c.value_len, val_s_buf, sizeof(val_s_buf));

  bool is_numeric = (c.value_type != DLMS_DATA_TYPE_OCTET_STRING &&
                     c.value_type != DLMS_DATA_TYPE_STRING &&
                     c.value_type != DLMS_DATA_TYPE_STRING_UTF8);

  if (c.has_scaler_unit && is_numeric) {
    val_f *= std::pow(10, c.scaler);
  }

  if (this->show_log_) {
    DLMS_LOGD(TAG, "Pattern match '%s' at idx %u ===============", pat.name.c_str(), c.elem_idx);
    uint16_t cid = c.class_id ? c.class_id : pat.default_class_id;

    DLMS_LOGI(TAG, "Found attribute descriptor: class_id=%d, obis=%s", cid, obis_str_buf);

    if (c.has_scaler_unit) {
      DLMS_LOGI(TAG, "Value type: %s, len %d, scaler %d, unit %d",
               dlms_data_type_to_string(c.value_type), c.value_len, c.scaler, c.unit_enum);
    } else {
      DLMS_LOGI(TAG, "Value type: %s, len %d", dlms_data_type_to_string(c.value_type), c.value_len);
    }

    if (c.value_ptr && c.value_len > 0) {
      char hex_buf[512];
      format_hex_pretty_to(hex_buf, sizeof(hex_buf), c.value_ptr, c.value_len);
      DLMS_LOGI(TAG, " as hex dump : %s", hex_buf);
    }
    DLMS_LOGI(TAG, " as string   :'%s'", val_s_buf);
    DLMS_LOGI(TAG, " as number   : %f", raw_val_f);

    if (c.has_scaler_unit && is_numeric) {
      DLMS_LOGI(TAG, " as number * scaler  : %f", val_f);
    }
  }

  this->callback_(obis_str_buf, val_f, val_s_buf, is_numeric);
  this->objects_found_++;
}

void DlmsParser::register_pattern_dsl_(const std::string &name, const std::string &dsl, int priority) {
  AxdrDescriptorPattern pat{name, priority, {}, 0};

  auto trim = [](const std::string &s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    size_t e = s.find_last_not_of(" \t\r\n");
    if (b == std::string::npos) return std::string();
    return s.substr(b, e - b + 1);
  };

  std::vector<std::string> tokens;
  std::string current;
  int paren = 0;
  for (char c : dsl) {
    if (c == '(') {
      paren++;
      current.push_back(c);
    } else if (c == ')') {
      paren--;
      current.push_back(c);
    } else if (c == ',' && paren == 0) {
      tokens.push_back(trim(current));
      current.clear();
    } else {
      current.push_back(c);
    }
  }
  if (!current.empty()) tokens.push_back(trim(current));

  for (size_t i = 0; i < tokens.size(); i++) {
    std::string tok = tokens[i];
    if (tok.empty()) continue;

    if (tok == "F") pat.steps.push_back({AxdrTokenType::EXPECT_TO_BE_FIRST});
    else if (tok == "C") pat.steps.push_back({AxdrTokenType::EXPECT_CLASS_ID_UNTAGGED});
    else if (tok == "TC") {
      pat.steps.push_back({AxdrTokenType::EXPECT_TYPE_EXACT, DLMS_DATA_TYPE_UINT16});
      pat.steps.push_back({AxdrTokenType::EXPECT_CLASS_ID_UNTAGGED});
    }
    else if (tok == "O") pat.steps.push_back({AxdrTokenType::EXPECT_OBIS6_UNTAGGED});
    else if (tok == "TO") pat.steps.push_back({AxdrTokenType::EXPECT_OBIS6_TAGGED});
    else if (tok == "A") pat.steps.push_back({AxdrTokenType::EXPECT_ATTR8_UNTAGGED});
    else if (tok == "TA") {
      pat.steps.push_back({AxdrTokenType::EXPECT_TYPE_U_I_8});
      pat.steps.push_back({AxdrTokenType::EXPECT_ATTR8_UNTAGGED});
    }
    else if (tok == "TS") pat.steps.push_back({AxdrTokenType::EXPECT_SCALER_TAGGED});
    else if (tok == "TU") pat.steps.push_back({AxdrTokenType::EXPECT_UNIT_ENUM_TAGGED});
    else if (tok == "TSU") {
      pat.steps.push_back({AxdrTokenType::EXPECT_STRUCTURE_N, 2});
      pat.steps.push_back({AxdrTokenType::GOING_DOWN});
      pat.steps.push_back({AxdrTokenType::EXPECT_SCALER_TAGGED});
      pat.steps.push_back({AxdrTokenType::EXPECT_UNIT_ENUM_TAGGED});
      pat.steps.push_back({AxdrTokenType::GOING_UP});
    }
    else if (tok == "V" || tok == "TV") pat.steps.push_back({AxdrTokenType::EXPECT_VALUE_GENERIC});
    else if (tok.size() >= 2 && tok.substr(0, 2) == "S(") {
      size_t l = tok.find('(');
      size_t r = tok.rfind(')');
      if (l != std::string::npos && r != std::string::npos && r > l + 1) {
        std::string inner = tok.substr(l + 1, r - l - 1);
        std::vector<std::string> inner_tokens;
        std::string cur;
        for (char c2 : inner) {
          if (c2 == ',') {
            inner_tokens.push_back(trim(cur));
            cur.clear();
          } else {
            cur.push_back(c2);
          }
        }
        if (!cur.empty()) inner_tokens.push_back(trim(cur));

        if (!inner_tokens.empty()) {
          pat.steps.push_back({AxdrTokenType::EXPECT_STRUCTURE_N, static_cast<uint8_t>(inner_tokens.size())});
          inner_tokens.insert(inner_tokens.begin(), "DN");
          inner_tokens.push_back("UP");
          tokens.insert(tokens.begin() + i + 1, inner_tokens.begin(), inner_tokens.end());
        }
      }
    }
    else if (tok == "DN") pat.steps.push_back({AxdrTokenType::GOING_DOWN});
    else if (tok == "UP") pat.steps.push_back({AxdrTokenType::GOING_UP});
  }

  auto it = std::upper_bound(this->patterns_.begin(), this->patterns_.end(), pat,
      [](const AxdrDescriptorPattern &a, const AxdrDescriptorPattern &b) { return a.priority < b.priority; });
  this->patterns_.insert(it, pat);
}

}  // namespace parser
}  // namespace dlms