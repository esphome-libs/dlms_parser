#include "utils.h"
#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstring>

namespace dlms_parser {

const char* to_string(const DlmsDataType vt) {
  switch (vt) {
  case DlmsDataType::NONE: return "NONE";
  case DlmsDataType::ARRAY: return "ARRAY";
  case DlmsDataType::STRUCTURE: return "STRUCTURE";
  case DlmsDataType::BOOLEAN: return "BOOLEAN";
  case DlmsDataType::BIT_STRING: return "BIT_STRING";
  case DlmsDataType::INT32: return "INT32";
  case DlmsDataType::UINT32: return "UINT32";
  case DlmsDataType::OCTET_STRING: return "OCTET_STRING";
  case DlmsDataType::STRING: return "STRING";
  case DlmsDataType::STRING_UTF8: return "STRING_UTF8";
  case DlmsDataType::BINARY_CODED_DECIMAL: return "BINARY_CODED_DECIMAL";
  case DlmsDataType::INT8: return "INT8";
  case DlmsDataType::INT16: return "INT16";
  case DlmsDataType::UINT8: return "UINT8";
  case DlmsDataType::UINT16: return "UINT16";
  case DlmsDataType::COMPACT_ARRAY: return "COMPACT_ARRAY";
  case DlmsDataType::INT64: return "INT64";
  case DlmsDataType::UINT64: return "UINT64";
  case DlmsDataType::ENUM: return "ENUM";
  case DlmsDataType::FLOAT32: return "FLOAT32";
  case DlmsDataType::FLOAT64: return "FLOAT64";
  case DlmsDataType::DATETIME: return "DATETIME";
  case DlmsDataType::DATE: return "DATE";
  case DlmsDataType::TIME: return "TIME";
  default: return "UNKNOWN";
  }
}

bool test_if_date_time_12b(const std::span<const uint8_t> p) {
  if (p.size() < 12) return false;

  const auto year = be16(p.data());
  if (year != 0x0000 && year != 0xFFFF && (year < 1970 || year > 2100)) return false;

  const uint8_t month = p[2];
  if (month != 0xFF && (month < 1 || month > 12)) return false;

  const uint8_t day = p[3];
  if (day != 0xFF && (day < 1 || day > 31)) return false;

  const uint8_t dow = p[4];
  if (dow != 0xFF && (dow < 1 || dow > 7)) return false;

  const uint8_t hour = p[5];
  if (hour != 0xFF && hour > 23) return false;

  const uint8_t minute = p[6];
  if (minute != 0xFF && minute > 59) return false;

  const uint8_t second = p[7];
  if (second != 0xFF && second > 59) return false;

  const uint8_t hundredths = p[8];
  if (hundredths != 0xFF && hundredths > 99) return false;

  const auto s_dev = static_cast<int16_t>(be16(p.data() + 9));
  if (s_dev != static_cast<int16_t>(0x8000) && (s_dev < -720 || s_dev > 720)) return false;

  return true;
}

void datetime_to_string(const std::span<const uint8_t> data, const std::span<char> buffer) {
  if (!buffer.empty()) buffer[0] = '\0';
  if (data.size() < 12 || buffer.empty()) return;

  const uint16_t year = be16(data.data());
  const uint8_t month = data[2], day = data[3];
  const uint8_t hour = data[5], minute = data[6], second = data[7];
  const uint8_t hundredths = data[8];
  const auto deviation = static_cast<int16_t>(be16(data.data() + 9));

  auto advance = [&](size_t& p, const int n) { if (n > 0 && p + static_cast<size_t>(n) < buffer.size()) p += static_cast<size_t>(n); };

  size_t pos = 0;
  // Date: YYYY-MM-DD
  if (year != 0x0000 && year != 0xFFFF)
    advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, "%04u", year));
  else
    advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, "????"));
  advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, "-"));
  if (month != 0xFF && month >= 1 && month <= 12)
    advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, "%02u", month));
  else
    advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, "??"));
  advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, "-"));
  if (day != 0xFF && day >= 1 && day <= 31)
    advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, "%02u", day));
  else
    advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, "??"));
  // Time: HH:MM:SS
  advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, " "));
  if (hour != 0xFF && hour <= 23)
    advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, "%02u", hour));
  else
    advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, "??"));
  advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, ":"));
  if (minute != 0xFF && minute <= 59)
    advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, "%02u", minute));
  else
    advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, "??"));
  advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, ":"));
  if (second != 0xFF && second <= 59)
    advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, "%02u", second));
  else
    advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, "??"));
  // Hundredths
  if (hundredths != 0xFF && hundredths <= 99)
    advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, ".%02u", hundredths));
  // Timezone deviation
  if (deviation != static_cast<int16_t>(0x8000)) {
    const int abs_dev = deviation >= 0 ? deviation : -deviation;
    advance(pos, snprintf(buffer.data() + pos, buffer.size() - pos, " %c%02d:%02d",
                    deviation >= 0 ? '+' : '-', abs_dev / 60, abs_dev % 60));
  }
}

uint32_t read_ber_length(const std::span<const uint8_t> buf, size_t& pos) {
  if (pos >= buf.size()) return 0;
  const uint8_t first = buf[pos++];
  if (first <= 0x7F) return first;
  const uint8_t num_bytes = first & 0x7F;
  if (num_bytes == 0 || num_bytes > 4) return 0;
  uint32_t length = 0;
  for (uint8_t i = 0; i < num_bytes; i++) {
    if (pos >= buf.size()) return 0;
    length = length << 8 | buf[pos++];
  }
  return length;
}

int get_data_type_size(const DlmsDataType type) {
  switch (type) {
  case DlmsDataType::NONE: return 0;
  case DlmsDataType::BOOLEAN:
  case DlmsDataType::INT8:
  case DlmsDataType::UINT8:
  case DlmsDataType::ENUM: return 1;
  case DlmsDataType::INT16:
  case DlmsDataType::UINT16: return 2;
  case DlmsDataType::INT32:
  case DlmsDataType::UINT32:
  case DlmsDataType::FLOAT32: return 4;
  case DlmsDataType::INT64:
  case DlmsDataType::UINT64:
  case DlmsDataType::FLOAT64: return 8;
  case DlmsDataType::DATETIME: return 12;
  case DlmsDataType::DATE: return 5;
  case DlmsDataType::TIME: return 4;
  default: return -1; // Variable or complex
  }
}

bool is_value_data_type(const DlmsDataType type) {
  switch (type) {
  case DlmsDataType::ARRAY:
  case DlmsDataType::STRUCTURE:
  case DlmsDataType:: COMPACT_ARRAY:
    return false;
  case DlmsDataType::NONE:
  case DlmsDataType::BOOLEAN:
  case DlmsDataType::BIT_STRING:
  case DlmsDataType::INT32:
  case DlmsDataType::UINT32:
  case DlmsDataType::OCTET_STRING:
  case DlmsDataType::STRING:
  case DlmsDataType::BINARY_CODED_DECIMAL:
  case DlmsDataType::STRING_UTF8:
  case DlmsDataType::INT8:
  case DlmsDataType::INT16:
  case DlmsDataType::UINT8:
  case DlmsDataType::UINT16:
  case DlmsDataType::INT64:
  case DlmsDataType::UINT64:
  case DlmsDataType::ENUM:
  case DlmsDataType::FLOAT32:
  case DlmsDataType::FLOAT64:
  case DlmsDataType::DATETIME:
  case DlmsDataType::DATE:
  case DlmsDataType::TIME:
    return true;
  default:
    return false;
  }
}

}
