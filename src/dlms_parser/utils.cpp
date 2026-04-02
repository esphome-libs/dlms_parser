#include "utils.h"
#include <algorithm>
#include <cinttypes>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace dlms_parser {

float data_as_float(const DlmsDataType value_type, const std::span<const uint8_t> data) {
  if (data.empty()) return 0.0f;
  const uint8_t* ptr = data.data();
  const auto len = data.size();

  switch (value_type) {
  case DLMS_DATA_TYPE_BOOLEAN:
  case DLMS_DATA_TYPE_ENUM:
  case DLMS_DATA_TYPE_UINT8: return ptr[0];
  case DLMS_DATA_TYPE_INT8: return static_cast<int8_t>(ptr[0]);
  case DLMS_DATA_TYPE_BIT_STRING: return static_cast<float>(ptr[0]);
  case DLMS_DATA_TYPE_UINT16: return len >= 2 ? static_cast<float>(be16(ptr)) : 0.0f;
  case DLMS_DATA_TYPE_INT16: return len >= 2 ? static_cast<float>(static_cast<int16_t>(be16(ptr))) : 0.0f;
  case DLMS_DATA_TYPE_UINT32: return len >= 4 ? static_cast<float>(be32(ptr)) : 0.0f;
  case DLMS_DATA_TYPE_INT32: return len >= 4 ? static_cast<float>(static_cast<int32_t>(be32(ptr))) : 0.0f;
  case DLMS_DATA_TYPE_UINT64: return len >= 8 ? static_cast<float>(be64(ptr)) : 0.0f;
  case DLMS_DATA_TYPE_INT64: return len >= 8 ? static_cast<float>(static_cast<int64_t>(be64(ptr))) : 0.0f;
  case DLMS_DATA_TYPE_FLOAT32: {
    if (len < 4) return 0.0f;
    const uint32_t i32 = be32(ptr);
    float f;
    std::memcpy(&f, &i32, sizeof(float));
    return f;
  }
  case DLMS_DATA_TYPE_FLOAT64: {
    if (len < 8) return 0.0f;
    const uint64_t i64 = be64(ptr);
    double d;
    std::memcpy(&d, &i64, sizeof(double));
    return static_cast<float>(d);
  }
  default: return 0.0f;
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

void datetime_to_string(const std::span<const uint8_t> data, const std::span<char> out) {
  if (!out.empty()) out[0] = '\0';
  if (data.size() < 12 || out.empty()) return;

  const uint16_t year = be16(data.data());
  const uint8_t month = data[2], day = data[3];
  const uint8_t hour = data[5], minute = data[6], second = data[7];
  const uint8_t hundredths = data[8];
  const auto deviation = static_cast<int16_t>(be16(data.data() + 9));

  auto advance = [&](size_t& p, const int n) { if (n > 0 && p + static_cast<size_t>(n) < out.size()) p += static_cast<size_t>(n); };

  size_t pos = 0;
  // Date: YYYY-MM-DD
  if (year != 0x0000 && year != 0xFFFF)
    advance(pos, snprintf(out.data() + pos, out.size() - pos, "%04u", year));
  else
    advance(pos, snprintf(out.data() + pos, out.size() - pos, "????"));
  advance(pos, snprintf(out.data() + pos, out.size() - pos, "-"));
  if (month != 0xFF && month >= 1 && month <= 12)
    advance(pos, snprintf(out.data() + pos, out.size() - pos, "%02u", month));
  else
    advance(pos, snprintf(out.data() + pos, out.size() - pos, "??"));
  advance(pos, snprintf(out.data() + pos, out.size() - pos, "-"));
  if (day != 0xFF && day >= 1 && day <= 31)
    advance(pos, snprintf(out.data() + pos, out.size() - pos, "%02u", day));
  else
    advance(pos, snprintf(out.data() + pos, out.size() - pos, "??"));
  // Time: HH:MM:SS
  advance(pos, snprintf(out.data() + pos, out.size() - pos, " "));
  if (hour != 0xFF && hour <= 23)
    advance(pos, snprintf(out.data() + pos, out.size() - pos, "%02u", hour));
  else
    advance(pos, snprintf(out.data() + pos, out.size() - pos, "??"));
  advance(pos, snprintf(out.data() + pos, out.size() - pos, ":"));
  if (minute != 0xFF && minute <= 59)
    advance(pos, snprintf(out.data() + pos, out.size() - pos, "%02u", minute));
  else
    advance(pos, snprintf(out.data() + pos, out.size() - pos, "??"));
  advance(pos, snprintf(out.data() + pos, out.size() - pos, ":"));
  if (second != 0xFF && second <= 59)
    advance(pos, snprintf(out.data() + pos, out.size() - pos, "%02u", second));
  else
    advance(pos, snprintf(out.data() + pos, out.size() - pos, "??"));
  // Hundredths
  if (hundredths != 0xFF && hundredths <= 99)
    advance(pos, snprintf(out.data() + pos, out.size() - pos, ".%02u", hundredths));
  // Timezone deviation
  if (deviation != static_cast<int16_t>(0x8000)) {
    const int abs_dev = deviation >= 0 ? deviation : -deviation;
    advance(pos, snprintf(out.data() + pos, out.size() - pos, " %c%02d:%02d",
                    deviation >= 0 ? '+' : '-', abs_dev / 60, abs_dev % 60));
  }
}

void data_to_string(const DlmsDataType value_type, const std::span<const uint8_t> data, const std::span<char> out) {
  if (!out.empty()) out[0] = '\0';
  if (data.empty() || out.empty()) return;

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
  case DLMS_DATA_TYPE_OCTET_STRING:
  case DLMS_DATA_TYPE_STRING:
  case DLMS_DATA_TYPE_STRING_UTF8: {
    const size_t copy_len = std::min(data.size(), out.size() - 1);
    std::memcpy(out.data(), data.data(), copy_len);
    out[copy_len] = '\0';
    break;
  }
  case DLMS_DATA_TYPE_DATETIME:
    datetime_to_string(data, out);
    break;
  case DLMS_DATA_TYPE_BIT_STRING:
  case DLMS_DATA_TYPE_BINARY_CODED_DECIMAL:
  case DLMS_DATA_TYPE_DATE:
  case DLMS_DATA_TYPE_TIME:
    hex_of(data, out);
    break;
  case DLMS_DATA_TYPE_BOOLEAN:
  case DLMS_DATA_TYPE_ENUM:
  case DLMS_DATA_TYPE_UINT8:
    snprintf(out.data(), out.size(), "%u", static_cast<unsigned>(data[0]));
    break;
  case DLMS_DATA_TYPE_INT8:
    snprintf(out.data(), out.size(), "%d", static_cast<int>(static_cast<int8_t>(data[0])));
    break;
  case DLMS_DATA_TYPE_UINT16:
    if (data.size() >= 2) snprintf(out.data(), out.size(), "%u", be16(data.data()));
    break;
  case DLMS_DATA_TYPE_INT16:
    if (data.size() >= 2) snprintf(out.data(), out.size(), "%d", static_cast<int16_t>(be16(data.data())));
    break;
  case DLMS_DATA_TYPE_UINT32:
    if (data.size() >= 4) snprintf(out.data(), out.size(), "%" PRIu32, be32(data.data()));
    break;
  case DLMS_DATA_TYPE_INT32:
    if (data.size() >= 4) snprintf(out.data(), out.size(), "%" PRId32, static_cast<int32_t>(be32(data.data())));
    break;
  case DLMS_DATA_TYPE_UINT64:
    if (data.size() >= 8) snprintf(out.data(), out.size(), "%" PRIu64, be64(data.data()));
    break;
  case DLMS_DATA_TYPE_INT64:
    if (data.size() >= 8) snprintf(out.data(), out.size(), "%" PRId64, static_cast<int64_t>(be64(data.data())));
    break;
  case DLMS_DATA_TYPE_FLOAT32:
  case DLMS_DATA_TYPE_FLOAT64: {
    snprintf(out.data(), out.size(), "%f", static_cast<double>(data_as_float(value_type, data)));
    break;
  }
  default:
    break;
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

void obis_to_string(const std::span<const uint8_t> obis, const std::span<char> out) {
  if (!out.empty()) out[0] = '\0';
  if (obis.size() < 6 || out.empty()) return;
  snprintf(out.data(), out.size(), "%u.%u.%u.%u.%u.%u", obis[0], obis[1], obis[2], obis[3], obis[4], obis[5]);
}

const char* dlms_data_type_to_string(const DlmsDataType vt) {
  switch (vt) {
  case DLMS_DATA_TYPE_NONE: return "NONE";
  case DLMS_DATA_TYPE_ARRAY: return "ARRAY";
  case DLMS_DATA_TYPE_STRUCTURE: return "STRUCTURE";
  case DLMS_DATA_TYPE_BOOLEAN: return "BOOLEAN";
  case DLMS_DATA_TYPE_BIT_STRING: return "BIT_STRING";
  case DLMS_DATA_TYPE_INT32: return "INT32";
  case DLMS_DATA_TYPE_UINT32: return "UINT32";
  case DLMS_DATA_TYPE_OCTET_STRING: return "OCTET_STRING";
  case DLMS_DATA_TYPE_STRING: return "STRING";
  case DLMS_DATA_TYPE_STRING_UTF8: return "STRING_UTF8";
  case DLMS_DATA_TYPE_BINARY_CODED_DECIMAL: return "BINARY_CODED_DECIMAL";
  case DLMS_DATA_TYPE_INT8: return "INT8";
  case DLMS_DATA_TYPE_INT16: return "INT16";
  case DLMS_DATA_TYPE_UINT8: return "UINT8";
  case DLMS_DATA_TYPE_UINT16: return "UINT16";
  case DLMS_DATA_TYPE_COMPACT_ARRAY: return "COMPACT_ARRAY";
  case DLMS_DATA_TYPE_INT64: return "INT64";
  case DLMS_DATA_TYPE_UINT64: return "UINT64";
  case DLMS_DATA_TYPE_ENUM: return "ENUM";
  case DLMS_DATA_TYPE_FLOAT32: return "FLOAT32";
  case DLMS_DATA_TYPE_FLOAT64: return "FLOAT64";
  case DLMS_DATA_TYPE_DATETIME: return "DATETIME";
  case DLMS_DATA_TYPE_DATE: return "DATE";
  case DLMS_DATA_TYPE_TIME: return "TIME";
  default: return "UNKNOWN";
  }
}

int get_data_type_size(const DlmsDataType type) {
  switch (type) {
  case DLMS_DATA_TYPE_NONE: return 0;
  case DLMS_DATA_TYPE_BOOLEAN:
  case DLMS_DATA_TYPE_INT8:
  case DLMS_DATA_TYPE_UINT8:
  case DLMS_DATA_TYPE_ENUM: return 1;
  case DLMS_DATA_TYPE_INT16:
  case DLMS_DATA_TYPE_UINT16: return 2;
  case DLMS_DATA_TYPE_INT32:
  case DLMS_DATA_TYPE_UINT32:
  case DLMS_DATA_TYPE_FLOAT32: return 4;
  case DLMS_DATA_TYPE_INT64:
  case DLMS_DATA_TYPE_UINT64:
  case DLMS_DATA_TYPE_FLOAT64: return 8;
  case DLMS_DATA_TYPE_DATETIME: return 12;
  case DLMS_DATA_TYPE_DATE: return 5;
  case DLMS_DATA_TYPE_TIME: return 4;
  default: return -1; // Variable or complex
  }
}

bool is_value_data_type(const DlmsDataType type) {
  switch (type) {
  case DLMS_DATA_TYPE_ARRAY:
  case DLMS_DATA_TYPE_STRUCTURE:
  case DLMS_DATA_TYPE_COMPACT_ARRAY:
    return false;
  case DLMS_DATA_TYPE_NONE:
  case DLMS_DATA_TYPE_BOOLEAN:
  case DLMS_DATA_TYPE_BIT_STRING:
  case DLMS_DATA_TYPE_INT32:
  case DLMS_DATA_TYPE_UINT32:
  case DLMS_DATA_TYPE_OCTET_STRING:
  case DLMS_DATA_TYPE_STRING:
  case DLMS_DATA_TYPE_BINARY_CODED_DECIMAL:
  case DLMS_DATA_TYPE_STRING_UTF8:
  case DLMS_DATA_TYPE_INT8:
  case DLMS_DATA_TYPE_INT16:
  case DLMS_DATA_TYPE_UINT8:
  case DLMS_DATA_TYPE_UINT16:
  case DLMS_DATA_TYPE_INT64:
  case DLMS_DATA_TYPE_UINT64:
  case DLMS_DATA_TYPE_ENUM:
  case DLMS_DATA_TYPE_FLOAT32:
  case DLMS_DATA_TYPE_FLOAT64:
  case DLMS_DATA_TYPE_DATETIME:
  case DLMS_DATA_TYPE_DATE:
  case DLMS_DATA_TYPE_TIME:
    return true;
  default:
    return false;
  }
}

void format_hex_pretty_to(const std::span<char> out, const std::span<const uint8_t> data) {
  if (out.empty()) return;
  out[0] = '\0';
  size_t pos = 0;
  for (size_t i = 0; i < data.size() && pos + 3 < out.size(); i++) {
    const int written = snprintf(out.data() + pos, out.size() - pos, "%02X.", data[i]);
    if (written > 0) pos += static_cast<size_t>(written);
  }
  if (pos > 0 && out[pos - 1] == '.') out[pos - 1] = '\0';
}

}
