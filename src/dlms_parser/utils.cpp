#include "utils.h"
#include <algorithm>
#include <cinttypes>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace dlms_parser {

float data_as_float(const DlmsDataType value_type, const uint8_t* ptr, const uint8_t len) {
  if (!ptr || len == 0) return 0.0f;

  switch (value_type) {
  case DLMS_DATA_TYPE_BOOLEAN:
  case DLMS_DATA_TYPE_ENUM:
  case DLMS_DATA_TYPE_UINT8: return ptr[0];
  case DLMS_DATA_TYPE_INT8: return static_cast<int8_t>(ptr[0]);
  case DLMS_DATA_TYPE_BIT_STRING: return len > 0 ? static_cast<float>(ptr[0]) : 0.0f;
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

void datetime_to_string(const uint8_t* ptr, const uint8_t len, char* buffer, const size_t max_len) {
  if (max_len > 0) buffer[0] = '\0';
  if (!ptr || len < 12 || max_len == 0) return;

  const uint16_t year = be16(ptr);
  const uint8_t month = ptr[2], day = ptr[3];
  const uint8_t hour = ptr[5], minute = ptr[6], second = ptr[7];
  const uint8_t hundredths = ptr[8];
  const auto deviation = static_cast<int16_t>(be16(ptr + 9));

  auto advance = [&](size_t& p, int n) { if (n > 0) p += static_cast<size_t>(n); };

  size_t pos = 0;
  // Date: YYYY-MM-DD
  if (year != 0x0000 && year != 0xFFFF)
    advance(pos, snprintf(buffer + pos, max_len - pos, "%04u", year));
  else
    advance(pos, snprintf(buffer + pos, max_len - pos, "????"));
  advance(pos, snprintf(buffer + pos, max_len - pos, "-"));
  if (month != 0xFF && month >= 1 && month <= 12)
    advance(pos, snprintf(buffer + pos, max_len - pos, "%02u", month));
  else
    advance(pos, snprintf(buffer + pos, max_len - pos, "??"));
  advance(pos, snprintf(buffer + pos, max_len - pos, "-"));
  if (day != 0xFF && day >= 1 && day <= 31)
    advance(pos, snprintf(buffer + pos, max_len - pos, "%02u", day));
  else
    advance(pos, snprintf(buffer + pos, max_len - pos, "??"));
  // Time: HH:MM:SS
  advance(pos, snprintf(buffer + pos, max_len - pos, " "));
  if (hour != 0xFF && hour <= 23)
    advance(pos, snprintf(buffer + pos, max_len - pos, "%02u", hour));
  else
    advance(pos, snprintf(buffer + pos, max_len - pos, "??"));
  advance(pos, snprintf(buffer + pos, max_len - pos, ":"));
  if (minute != 0xFF && minute <= 59)
    advance(pos, snprintf(buffer + pos, max_len - pos, "%02u", minute));
  else
    advance(pos, snprintf(buffer + pos, max_len - pos, "??"));
  advance(pos, snprintf(buffer + pos, max_len - pos, ":"));
  if (second != 0xFF && second <= 59)
    advance(pos, snprintf(buffer + pos, max_len - pos, "%02u", second));
  else
    advance(pos, snprintf(buffer + pos, max_len - pos, "??"));
  // Hundredths
  if (hundredths != 0xFF && hundredths <= 99)
    advance(pos, snprintf(buffer + pos, max_len - pos, ".%02u", hundredths));
  // Timezone deviation
  if (deviation != static_cast<int16_t>(0x8000)) {
    const int abs_dev = deviation >= 0 ? deviation : -deviation;
    advance(pos, snprintf(buffer + pos, max_len - pos, " %c%02d:%02d",
                    deviation >= 0 ? '+' : '-', abs_dev / 60, abs_dev % 60));
  }
}

void data_to_string(const DlmsDataType value_type, const uint8_t* ptr, const uint8_t len, char* buffer,
                    const size_t max_len) {
  if (max_len > 0) buffer[0] = '\0';
  if (!ptr || len == 0 || max_len == 0) return;

  auto hex_of = [](const uint8_t* p, const uint8_t l, char* out, const size_t max_out) {
    if (max_out == 0) return;
    out[0] = '\0';
    size_t pos = 0;
    for (uint8_t i = 0; i < l && pos + 2 < max_out; i++) {
      const int written = snprintf(out + pos, max_out - pos, "%02x", p[i]);
      if (written > 0) pos += static_cast<size_t>(written);
    }
  };

  switch (value_type) {
  case DLMS_DATA_TYPE_OCTET_STRING:
  case DLMS_DATA_TYPE_STRING:
  case DLMS_DATA_TYPE_STRING_UTF8: {
    const size_t copy_len = std::min(static_cast<size_t>(len), max_len - 1);
    std::memcpy(buffer, ptr, copy_len);
    buffer[copy_len] = '\0';
    break;
  }
  case DLMS_DATA_TYPE_DATETIME:
    datetime_to_string(ptr, len, buffer, max_len);
    break;
  case DLMS_DATA_TYPE_BIT_STRING:
  case DLMS_DATA_TYPE_BINARY_CODED_DESIMAL:
  case DLMS_DATA_TYPE_DATE:
  case DLMS_DATA_TYPE_TIME:
    hex_of(ptr, len, buffer, max_len);
    break;
  case DLMS_DATA_TYPE_BOOLEAN:
  case DLMS_DATA_TYPE_ENUM:
  case DLMS_DATA_TYPE_UINT8:
    snprintf(buffer, max_len, "%u", static_cast<unsigned>(ptr[0]));
    break;
  case DLMS_DATA_TYPE_INT8:
    snprintf(buffer, max_len, "%d", static_cast<int>(static_cast<int8_t>(ptr[0])));
    break;
  case DLMS_DATA_TYPE_UINT16:
    if (len >= 2) snprintf(buffer, max_len, "%u", be16(ptr));
    break;
  case DLMS_DATA_TYPE_INT16:
    if (len >= 2) snprintf(buffer, max_len, "%d", static_cast<int16_t>(be16(ptr)));
    break;
  case DLMS_DATA_TYPE_UINT32:
    if (len >= 4) snprintf(buffer, max_len, "%" PRIu32, be32(ptr));
    break;
  case DLMS_DATA_TYPE_INT32:
    if (len >= 4) snprintf(buffer, max_len, "%" PRId32, static_cast<int32_t>(be32(ptr)));
    break;
  case DLMS_DATA_TYPE_UINT64:
    if (len >= 8) snprintf(buffer, max_len, "%" PRIu64, be64(ptr));
    break;
  case DLMS_DATA_TYPE_INT64:
    if (len >= 8) snprintf(buffer, max_len, "%" PRId64, static_cast<int64_t>(be64(ptr)));
    break;
  case DLMS_DATA_TYPE_FLOAT32:
  case DLMS_DATA_TYPE_FLOAT64: {
    snprintf(buffer, max_len, "%f", static_cast<double>(data_as_float(value_type, ptr, len)));
    break;
  }
  default:
    break;
  }
}

void obis_to_string(const uint8_t* obis, char* buffer, const size_t max_len) {
  if (max_len > 0) buffer[0] = '\0';
  if (!obis || max_len == 0) return;
  snprintf(buffer, max_len, "%u.%u.%u.%u.%u.%u", obis[0], obis[1], obis[2], obis[3], obis[4], obis[5]);
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
  case DLMS_DATA_TYPE_BINARY_CODED_DESIMAL: return "BINARY_CODED_DESIMAL";
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
  case DLMS_DATA_TYPE_BINARY_CODED_DESIMAL:
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

void format_hex_pretty_to(char* out, const size_t max_out, const uint8_t* data, const size_t length) {
  if (max_out == 0) return;
  out[0] = '\0';
  size_t pos = 0;
  for (size_t i = 0; i < length && pos + 3 < max_out; i++) {
    const int written = snprintf(out + pos, max_out - pos, "%02X.", data[i]);
    if (written > 0) pos += static_cast<size_t>(written);
  }
  if (pos > 0 && out[pos - 1] == '.') out[pos - 1] = '\0';
}

}
