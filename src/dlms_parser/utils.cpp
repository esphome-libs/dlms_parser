#include "utils.h"
#include <cmath>
#include <cstring>
#include <cstdio>
#include <algorithm>

namespace dlms {
namespace parser {

float data_as_float(DlmsDataType value_type, const uint8_t *ptr, uint8_t len) {
  if (!ptr || len == 0) return 0.0f;

  auto be16 = [](const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); };
  auto be32 = [](const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
  };
  auto be64 = [](const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) | ((uint64_t)p[6] << 8)  | (uint64_t)p[7];
  };

  switch (value_type) {
    case DLMS_DATA_TYPE_BOOLEAN:
    case DLMS_DATA_TYPE_ENUM:
    case DLMS_DATA_TYPE_UINT8: return static_cast<float>(ptr[0]);
    case DLMS_DATA_TYPE_INT8: return static_cast<float>(static_cast<int8_t>(ptr[0]));
    case DLMS_DATA_TYPE_BIT_STRING: return (len > 0 && ptr) ? static_cast<float>(ptr[0]) : 0.0f;
    case DLMS_DATA_TYPE_UINT16: return len >= 2 ? static_cast<float>(be16(ptr)) : 0.0f;
    case DLMS_DATA_TYPE_INT16: return len >= 2 ? static_cast<float>(static_cast<int16_t>(be16(ptr))) : 0.0f;
    case DLMS_DATA_TYPE_UINT32: return len >= 4 ? static_cast<float>(be32(ptr)) : 0.0f;
    case DLMS_DATA_TYPE_INT32: return len >= 4 ? static_cast<float>(static_cast<int32_t>(be32(ptr))) : 0.0f;
    case DLMS_DATA_TYPE_UINT64: return len >= 8 ? static_cast<float>(be64(ptr)) : 0.0f;
    case DLMS_DATA_TYPE_INT64: return len >= 8 ? static_cast<float>(static_cast<int64_t>(be64(ptr))) : 0.0f;
    case DLMS_DATA_TYPE_FLOAT32: {
      if (len < 4) return 0.0f;
      uint32_t i32 = be32(ptr);
      float f;
      std::memcpy(&f, &i32, sizeof(float));
      return f;
    }
    case DLMS_DATA_TYPE_FLOAT64: {
      if (len < 8) return 0.0f;
      uint64_t i64 = be64(ptr);
      double d;
      std::memcpy(&d, &i64, sizeof(double));
      return static_cast<float>(d);
    }
    default: return 0.0f;
  }
}

void data_to_string(DlmsDataType value_type, const uint8_t *ptr, uint8_t len, char *buffer, size_t max_len) {
  if (max_len > 0) buffer[0] = '\0';
  if (!ptr || len == 0 || max_len == 0) return;

  auto hex_of = [](const uint8_t *p, uint8_t l, char *out, size_t max_out) {
    if (max_out == 0) return;
    out[0] = '\0';
    size_t pos = 0;
    for (uint8_t i = 0; i < l && pos + 2 < max_out; i++) {
      pos += snprintf(out + pos, max_out - pos, "%02x", p[i]);
    }
  };

  auto be16 = [](const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); };
  auto be32 = [](const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
  };
  auto be64 = [](const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
  };

  switch (value_type) {
    case DLMS_DATA_TYPE_OCTET_STRING:
    case DLMS_DATA_TYPE_STRING:
    case DLMS_DATA_TYPE_STRING_UTF8: {
      size_t copy_len = std::min((size_t)len, max_len - 1);
      std::memcpy(buffer, ptr, copy_len);
      buffer[copy_len] = '\0';
      break;
    }
    case DLMS_DATA_TYPE_BIT_STRING:
    case DLMS_DATA_TYPE_BINARY_CODED_DESIMAL:
    case DLMS_DATA_TYPE_DATETIME:
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
      if (len >= 4) snprintf(buffer, max_len, "%lu", (unsigned long)be32(ptr));
      break;
    case DLMS_DATA_TYPE_INT32:
      if (len >= 4) snprintf(buffer, max_len, "%ld", (long)static_cast<int32_t>(be32(ptr)));
      break;
    case DLMS_DATA_TYPE_UINT64:
      if (len >= 8) snprintf(buffer, max_len, "%llu", (unsigned long long)be64(ptr));
      break;
    case DLMS_DATA_TYPE_INT64:
      if (len >= 8) snprintf(buffer, max_len, "%lld", (long long)static_cast<int64_t>(be64(ptr)));
      break;
    case DLMS_DATA_TYPE_FLOAT32:
    case DLMS_DATA_TYPE_FLOAT64: {
      snprintf(buffer, max_len, "%f", data_as_float(value_type, ptr, len));
      break;
    }
    default:
      break;
  }
}

void obis_to_string(const uint8_t *obis, char *buffer, size_t max_len) {
  if (max_len > 0) buffer[0] = '\0';
  if (!obis || max_len == 0) return;
  snprintf(buffer, max_len, "%u.%u.%u.%u.%u.%u", obis[0], obis[1], obis[2], obis[3], obis[4], obis[5]);
}

const char *dlms_data_type_to_string(DlmsDataType vt) {
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

int get_data_type_size(DlmsDataType type) {
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

bool is_value_data_type(DlmsDataType type) {
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

void format_hex_pretty_to(char *out, size_t max_out, const uint8_t *data, size_t length) {
  if (max_out == 0) return;
  out[0] = '\0';
  size_t pos = 0;
  for (size_t i = 0; i < length && pos + 3 < max_out; i++) {
    pos += snprintf(out + pos, max_out - pos, "%02X.", data[i]);
  }
  if (pos > 0 && out[pos - 1] == '.') out[pos - 1] = '\0';
}

}  // namespace parser
}  // namespace dlms