// decode_readout — standalone CLI tool demonstrating dlms_parser usage.
//
// Build (from repo root):
//   cmake -S . -B build && cmake --build build
//   # binary: build/decode_readout
//
// Usage:
//   ./decode_readout [options] <file>
//
// Options:
//   -f hdlc|mbus|raw    Frame format (default: auto-detect)
//   -k <hex_key>        AES-128-GCM decryption key (32 hex chars)
//   -p <dsl>            Register a custom pattern (can be repeated)
//   -P                  Skip loading default patterns
//   -C                  Skip CRC/checksum validation
//   -v                  Verbose logging (default: warnings only)
//   -vv                 Very verbose logging (all levels)
//
// Examples:
//   ./decode_readout tests/dumps/hdlc_norway_han_1phase.log
//   ./decode_readout -f mbus -k 36C66639E48A8CA4D6BC8B282A793BBB tests/dumps/mbus_netz_noe_p1.log
//   ./decode_readout -p "TO, TV" -p "L, TSTR" tests/dumps/hdlc_landis_gyr_e450.log

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "dlms_parser/dlms_parser.h"
#include "dlms_parser/log.h"
#include "dlms_parser/decryption/aes_128_gcm_decryptor_mbedtls.h"

// ---------------------------------------------------------------------------
// Hex file reader — supports spaced hex, concatenated hex, line continuations
// ---------------------------------------------------------------------------
static bool is_hex_char(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static std::vector<uint8_t> read_hex_file(const char* path) {
  std::ifstream f(path);
  if (!f) {
    fprintf(stderr, "Error: cannot open '%s'\n", path);
    return {};
  }

  std::ostringstream ss;
  ss << f.rdbuf();
  std::string raw = ss.str();

  // Remove dash-newline line continuations before parsing
  std::string text;
  for (size_t i = 0; i < raw.size(); i++) {
    if (raw[i] == '-' && i + 1 < raw.size() && raw[i + 1] == '\n') {
      i++;  // skip dash + newline
    } else {
      text += raw[i];
    }
  }

  // File contains only hex chars + separators (spaces, newlines, dots, semicolons, commas).
  // Extract contiguous hex pairs, skip everything else.
  std::vector<uint8_t> result;
  const char* p = text.c_str();
  while (*p) {
    // Skip non-hex separators
    while (*p && !is_hex_char(*p)) p++;
    if (!*p) break;
    // Collect contiguous hex chars
    const char* start = p;
    while (is_hex_char(*p)) p++;
    size_t len = static_cast<size_t>(p - start);
    if (len % 2 != 0) continue;  // odd-length token — skip
    for (size_t i = 0; i < len; i += 2) {
      char bs[3] = {start[i], start[i + 1], '\0'};
      result.push_back(static_cast<uint8_t>(strtoul(bs, nullptr, 16)));
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Binary file reader
// ---------------------------------------------------------------------------
static std::vector<uint8_t> read_bin_file(const char* path) {
  std::ifstream f(path, std::ios::binary | std::ios::ate);
  if (!f) {
    fprintf(stderr, "Error: cannot open '%s'\n", path);
    return {};
  }
  std::streamsize size = f.tellg();
  f.seekg(0, std::ios::beg);
  std::vector<uint8_t> result(static_cast<size_t>(size));
  if (!f.read(reinterpret_cast<char*>(result.data()), size)) {
    result.clear();
  }
  return result;
}

// ---------------------------------------------------------------------------
// Auto-detect file type: if all bytes are hex chars/spaces/newlines, treat as hex
// ---------------------------------------------------------------------------
static bool looks_like_hex_file(const char* path) {
  std::ifstream f(path);
  if (!f) return false;
  char buf[256];
  f.read(buf, sizeof(buf) - 1);
  size_t n = static_cast<size_t>(f.gcount());
  buf[n] = '\0';
  for (size_t i = 0; i < n; i++) {
    char c = buf[i];
    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') ||
        c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '-' || c == ',') {
      continue;
    }
    // Allow some text (log files have comments) — if first hex-like byte is 0x7E/0x68/0x0F, it's hex
    return true;  // be lenient, default to hex
  }
  return true;
}

// ---------------------------------------------------------------------------
// Auto-detect frame format from first byte
// ---------------------------------------------------------------------------
static dlms_parser::FrameFormat detect_format(const std::vector<uint8_t>& data) {
  if (data.empty()) return dlms_parser::FrameFormat::RAW;
  switch (data[0]) {
    case 0x7E: return dlms_parser::FrameFormat::HDLC;
    case 0x68: return dlms_parser::FrameFormat::MBUS;
    default:   return dlms_parser::FrameFormat::RAW;
  }
}

static const char* format_name(dlms_parser::FrameFormat fmt) {
  switch (fmt) {
    case dlms_parser::FrameFormat::HDLC: return "HDLC";
    case dlms_parser::FrameFormat::MBUS: return "MBUS";
    case dlms_parser::FrameFormat::RAW:  return "RAW";
  }
  return "?";
}

// ---------------------------------------------------------------------------
// Parse hex key string
// ---------------------------------------------------------------------------
static std::vector<uint8_t> parse_hex_key(const char* hex) {
  std::vector<uint8_t> key;
  size_t len = strlen(hex);
  if (len != 32) return {};
  for (size_t i = 0; i < 32; i += 2) {
    char byte_str[3] = {hex[i], hex[i + 1], '\0'};
    key.push_back(static_cast<uint8_t>(strtoul(byte_str, nullptr, 16)));
  }
  return key;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
  // Parse arguments
  const char* file_path = nullptr;
  const char* format_str = nullptr;
  const char* key_str = nullptr;
  std::vector<std::string> custom_patterns;
  bool skip_defaults = false;
  bool skip_crc = false;
  int verbosity = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
      format_str = argv[++i];
    } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
      key_str = argv[++i];
    } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
      custom_patterns.emplace_back(argv[++i]);
    } else if (strcmp(argv[i], "-P") == 0) {
      skip_defaults = true;
    } else if (strcmp(argv[i], "-C") == 0) {
      skip_crc = true;
    } else if (strcmp(argv[i], "-vv") == 0) {
      verbosity = 2;
    } else if (strcmp(argv[i], "-v") == 0) {
      verbosity = 1;
    } else if (argv[i][0] != '-') {
      file_path = argv[i];
    } else {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      return 1;
    }
  }

  if (!file_path) {
    fprintf(stderr,
        "Usage: %s [options] <file>\n"
        "\n"
        "Options:\n"
        "  -f hdlc|mbus|raw    Frame format (default: auto-detect)\n"
        "  -k <hex_key>        AES-128-GCM decryption key (32 hex chars)\n"
        "  -p <dsl>            Register a custom pattern (repeatable)\n"
        "  -P                  Skip loading default patterns\n"
        "  -C                  Skip CRC/checksum validation\n"
        "  -v                  Verbose logging\n"
        "  -vv                 Very verbose logging\n"
        "\n"
        "Examples:\n"
        "  %s tests/dumps/hdlc_norway_han_1phase.log\n"
        "  %s -f mbus -k 36C66639E48A8CA4D6BC8B282A793BBB tests/dumps/mbus_netz_noe_p1.log\n"
        "  %s -p \"TO, TV\" -k 5C316162209EBB790B52EB0E7FC5B11C tests/dumps/hdlc_landis_gyr_e450.log\n",
        argv[0], argv[0], argv[0], argv[0]);
    return 1;
  }

  // ---- Install logger ----
  dlms_parser::LogLevel min_level = dlms_parser::LogLevel::WARNING;
  if (verbosity == 1) min_level = dlms_parser::LogLevel::INFO;
  if (verbosity >= 2) min_level = dlms_parser::LogLevel::DEBUG;

  dlms_parser::Logger::set_log_function(
      [min_level](dlms_parser::LogLevel level, const char* fmt, va_list args) {
        if (level < min_level) return;
        const char* prefix = "";
        switch (level) {
          case dlms_parser::LogLevel::DEBUG:        prefix = "[DBG] "; break;
          case dlms_parser::LogLevel::VERY_VERBOSE: prefix = "[VV]  "; break;
          case dlms_parser::LogLevel::VERBOSE:      prefix = "[VRB] "; break;
          case dlms_parser::LogLevel::INFO:         prefix = "[INF] "; break;
          case dlms_parser::LogLevel::WARNING:      prefix = "[WRN] "; break;
          case dlms_parser::LogLevel::ERROR:        prefix = "[ERR] "; break;
        }
        fprintf(stderr, "%s", prefix);
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
      });

  // ---- Read input ----
  std::vector<uint8_t> data;
  if (looks_like_hex_file(file_path)) {
    data = read_hex_file(file_path);
  } else {
    data = read_bin_file(file_path);
  }

  if (data.empty()) {
    fprintf(stderr, "Error: no data read from '%s'\n", file_path);
    return 1;
  }

  // ---- Configure parser ----
  dlms_parser::Aes128GcmDecryptorMbedTls decryptor;
  dlms_parser::DlmsParser parser(decryptor);

  // Frame format
  dlms_parser::FrameFormat fmt;
  if (format_str) {
    if (strcmp(format_str, "hdlc") == 0) fmt = dlms_parser::FrameFormat::HDLC;
    else if (strcmp(format_str, "mbus") == 0) fmt = dlms_parser::FrameFormat::MBUS;
    else if (strcmp(format_str, "raw") == 0) fmt = dlms_parser::FrameFormat::RAW;
    else {
      fprintf(stderr, "Error: unknown format '%s' (use hdlc, mbus, or raw)\n", format_str);
      return 1;
    }
  } else {
    fmt = detect_format(data);
  }
  parser.set_frame_format(fmt);

  // Work buffer — sized to input data (always sufficient)
  std::vector<uint8_t> work_buf(data.size());
  parser.set_work_buffer(work_buf.data(), work_buf.size());

  if (skip_crc) {
    parser.set_skip_crc_check(true);
  }

  // Decryption key
  if (key_str) {
    auto key = parse_hex_key(key_str);
    if (key.size() != 16) {
      fprintf(stderr, "Error: key must be exactly 32 hex characters\n");
      return 1;
    }
    parser.set_decryption_key(key);
  }

  // Patterns
  if (!skip_defaults) {
    parser.load_default_patterns();
  }
  for (const auto& pat : custom_patterns) {
    parser.register_pattern(pat);
  }

  fprintf(stdout, "Input:   %s (%zu bytes)\n", file_path, data.size());
  fprintf(stdout, "Format:  %s%s\n", format_name(fmt), format_str ? "" : " (auto-detected)");
  if (key_str) fprintf(stdout, "Key:     %s\n", key_str);
  fprintf(stdout, "\n");

  // ---- Check frame completeness (demonstrates the check_frame API) ----
  auto status = parser.check_frame(data.data(), data.size());
  const char* status_str = "?";
  switch (status) {
    case dlms_parser::FrameStatus::COMPLETE:  status_str = "COMPLETE"; break;
    case dlms_parser::FrameStatus::NEED_MORE: status_str = "NEED_MORE"; break;
    case dlms_parser::FrameStatus::ERROR:     status_str = "ERROR"; break;
  }
  fprintf(stdout, "Status:  %s\n\n", status_str);

  if (status == dlms_parser::FrameStatus::NEED_MORE) {
    fprintf(stderr, "Frame incomplete - more data needed. In a real application,\n"
                    "keep reading from UART and call check_frame() again with\n"
                    "the accumulated buffer.\n");
    return 2;
  }
  if (status == dlms_parser::FrameStatus::ERROR) {
    fprintf(stderr, "Frame error - invalid data. Discard and resync.\n");
    return 3;
  }

  // ---- Parse ----
  size_t obj_count = 0;

  auto cooked_cb = [&](const char* obis, float val, const char* str, bool is_numeric) {
    obj_count++;
    if (is_numeric) {
      fprintf(stdout, "  [%2zu] %-20s = %.4f\n", obj_count, obis, static_cast<double>(val));
    } else {
      fprintf(stdout, "  [%2zu] %-20s = \"%s\"\n", obj_count, obis, str);
    }
  };

  auto [count, consumed] = parser.parse(data.data(), data.size(), cooked_cb);

  fprintf(stdout, "\nTotal: %zu objects matched, %zu bytes consumed\n", count, consumed);

  return count > 0 ? 0 : 1;
}
