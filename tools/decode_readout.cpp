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

#include <array>
#include <charconv>
#include <cstdarg>
#include <cstdio>
#include <format>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "dlms_parser/dlms_parser.h"
#include "dlms_parser/log.h"
#include "dlms_parser/decryption/aes_128_gcm_decryptor_mbedtls.h"

// ---------------------------------------------------------------------------
// Hex file reader — supports spaced hex, concatenated hex, line continuations
// ---------------------------------------------------------------------------
static constexpr bool is_hex_char(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static std::vector<uint8_t> read_hex_file(std::string_view path) {
  std::ifstream f(std::string{path});
  if (!f) {
    std::cerr << std::format("Error: cannot open '{}'\n", path);
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
      uint8_t byte{};
      std::from_chars(start + i, start + i + 2, byte, 16);
      result.push_back(byte);
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Binary file reader
// ---------------------------------------------------------------------------
static std::vector<uint8_t> read_bin_file(std::string_view path) {
  std::ifstream f(std::string{path}, std::ios::binary | std::ios::ate);
  if (!f) {
    std::cerr << std::format("Error: cannot open '{}'\n", path);
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
static bool looks_like_hex_file(std::string_view path) {
  std::ifstream f(std::string{path});
  if (!f) return false;
  std::array<char, 256> buf{};
  f.read(buf.data(), buf.size() - 1);
  auto n = static_cast<size_t>(f.gcount());
  for (size_t i = 0; i < n; i++) {
    auto c = static_cast<unsigned char>(buf[i]);
    if (is_hex_char(static_cast<char>(c)) ||
        c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '-' || c == ',') {
      continue;
    }
    // Non-printable byte (control char or high byte) → likely raw binary
    if (c < 0x20 || c >= 0x7F) {
      return false;
    }
    // Printable non-hex ASCII (log-file comments, labels) — still treat as hex text
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

static std::string_view format_name(dlms_parser::FrameFormat fmt) {
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
static std::vector<uint8_t> parse_hex_key(std::string_view hex) {
  std::vector<uint8_t> key;
  if (hex.size() != 32) return {};
  for (size_t i = 0; i < 32; i += 2) {
    uint8_t byte{};
    auto [ptr, ec] = std::from_chars(hex.data() + i, hex.data() + i + 2, byte, 16);
    if (ec != std::errc{}) return {};
    key.push_back(byte);
  }
  return key;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
  // Parse arguments
  std::string_view file_path;
  std::string_view format_str;
  std::string_view key_str;
  std::vector<std::string> custom_patterns;
  bool skip_defaults = false;
  bool skip_crc = false;
  int verbosity = 0;

  for (int i = 1; i < argc; i++) {
    std::string_view arg = argv[i];
    if (arg == "-f" && i + 1 < argc) {
      format_str = argv[++i];
    } else if (arg == "-k" && i + 1 < argc) {
      key_str = argv[++i];
    } else if (arg == "-p" && i + 1 < argc) {
      custom_patterns.emplace_back(argv[++i]);
    } else if (arg == "-P") {
      skip_defaults = true;
    } else if (arg == "-C") {
      skip_crc = true;
    } else if (arg == "-vv") {
      verbosity = 2;
    } else if (arg == "-v") {
      verbosity = 1;
    } else if (!arg.starts_with('-')) {
      file_path = arg;
    } else {
      std::cerr << std::format("Unknown option: {}\n", arg);
      return 1;
    }
  }

  if (file_path.empty()) {
    std::cerr << std::format(
        "Usage: {} [options] <file>\n"
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
        "  {} tests/dumps/hdlc_norway_han_1phase.log\n"
        "  {} -f mbus -k 36C66639E48A8CA4D6BC8B282A793BBB tests/dumps/mbus_netz_noe_p1.log\n"
        "  {} -p \"TO, TV\" -k 5C316162209EBB790B52EB0E7FC5B11C tests/dumps/hdlc_landis_gyr_e450.log\n",
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
    std::cerr << std::format("Error: no data read from '{}'\n", file_path);
    return 1;
  }

  // ---- Configure parser ----
  dlms_parser::Aes128GcmDecryptorMbedTls decryptor;
  dlms_parser::DlmsParser parser(decryptor);

  // Frame format
  dlms_parser::FrameFormat fmt;
  if (!format_str.empty()) {
    if (format_str == "hdlc") fmt = dlms_parser::FrameFormat::HDLC;
    else if (format_str == "mbus") fmt = dlms_parser::FrameFormat::MBUS;
    else if (format_str == "raw") fmt = dlms_parser::FrameFormat::RAW;
    else {
      std::cerr << std::format("Error: unknown format '{}' (use hdlc, mbus, or raw)\n", format_str);
      return 1;
    }
  } else {
    fmt = detect_format(data);
  }
  parser.set_frame_format(fmt);

  // Work buffer — sized to input data (always sufficient)
  std::vector<uint8_t> work_buf(data.size());
  parser.set_work_buffer(work_buf);

  if (skip_crc) {
    parser.set_skip_crc_check(true);
  }

  // Decryption key
  if (!key_str.empty()) {
    auto key_bytes = parse_hex_key(key_str);
    auto key = dlms_parser::Aes128GcmDecryptionKey::from_bytes(key_bytes);
    if (!key) {
      std::cerr << "Error: key must be exactly 32 hex characters\n";
      return 1;
    }
    parser.set_decryption_key(*key);
  }

  // Patterns
  if (!skip_defaults) {
    parser.load_default_patterns();
  }
  for (const auto& pat : custom_patterns) {
    parser.register_pattern(pat.c_str());
  }

  std::cout << std::format("Input:   {} ({} bytes)\n", file_path, data.size());
  std::cout << std::format("Format:  {}{}\n", format_name(fmt), format_str.empty() ? " (auto-detected)" : "");
  if (!key_str.empty()) std::cout << std::format("Key:     {}\n", key_str);
  std::cout << "\n";

  // ---- Check frame completeness (demonstrates the check_frame API) ----
  auto status = parser.check_frame(data);
  const char* status_str = "?";
  switch (status) {
    case dlms_parser::FrameStatus::COMPLETE:  status_str = "COMPLETE"; break;
    case dlms_parser::FrameStatus::NEED_MORE: status_str = "NEED_MORE"; break;
    case dlms_parser::FrameStatus::ERROR:     status_str = "ERROR"; break;
  }
  std::cout << std::format("Status:  {}\n\n", status_str);

  if (status == dlms_parser::FrameStatus::NEED_MORE) {
    std::cerr << "Frame incomplete - more data needed. In a real application,\n"
                  "keep reading from UART and call check_frame() again with\n"
                  "the accumulated buffer.\n";
    return 2;
  }
  if (status == dlms_parser::FrameStatus::ERROR) {
    std::cerr << "Frame error - invalid data. Discard and resync.\n";
    return 3;
  }

  // ---- Parse ----
  size_t obj_count = 0;

  auto cooked_cb = [&](const char* obis, float val, const char* str, bool is_numeric) {
    obj_count++;
    if (is_numeric) {
      std::cout << std::format("  [{:2}] {:<20} = {:.4f}\n", obj_count, obis, static_cast<double>(val));
    } else {
      std::cout << std::format("  [{:2}] {:<20} = \"{}\"\n", obj_count, obis, str);
    }
  };

  auto [count, consumed] = parser.parse(data, cooked_cb);

  std::cout << std::format("\nTotal: {} objects matched, {} bytes consumed\n", count, consumed);

  return count > 0 ? 0 : 1;
}
