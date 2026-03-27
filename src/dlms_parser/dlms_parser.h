#pragma once

#include "apdu_handler.h"
#include "axdr_parser.h"
#include "gcm_decryptor.h"
#include "hdlc_decoder.h"
#include "mbus_decoder.h"
#include "utils.h"
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace dlms_parser {

enum class FrameFormat { RAW, MBUS, HDLC };

// Facade — composes frame decoder, APDU handler, decryptor, and AXDR parser.
class DlmsParser final : NonCopyableAndNonMovable {
 public:
  DlmsParser();

  void set_frame_format(FrameFormat fmt) { frame_format_ = fmt; }
  void set_skip_crc_check(bool skip);
  void set_decryption_key(const std::array<uint8_t, 16>& key);
  void set_decryption_key(const std::vector<uint8_t>& key);

  // Load built-in patterns (T1, T2, T3, U.ZPA).
  void load_default_patterns();

  // Register a custom AXDR pattern (priority 0 — tried before built-in patterns).
  void register_pattern(const std::string& dsl);
  void register_pattern(const std::string& name, const std::string& dsl, int priority = 0);

  // Parse a full frame. Fires cooked_cb for each matched COSEM object.
  // Optionally fires raw_cb with unmodified captures before conversion.
  size_t parse(const uint8_t* buf, size_t len,
               DlmsDataCallback cooked_cb,
               DlmsRawCallback raw_cb = nullptr);

 private:
  FrameFormat frame_format_{FrameFormat::RAW};
  GcmDecryptor decryptor_;
  ApduHandler apdu_handler_;
  AxdrParser axdr_parser_;
  MBusDecoder mbus_decoder_;
  HdlcDecoder hdlc_decoder_;
};

}  // namespace dlms_parser
