#pragma once

#include "apdu_handler.h"
#include "axdr_parser.h"
#include "hdlc_decoder.h"
#include "mbus_decoder.h"
#include "utils.h"
#include <cstdint>

namespace dlms_parser {

enum class FrameFormat { RAW, MBUS, HDLC };

// Facade — composes frame decoder, APDU handler, decryptor, and AXDR parser.
class DlmsParser final : NonCopyableAndNonMovable {
 public:
  explicit DlmsParser(Aes128GcmDecryptor& decryptor);

  void set_frame_format(const FrameFormat fmt) { this->frame_format_ = fmt; }
  void set_skip_crc_check(bool skip);
  void set_work_buffer(uint8_t* buf, size_t capacity);
  void set_decryption_key(const Aes128GcmDecryptionKey& key) const;
  void set_authentication_key(const Aes128GcmAuthenticationKey& key) const;

  // Load built-in patterns (T1, T2, T3, U.ZPA).
  void load_default_patterns();

  // Register a custom AXDR pattern (priority 0 — tried before built-in patterns).
  void register_pattern(const char* dsl);
  void register_pattern(const char* name, const char* dsl, int priority = 0);
  // Register with a default OBIS (used when the pattern captures no OBIS).
  void register_pattern(const char* name, const char* dsl, int priority, const uint8_t default_obis[6]);

  // Check whether buf contains a complete message ready for parse().
  // Stateless — the library does not accumulate; the caller owns the buffer.
  FrameStatus check_frame(const uint8_t* buf, size_t len) const;

  // Parse a full frame. Fires cooked_cb for each matched COSEM object.
  // Optionally fires raw_cb with unmodified captures before conversion.
  ParseResult parse(const uint8_t* buf, size_t len,
                    const DlmsDataCallback& cooked_cb,
                    const DlmsRawCallback& raw_cb = nullptr);

 private:
  FrameFormat frame_format_{FrameFormat::RAW};
  uint8_t* work_buf_{nullptr};
  size_t work_buf_capacity_{0};
  Aes128GcmDecryptor& decryptor_;
  ApduHandler apdu_handler_;
  AxdrParser axdr_parser_;
  MBusDecoder mbus_decoder_;
  HdlcDecoder hdlc_decoder_;
};

}  // namespace dlms_parser
