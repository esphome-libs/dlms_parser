#pragma once

#include "apdu_handler.h"
#include "axdr_parser.h"
#include "hdlc_decoder.h"
#include "mbus_decoder.h"
#include "utils.h"
#include <cstdint>
#include <span>

namespace dlms_parser {

// Facade — composes frame decoder, APDU handler, decryptor, and AXDR parser.
class DlmsParser final : NonCopyableAndNonMovable {
 public:
  explicit DlmsParser(Aes128GcmDecryptor& decryptor);

  void set_skip_crc_check(bool skip);
  void set_decryption_key(const Aes128GcmDecryptionKey& key) const;
  void set_authentication_key(const Aes128GcmAuthenticationKey& key) const;

  // Load built-in patterns (T1, T2, T3, U.ZPA).
  void load_default_patterns();

  // Register a custom AXDR pattern (priority 0 — tried before built-in patterns).
  void register_pattern(const char* dsl);
  void register_pattern(const char* name, const char* dsl, int priority = 0);
  // Register with a default OBIS (used when the pattern captures no OBIS).
  void register_pattern(const char* name, const char* dsl, int priority, std::span<const uint8_t, 6> default_obis);

  // Parse a full frame (in-place). buf is modified during parsing.
  // Fires cooked_cb for each matched COSEM object.
  // Optionally fires raw_cb with unmodified captures before conversion.
  ParseResult parse(std::span<uint8_t> buf, const DlmsDataCallback& cooked_cb, const DlmsRawCallback& raw_cb = nullptr);

 private:
  Aes128GcmDecryptor& decryptor_;
  ApduHandler apdu_handler_;
  AxdrParser axdr_parser_;
  MBusDecoder mbus_decoder_;
  HdlcDecoder hdlc_decoder_;
};

}
