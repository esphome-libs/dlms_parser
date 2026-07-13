#pragma once

#include "axdr_parser.h"
#include "obis_id.h"
#include "decryption/aes_128_gcm_decryptor.h"
#include "utils.h"
#include <cstdint>
#include <span>

namespace dlms_parser {

// Facade — composes frame decoder, APDU handler, decryptor, and AXDR parser.
class DlmsParser final : NonCopyableAndNonMovable {
 public:
  explicit DlmsParser(DlmsDataCallback dlmsDataCallback, Aes128GcmDecryptor* decryptor = nullptr);

  void set_skip_crc_check(bool skip);
  void set_decryption_key(const Aes128GcmDecryptionKey& key) const;
  void set_authentication_key(const Aes128GcmAuthenticationKey& key) const;

  // Load built-in patterns.
  void load_default_patterns();

  void register_pattern(const char* name, const char* dsl, int priority, ObisId default_obis);

  // Parse a full frame (in-place). buf is modified during parsing.
  ParseResult parse(std::span<uint8_t> buf);

 private:
  Aes128GcmDecryptor* decryptor_;
  AxdrParser axdr_parser_;
  bool skip_crc_check_{false};
};

}
