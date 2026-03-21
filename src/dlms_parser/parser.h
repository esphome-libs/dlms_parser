#pragma once

#include "pattern.h"
#include "utils.h"
#include "types.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <array>

namespace dlms_parser {

class DlmsParser final : NonCopyableAndNonMovable {
public:
  DlmsParser();

  // Registers a custom parsing pattern from the YAML config
  void register_custom_pattern(const std::string& dsl);

  // Sets the AES-128-GCM decryption key
  void set_decryption_key(const std::array<uint8_t, 16> &key);
  void set_decryption_key(const std::vector<uint8_t> &key);

  // Parses the buffer and fires callbacks for each found sensor value
  size_t parse(const uint8_t* buffer, size_t length, DlmsDataCallback callback);

private:
  void register_pattern_dsl_(const std::string& name, const std::string& dsl, int priority);
  void load_default_patterns_();

  uint8_t find_apdu_tag_();
  void parse_data_notification_();
  void parse_ciphered_apdu_(uint8_t apdu_tag);
  bool decrypt_gcm_(const uint8_t *iv, const uint8_t *cipher_text, size_t cipher_len, uint8_t *plain_text);

  uint8_t read_byte_();
  uint16_t read_u16_();
  uint32_t read_u32_();

  bool skip_data_(uint8_t type);
  bool parse_element_(uint8_t type, uint8_t depth = 0);
  bool parse_sequence_(uint8_t type, uint8_t depth = 0);

  bool capture_generic_value_(AxdrCaptures& c);
  bool try_match_patterns_(uint8_t elem_idx);
  bool match_pattern_(uint8_t elem_idx, const AxdrDescriptorPattern& pat, uint8_t& elements_consumed_at_level0);
  void emit_object_(const AxdrDescriptorPattern& pat, const AxdrCaptures& c);

  const uint8_t* buffer_{nullptr};
  size_t buffer_len_{0};

  size_t pos_{0};
  DlmsDataCallback callback_;
  size_t objects_found_{0};
  uint8_t last_pattern_elements_consumed_{0};

  bool has_decryption_key_{false};
  std::array<uint8_t, 16> decryption_key_{};

  std::vector<AxdrDescriptorPattern> patterns_;
};

}
