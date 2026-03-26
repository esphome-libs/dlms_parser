#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace dlms_parser {

// AES-128-GCM decryptor. Platform-abstracted:
//   ESP8266            : BearSSL
//   ESP32 IDF >= 6.0   : PSA Crypto
//   all others         : mbedTLS
class GcmDecryptor {
 public:
  void set_key(const std::array<uint8_t, 16>& key);
  void set_key(const std::vector<uint8_t>& key);

  bool has_key() const { return has_key_; }

  // Decrypts AES-128-GCM ciphertext. iv must be exactly 12 bytes.
  // On success, plain_out is filled with cipher_len decrypted bytes and true is returned.
  bool decrypt(const uint8_t* iv, const uint8_t* cipher, size_t cipher_len,
               std::vector<uint8_t>& plain_out) const;

 private:
  bool has_key_{false};
  std::array<uint8_t, 16> key_{};
};

}  // namespace dlms_parser
