#pragma once

#include <array>
#include <cstdint>
#include <vector>
#include <span>

namespace dlms_parser {

class Aes128GcmDecryptor {
 public:
  virtual void set_decryption_key(std::span<const uint8_t> key_bytes) = 0;
  virtual bool decrypt_in_place(std::span<uint8_t> iv, std::span<uint8_t> cipher) = 0;
  [[nodiscard]] bool has_key() const { return _has_key; }

  virtual ~Aes128GcmDecryptor() = default;

 protected:
  Aes128GcmDecryptor() = default;
  bool _has_key = false;
};

}
