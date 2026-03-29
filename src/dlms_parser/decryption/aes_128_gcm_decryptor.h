#pragma once

#include <cstdint>
#include <optional>
#include <array>
#include <span>

namespace dlms_parser {

class Aes128GcmDecryptionKey {
public:
  static std::optional<Aes128GcmDecryptionKey> from_bytes(std::span<const uint8_t> key_bytes) {
    if (key_bytes.size() != 16) return std::nullopt;
    std::array<uint8_t, 16> arr{};
    std::copy(key_bytes.begin(), key_bytes.end(), arr.begin());
    return Aes128GcmDecryptionKey(arr);
  }

  [[nodiscard]] const uint8_t* data() const { return key.data(); }

private:
  explicit Aes128GcmDecryptionKey(const std::array<uint8_t, 16> k) : key(k) {}
  std::array<uint8_t, 16> key;
};

class Aes128GcmDecryptor {
 public:
  virtual void set_decryption_key(const Aes128GcmDecryptionKey& key) = 0;
  virtual bool decrypt_in_place(std::span<uint8_t> iv, std::span<uint8_t> cipher) = 0;
  [[nodiscard]] bool has_key() const { return _has_key; }

  virtual ~Aes128GcmDecryptor() = default;

 protected:
  Aes128GcmDecryptor() = default;
  bool _has_key = false;
};

}
