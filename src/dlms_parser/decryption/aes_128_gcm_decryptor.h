#pragma once

#include <cstdint>
#include <cstring>
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

  virtual void set_authentication_key(const Aes128GcmDecryptionKey& key) {
    std::memcpy(auth_key_.data(), key.data(), 16);
    has_auth_key_ = true;
  }

  // Decrypt cipher in-place.
  // When aad + tag are non-empty, verifies the GCM authentication tag.
  // aad = security_control(1) + authentication_key(16), per DLMS Green Book.
  virtual bool decrypt_in_place(std::span<uint8_t> iv,
                                std::span<uint8_t> cipher,
                                std::span<const uint8_t> aad,
                                std::span<const uint8_t> tag) = 0;

  [[nodiscard]] bool has_key() const { return has_decryption_key_; }
  [[nodiscard]] bool has_auth_key() const { return has_auth_key_ && !skip_auth_; }
  [[nodiscard]] const uint8_t* auth_key_data() const { return auth_key_.data(); }
  void set_skip_auth_check(bool skip) { skip_auth_ = skip; }

  virtual ~Aes128GcmDecryptor() = default;

 protected:
  Aes128GcmDecryptor() = default;
  bool has_decryption_key_ = false;
  bool has_auth_key_ = false;
  bool skip_auth_ = false;
  std::array<uint8_t, 16> auth_key_{};
};

}
