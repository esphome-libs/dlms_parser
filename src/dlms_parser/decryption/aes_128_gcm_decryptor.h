#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <array>
#include <span>

namespace dlms_parser {

namespace detail {
struct DecryptionKeyTag {};
struct AuthenticationKeyTag {};
}

template <typename Tag>
class Aes128Key {
public:
  static [[nodiscard]] std::optional<Aes128Key> from_bytes(std::span<const uint8_t> key_bytes) {
    if (key_bytes.size() != 16) return std::nullopt;
    std::array<uint8_t, 16> arr{};
    std::copy(key_bytes.begin(), key_bytes.end(), arr.begin());
    return Aes128Key(arr);
  }

  [[nodiscard]] const uint8_t* data() const { return key.data(); }

private:
  explicit Aes128Key(const std::array<uint8_t, 16> k) : key(k) {}
  std::array<uint8_t, 16> key;
};

using Aes128GcmDecryptionKey = Aes128Key<detail::DecryptionKeyTag>;
using Aes128GcmAuthenticationKey = Aes128Key<detail::AuthenticationKeyTag>;

class Aes128GcmDecryptor {
 public:
  virtual void set_decryption_key(const Aes128GcmDecryptionKey& key) = 0;

  virtual void set_authentication_key(const Aes128GcmAuthenticationKey& key) {
    auth_key_ = key;
  }

  // Decrypt cipher in-place.
  // When aad + tag are non-empty, verifies the GCM authentication tag.
  // aad = security_control(1) + authentication_key(16), per DLMS Green Book.
  virtual bool decrypt_in_place(std::span<const uint8_t> iv,
                                std::span<uint8_t> cipher,
                                std::span<const uint8_t> aad,
                                std::span<const uint8_t> tag) = 0;

  [[nodiscard]] std::optional<Aes128GcmDecryptionKey> decryption_key() const { return decryption_key_; }
  [[nodiscard]] std::optional<Aes128GcmAuthenticationKey> auth_key() const { return auth_key_; }

  virtual ~Aes128GcmDecryptor() = default;

 protected:
  Aes128GcmDecryptor() = default;

  std::optional<Aes128GcmDecryptionKey> decryption_key_;
  std::optional<Aes128GcmAuthenticationKey> auth_key_;
};

}
