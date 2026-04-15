#pragma once

#include <charconv>
#include <cstdint>
#include <optional>
#include <array>
#include <span>
#include <string_view>

namespace dlms_parser {

namespace detail {

struct DecryptionKeyTag {};
struct AuthenticationKeyTag {};

template <typename Tag>
class Aes128Key final {
public:
  [[nodiscard]] static std::optional<Aes128Key> from_bytes(std::span<const uint8_t> key_bytes) {
    if (key_bytes.size() != 16) return std::nullopt;
    std::array<uint8_t, 16> arr{};
    std::copy(key_bytes.begin(), key_bytes.end(), arr.begin());
    return Aes128Key(arr);
  }

  [[nodiscard]] static std::optional<Aes128Key> from_hex(const std::string_view hex) {
    if (hex.size() != 32) return std::nullopt;
    std::array<uint8_t, 16> arr{};
    for (size_t i = 0; i < 16; ++i) {
      auto [ptr, ec] = std::from_chars(hex.data() + i * 2, hex.data() + i * 2 + 2, arr[i], 16);
      if (ec != std::errc{}) return std::nullopt;
    }
    return Aes128Key(arr);
  }

  [[nodiscard]] const uint8_t* data() const { return key.data(); }

private:
  explicit Aes128Key(const std::array<uint8_t, 16> k) : key(k) {}
  std::array<uint8_t, 16> key;
};

}

using Aes128GcmDecryptionKey = detail::Aes128Key<detail::DecryptionKeyTag>;
using Aes128GcmAuthenticationKey = detail::Aes128Key<detail::AuthenticationKeyTag>;

class Aes128GcmDecryptor {
 public:
  virtual void set_decryption_key(const Aes128GcmDecryptionKey& key) = 0;

  void set_authentication_key(const Aes128GcmAuthenticationKey& key) {
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
