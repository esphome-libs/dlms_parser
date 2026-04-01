#pragma once

#include <mbedtls/gcm.h>
#include "aes_128_gcm_decryptor.h"
#include "../utils.h"
#include "../log.h"

namespace dlms_parser {

class Aes128GcmDecryptorMbedTls : public Aes128GcmDecryptor, NonCopyableAndNonMovable {
  mbedtls_gcm_context gcm{};

public:
  Aes128GcmDecryptorMbedTls() { mbedtls_gcm_init(&gcm); }
  ~Aes128GcmDecryptorMbedTls() override { mbedtls_gcm_free(&gcm); }

  void set_decryption_key(const Aes128GcmDecryptionKey& key) override {
    if (const auto res = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), 128); res != 0) {
      Logger::log(LogLevel::ERROR, "Failed to set decryption key: %d", res);
      return;
    }

    decryption_key_ = key;
  }

  bool decrypt_in_place(std::span<const uint8_t> iv,
                        std::span<uint8_t> cipher,
                        std::span<const uint8_t> aad,
                        std::span<const uint8_t> tag) override {
    if (!decryption_key_) {
      Logger::log(LogLevel::ERROR, "Decryption key is not set");
      return false;
    }

    if (!tag.empty()) {
      Logger::log(LogLevel::VERY_VERBOSE, "Decrypt using tag");

      // Authenticated: decrypt and verify tag in one call
      return mbedtls_gcm_auth_decrypt(/* ctx     */ &gcm,
                                      /* length  */ cipher.size(),
                                      /* iv      */ iv.data(),
                                      /* iv_len  */ iv.size(),
                                      /* aad     */ aad.data(),
                                      /* aad_len */ aad.size(),
                                      /* tag     */ tag.data(),
                                      /* tag_len */ tag.size(),
                                      /* input   */ cipher.data(),
                                      /* output  */ cipher.data()) == 0;
    }

    // Encrypt-only: no tag verification, no AAD
    Logger::log(LogLevel::VERY_VERBOSE, "Decrypt without tag. No data corruption verification");
    unsigned char dummy_tag[12];
    return mbedtls_gcm_crypt_and_tag(/* ctx     */ &gcm,
                                     /* mode    */ MBEDTLS_GCM_DECRYPT,
                                     /* length  */ cipher.size(),
                                     /* iv      */ iv.data(),
                                     /* iv_len  */ iv.size(),
                                     /* aad     */ nullptr,
                                     /* aad_len */ 0,
                                     /* input   */ cipher.data(),
                                     /* output  */ cipher.data(),
                                     /* tag_len */ sizeof(dummy_tag),
                                     /* tag     */ dummy_tag) == 0;
  }
};

}
