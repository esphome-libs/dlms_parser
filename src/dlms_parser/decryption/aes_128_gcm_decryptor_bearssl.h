#pragma once

#if __has_include(<bearssl/bearssl.h>)
#include <bearssl/bearssl.h>
#elif __has_include(<bearssl.h>)
#include <bearssl.h>
#else
#error "BearSSL header not found"
#endif

#include "aes_128_gcm_decryptor.h"
#include "../utils.h"

namespace dlms_parser {

class Aes128GcmDecryptorBearSsl : public Aes128GcmDecryptor, NonCopyableAndNonMovable {
  br_gcm_context gcm{};
  br_aes_ct_ctr_keys aes{};

 public:
  Aes128GcmDecryptorBearSsl() = default;

  void set_decryption_key(const Aes128GcmDecryptionKey& key) override {
    br_aes_ct_ctr_init(&aes, key.data(), 16);
    br_gcm_init(&gcm, &aes.vtable, br_ghash_ctmul32);
    decryption_key_ = key;
  }

  bool decrypt_in_place(const std::span<const uint8_t> iv,
                        std::span<uint8_t> cipher,
                        const std::span<const uint8_t> aad,
                        const std::span<const uint8_t> tag) override {
    if (!decryption_key_) {
      Logger::log(LogLevel::ERROR, "Decryption key is not set");
      return false;
    }

    br_gcm_reset(&gcm, iv.data(), iv.size());
    if (!aad.empty()) {
      br_gcm_aad_inject(&gcm, aad.data(), aad.size());
    }
    br_gcm_flip(&gcm);
    br_gcm_run(&gcm, 0, cipher.data(), cipher.size());

    if (!tag.empty()) {
      Logger::log(LogLevel::VERY_VERBOSE, "Verify tag");
      return br_gcm_check_tag_trunc(&gcm, tag.data(), tag.size()) == 1;
    }
    return true;
  }
};

}
