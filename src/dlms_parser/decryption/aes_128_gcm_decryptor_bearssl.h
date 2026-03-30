#pragma once

#include <bearssl.h>
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
    has_decryption_key_ = true;
  }

  bool decrypt_in_place(std::span<uint8_t> iv,
                        std::span<uint8_t> cipher,
                        std::span<const uint8_t> aad,
                        std::span<const uint8_t> tag) override {
    if (!has_decryption_key_) { return false; }

    br_gcm_reset(&gcm, iv.data(), iv.size());
    if (!aad.empty()) {
      br_gcm_aad_inject(&gcm, aad.data(), aad.size());
    }
    br_gcm_flip(&gcm);
    br_gcm_run(&gcm, 0, cipher.data(), cipher.size());

    if (!tag.empty()) {
      return br_gcm_check_tag_trunc(&gcm, tag.data(), tag.size()) == 1;
    }
    return true;
  }
};

}
