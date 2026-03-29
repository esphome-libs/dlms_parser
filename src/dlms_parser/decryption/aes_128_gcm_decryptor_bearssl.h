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
    _has_key = true;
  }
  
  bool decrypt_in_place(const std::span<uint8_t> iv, std::span<uint8_t> cipher) override {
    if (!_has_key) { return false; }

    br_gcm_reset(&gcm, iv.data(), iv.size());
    br_gcm_flip(&gcm);
    br_gcm_run(&gcm, 0, cipher.data(), cipher.size());
    return true;
  }
};

}
