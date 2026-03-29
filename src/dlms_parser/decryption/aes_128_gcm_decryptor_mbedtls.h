#pragma once

#include <mbedtls/gcm.h>
#include "aes_128_gcm_decryptor.h"

namespace dlms_parser {

class Aes128GcmDecryptorMbedTls : public Aes128GcmDecryptor {
  mbedtls_gcm_context gcm{};

public:
  Aes128GcmDecryptorMbedTls() { mbedtls_gcm_init(&gcm); }
  ~Aes128GcmDecryptorMbedTls() override { mbedtls_gcm_free(&gcm); }

  void set_decryption_key(const std::span<const uint8_t> key_bytes) override {
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key_bytes.data(), 128);
    _has_key = true;
  }

  bool decrypt_in_place(const std::span<uint8_t> iv, std::span<uint8_t> cipher) override {
    unsigned char tag[12]; // dummy tag to satisfy the API
    return mbedtls_gcm_crypt_and_tag(/* ctx     */ &gcm,
                                     /* mode    */ MBEDTLS_GCM_DECRYPT,
                                     /* length  */ cipher.size(),
                                     /* iv      */ iv.data(),
                                     /* iv_len  */ iv.size(),
                                     /* aad     */ nullptr,
                                     /* aad_len */ 0,
                                     /* input   */ cipher.data(),
                                     /* output  */ cipher.data(),
                                     /* tag_len */ sizeof(tag),
                                     /* tag     */ tag) == 0;
  }
};

}
