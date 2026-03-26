#include "gcm_decryptor.h"
#include "log.h"
#include <algorithm>
#include <cstring>

#if defined(USE_ESP8266_FRAMEWORK_ARDUINO) || defined(USE_ESP8266) || defined(ESP8266)
#include <bearssl/bearssl.h>
// ESP_IDF_VERSION_VAL(6,0,0) == 0x60000; written as literal to avoid expansion errors when the macro is undefined
#elif defined(USE_ESP32) && defined(ESP_IDF_VERSION) && (ESP_IDF_VERSION >= 0x60000)
#include <psa/crypto.h>
#else
#include <mbedtls/gcm.h>
#endif

namespace dlms_parser {

void GcmDecryptor::set_key(const std::array<uint8_t, 16>& key) {
  key_ = key;
  has_key_ = true;
}

void GcmDecryptor::set_key(const std::vector<uint8_t>& key) {
  if (key.size() == 16) {
    std::copy(key.begin(), key.end(), key_.begin());
    has_key_ = true;
  }
}

bool GcmDecryptor::decrypt(const uint8_t* iv, const uint8_t* cipher, size_t cipher_len,
                           std::vector<uint8_t>& plain_out) const {
  plain_out.resize(cipher_len);

#if defined(USE_ESP8266_FRAMEWORK_ARDUINO) || defined(USE_ESP8266) || defined(ESP8266)

  std::memcpy(plain_out.data(), cipher, cipher_len);
  br_gcm_context gcm_ctx;
  br_aes_ct_ctr_keys bc;
  br_aes_ct_ctr_init(&bc, key_.data(), key_.size());
  br_gcm_init(&gcm_ctx, &bc.vtable, br_ghash_ctmul32);
  br_gcm_reset(&gcm_ctx, iv, 12);
  br_gcm_flip(&gcm_ctx);
  br_gcm_run(&gcm_ctx, 0, plain_out.data(), cipher_len);
  return true;

// ESP_IDF_VERSION_VAL(6,0,0) == 0x60000; written as literal to avoid expansion errors when the macro is undefined
#elif defined(USE_ESP32) && defined(ESP_IDF_VERSION) && (ESP_IDF_VERSION >= 0x60000)

  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attributes, static_cast<psa_key_bits_t>(key_.size() * 8));
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
  psa_set_key_algorithm(&attributes, PSA_ALG_GCM);

  mbedtls_svc_key_id_t key_id;
  bool ok = false;
  if (psa_import_key(&attributes, key_.data(), key_.size(), &key_id) == PSA_SUCCESS) {
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    if (psa_aead_decrypt_setup(&op, key_id, PSA_ALG_GCM) == PSA_SUCCESS &&
        psa_aead_set_nonce(&op, iv, 12) == PSA_SUCCESS) {
      size_t outlen = 0;
      if (psa_aead_update(&op, cipher, cipher_len, plain_out.data(), cipher_len, &outlen) == PSA_SUCCESS &&
          outlen == cipher_len) {
        ok = true;
      }
    }
    psa_aead_abort(&op);
    psa_destroy_key(key_id);
  }
  if (!ok) {
    Logger::log(LogLevel::ERROR, "PSA decryption failed");
  }
  return ok;

#else

  mbedtls_gcm_context gcm_ctx;
  mbedtls_gcm_init(&gcm_ctx);
  mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key_.data(),
                     static_cast<unsigned int>(key_.size() * 8));
  mbedtls_gcm_starts(&gcm_ctx, MBEDTLS_GCM_DECRYPT, iv, 12);
  size_t outlen = 0;
  const int ret = mbedtls_gcm_update(&gcm_ctx, cipher, cipher_len,
                                     plain_out.data(), cipher_len, &outlen);
  mbedtls_gcm_free(&gcm_ctx);
  if (ret != 0) {
    Logger::log(LogLevel::ERROR, "mbedTLS decryption failed: %d", ret);
    return false;
  }
  return true;

#endif
}

}  // namespace dlms_parser
