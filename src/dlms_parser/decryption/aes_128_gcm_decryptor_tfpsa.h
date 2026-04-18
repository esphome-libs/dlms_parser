#pragma once

#include <psa/crypto.h>
#include "aes_128_gcm_decryptor.h"
#include "../utils.h"

namespace dlms_parser {

class Aes128GcmDecryptorTfPsa : public Aes128GcmDecryptor, NonCopyableAndNonMovable {
  psa_key_id_t key_id_{};
  bool psa_initialized_{ false };

  void destroy_key() {
    if (key_id_ != PSA_KEY_ID_NULL) {
      psa_destroy_key(key_id_);
      key_id_ = PSA_KEY_ID_NULL;
    }
  }

public:
  Aes128GcmDecryptorTfPsa() {
    if (psa_crypto_init() == PSA_SUCCESS) {
      psa_initialized_ = true;
    }
  }

  ~Aes128GcmDecryptorTfPsa() override {
    destroy_key();
  }

  void set_decryption_key(const Aes128GcmDecryptionKey& key) override {
    if (!psa_initialized_) {
      Logger::log(LogLevel::ERROR, "PSA crypto not initialized");
      decryption_key_.reset();
      return;
    }

    destroy_key();

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(PSA_ALG_GCM, 4));

    if (psa_import_key(&attributes, key.data(), 16, &key_id_) != PSA_SUCCESS) {
      Logger::log(LogLevel::ERROR, "Failed to import PSA key");
      decryption_key_.reset();
      return;
    }

    decryption_key_ = key;
  }

  bool decrypt_in_place(std::span<const uint8_t> iv,
                        std::span<uint8_t> cipher,
                        std::span<const uint8_t> aad,
                        std::span<const uint8_t> tag) override {
    if (!psa_initialized_) {
      Logger::log(LogLevel::ERROR, "PSA crypto is not initialized");
      return false;
    }

    if (!decryption_key_ || key_id_ == PSA_KEY_ID_NULL) {
      Logger::log(LogLevel::ERROR, "Decryption key is not set");
      return false;
    }

    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;

    const auto abort_and_fail = [&](const char* what, const psa_status_t status) -> bool {
      Logger::log(LogLevel::ERROR, "%s failed: %ld", what, static_cast<long>(status));
      const psa_status_t abort_status = psa_aead_abort(&op);
      if (abort_status != PSA_SUCCESS) {
        Logger::log(LogLevel::ERROR, "psa_aead_abort failed: %ld", static_cast<long>(abort_status));
      }
      return false;
      };

    // Use the exact tag length so PSA computes/verifies the correct truncated tag.
    // DLMS uses 12-byte GCM tags; PSA_ALG_GCM defaults to 16 and would reject shorter tags.
    const psa_algorithm_t alg = tag.empty()
      ? PSA_ALG_GCM
      : PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, tag.size());
    psa_status_t status = psa_aead_decrypt_setup(&op, key_id_, alg);
    if (status != PSA_SUCCESS) {
      return abort_and_fail("psa_aead_decrypt_setup", status);
    }

    status = psa_aead_set_nonce(&op, iv.data(), iv.size());
    if (status != PSA_SUCCESS) {
      return abort_and_fail("psa_aead_set_nonce", status);
    }

    if (!aad.empty()) {
      status = psa_aead_update_ad(&op, aad.data(), aad.size());
      if (status != PSA_SUCCESS) {
        return abort_and_fail("psa_aead_update_ad", status);
      }
    }

    size_t produced = 0;
    status = psa_aead_update(/* operation     */ &op,
                             /* input         */ cipher.data(),
                             /* input_length  */ cipher.size(),
                             /* output        */ cipher.data(),
                             /* output_size   */ cipher.size(),
                             /* output_length */ &produced);
    if (status != PSA_SUCCESS) {
      return abort_and_fail("psa_aead_update", status);
    }

    if (produced != cipher.size()) {
      Logger::log(LogLevel::ERROR, "Unexpected plaintext size from psa_aead_update: %zu != %zu", produced, cipher.size());
      psa_aead_abort(&op);
      return false;
    }

    if (!tag.empty()) {
      Logger::log(LogLevel::VERY_VERBOSE, "Decrypt using tag");

      size_t tail_len = 0;
      status = psa_aead_verify(/* operation      */ &op,
                               /* plaintext      */ nullptr,
                               /* plaintext_size */ 0,
                               /* plaintext_len  */ &tail_len,
                               /* tag            */ tag.data(),
                               /* tag_len        */ tag.size());
      if (status != PSA_SUCCESS) {
        return abort_and_fail("psa_aead_verify", status);
      }

      if (tail_len != 0) {
        Logger::log(LogLevel::ERROR, "Unexpected trailing plaintext from psa_aead_verify: %zu", tail_len);
        return false;
      }

      return true;
    }

    Logger::log(LogLevel::VERY_VERBOSE, "Decrypt without tag. No data corruption verification");

    status = psa_aead_abort(&op);
    if (status != PSA_SUCCESS) {
      Logger::log(LogLevel::ERROR, "psa_aead_abort failed: %ld", static_cast<long>(status));
      return false;
    }

    return true;
  }
};

}
