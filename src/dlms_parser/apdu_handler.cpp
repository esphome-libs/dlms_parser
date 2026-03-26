#include "apdu_handler.h"
#include "log.h"
#include <cstring>

namespace dlms_parser {

bool ApduHandler::parse(const uint8_t* buf, size_t len, AxdrPayloadCallback cb) const {
  for (size_t pos = 0; pos < len; pos++) {
    const uint8_t tag = buf[pos];
    const uint8_t* rest = buf + pos + 1;
    const size_t rest_len = len - pos - 1;

    if (tag == DLMS_APDU_DATA_NOTIFICATION) {
      Logger::log(LogLevel::DEBUG, "Found DATA-NOTIFICATION (0x0F) at offset %zu", pos);
      return parse_data_notification_(rest, rest_len, cb);
    }
    if (tag == DLMS_APDU_GENERAL_GLO_CIPHERING || tag == DLMS_APDU_GENERAL_DED_CIPHERING) {
      Logger::log(LogLevel::DEBUG, "Found ciphered APDU (0x%02X) at offset %zu", tag, pos);
      return parse_ciphered_apdu_(rest, rest_len, tag, cb);
    }
    if (tag == DLMS_DATA_TYPE_ARRAY || tag == DLMS_DATA_TYPE_STRUCTURE) {
      Logger::log(LogLevel::DEBUG, "Found raw AXDR %s (0x%02X) at offset %zu — no APDU wrapper",
                  tag == DLMS_DATA_TYPE_ARRAY ? "ARRAY" : "STRUCTURE", tag, pos);
      cb(buf + pos, len - pos);
      return true;
    }
  }

  Logger::log(LogLevel::WARNING, "No supported APDU tag found in buffer");
  return false;
}

bool ApduHandler::parse_data_notification_(const uint8_t* buf, size_t len,
                                           AxdrPayloadCallback cb) const {
  if (len < 5) {
    Logger::log(LogLevel::WARNING, "DATA-NOTIFICATION payload too short (%zu bytes)", len);
    return false;
  }

  size_t pos = 0;

  // Long-Invoke-ID-And-Priority (4 bytes)
  pos += 4;

  // Date-Time presence flag (1 byte): 0x00 = absent, anything else = 12-byte datetime follows
  const uint8_t has_datetime = buf[pos++];
  if (has_datetime != 0x00) {
    Logger::log(LogLevel::VERBOSE, "Datetime flag 0x%02X — skipping 12-byte datetime", has_datetime);
    if (pos + 12 > len) {
      Logger::log(LogLevel::WARNING, "Buffer too short to skip datetime object");
      return false;
    }
    pos += 12;
  }

  if (pos >= len) {
    Logger::log(LogLevel::WARNING, "No AXDR payload after DATA-NOTIFICATION header");
    return false;
  }

  cb(buf + pos, len - pos);
  return true;
}

bool ApduHandler::parse_ciphered_apdu_(const uint8_t* buf, size_t len, uint8_t /*tag*/,
                                       AxdrPayloadCallback cb) const {
  if (!decryptor_ || !decryptor_->has_key()) {
    Logger::log(LogLevel::WARNING, "Encrypted APDU received but no decryption key is set");
    return false;
  }

  size_t pos = 0;

  // System title length byte (must be 8)
  if (pos >= len || buf[pos] != DLMS_SYSTITLE_LENGTH) {
    Logger::log(LogLevel::WARNING, "Unexpected system title length byte: 0x%02X",
                pos < len ? buf[pos] : 0xFF);
    return false;
  }
  pos++;

  // System title (8 bytes) → first 8 bytes of the 12-byte IV
  if (pos + DLMS_SYSTITLE_LENGTH > len) return false;
  uint8_t iv[DLMS_IV_LENGTH];
  std::memcpy(iv, buf + pos, DLMS_SYSTITLE_LENGTH);
  pos += DLMS_SYSTITLE_LENGTH;

  // BER length field: single byte if <= 127, otherwise 0x8N + N bytes
  if (pos >= len) return false;
  const uint8_t len_byte = buf[pos++];
  uint32_t cipher_len = len_byte;
  if (len_byte > DLMS_LENGTH_SINGLE_BYTE_MAX) {
    const uint8_t num_bytes = len_byte & 0x7F;
    cipher_len = 0;
    for (uint8_t i = 0; i < num_bytes; i++) {
      if (pos >= len) return false;
      cipher_len = (cipher_len << 8) | buf[pos++];
    }
  }

  // Security control byte (1 byte, informational — skip)
  if (pos >= len) return false;
  pos++;

  // Frame counter (4 bytes) → last 4 bytes of IV
  if (pos + DLMS_FRAME_COUNTER_LENGTH > len) return false;
  std::memcpy(iv + DLMS_SYSTITLE_LENGTH, buf + pos, DLMS_FRAME_COUNTER_LENGTH);
  pos += DLMS_FRAME_COUNTER_LENGTH;

  // The length field includes the security control byte and frame counter (5 bytes total)
  if (cipher_len < DLMS_LENGTH_CORRECTION) {
    Logger::log(LogLevel::WARNING, "Cipher length field too small: %u", cipher_len);
    return false;
  }
  const uint32_t payload_len = cipher_len - DLMS_LENGTH_CORRECTION;

  if (pos + payload_len > len) {
    Logger::log(LogLevel::WARNING, "Buffer too short for ciphertext (need %u, have %zu)", payload_len,
                len - pos);
    return false;
  }

  std::vector<uint8_t> plain;
  if (!decryptor_->decrypt(iv, buf + pos, payload_len, plain)) {
    Logger::log(LogLevel::ERROR, "Decryption failed");
    return false;
  }

  // Decrypted payload begins with the inner APDU tag (typically 0x0F) — recurse
  return parse(plain.data(), plain.size(), cb);
}

}  // namespace dlms_parser
