#include "apdu_handler.h"
#include "log.h"
#include "utils.h"
#include <cstring>

namespace dlms_parser {

bool ApduHandler::parse(const std::span<uint8_t> buf, const AxdrPayloadCallback& cb) const {
  if (auto [offset, length] = unwrap_in_place(buf); length > 0) {
    cb(std::span<const uint8_t>(buf.data() + offset, length));
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// In-place unwrap: sequential pipeline replacing recursive parse().
// Scans for known APDU tag, transforms in-place, loops until AXDR is exposed.
// ---------------------------------------------------------------------------
ApduHandler::UnwrapResult ApduHandler::unwrap_in_place(const std::span<uint8_t> buf_span) const {
  constexpr int MAX_ITERATIONS = 4;  // GBT → cipher → DATA-NOTIFICATION → AXDR
  uint8_t* const buf = buf_span.data();
  size_t len = buf_span.size();

  for (int iter = 0; iter < MAX_ITERATIONS; iter++) {
    // Scan for first known tag
    size_t tag_pos = 0;
    bool found = false;
    for (size_t i = 0; i < len; i++) {
      if (const uint8_t tag = buf[i];
          tag == DLMS_APDU_GENERAL_BLOCK_TRANSFER ||
          tag == DLMS_APDU_DATA_NOTIFICATION ||
          tag == DLMS_APDU_GENERAL_GLO_CIPHERING ||
          tag == DLMS_APDU_GENERAL_DED_CIPHERING ||
          tag == DLMS_DATA_TYPE_ARRAY ||
          tag == DLMS_DATA_TYPE_STRUCTURE) {
        tag_pos = i;
        found = true;
        break;
      }
    }
    if (!found) {
      Logger::log(LogLevel::WARNING, "No supported APDU tag found in buffer");
      return {0, 0};
    }

    // Shift to tag position if needed
    if (tag_pos > 0) {
      len -= tag_pos;
      std::memmove(buf, buf + tag_pos, len);
    }

    const uint8_t tag = buf[0];

    // --- Raw AXDR (0x01/0x02): done
    if (tag == DLMS_DATA_TYPE_ARRAY || tag == DLMS_DATA_TYPE_STRUCTURE) {
      Logger::log(LogLevel::DEBUG, "Found raw AXDR %s (0x%02X) - no APDU wrapper",
                  tag == DLMS_DATA_TYPE_ARRAY ? "ARRAY" : "STRUCTURE", tag);
      return {0, len};
    }

    // --- DATA-NOTIFICATION (0x0F): strip header, return AXDR
    if (tag == DLMS_APDU_DATA_NOTIFICATION) {
      Logger::log(LogLevel::DEBUG, "Found DATA-NOTIFICATION (0x0F)");
      size_t pos = 1;
      if (pos + 4 > len) return {0, 0};
      pos += 4;  // Long-Invoke-ID

      // DLMS Green Book: date-time is an AXDR-encoded optional OCTET STRING.
      // Per spec only two encodings exist:
      //   0x00                  - NullData (absent)
      //   0x09 <len> <data...>  - tagged OCTET STRING (e.g. Kaifa meters)
      // In practice many meters (Iskra, Landis+Gyr, Kamstrup, Salzburg, etc.)
      // send it as a bare length + data without the 0x09 tag prefix:
      //   0x0C <12 bytes>       - untagged, length=12 directly
      if (pos >= len) return {0, 0};
      const uint8_t dt_tag = buf[pos++];
      if (dt_tag == 0x09) {
        // Tagged OCTET_STRING: length byte + data
        if (pos >= len) return {0, 0};
        const uint8_t dt_len = buf[pos++];
        if (pos + dt_len > len) return {0, 0};
        pos += dt_len;
      } else if (dt_tag != 0x00) {
        // Untagged: dt_tag is the length (typically 0x0C = 12)
        if (pos + dt_tag > len) return {0, 0};
        pos += dt_tag;
      }

      if (pos >= len) return {0, 0};
      return {pos, len - pos};
    }

    // --- General-Block-Transfer (0xE0): reassemble blocks in-place
    // Block format: E0 [ctrl:1] [block_num:2] [block_num_ack:2] [BER_len] [data...]
    if (tag == DLMS_APDU_GENERAL_BLOCK_TRANSFER) {
      Logger::log(LogLevel::DEBUG, "Found General-Block-Transfer (0xE0)");
      size_t read_pos = 0;
      size_t write_pos = 0;

      while (read_pos < len && buf[read_pos] == DLMS_APDU_GENERAL_BLOCK_TRANSFER) {
        if (read_pos + 6 > len) {
          Logger::log(LogLevel::WARNING, "GBT: truncated block header");
          return {0, 0};
        }
        const uint8_t ctrl = buf[read_pos + 1];
        const bool is_last = (ctrl & 0x80U) != 0;
        // BER length starts at offset 6 within the block
        size_t ber_pos = read_pos + 6;
        const uint32_t block_len = utils::read_ber_length(std::span<const uint8_t>{buf, len}, ber_pos);

        if (ber_pos + block_len > len) {
          Logger::log(LogLevel::WARNING, "GBT: block truncated");
          return {0, 0};
        }

        std::memmove(buf + write_pos, buf + ber_pos, block_len);
        write_pos += block_len;
        read_pos = ber_pos + block_len;

        if (is_last) break;
      }

      if (write_pos == 0) {
        Logger::log(LogLevel::WARNING, "GBT: no payload after reassembly");
        return {0, 0};
      }
      Logger::log(LogLevel::DEBUG, "GBT: reassembled %zu bytes", write_pos);
      len = write_pos;
      continue;  // re-enter loop to process reassembled content
    }

    // --- Ciphered APDU (0xDB/0xDF): decrypt in-place
    if (tag == DLMS_APDU_GENERAL_GLO_CIPHERING || tag == DLMS_APDU_GENERAL_DED_CIPHERING) {
      Logger::log(LogLevel::DEBUG, "Found ciphered APDU (0x%02X)", tag);

      if (!this->decryptor_ || !this->decryptor_->decryption_key()) {
        Logger::log(LogLevel::WARNING, "Encrypted APDU received but no decryption key is set");
        return {0, 0};
      }

      size_t pos = 1;
      // System title
      if (pos >= len) return {0, 0};
      const uint8_t st_len = buf[pos++];
      if (pos + st_len > len || st_len != DLMS_SYSTITLE_LENGTH) return {0, 0};
      // Build IV: systitle(8) + frame_counter(4) — copy to stack before buf is modified
      uint8_t iv[DLMS_IV_LENGTH];
      std::memcpy(iv, buf + pos, st_len);
      pos += st_len;

      // BER length
      const uint32_t cipher_len = utils::read_ber_length(std::span<const uint8_t>{buf, len}, pos);
      if (cipher_len == 0) return {0, 0};

      // Security control byte
      if (pos >= len) return {0, 0};
      const uint8_t security_control = buf[pos++];
      const bool has_auth_tag = (security_control & 0x10U) != 0;
      const uint32_t tag_len = has_auth_tag ? DLMS_GCM_TAG_LENGTH : 0;

      // Frame counter → last 4 bytes of IV
      if (pos + DLMS_FRAME_COUNTER_LENGTH > len) return {0, 0};
      std::memcpy(iv + DLMS_SYSTITLE_LENGTH, buf + pos, DLMS_FRAME_COUNTER_LENGTH);
      pos += DLMS_FRAME_COUNTER_LENGTH;

      if (cipher_len < DLMS_LENGTH_CORRECTION + tag_len) return {0, 0};
      const uint32_t payload_len = cipher_len - DLMS_LENGTH_CORRECTION - tag_len;
      if (pos + payload_len + tag_len > len) return {0, 0};

      // Build AAD and tag spans for GCM.
      // AAD = security_control(1) + authentication_key(16), per DLMS Green Book.
      // Tag verification only happens when auth bit is set AND auth key is provided.
      uint8_t aad[17];
      size_t aad_len = 0;
      std::span<const uint8_t> gcm_tag;

      if (has_auth_tag && this->decryptor_->auth_key()) {
        aad[0] = security_control;
        std::memcpy(aad + 1, this->decryptor_->auth_key()->data(), 16);
        aad_len = 17;
        gcm_tag = std::span<const uint8_t>(buf + pos + payload_len, DLMS_GCM_TAG_LENGTH);
      }

      if (!this->decryptor_->decrypt_in_place(
              iv, std::span(buf + pos, payload_len),
              std::span<const uint8_t>(aad, aad_len), gcm_tag)) {
        Logger::log(LogLevel::ERROR, "Decryption failed (auth tag mismatch?)");
        return {0, 0};
      }
      std::memmove(buf, buf + pos, payload_len);
      Logger::log(LogLevel::DEBUG, "Decrypted %u bytes", payload_len);
      len = payload_len;
      continue;  // re-enter loop to process decrypted content
    }
  }

  Logger::log(LogLevel::WARNING, "APDU unwrap: exceeded max iterations");
  return {0, 0};
}

}  // namespace dlms_parser
