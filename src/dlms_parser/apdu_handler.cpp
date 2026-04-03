#include "apdu_handler.h"
#include "log.h"
#include "utils.h"
#include <algorithm>
#include <array>

namespace dlms_parser {

static bool is_known_tag(const uint8_t b) {
  switch (b) {
  case DLMS_APDU_GENERAL_BLOCK_TRANSFER:
  case DLMS_APDU_DATA_NOTIFICATION:
  case DLMS_APDU_GENERAL_GLO_CIPHERING:
  case DLMS_APDU_GENERAL_DED_CIPHERING:
  case DLMS_DATA_TYPE_ARRAY:
  case DLMS_DATA_TYPE_STRUCTURE:
    return true;
  default:
    return false;
  }
}

std::span<uint8_t> parse_apdu_in_place(std::span<uint8_t> buf, Aes128GcmDecryptor* decryptor) {
  constexpr int MAX_ITERATIONS = 4;  // GBT → cipher → DATA-NOTIFICATION → AXDR
  for (int iter = 0; iter < MAX_ITERATIONS; iter++) {
    // Scan for first known tag
    const auto it = std::ranges::find_if(buf, is_known_tag);
    if (it == buf.end()) {
      Logger::log(LogLevel::WARNING, "No supported APDU tag found in buffer");
      return {};
    }

    buf = buf.subspan(static_cast<size_t>(it - buf.begin()));

    const uint8_t tag = buf[0];

    // --- Raw AXDR (0x01/0x02): done
    if (tag == DLMS_DATA_TYPE_ARRAY || tag == DLMS_DATA_TYPE_STRUCTURE) {
      Logger::log(LogLevel::DEBUG, "Found raw AXDR %s (0x%02X) - no APDU wrapper",
                  tag == DLMS_DATA_TYPE_ARRAY ? "ARRAY" : "STRUCTURE", tag);
      return buf;
    }

    // --- DATA-NOTIFICATION (0x0F): strip header, return AXDR
    if (tag == DLMS_APDU_DATA_NOTIFICATION) {
      Logger::log(LogLevel::DEBUG, "Found DATA-NOTIFICATION (0x0F)");
      size_t pos = 1;
      if (pos + 4 > buf.size()) return {};
      pos += 4;  // Long-Invoke-ID

      // DLMS Green Book: date-time is an AXDR-encoded optional OCTET STRING.
      // Per spec only two encodings exist:
      //   0x00                  - NullData (absent)
      //   0x09 <len> <data...>  - tagged OCTET STRING (e.g. Kaifa meters)
      // In practice many meters (Iskra, Landis+Gyr, Kamstrup, Salzburg, etc.)
      // send it as a bare length + data without the 0x09 tag prefix:
      //   0x0C <12 bytes>       - untagged, length=12 directly
      if (pos >= buf.size()) return {};
      const uint8_t dt_tag = buf[pos++];
      if (dt_tag == 0x09) {
        // Tagged OCTET_STRING: length byte + data
        if (pos >= buf.size()) return {};
        const uint8_t dt_len = buf[pos++];
        if (pos + dt_len > buf.size()) return {};
        pos += dt_len;
      } else if (dt_tag != 0x00) {
        // Untagged: dt_tag is the length (typically 0x0C = 12)
        if (pos + dt_tag > buf.size()) return {};
        pos += dt_tag;
      }

      if (pos >= buf.size()) return {};
      return buf.subspan(pos);
    }

    // --- General-Block-Transfer (0xE0): reassemble blocks in-place
    // Block format: E0 [ctrl:1] [block_num:2] [block_num_ack:2] [BER_len] [data...]
    if (tag == DLMS_APDU_GENERAL_BLOCK_TRANSFER) {
      Logger::log(LogLevel::DEBUG, "Found General-Block-Transfer (0xE0)");
      size_t read_pos = 0;
      size_t write_pos = 0;

      while (read_pos < buf.size() && buf[read_pos] == DLMS_APDU_GENERAL_BLOCK_TRANSFER) {
        if (read_pos + 6 > buf.size()) {
          Logger::log(LogLevel::WARNING, "GBT: truncated block header");
          return {};
        }
        const uint8_t ctrl = buf[read_pos + 1];
        const bool is_last = (ctrl & 0x80U) != 0;
        // BER length starts at offset 6 within the block
        size_t ber_pos = read_pos + 6;
        const uint32_t block_len = read_ber_length(buf, ber_pos);

        if (ber_pos + block_len > buf.size()) {
          Logger::log(LogLevel::WARNING, "GBT: block truncated");
          return {};
        }

        std::ranges::copy(buf.subspan(ber_pos, block_len), buf.subspan(write_pos).begin());
        write_pos += block_len;
        read_pos = ber_pos + block_len;

        if (is_last) break;
      }

      if (write_pos == 0) {
        Logger::log(LogLevel::WARNING, "GBT: no payload after reassembly");
        return {};
      }
      Logger::log(LogLevel::DEBUG, "GBT: reassembled %zu bytes", write_pos);
      buf = buf.first(write_pos);
      continue;  // re-enter loop to process reassembled content
    }

    // --- Ciphered APDU (0xDB/0xDF): decrypt in-place
    if (tag == DLMS_APDU_GENERAL_GLO_CIPHERING || tag == DLMS_APDU_GENERAL_DED_CIPHERING) {
      Logger::log(LogLevel::DEBUG, "Found ciphered APDU (0x%02X)", tag);

      if (!decryptor || !decryptor->decryption_key()) {
        Logger::log(LogLevel::WARNING, "Encrypted APDU received but no decryption key is set");
        return {};
      }

      size_t pos = 1;
      // System title
      if (pos >= buf.size()) return {};
      const uint8_t st_len = buf[pos++];
      if (pos + st_len > buf.size() || st_len != DLMS_SYSTITLE_LENGTH) return {};
      // Build IV: systitle(8) + frame_counter(4) — copy to stack before buf is modified
      std::array<uint8_t, DLMS_IV_LENGTH> iv{};
      std::ranges::copy(buf.subspan(pos, st_len), iv.begin());
      pos += st_len;

      // BER length
      const uint32_t cipher_len = read_ber_length(buf, pos);
      if (cipher_len == 0) return {};

      // Security control byte
      if (pos >= buf.size()) return {};
      const uint8_t security_control = buf[pos++];
      const bool has_auth_tag = (security_control & 0x10U) != 0;
      const uint32_t tag_len = has_auth_tag ? DLMS_GCM_TAG_LENGTH : 0;

      // Frame counter → last 4 bytes of IV
      if (pos + DLMS_FRAME_COUNTER_LENGTH > buf.size()) return {};
      std::ranges::copy(buf.subspan(pos, DLMS_FRAME_COUNTER_LENGTH), iv.begin() + DLMS_SYSTITLE_LENGTH);
      pos += DLMS_FRAME_COUNTER_LENGTH;

      if (cipher_len < DLMS_LENGTH_CORRECTION + tag_len) return {};
      const uint32_t payload_len = cipher_len - DLMS_LENGTH_CORRECTION - tag_len;
      if (pos + payload_len + tag_len > buf.size()) return {};

      // Build AAD and tag spans for GCM.
      // AAD = security_control(1) + authentication_key(16), per DLMS Green Book.
      // Tag verification only happens when auth bit is set AND auth key is provided.
      std::array<uint8_t, 17> aad{};
      size_t aad_len = 0;
      std::span<const uint8_t> gcm_tag;

      if (has_auth_tag && decryptor->auth_key()) {
        aad[0] = security_control;
        std::copy_n(decryptor->auth_key()->data(), 16, aad.begin() + 1);
        aad_len = 17;
        gcm_tag = buf.subspan(pos + payload_len, DLMS_GCM_TAG_LENGTH);
      }

      if (!decryptor->decrypt_in_place(iv, buf.subspan(pos, payload_len), std::span(aad).first(aad_len), gcm_tag)) {
        Logger::log(LogLevel::ERROR, "Decryption failed (auth tag mismatch?)");
        return {};
      }
      Logger::log(LogLevel::DEBUG, "Decrypted %u bytes", payload_len);
      buf = buf.subspan(pos, payload_len);
      continue;  // re-enter loop to process decrypted content
    }
  }

  Logger::log(LogLevel::WARNING, "APDU unwrap: exceeded max iterations");
  return {};
}

}
