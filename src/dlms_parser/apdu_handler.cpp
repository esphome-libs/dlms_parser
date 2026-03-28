#include "apdu_handler.h"
#include "log.h"
#include "utils.h"
#include <cstring>

namespace dlms_parser {

bool ApduHandler::parse(const uint8_t* buf, size_t len, AxdrPayloadCallback cb) const {
  for (size_t pos = 0; pos < len; pos++) {
    const uint8_t tag = buf[pos];
    const uint8_t* rest = buf + pos + 1;
    const size_t rest_len = len - pos - 1;

    if (tag == DLMS_APDU_GENERAL_BLOCK_TRANSFER) {
      Logger::log(LogLevel::DEBUG, "Found General-Block-Transfer (0xE0) at offset %zu", pos);
      return parse_general_block_transfer_(buf + pos, len - pos, cb);
    }
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

  // BER length
  const uint32_t cipher_len = utils::read_ber_length(buf, pos, len);
  if (cipher_len == 0) return false;

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

bool ApduHandler::parse_general_block_transfer_(const uint8_t* buf, size_t len,
                                                 AxdrPayloadCallback cb) const {
  // GBT block format: E0 [ctrl:1] [block_num:2] [block_num_ack:2] [BER_len] [data...]
  // Reassemble all blocks, then recurse into parse().
  std::vector<uint8_t> reassembled;
  size_t pos = 0;

  while (pos < len && buf[pos] == DLMS_APDU_GENERAL_BLOCK_TRANSFER) {
    if (pos + 6 > len) {
      Logger::log(LogLevel::WARNING, "GBT: truncated block header at offset %zu", pos);
      return false;
    }
    const uint8_t ctrl = buf[pos + 1];
    const bool is_last = (ctrl & 0x80U) != 0;
    const uint16_t block_num = static_cast<uint16_t>(buf[pos + 2] << 8 | buf[pos + 3]);
    // pos+4..pos+5: block_num_ack (skip)
    size_t ber_pos = pos + 6;
    const uint32_t block_len = utils::read_ber_length(buf, ber_pos, len);

    if (ber_pos + block_len > len) {
      Logger::log(LogLevel::WARNING, "GBT: block %u truncated (need %u, have %zu)",
                  block_num, block_len, len - ber_pos);
      return false;
    }

    Logger::log(LogLevel::DEBUG, "GBT block %u: %u bytes%s", block_num, block_len,
                is_last ? " (last)" : "");
    reassembled.insert(reassembled.end(), buf + ber_pos, buf + ber_pos + block_len);
    pos = ber_pos + block_len;

    if (is_last) break;
  }

  if (reassembled.empty()) {
    Logger::log(LogLevel::WARNING, "GBT: no payload after reassembly");
    return false;
  }

  Logger::log(LogLevel::DEBUG, "GBT: reassembled %zu bytes from blocks", reassembled.size());
  return parse(reassembled.data(), reassembled.size(), cb);
}

// ---------------------------------------------------------------------------
// In-place unwrap: sequential pipeline replacing recursive parse().
// Scans for known APDU tag, transforms in-place, loops until AXDR is exposed.
// ---------------------------------------------------------------------------
ApduHandler::UnwrapResult ApduHandler::unwrap_in_place(uint8_t* buf, size_t len) const {
  constexpr int MAX_ITERATIONS = 4;  // GBT → cipher → DATA-NOTIFICATION → AXDR

  for (int iter = 0; iter < MAX_ITERATIONS; iter++) {
    // Scan for first known tag
    size_t tag_pos = 0;
    bool found = false;
    for (size_t i = 0; i < len; i++) {
      const uint8_t tag = buf[i];
      if (tag == DLMS_APDU_GENERAL_BLOCK_TRANSFER ||
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
      Logger::log(LogLevel::DEBUG, "Found raw AXDR %s (0x%02X) — no APDU wrapper",
                  tag == DLMS_DATA_TYPE_ARRAY ? "ARRAY" : "STRUCTURE", tag);
      return {0, len};
    }

    // --- DATA-NOTIFICATION (0x0F): strip header, return AXDR
    if (tag == DLMS_APDU_DATA_NOTIFICATION) {
      Logger::log(LogLevel::DEBUG, "Found DATA-NOTIFICATION (0x0F)");
      size_t pos = 1;
      if (pos + 4 > len) return {0, 0};
      pos += 4;  // Long-Invoke-ID

      if (pos >= len) return {0, 0};
      const uint8_t has_datetime = buf[pos++];
      if (has_datetime != 0x00) {
        Logger::log(LogLevel::VERBOSE, "Datetime flag 0x%02X — skipping 12-byte datetime", has_datetime);
        if (pos + 12 > len) return {0, 0};
        pos += 12;
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
        const uint32_t block_len = utils::read_ber_length(buf, ber_pos, len);

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

      if (!this->decryptor_ || !this->decryptor_->has_key()) {
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
      const uint32_t cipher_len = utils::read_ber_length(buf, pos, len);
      if (cipher_len == 0) return {0, 0};

      // Security control byte (skip)
      if (pos >= len) return {0, 0};
      pos++;

      // Frame counter → last 4 bytes of IV
      if (pos + DLMS_FRAME_COUNTER_LENGTH > len) return {0, 0};
      std::memcpy(iv + DLMS_SYSTITLE_LENGTH, buf + pos, DLMS_FRAME_COUNTER_LENGTH);
      pos += DLMS_FRAME_COUNTER_LENGTH;

      if (cipher_len < DLMS_LENGTH_CORRECTION) return {0, 0};
      const uint32_t payload_len = cipher_len - DLMS_LENGTH_CORRECTION;
      if (pos + payload_len > len) return {0, 0};

      // Decrypt: read from buf+pos, write to buf+0
      const size_t plain_len = this->decryptor_->decrypt_in_place(iv, buf, pos, payload_len);
      if (plain_len == 0) {
        Logger::log(LogLevel::ERROR, "Decryption failed");
        return {0, 0};
      }
      Logger::log(LogLevel::DEBUG, "Decrypted %zu bytes", plain_len);
      len = plain_len;
      continue;  // re-enter loop to process decrypted content
    }
  }

  Logger::log(LogLevel::WARNING, "APDU unwrap: exceeded max iterations");
  return {0, 0};
}

}  // namespace dlms_parser
