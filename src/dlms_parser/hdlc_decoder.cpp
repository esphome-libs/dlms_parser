#include "hdlc_decoder.h"
#include "log.h"

namespace dlms_parser {

static constexpr uint8_t HDLC_FLAG       = 0x7E;
static constexpr uint8_t HDLC_ESCAPE     = 0x7D;
static constexpr uint8_t HDLC_ESCAPE_XOR = 0x20;
static constexpr uint8_t HDLC_SEG_BIT   = 0x08;  // bit 3 of frame-type byte: "more frames follow"

// After running crc16_x25_check_ over a data region AND then over the two stored CRC
// bytes, the result must equal this constant (from RFC 1662 / hdlcpp).
static constexpr uint16_t FCS16_GOOD_VALUE = 0xF0B8U;

// ---------------------------------------------------------------------------
// Public entry point — handles single frames and segmented multi-frame messages.
// Segmented frames (bit 3 of frame-type byte set) are reassembled by concatenating
// the payload of each frame. The LLC header (0xE6 0xE7/0xE6 0x00) is only stripped
// from the first frame; subsequent frames carry raw continuation data.
// ---------------------------------------------------------------------------
bool HdlcDecoder::decode(const uint8_t* buf, size_t len, std::vector<uint8_t>& apdu_out) const {
  apdu_out.clear();
  bool is_first = true;
  size_t offset = 0;

  do {
    if (offset + 4 > len) {
      Logger::log(LogLevel::WARNING, "HDLC: truncated at offset %zu", offset);
      return false;
    }
    if (buf[offset] != HDLC_FLAG) {
      Logger::log(LogLevel::WARNING, "HDLC: expected 0x7E at offset %zu, got 0x%02X",
                  offset, buf[offset]);
      return false;
    }

    // Use the length field (rather than scanning for 0x7E) to find frame boundaries —
    // this is safe because byte stuffing ensures 0x7E never appears inside frame content.
    const bool   segmented   = (buf[offset + 1] & HDLC_SEG_BIT) != 0;
    const size_t frame_len   = (static_cast<size_t>(buf[offset + 1] & 0x07U) << 8) | buf[offset + 2];
    const size_t frame_total = frame_len + 2;  // add BOP and EOP flags

    if (offset + frame_total > len) {
      Logger::log(LogLevel::WARNING, "HDLC: incomplete frame at offset %zu (need %zu, have %zu)",
                  offset, frame_total, len - offset);
      return false;
    }

    std::vector<uint8_t> chunk;
    if (!decode_one_(buf + offset, frame_total, is_first, chunk)) return false;
    apdu_out.insert(apdu_out.end(), chunk.begin(), chunk.end());

    offset  += frame_total;
    is_first = false;

    if (!segmented) break;
  } while (offset < len);

  if (apdu_out.empty()) {
    Logger::log(LogLevel::WARNING, "HDLC: no payload extracted");
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Single-frame decode: destuff → validate HCS + FCS → strip LLC (first frame only)
// → return payload bytes in chunk_out.
// ---------------------------------------------------------------------------
bool HdlcDecoder::decode_one_(const uint8_t* frame, size_t len,
                               bool is_first, std::vector<uint8_t>& chunk_out) const {
  // Minimum: 0x7E + type(1) + len(1) + dst(1) + src(1) + ctrl(1) + hcs(2) + fcs(2) + 0x7E = 11
  if (len < 11) {
    Logger::log(LogLevel::WARNING, "HDLC: frame too short (%zu bytes)", len);
    return false;
  }
  if (frame[0] != HDLC_FLAG || frame[len - 1] != HDLC_FLAG) {
    Logger::log(LogLevel::WARNING, "HDLC: missing frame delimiters");
    return false;
  }

  // Destuff: remove 0x7D escape bytes from frame[1..len-2].
  // Per HDLC / RFC 1662: 0x7D prefix means the next byte is XOR'd with 0x20.
  std::vector<uint8_t> buf;
  buf.reserve(len - 2);
  {
    bool escaped = false;
    for (size_t i = 1; i < len - 1; ++i) {
      if (frame[i] == HDLC_ESCAPE) {
        escaped = true;
      } else if (escaped) {
        buf.push_back(static_cast<uint8_t>(frame[i] ^ HDLC_ESCAPE_XOR));
        escaped = false;
      } else {
        buf.push_back(frame[i]);
      }
    }
    if (escaped) {
      Logger::log(LogLevel::WARNING, "HDLC: trailing escape byte");
      return false;
    }
  }
  const uint8_t* b    = buf.data();
  const size_t   blen = buf.size();

  if (blen < 2) {
    Logger::log(LogLevel::WARNING, "HDLC: destuffed frame too short");
    return false;
  }

  // Length field (11-bit) must equal the total number of destuffed bytes.
  const size_t frame_len = (static_cast<size_t>(b[0] & 0x07U) << 8) | b[1];
  if (frame_len != blen) {
    Logger::log(LogLevel::WARNING, "HDLC: length mismatch (field=%zu, destuffed=%zu)",
                frame_len, blen);
    return false;
  }

  // Variable-length destination address (starts at b[2]).
  size_t pos = 2;
  const size_t dst_len = address_length_(b + pos, blen - pos);
  if (dst_len == 0) {
    Logger::log(LogLevel::WARNING, "HDLC: invalid destination address");
    return false;
  }
  pos += dst_len;

  // Source address.
  const size_t src_len = address_length_(b + pos, blen - pos);
  if (src_len == 0) {
    Logger::log(LogLevel::WARNING, "HDLC: invalid source address");
    return false;
  }
  pos += src_len;

  // Control byte.
  pos += 1;

  // HCS: covers b[0..pos-1]; valid when CRC run over (b[0..pos+1]) == FCS16_GOOD_VALUE.
  if (pos + 2 > blen) {
    Logger::log(LogLevel::WARNING, "HDLC: frame too short for HCS");
    return false;
  }
  if (crc16_x25_check_(b, pos + 2) != FCS16_GOOD_VALUE) {
    Logger::log(LogLevel::WARNING, "HDLC: HCS error");
    return false;
  }
  pos += 2;

  // FCS: valid when CRC run over the entire destuffed content == FCS16_GOOD_VALUE.
  if (blen < 3) {
    Logger::log(LogLevel::WARNING, "HDLC: frame too short for FCS");
    return false;
  }
  if (crc16_x25_check_(b, blen) != FCS16_GOOD_VALUE) {
    Logger::log(LogLevel::WARNING, "HDLC: FCS error");
    return false;
  }

  const size_t data_end = blen - 2;  // index of FCS low byte

  // Strip LLC header only on the first frame of a (possibly segmented) message.
  // {0xE6, 0xE7, 0x00} meter→reader;  {0xE6, 0xE6, 0x00} reader→meter.
  if (is_first && pos + 3 <= data_end &&
      b[pos] == 0xE6 && (b[pos + 1] == 0xE7 || b[pos + 1] == 0xE6) && b[pos + 2] == 0x00) {
    pos += 3;
  }

  if (pos >= data_end) {
    // No payload in this frame (e.g. U-frame ACK); not an error for multi-frame messages.
    return true;
  }

  chunk_out.assign(b + pos, b + data_end);
  return true;
}

size_t HdlcDecoder::address_length_(const uint8_t* p, size_t remaining) {
  for (size_t i = 0; i < remaining && i < 4; ++i) {
    if (p[i] & 0x01U) return i + 1;  // LSB=1 marks the last address byte
  }
  return 0;
}

// CRC-16/IBM-SDLC (X.25): poly=0x8408, init=0xFFFF, xorout=0xFFFF.
// Running this over (data bytes + the two stored CRC bytes) yields FCS16_GOOD_VALUE for a valid frame.
uint16_t HdlcDecoder::crc16_x25_check_(const uint8_t* data, size_t len) {
  uint16_t crc = 0xFFFFU;
  for (size_t i = 0; i < len; ++i) {
    crc ^= static_cast<uint16_t>(data[i]);
    for (int k = 0; k < 8; ++k) {
      crc = (crc & 1U) ? static_cast<uint16_t>((crc >> 1) ^ 0x8408U) : static_cast<uint16_t>(crc >> 1);
    }
  }
  // Return raw register value (no xor-out) for "good value" verification:
  // when CRC is run over (data + stored_FCS), the raw register equals FCS16_GOOD_VALUE.
  return crc;
}

}  // namespace dlms_parser
