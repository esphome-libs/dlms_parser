#include "hdlc_decoder.h"
#include "log.h"
#include <cstring>

namespace dlms_parser {

static constexpr uint8_t HDLC_FLAG       = 0x7E;
// static constexpr uint8_t HDLC_ESCAPE     = 0x7D;   // byte-stuffing disabled, see decode_one_()
// static constexpr uint8_t HDLC_ESCAPE_XOR = 0x20;
static constexpr uint8_t HDLC_SEG_BIT    = 0x08;  // bit 3 of frame-type byte: "more frames follow"

// ---------------------------------------------------------------------------
// check() — stateless frame completeness check
// Walks frame boundaries using length fields. Returns COMPLETE when the last
// frame in the buffer has no segmentation bit set and no more data follows.
// ---------------------------------------------------------------------------
FrameStatus HdlcDecoder::check(const std::span<const uint8_t> buf) {
  if (buf.size() < 2 || buf[0] != HDLC_FLAG) return FrameStatus::ERROR;

  size_t offset = 0;
  while (offset < buf.size()) {
    if (buf[offset] != HDLC_FLAG) return FrameStatus::ERROR;
    if (offset + 3 > buf.size()) return FrameStatus::NEED_MORE;  // can't read format field yet

    const bool segmented = (buf[offset + 1] & HDLC_SEG_BIT) != 0;
    const size_t frame_len = static_cast<size_t>(buf[offset + 1] & 0x07U) << 8 | buf[offset + 2];
    const size_t frame_total = frame_len + 2;

    if (offset + frame_total > buf.size()) return FrameStatus::NEED_MORE;  // frame incomplete

    // Verify closing flag
    if (buf[offset + frame_total - 1] != HDLC_FLAG) return FrameStatus::ERROR;

    offset += frame_total;

    if (!segmented && offset >= buf.size()) return FrameStatus::COMPLETE;
    // Not segmented but more data follows — continue (GBT multi-frame case)
  }

  return FrameStatus::NEED_MORE;
}

// After running crc16_x25_check_ over a data region AND then over the two stored CRC
// bytes, the result must equal this constant (from RFC 1662 / hdlcpp).
static constexpr uint16_t FCS16_GOOD_VALUE = 0xF0B8U;

size_t HdlcDecoder::address_length_(const std::span<const uint8_t> p) {
  for (size_t i = 0; i < p.size() && i < 4; ++i) {
    if (p[i] & 0x01U) return i + 1;  // LSB=1 marks the last address byte
  }
  return 0;
}

// CRC-16/IBM-SDLC (X.25): poly=0x8408, init=0xFFFF, xorout=0xFFFF.
// Running this over (data bytes + the two stored CRC bytes) yields FCS16_GOOD_VALUE for a valid frame.
uint16_t HdlcDecoder::crc16_x25_check_(const std::span<const uint8_t> data) {
  uint16_t crc = 0xFFFFU;
  for (size_t i = 0; i < data.size(); ++i) {
    crc = crc >> 8 ^ CRC16_X25_TABLE[(crc ^ data[i]) & 0xFF];
  }
  // Return raw register value (no xor-out) for "good value" verification:
  // when CRC is run over (data + stored_FCS), the raw register equals FCS16_GOOD_VALUE.
  return crc;
}

// ---------------------------------------------------------------------------
// In-place decode: extracts and concatenates payloads from all HDLC frames
// in buf, writing them sequentially to buf[0..]. Returns new length, 0 on error.
// ---------------------------------------------------------------------------
size_t HdlcDecoder::decode(const std::span<uint8_t> buf_span) const {
  uint8_t* const buf = buf_span.data();
  const size_t len = buf_span.size();
  size_t read_offset = 0;
  size_t write_offset = 0;
  bool is_first = true;

  do {
    if (read_offset + 4 > len || buf[read_offset] != HDLC_FLAG) {
      Logger::log(LogLevel::WARNING, "HDLC: invalid frame at offset %zu", read_offset);
      return 0;
    }

    const bool segmented = (buf[read_offset + 1] & HDLC_SEG_BIT) != 0;
    const size_t frame_len = static_cast<size_t>(buf[read_offset + 1] & 0x07U) << 8 | buf[read_offset + 2];
    const size_t frame_total = frame_len + 2;

    if (read_offset + frame_total > len) {
      Logger::log(LogLevel::WARNING, "HDLC: incomplete frame at offset %zu", read_offset);
      return 0;
    }

    // Content between the two 7E flags
    const uint8_t* b = buf + read_offset + 1;
    const size_t blen = frame_total - 2;

    if (blen < 9) { // minimum: format(2) + dst(1) + src(1) + ctrl(1) + hcs(2) + fcs(2)
      Logger::log(LogLevel::WARNING, "HDLC: frame too short (%zu bytes)", blen);
      return 0;
    }

    // Skip addresses + control
    size_t pos = 2;
    const size_t dst_len = address_length_({b + pos, blen - pos});
    if (dst_len == 0) return 0;
    pos += dst_len;

    const size_t src_len = address_length_({b + pos, blen - pos});
    if (src_len == 0) return 0;
    pos += src_len;
    pos += 1;  // control byte

    // HCS
    if (pos + 2 > blen) return 0;
    if (!this->skip_crc_check_ && crc16_x25_check_({b, pos + 2}) != FCS16_GOOD_VALUE) {
      Logger::log(LogLevel::WARNING, "HDLC: HCS error");
      return 0;
    }
    pos += 2;

    // FCS
    if (!this->skip_crc_check_ && crc16_x25_check_({b, blen}) != FCS16_GOOD_VALUE) {
      Logger::log(LogLevel::WARNING, "HDLC: FCS error");
      return 0;
    }

    const size_t data_end = blen - 2;

    // Strip LLC on first frame
    if (is_first && pos + 3 <= data_end &&
        b[pos] == 0xE6 && (b[pos + 1] == 0xE7 || b[pos + 1] == 0xE6) && b[pos + 2] == 0x00) {
      pos += 3;
    }

    // Copy payload to write position (memmove safe: dst <= src always)
    const size_t payload_len = pos < data_end ? data_end - pos : 0;
    if (payload_len > 0) {
      std::memmove(buf + write_offset, b + pos, payload_len);
      write_offset += payload_len;
    }

    read_offset += frame_total;
    is_first = false;

    if (!segmented && read_offset >= len) break;
  } while (read_offset < len);

  if (write_offset == 0) {
    Logger::log(LogLevel::WARNING, "HDLC: no payload extracted");
    return 0;
  }
  return write_offset;
}

}  // namespace dlms_parser
