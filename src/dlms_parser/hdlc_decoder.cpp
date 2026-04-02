#include "hdlc_decoder.h"
#include "log.h"
#include <algorithm>

namespace dlms_parser {

// Precomputed CRC-16/IBM-SDLC (X.25) Lookup Table
constexpr uint16_t CRC16_X25_TABLE[256] = {
  0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
  0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
  0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
  0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
  0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
  0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
  0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
  0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
  0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
  0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
  0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
  0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
  0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
  0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
  0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
  0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
  0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
  0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
  0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
  0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
  0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
  0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
  0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
  0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
  0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
  0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
  0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
  0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
  0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
  0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
  0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
  0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78 };

// CRC-16/IBM-SDLC (X.25): poly=0x8408, init=0xFFFF, xorout=0xFFFF.
// Running this over (data bytes + the two stored CRC bytes) yields FCS16_GOOD_VALUE for a valid frame.
bool crc16_x25_check(const std::span<const uint8_t> data) {
  uint16_t crc = 0xFFFFU;
  for (const auto byte : data) {
    crc = crc >> 8 ^ CRC16_X25_TABLE[(crc ^ byte) & 0xFF];
  }
  return crc == 0xF0B8U;
}

// Returns the number of bytes in a variable-length HDLC address field (1, 2 or 4).
// Returns 0 if the terminating LSB=1 bit is not found within 4 bytes.
static size_t address_length(std::span<const uint8_t> p) {
  const auto limit = std::min(p.size(), size_t{ 4 });
  for (size_t i = 0; i < limit; ++i) {
    if (p[i] & 0x01U) return i + 1;  // LSB=1 marks the last address byte
  }
  return 0;
}

static constexpr uint8_t HDLC_FLAG    = 0x7E;
static constexpr uint8_t HDLC_SEG_BIT = 0x08;  // bit 3 of frame-type byte: "more frames follow"

// ---------------------------------------------------------------------------
// check() — stateless frame completeness check
// Walks frame boundaries using length fields. Returns COMPLETE when the last
// frame in the buffer has no segmentation bit set and no more data follows.
// ---------------------------------------------------------------------------
FrameStatus HdlcDecoder::check(const std::span<const uint8_t> buf) {
  if (buf.size() < 2 || buf[0] != HDLC_FLAG) return FrameStatus::ERROR;

  size_t offset = 0;
  while (offset < buf.size()) {
    const auto remaining = buf.subspan(offset);
    if (remaining[0] != HDLC_FLAG) return FrameStatus::ERROR;
    if (remaining.size() < 3) return FrameStatus::NEED_MORE;  // can't read format field yet

    const bool segmented = (remaining[1] & HDLC_SEG_BIT) != 0;
    const auto frame_len = static_cast<size_t>(remaining[1] & 0x07U) << 8 | remaining[2];
    const auto frame_total = frame_len + 2;

    if (frame_total > remaining.size()) return FrameStatus::NEED_MORE;  // frame incomplete

    // Verify closing flag
    if (remaining[frame_total - 1] != HDLC_FLAG) return FrameStatus::ERROR;

    offset += frame_total;

    if (!segmented && offset >= buf.size()) return FrameStatus::COMPLETE;
    // Not segmented but more data follows — continue (GBT multi-frame case)
  }

  return FrameStatus::NEED_MORE;
}

// ---------------------------------------------------------------------------
// In-place decode: extracts and concatenates payloads from all HDLC frames
// in buf, writing them sequentially to buf[0..]. Returns new length, 0 on error.
// ---------------------------------------------------------------------------
size_t HdlcDecoder::decode(const std::span<uint8_t> buf_span) const {
  size_t read_offset = 0;
  size_t write_offset = 0;
  bool is_first = true;

  do {
    const auto remaining = buf_span.subspan(read_offset);
    if (remaining.size() < 4 || remaining[0] != HDLC_FLAG) {
      Logger::log(LogLevel::WARNING, "HDLC: invalid frame at offset %zu", read_offset);
      return 0;
    }

    const bool segmented = (remaining[1] & HDLC_SEG_BIT) != 0;
    const auto frame_len = static_cast<size_t>(remaining[1] & 0x07U) << 8 | remaining[2];
    const auto frame_total = frame_len + 2;

    if (frame_total > remaining.size()) {
      Logger::log(LogLevel::WARNING, "HDLC: incomplete frame at offset %zu", read_offset);
      return 0;
    }

    // Content between the two 7E flags
    const auto inner = remaining.subspan(1).first(frame_total - 2);

    if (inner.size() < 9) { // minimum: format(2) + dst(1) + src(1) + ctrl(1) + hcs(2) + fcs(2)
      Logger::log(LogLevel::WARNING, "HDLC: frame too short (%zu bytes)", inner.size());
      return 0;
    }

    // Skip addresses + control
    size_t pos = 2;
    const auto dst_len = address_length(inner.subspan(pos));
    if (dst_len == 0) return 0;
    pos += dst_len;

    const auto src_len = address_length(inner.subspan(pos));
    if (src_len == 0) return 0;
    pos += src_len;
    pos += 1;  // control byte

    // HCS
    if (pos + 2 > inner.size()) return 0;
    if (!skip_crc_check_ && !crc16_x25_check(inner.first(pos + 2))) {
      Logger::log(LogLevel::WARNING, "HDLC: HCS error");
      return 0;
    }
    pos += 2;

    // FCS
    if (!skip_crc_check_ && !crc16_x25_check(inner)) {
      Logger::log(LogLevel::WARNING, "HDLC: FCS error");
      return 0;
    }

    const auto data_end = inner.size() - 2;

    // Strip LLC on first frame
    if (is_first && pos + 3 <= data_end &&
        inner[pos] == 0xE6 && (inner[pos + 1] == 0xE7 || inner[pos + 1] == 0xE6) && inner[pos + 2] == 0x00) {
      pos += 3;
    }

    // Copy payload to write position (dst <= src always)
    const auto payload_len = pos < data_end ? data_end - pos : size_t{0};
    if (payload_len > 0) {
      std::ranges::copy(inner.subspan(pos, payload_len), buf_span.subspan(write_offset).begin());
      write_offset += payload_len;
    }

    read_offset += frame_total;
    is_first = false;

    if (!segmented && read_offset >= buf_span.size()) break;
  } while (read_offset < buf_span.size());

  if (write_offset == 0) {
    Logger::log(LogLevel::WARNING, "HDLC: no payload extracted");
    return 0;
  }
  return write_offset;
}

}
