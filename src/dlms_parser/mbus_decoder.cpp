#include "mbus_decoder.h"
#include "log.h"
#include <cstring>

namespace dlms_parser {

static constexpr uint8_t MBUS_START  = 0x68;
static constexpr uint8_t MBUS_STOP   = 0x16;
static constexpr size_t  MBUS_INTRO  = 4;  // 0x68, L, L, 0x68
static constexpr size_t  MBUS_HEADER = 9;  // intro(4) + C(1) + A(1) + CI(1) + STSAP(1) + DTSAP(1)
static constexpr size_t  MBUS_FOOTER = 2;  // CS(1) + 0x16(1)

// ---------------------------------------------------------------------------
// check() — stateless frame completeness check
// Walks M-Bus frame boundaries. Multiple frames are expected when CI byte
// indicates continuation (0x11 for second+ frames). Returns COMPLETE when
// the last frame's CI is not a continuation indicator.
// ---------------------------------------------------------------------------
FrameStatus MBusDecoder::check(const std::span<const uint8_t> buf) {
  if (buf.size() < MBUS_INTRO || buf[0] != MBUS_START) return FrameStatus::ERROR;

  size_t offset = 0;
  while (offset < buf.size()) {
    if (offset + MBUS_INTRO > buf.size()) return FrameStatus::NEED_MORE;
    if (buf[offset] != MBUS_START || buf[offset + 3] != MBUS_START) return FrameStatus::ERROR;
    if (buf[offset + 1] != buf[offset + 2]) return FrameStatus::ERROR;

    const size_t L = buf[offset + 1];
    if (MBUS_INTRO + L < MBUS_HEADER) return FrameStatus::ERROR;
    const size_t frame_size = MBUS_INTRO + L + MBUS_FOOTER;
    if (offset + frame_size > buf.size()) return FrameStatus::NEED_MORE;

    // Check stop byte
    if (buf[offset + MBUS_INTRO + L + 1] != MBUS_STOP) return FrameStatus::ERROR;

    offset += frame_size;

    // If next byte is another MBUS_START, more frames follow
    if (offset < buf.size() && buf[offset] == MBUS_START) continue;

    // All bytes must be consumed; trailing garbage is an error
    if (offset < buf.size()) return FrameStatus::ERROR;

    return FrameStatus::COMPLETE;
  }

  return FrameStatus::NEED_MORE;
}

// ---------------------------------------------------------------------------
// In-place decode: extracts and concatenates payloads from all M-Bus frames,
// writing them sequentially to buf[0..]. Returns new length, 0 on error.
// ---------------------------------------------------------------------------
size_t MBusDecoder::decode(const std::span<uint8_t> buf_span) const {
  uint8_t* const buf = buf_span.data();
  const size_t len = buf_span.size();
  size_t read_offset = 0;
  size_t write_offset = 0;

  while (read_offset < len) {
    if (len - read_offset < MBUS_INTRO) {
      Logger::log(LogLevel::WARNING, "MBUS: too short for header (%zu remaining)", len - read_offset);
      return 0;
    }
    if (buf[read_offset] != MBUS_START || buf[read_offset + 3] != MBUS_START) {
      Logger::log(LogLevel::WARNING, "MBUS: invalid start bytes at offset %zu", read_offset);
      return 0;
    }
    if (buf[read_offset + 1] != buf[read_offset + 2]) {
      Logger::log(LogLevel::WARNING, "MBUS: length mismatch at offset %zu", read_offset);
      return 0;
    }

    const size_t L = buf[read_offset + 1];
    if (MBUS_INTRO + L < MBUS_HEADER) {
      Logger::log(LogLevel::WARNING, "MBUS: L too small (%zu) at offset %zu", L, read_offset);
      return 0;
    }
    const size_t frame_size = MBUS_INTRO + L + MBUS_FOOTER;

    if (len - read_offset < frame_size) {
      Logger::log(LogLevel::WARNING, "MBUS: incomplete frame at offset %zu", read_offset);
      return 0;
    }
    if (buf[read_offset + MBUS_INTRO + L + 1] != MBUS_STOP) {
      Logger::log(LogLevel::WARNING, "MBUS: invalid stop byte at offset %zu", read_offset);
      return 0;
    }

    // Checksum
    if (!this->skip_crc_check_) {
      uint8_t cs = 0;
      for (size_t i = 0; i < L; ++i) cs += buf[read_offset + MBUS_INTRO + i];
      if (cs != buf[read_offset + MBUS_INTRO + L]) {
        Logger::log(LogLevel::WARNING, "MBUS: checksum error at offset %zu", read_offset);
        return 0;
      }
    }

    // Payload: bytes after C, A, CI, STSAP, DTSAP
    if (MBUS_HEADER < MBUS_INTRO + L) {
      const size_t payload_len = MBUS_INTRO + L - MBUS_HEADER;
      std::memmove(buf + write_offset, buf + read_offset + MBUS_HEADER, payload_len);
      write_offset += payload_len;
    }

    read_offset += frame_size;
  }

  if (write_offset == 0) {
    Logger::log(LogLevel::WARNING, "MBUS: no payload in frame(s)");
    return 0;
  }
  return write_offset;
}

}  // namespace dlms_parser
