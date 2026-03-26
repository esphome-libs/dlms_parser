#include "mbus_decoder.h"
#include "log.h"

namespace dlms_parser {

static constexpr uint8_t MBUS_START  = 0x68;
static constexpr uint8_t MBUS_STOP   = 0x16;
static constexpr size_t  MBUS_INTRO  = 4;  // 0x68, L, L, 0x68
static constexpr size_t  MBUS_HEADER = 9;  // intro(4) + C(1) + A(1) + CI(1) + STSAP(1) + DTSAP(1)
static constexpr size_t  MBUS_FOOTER = 2;  // CS(1) + 0x16(1)

bool MBusDecoder::decode(const uint8_t* frame, size_t len, std::vector<uint8_t>& apdu_out) const {
  apdu_out.clear();
  size_t offset = 0;

  while (offset < len) {
    // --- intro header ---
    if (len - offset < MBUS_INTRO) {
      Logger::log(LogLevel::WARNING, "MBUS: too short for header (%zu remaining)", len - offset);
      return false;
    }

    if (frame[offset] != MBUS_START || frame[offset + 3] != MBUS_START) {
      Logger::log(LogLevel::WARNING, "MBUS: invalid start bytes (0x%02X, 0x%02X)",
                  frame[offset], frame[offset + 3]);
      return false;
    }

    if (frame[offset + 1] != frame[offset + 2]) {
      Logger::log(LogLevel::WARNING, "MBUS: length bytes mismatch (0x%02X != 0x%02X)",
                  frame[offset + 1], frame[offset + 2]);
      return false;
    }

    const size_t L          = frame[offset + 1];
    const size_t frame_size = MBUS_INTRO + L + MBUS_FOOTER;

    if (len - offset < frame_size) {
      Logger::log(LogLevel::WARNING, "MBUS: incomplete frame (need %zu, have %zu)",
                  frame_size, len - offset);
      return false;
    }

    // --- stop byte ---
    if (frame[offset + MBUS_INTRO + L + 1] != MBUS_STOP) {
      Logger::log(LogLevel::WARNING, "MBUS: invalid stop byte (0x%02X)", frame[offset + MBUS_INTRO + L + 1]);
      return false;
    }

    // --- checksum: 8-bit sum of the L bytes starting right after the intro ---
    uint8_t cs = 0;
    for (size_t i = 0; i < L; ++i) {
      cs += frame[offset + MBUS_INTRO + i];
    }
    if (cs != frame[offset + MBUS_INTRO + L]) {
      Logger::log(LogLevel::WARNING, "MBUS: checksum error (calc=0x%02X, stored=0x%02X)",
                  cs, frame[offset + MBUS_INTRO + L]);
      return false;
    }

    // --- payload: bytes after C, A, CI, STSAP, DTSAP ---
    if (MBUS_HEADER < MBUS_INTRO + L) {
      apdu_out.insert(apdu_out.end(),
                      frame + offset + MBUS_HEADER,
                      frame + offset + MBUS_INTRO + L);
    }

    offset += frame_size;
  }

  if (apdu_out.empty()) {
    Logger::log(LogLevel::WARNING, "MBUS: no payload in frame(s)");
    return false;
  }

  return true;
}

}  // namespace dlms_parser
