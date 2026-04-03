#include "mbus_decoder.h"
#include "log.h"
#include <algorithm>
#include <numeric>
#include <utility>

namespace dlms_parser {

static constexpr uint8_t MBUS_START  = 0x68;
static constexpr uint8_t MBUS_STOP   = 0x16;
static constexpr size_t  MBUS_INTRO  = 4;  // 0x68, L, L, 0x68
static constexpr size_t  MBUS_HEADER = 9;  // intro(4) + C(1) + A(1) + CI(1) + STSAP(1) + DTSAP(1)
static constexpr size_t  MBUS_FOOTER = 2;  // CS(1) + 0x16(1)

size_t MBusDecoder::decode(const std::span<uint8_t> buf) const {
  auto remaining = std::as_const(buf);
  size_t write_offset = 0;

  while (!remaining.empty()) {
    // Ignore trailing garbage after the last frame
    if (remaining.size() < MBUS_INTRO) break;
    if (remaining[0] != MBUS_START) break;

    const auto read_offset = buf.size() - remaining.size();

    if (remaining[3] != MBUS_START) {
      Logger::log(LogLevel::WARNING, "MBUS: invalid second start byte at offset %zu", read_offset);
      return 0;
    }
    if (remaining[1] != remaining[2]) {
      Logger::log(LogLevel::WARNING, "MBUS: length mismatch at offset %zu", read_offset);
      return 0;
    }

    const auto L = static_cast<size_t>(remaining[1]);
    if (MBUS_INTRO + L < MBUS_HEADER) {
      Logger::log(LogLevel::WARNING, "MBUS: L too small (%zu) at offset %zu", L, read_offset);
      return 0;
    }
    const auto frame_size = MBUS_INTRO + L + MBUS_FOOTER;

    if (remaining.size() < frame_size) {
      Logger::log(LogLevel::WARNING, "MBUS: incomplete frame at offset %zu", read_offset);
      return 0;
    }
    if (remaining[MBUS_INTRO + L + 1] != MBUS_STOP) {
      Logger::log(LogLevel::WARNING, "MBUS: invalid stop byte at offset %zu", read_offset);
      return 0;
    }

    // Checksum
    if (!skip_crc_check_) {
      const auto l_bytes = remaining.subspan(MBUS_INTRO, L);
      const auto cs = std::accumulate(l_bytes.begin(), l_bytes.end(), uint8_t{0},
                                      [](uint8_t a, uint8_t b) -> uint8_t { return a + b; });
      if (cs != remaining[MBUS_INTRO + L]) {
        Logger::log(LogLevel::WARNING, "MBUS: checksum error at offset %zu", read_offset);
        return 0;
      }
    }

    // Payload: bytes after C, A, CI, STSAP, DTSAP
    if (MBUS_HEADER < MBUS_INTRO + L) {
      const auto payload = remaining.subspan(MBUS_HEADER, MBUS_INTRO + L - MBUS_HEADER);
      std::ranges::copy(payload, buf.subspan(write_offset).begin());
      write_offset += payload.size();
    }

    remaining = remaining.subspan(frame_size);
  }

  if (write_offset == 0) {
    Logger::log(LogLevel::WARNING, "MBUS: no payload in frame(s)");
    return 0;
  }
  return write_offset;
}

}
