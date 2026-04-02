#pragma once

#include "types.h"
#include "utils.h"
#include <cstdint>
#include <span>

namespace dlms_parser {

// Decodes one or more consecutive M-Bus long frames as used in DLMS/COSEM push telegrams.
//
// Frame layout (EN 62056-46 / IEC 870-5-2 long frame):
//
//   0x68 | L | L | 0x68 | C | A | CI | STSAP | DTSAP | data... | CS | 0x16
//   └────────────────────┘                                        └──────────┘
//        intro (4 B)                                              footer (2 B)
//
//   L     = number of bytes from C through end of data (= 5 overhead + data_len)
//   CS    = 8-bit sum (mod 256) of the L bytes starting at C
//
// Multiple frames are concatenated into a single apdu_out buffer.
// The intro (0x68 L L 0x68), C, A, CI, STSAP, DTSAP, CS and 0x16 are all stripped;
// only the raw DLMS/COSEM application bytes (data...) are returned.
// Any trailing bytes after the last valid frame are silently ignored.
class MBusDecoder final : NonCopyableAndNonMovable {
 public:
  void set_skip_crc_check(const bool skip) { skip_crc_check_ = skip; }

  // Check if buf contains a complete M-Bus message ready for decode().
  static FrameStatus check(std::span<const uint8_t> buf);

  // In-place decode: transforms buf contents, returns new length. 0 = error.
  size_t decode(std::span<uint8_t> buf) const;

 private:
  bool skip_crc_check_{false};
};

}  // namespace dlms_parser
