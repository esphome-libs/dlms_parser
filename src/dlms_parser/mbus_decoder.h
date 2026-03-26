#pragma once

#include <cstdint>
#include <vector>

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
class MBusDecoder {
 public:
  bool decode(const uint8_t* frame, size_t len, std::vector<uint8_t>& apdu_out) const;
};

}  // namespace dlms_parser
