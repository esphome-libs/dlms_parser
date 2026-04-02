#pragma once

#include "types.h"
#include "utils.h"
#include <cstdint>
#include <span>

namespace dlms_parser {

// Decodes a single complete HDLC frame as used in DLMS/COSEM push-mode telegrams.
//
// Frame layout:
//   0x7E | 0xA0+len_hi | len_lo | DST(1/2/4B) | SRC(1/2/4B) | CTRL | HCS[2] | LLC[3] | APDU... | FCS[2] | 0x7E
//
// - Length field (11-bit): counts all bytes between the two 0x7E delimiters
// - Addresses: variable-length (1, 2 or 4 bytes); LSB=1 marks the last byte
// - HCS: CRC16/IBM-SDLC over frame[1..before_HCS]
// - LLC header stripped if present: {0xE6, 0xE7, 0x00} or {0xE6, 0xE6, 0x00}
// - FCS: CRC16/IBM-SDLC over frame[1..before_FCS]
class HdlcDecoder final : NonCopyableAndNonMovable {
 public:
  void set_skip_crc_check(const bool skip) { skip_crc_check_ = skip; }

  // Check if buf contains a complete HDLC message ready for decode().
  static FrameStatus check(std::span<const uint8_t> buf);

  // In-place decode: transforms buf contents, returns new length. 0 = error.
  size_t decode(std::span<uint8_t> buf) const;

 private:
  bool skip_crc_check_{false};
};

}  // namespace dlms_parser
