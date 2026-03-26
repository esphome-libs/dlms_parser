#pragma once

#include <cstdint>
#include <vector>

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
class HdlcDecoder {
 public:
  bool decode(const uint8_t* frame, size_t len, std::vector<uint8_t>& apdu_out) const;

 private:
  // Decode a single 7E-delimited frame; appends payload bytes to chunk_out.
  // is_first controls LLC header stripping (only on the first frame).
  bool decode_one_(const uint8_t* frame, size_t len, bool is_first,
                   std::vector<uint8_t>& chunk_out) const;

  // Returns the number of bytes in a variable-length HDLC address field (1, 2 or 4).
  // Returns 0 if the terminating LSB=1 bit is not found within 4 bytes.
  static size_t address_length_(const uint8_t* p, size_t remaining);

  // CRC16/IBM-SDLC (X.25) run over `len` bytes.
  // When called over (data + stored_fcs_bytes), returns 0xF0B8 for a valid frame.
  static uint16_t crc16_x25_check_(const uint8_t* data, size_t len);
};

}  // namespace dlms_parser
