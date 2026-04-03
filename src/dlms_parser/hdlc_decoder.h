#pragma once

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
//
// In-place decode: extracts and concatenates payloads from all HDLC frames
// in buf, writing them sequentially to buf[0..]. Returns a subspan of buf, empty on error.
std::span<uint8_t> decode_hdlc_frames_in_place(std::span<uint8_t> buf, bool skip_crc_check = false);

}
