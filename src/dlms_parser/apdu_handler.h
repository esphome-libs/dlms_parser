#pragma once

#include "decryption/aes_128_gcm_decryptor.h"
#include <cstdint>
#include <functional>
#include <span>

namespace dlms_parser {

// Callback fired by ApduHandler with raw AXDR payload bytes (after header stripping / decryption).
using AxdrPayloadCallback = std::function<void(std::span<const uint8_t> axdr)>;

// Scans a buffer byte-by-byte for the first recognized DLMS APDU tag.
// Unknown leading bytes are skipped. Recognized tags:
//   0xE0  General-Block-Transfer   : reassembles numbered blocks
//   0x0F  DATA-NOTIFICATION        : strips Long-Invoke-ID and optional datetime header
//   0xDB  General-Glo-Ciphering    : decrypts with GcmDecryptor
//   0xDF  General-Ded-Ciphering    : decrypts with GcmDecryptor
//   0x01 / 0x02  raw ARRAY/STRUCT  : no APDU wrapper (e.g. HDLC/Aidon)
class ApduHandler {
 public:
  void set_decryptor(Aes128GcmDecryptor* d) { decryptor_ = d; }

  // Fires cb exactly once on success with the raw AXDR payload span.
  // Requires a mutable buffer for in-place decryption and reassembly.
  bool parse(std::span<uint8_t> buf, const AxdrPayloadCallback& cb) const;

  // In-place unwrap: transforms buf in a loop (GBT→decrypt→strip header).
  // Returns the offset and length of the AXDR payload within buf.
  // Returns {0, 0} on error.
  struct UnwrapResult { size_t offset; size_t length; };
  UnwrapResult unwrap_in_place(std::span<uint8_t> buf) const;

 private:
  Aes128GcmDecryptor* decryptor_{nullptr};
};

}  // namespace dlms_parser
