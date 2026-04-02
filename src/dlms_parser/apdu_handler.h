#pragma once

#include "decryption/aes_128_gcm_decryptor.h"
#include "utils.h"
#include <cstdint>
#include <functional>
#include <span>

namespace dlms_parser {

// Scans a buffer byte-by-byte for the first recognized DLMS APDU tag.
// Unknown leading bytes are skipped. Recognized tags:
//   0xE0  General-Block-Transfer   : reassembles numbered blocks
//   0x0F  DATA-NOTIFICATION        : strips Long-Invoke-ID and optional datetime header
//   0xDB  General-Glo-Ciphering    : decrypts with GcmDecryptor
//   0xDF  General-Ded-Ciphering    : decrypts with GcmDecryptor
//   0x01 / 0x02  raw ARRAY/STRUCT  : no APDU wrapper (e.g. HDLC/Aidon)
class ApduHandler final : NonCopyableAndNonMovable {
 public:
  void set_decryptor(Aes128GcmDecryptor* d) { decryptor_ = d; }

  // Returns a span over the AXDR payload within buf (empty on error).
  std::span<uint8_t> parse(std::span<uint8_t> buf) const;

 private:
  Aes128GcmDecryptor* decryptor_{nullptr};
};

}  // namespace dlms_parser
