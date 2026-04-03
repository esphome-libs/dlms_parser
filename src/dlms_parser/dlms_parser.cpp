#include "dlms_parser.h"
#include "log.h"
#include <cstddef>

namespace dlms_parser {

enum class FrameFormat { RAW, MBUS, HDLC };

DlmsParser::DlmsParser(Aes128GcmDecryptor& decryptor) : decryptor_(decryptor) {
  apdu_handler_.set_decryptor(&decryptor_);
}

void DlmsParser::set_skip_crc_check(const bool skip) {
  this->hdlc_decoder_.set_skip_crc_check(skip);
  this->mbus_decoder_.set_skip_crc_check(skip);
}

void DlmsParser::set_decryption_key(const Aes128GcmDecryptionKey& key) const {
  decryptor_.set_decryption_key(key);
}

void DlmsParser::set_authentication_key(const Aes128GcmAuthenticationKey& key) const {
  decryptor_.set_authentication_key(key);
}

void DlmsParser::load_default_patterns() {
  axdr_parser_.register_pattern("T1", "TC,TO,TS,TV", 10);
  axdr_parser_.register_pattern("T2", "TO,TV,TSU", 20);
  axdr_parser_.register_pattern("T3", "TV,TC,TSU,TO", 30);
  axdr_parser_.register_pattern("ADV", "ADV", 40);
}

void DlmsParser::register_pattern(const char* dsl) {
  axdr_parser_.register_pattern("CUSTOM", dsl, 0);
}

void DlmsParser::register_pattern(const char* name, const char* dsl, const int priority) {
  axdr_parser_.register_pattern(name, dsl, priority);
}

void DlmsParser::register_pattern(const char* name, const char* dsl, const int priority, const std::span<const uint8_t, 6> default_obis) {
  axdr_parser_.register_pattern(name, dsl, priority, default_obis);
}

ParseResult DlmsParser::parse(std::span<uint8_t> buf, const DlmsDataCallback& cooked_cb, const DlmsRawCallback& raw_cb) {
  if (buf.empty()) {
    Logger::log(LogLevel::ERROR, "Empty buffer passed to parse()");
    return {};
  }

  std::span<uint8_t> decoded;

  // Step 1: Frame decode (auto-detect HDLC / MBus / RAW from first byte)
  switch (buf[0]) {
    case 0x7E: // HDLC
      decoded = hdlc_decoder_.decode(buf);
      break;
    case 0x68: // MBus
      decoded = mbus_decoder_.decode(buf);
      break;
    default: // RAW
      decoded = buf;
      break;
  }

  if (decoded.empty()) return {};

  // Step 2: APDU unwrap (GBT → decrypt → strip header) — sequential loop, no recursion
  const auto axdr = apdu_handler_.parse(decoded);
  if (axdr.empty()) return {};

  // Step 3: AXDR parse — loop over successive top-level containers
  ParseResult result;
  size_t offset = 0;
  while (offset < axdr.size()) {
    auto [count, bytes_consumed] = axdr_parser_.parse(axdr.subspan(offset), cooked_cb, raw_cb);
    if (bytes_consumed == 0) break;
    result.count += count;
    result.bytes_consumed += bytes_consumed;
    offset += bytes_consumed;
  }
  return result;
}

}  // namespace dlms_parser
