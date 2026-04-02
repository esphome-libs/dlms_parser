#include "dlms_parser.h"
#include "log.h"
#include <algorithm>

namespace dlms_parser {

DlmsParser::DlmsParser(Aes128GcmDecryptor& decryptor) : decryptor_(decryptor) {
  apdu_handler_.set_decryptor(&decryptor_);
}

FrameStatus DlmsParser::check_frame(const std::span<const uint8_t> buf) const {
  if (buf.empty()) return FrameStatus::NEED_MORE;

  switch (frame_format_) {
    case FrameFormat::HDLC: return HdlcDecoder::check(buf);
    case FrameFormat::MBUS: return MBusDecoder::check(buf);
    case FrameFormat::RAW:
    default:
      return FrameStatus::COMPLETE;  // RAW: always complete (caller's responsibility)
  }
}

void DlmsParser::set_skip_crc_check(const bool skip) {
  this->hdlc_decoder_.set_skip_crc_check(skip);
  this->mbus_decoder_.set_skip_crc_check(skip);
}

void DlmsParser::set_work_buffer(const std::span<uint8_t> buf) {
  this->work_buf_ = buf;
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
  axdr_parser_.register_pattern("U.ZPA", "F,C,O,A,TV", 40);
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

ParseResult DlmsParser::parse(const std::span<const uint8_t> buf, const DlmsDataCallback& cooked_cb,
                              const DlmsRawCallback& raw_cb) {
  if (work_buf_.empty()) {
    Logger::log(LogLevel::ERROR, "No work buffer set - call set_work_buffer() before parse()");
    return {};
  }
  if (buf.size() > work_buf_.size()) {
    Logger::log(LogLevel::ERROR, "Frame too large for work buffer (%zu > %zu)", buf.size(), work_buf_.size());
    return {};
  }

  // Copy input into work buffer — all transforms happen in-place from here
  std::ranges::copy(buf, work_buf_.data());
  auto work_len = buf.size();

  // Step 1: Frame decode (HDLC / MBus / RAW pass-through)
  switch (frame_format_) {
    case FrameFormat::HDLC:
      work_len = hdlc_decoder_.decode(work_buf_.first(work_len));
      if (work_len == 0) return {};
      break;
    case FrameFormat::MBUS:
      work_len = mbus_decoder_.decode(work_buf_.first(work_len));
      if (work_len == 0) return {};
      break;
    case FrameFormat::RAW:
    default:
      break;
  }

  // Step 2: APDU unwrap (GBT → decrypt → strip header) — sequential loop, no recursion
  auto axdr = apdu_handler_.parse(work_buf_.first(work_len));
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
