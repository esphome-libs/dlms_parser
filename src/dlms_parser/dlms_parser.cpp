#include "dlms_parser.h"
#include "log.h"
#include <cstring>

namespace dlms_parser {

DlmsParser::DlmsParser(Aes128GcmDecryptor& decryptor) : decryptor_(decryptor) {
  apdu_handler_.set_decryptor(&decryptor_);
}

FrameStatus DlmsParser::check_frame(const uint8_t* buf, const size_t len) const {
  if (!buf || len == 0) return FrameStatus::NEED_MORE;

  switch (frame_format_) {
    case FrameFormat::HDLC: return HdlcDecoder::check(buf, len);
    case FrameFormat::MBUS: return MBusDecoder::check(buf, len);
    case FrameFormat::RAW:
    default:
      return FrameStatus::COMPLETE;  // RAW: always complete (caller's responsibility)
  }
}

void DlmsParser::set_skip_crc_check(const bool skip) {
  this->hdlc_decoder_.set_skip_crc_check(skip);
  this->mbus_decoder_.set_skip_crc_check(skip);
}

void DlmsParser::set_work_buffer(uint8_t* buf, const size_t capacity) {
  this->work_buf_ = buf;
  this->work_buf_capacity_ = capacity;
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

void DlmsParser::register_pattern(const char* name, const char* dsl, const int priority, const uint8_t default_obis[6]) {
  axdr_parser_.register_pattern(name, dsl, priority, default_obis);
}

ParseResult DlmsParser::parse(const uint8_t* buf, const size_t len, const DlmsDataCallback& cooked_cb,
                              const DlmsRawCallback& raw_cb) {
  if (!this->work_buf_) {
    Logger::log(LogLevel::ERROR, "No work buffer set - call set_work_buffer() before parse()");
    return {};
  }
  if (len > this->work_buf_capacity_) {
    Logger::log(LogLevel::ERROR, "Frame too large for work buffer (%zu > %zu)", len, this->work_buf_capacity_);
    return {};
  }

  // Copy input into work buffer — all transforms happen in-place from here
  std::memcpy(this->work_buf_, buf, len);
  size_t work_len = len;

  // Step 1: Frame decode (HDLC / MBus / RAW pass-through)
  switch (this->frame_format_) {
    case FrameFormat::HDLC:
      work_len = this->hdlc_decoder_.decode(this->work_buf_, work_len);
      if (work_len == 0) return {};
      break;
    case FrameFormat::MBUS:
      work_len = this->mbus_decoder_.decode(this->work_buf_, work_len);
      if (work_len == 0) return {};
      break;
    case FrameFormat::RAW:
    default:
      break;
  }

  // Step 2: APDU unwrap (GBT → decrypt → strip header) — sequential loop, no recursion
  auto [axdr_offset, axdr_len] = this->apdu_handler_.unwrap_in_place(this->work_buf_, work_len);
  if (axdr_len == 0) return {};

  // Step 3: AXDR parse — loop over successive top-level containers
  const uint8_t* axdr = this->work_buf_ + axdr_offset;
  ParseResult result;
  size_t offset = 0;
  while (offset < axdr_len) {
    auto [count, bytes_consumed] = this->axdr_parser_.parse(axdr + offset, axdr_len - offset, cooked_cb, raw_cb);
    if (bytes_consumed == 0) break;
    result.count += count;
    result.bytes_consumed += bytes_consumed;
    offset += bytes_consumed;
  }
  return result;
}

}  // namespace dlms_parser
