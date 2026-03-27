#include "dlms_parser.h"

namespace dlms_parser {

DlmsParser::DlmsParser() {
  apdu_handler_.set_decryptor(&decryptor_);
}

void DlmsParser::set_skip_crc_check(bool skip) {
  hdlc_decoder_.set_skip_crc_check(skip);
  mbus_decoder_.set_skip_crc_check(skip);
}

void DlmsParser::set_decryption_key(const std::array<uint8_t, 16>& key) {
  decryptor_.set_key(key);
}

void DlmsParser::set_decryption_key(const std::vector<uint8_t>& key) {
  decryptor_.set_key(key);
}

void DlmsParser::load_default_patterns() {
  axdr_parser_.register_pattern("T1", "TC,TO,TS,TV", 10);
  axdr_parser_.register_pattern("T2", "TO,TV,TSU", 20);
  axdr_parser_.register_pattern("T3", "TV,TC,TSU,TO", 30);
  axdr_parser_.register_pattern("U.ZPA", "F,C,O,A,TV", 40);
}

void DlmsParser::register_pattern(const std::string& dsl) {
  axdr_parser_.register_pattern("CUSTOM", dsl, 0);
}

void DlmsParser::register_pattern(const std::string& name, const std::string& dsl, int priority) {
  axdr_parser_.register_pattern(name, dsl, priority);
}

size_t DlmsParser::parse(const uint8_t* buf, size_t len,
                         DlmsDataCallback cooked_cb,
                         DlmsRawCallback raw_cb) {
  const uint8_t* apdu = buf;
  size_t apdu_len = len;
  std::vector<uint8_t> frame_buf;  // used for MBUS / HDLC (may copy/concatenate)

  switch (frame_format_) {
    case FrameFormat::MBUS:
      if (!mbus_decoder_.decode(buf, len, frame_buf)) return 0;
      apdu = frame_buf.data();
      apdu_len = frame_buf.size();
      break;
    case FrameFormat::HDLC:
      if (!hdlc_decoder_.decode(buf, len, frame_buf)) return 0;
      apdu = frame_buf.data();
      apdu_len = frame_buf.size();
      break;
    case FrameFormat::RAW:
    default:
      break;
  }

  size_t total = 0;
  apdu_handler_.parse(apdu, apdu_len, [&](const uint8_t* axdr, size_t axdr_len) {
    total += axdr_parser_.parse(axdr, axdr_len, cooked_cb, raw_cb);
  });
  return total;
}

}  // namespace dlms_parser
