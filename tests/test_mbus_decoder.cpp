#include <doctest.h>
#include <vector>
#include <cstdint>
#include <cstring>

#include "dlms_parser/mbus_decoder.h"
#include "dlms_parser/types.h"

using namespace dlms_parser;

// Helper function to construct valid M-Bus long frames
static void build_mbus_frame(std::vector<uint8_t>& frame, const std::vector<uint8_t>& payload) {
  frame.push_back(0x68);

  uint8_t L = static_cast<uint8_t>(5 + payload.size()); // 5 bytes for C, A, CI, STSAP, DTSAP
  frame.push_back(L);
  frame.push_back(L);
  frame.push_back(0x68);

  frame.push_back(0x53); // C
  frame.push_back(0x01); // A
  frame.push_back(0x00); // CI
  frame.push_back(0x02); // STSAP
  frame.push_back(0x03); // DTSAP

  frame.insert(frame.end(), payload.begin(), payload.end());

  // Checksum: Sum of bytes from C to end of payload mod 256
  uint8_t cs = 0;
  for (size_t i = 4; i < frame.size(); ++i) {
    cs += frame[i];
  }
  frame.push_back(cs);

  frame.push_back(0x16);
}

TEST_CASE("MBus Decoder - Frame Status Check (check)") {
  std::vector<uint8_t> base_frame;
  build_mbus_frame(base_frame, {0xAA, 0xBB, 0xCC});

  SUBCASE("Valid Complete Frame") {
    CHECK(MBusDecoder::check(base_frame) == FrameStatus::COMPLETE);
  }

  SUBCASE("Zero-Length / Null Buffer") {
    CHECK(MBusDecoder::check({base_frame.data(), 0}) == FrameStatus::ERROR);
    CHECK(MBusDecoder::check({}) == FrameStatus::ERROR);
  }

  SUBCASE("Exactly MBUS_INTRO Bytes (4 bytes)") {
    // Ensures check() safely calculates NEED_MORE without reading out-of-bounds
    std::vector<uint8_t> intro_only = {0x68, 0x05, 0x05, 0x68};
    CHECK(MBusDecoder::check(intro_only) == FrameStatus::NEED_MORE);
  }

  SUBCASE("Buffer Too Short (Under Intro Size)") {
    std::vector<uint8_t> tiny = {0x68, 0x08, 0x08};
    CHECK(MBusDecoder::check(tiny) == FrameStatus::ERROR);
  }

  SUBCASE("Missing First Start Byte") {
    auto frame = base_frame;
    frame[0] = 0x00;
    CHECK(MBusDecoder::check(frame) == FrameStatus::ERROR);
  }

  SUBCASE("Missing Second Start Byte") {
    auto frame = base_frame;
    frame[3] = 0x00;
    CHECK(MBusDecoder::check(frame) == FrameStatus::ERROR);
  }

  SUBCASE("Length Mismatch") {
    auto frame = base_frame;
    frame[1] = 0x09; // Corrupt L1
    CHECK(MBusDecoder::check(frame) == FrameStatus::ERROR);
  }

  SUBCASE("Incomplete Frame (Cut off payload)") {
    CHECK(MBusDecoder::check({base_frame.data(), base_frame.size() - 3}) == FrameStatus::NEED_MORE);
  }

  SUBCASE("Invalid Stop Byte") {
    auto frame = base_frame;
    frame.back() = 0xFF;
    CHECK(MBusDecoder::check(frame) == FrameStatus::ERROR);
  }

  SUBCASE("Garbage Data Before the Frame") {
    // Enforces strict alignment (should not auto-seek to 0x68)
    std::vector<uint8_t> offset_frame = {0xFF, 0xAA};
    offset_frame.insert(offset_frame.end(), base_frame.begin(), base_frame.end());
    CHECK(MBusDecoder::check(offset_frame) == FrameStatus::ERROR);
  }

  SUBCASE("Maximum Length Frame (L = 255)") {
    std::vector<uint8_t> max_payload(250, 0xAB); // Max payload is 250 (L - 5)
    std::vector<uint8_t> max_frame;
    build_mbus_frame(max_frame, max_payload);
    CHECK(MBusDecoder::check(max_frame) == FrameStatus::COMPLETE);
  }

  SUBCASE("Multiple Frames Concatenated") {
    std::vector<uint8_t> multi_frame = base_frame;
    std::vector<uint8_t> frame2;
    build_mbus_frame(frame2, {0xDD, 0xEE});
    multi_frame.insert(multi_frame.end(), frame2.begin(), frame2.end());

    CHECK(MBusDecoder::check(multi_frame) == FrameStatus::COMPLETE);
  }

  SUBCASE("Multiple Frames - Last Frame Incomplete") {
    std::vector<uint8_t> multi_frame = base_frame;
    std::vector<uint8_t> frame2;
    build_mbus_frame(frame2, {0xDD, 0xEE});
    multi_frame.insert(multi_frame.end(), frame2.begin(), frame2.end() - 2);

    CHECK(MBusDecoder::check(multi_frame) == FrameStatus::NEED_MORE);
  }

  SUBCASE("Valid Frame Followed by Trailing Garbage") {
    auto frame = base_frame;
    frame.push_back(0xFF);
    CHECK(MBusDecoder::check(frame) == FrameStatus::ERROR);
  }
}

TEST_CASE("MBus Decoder - Payload Decoding (decode)") {
  MBusDecoder decoder;
  decoder.set_skip_crc_check(true);

  std::vector<uint8_t> base_frame;
  build_mbus_frame(base_frame, {0xAA, 0xBB, 0xCC});

  SUBCASE("Single Frame Decoding") {
    auto frame = base_frame;
    size_t new_len = decoder.decode(frame);

    CHECK(new_len == 3);
    CHECK(frame[0] == 0xAA);
    CHECK(frame[1] == 0xBB);
    CHECK(frame[2] == 0xCC);
  }

  SUBCASE("Multiple Concatenated Frames") {
    std::vector<uint8_t> multi_frame = base_frame;
    std::vector<uint8_t> frame2;
    build_mbus_frame(frame2, {0xDD, 0xEE, 0xFF});
    multi_frame.insert(multi_frame.end(), frame2.begin(), frame2.end());

    size_t new_len = decoder.decode(multi_frame);

    CHECK(new_len == 6);
    CHECK(multi_frame[0] == 0xAA);
    CHECK(multi_frame[2] == 0xCC);
    CHECK(multi_frame[3] == 0xDD);
    CHECK(multi_frame[5] == 0xFF);
  }

  SUBCASE("Strict CRC Enabled - Accepts Valid Checksum") {
    decoder.set_skip_crc_check(false);
    auto frame = base_frame;
    CHECK(decoder.decode(frame) == 3);
  }

  SUBCASE("Strict CRC Enabled - Rejects Invalid Checksum") {
    decoder.set_skip_crc_check(false);
    auto frame = base_frame;
    frame[10] ^= 0xFF; // Corrupt a byte
    CHECK(decoder.decode(frame) == 0);
  }
}

TEST_CASE("MBus Decoder - Malformed Frame Handling") {
  MBusDecoder decoder;
  decoder.set_skip_crc_check(true);

  std::vector<uint8_t> base_frame;
  build_mbus_frame(base_frame, {0xAA, 0xBB, 0xCC});

  SUBCASE("Decode returns 0 for Length < MBUS_INTRO") {
    auto frame = base_frame;
    CHECK(decoder.decode({frame.data(), 3}) == 0);
  }

  SUBCASE("Decode returns 0 for Length Mismatch") {
    auto frame = base_frame;
    frame[1] = 0x10;
    CHECK(decoder.decode(frame) == 0);
  }

  SUBCASE("Decode returns 0 for Invalid Stop Byte") {
    auto frame = base_frame;
    frame.back() = 0x17;
    CHECK(decoder.decode(frame) == 0);
  }

  SUBCASE("Decode returns 0 for Incomplete Final Frame") {
    auto frame = base_frame;
    CHECK(decoder.decode({frame.data(), frame.size() - 1}) == 0);
  }

  SUBCASE("Decode fails immediately if trailing garbage is present") {
    // decode() requires strict frame boundaries, unlike check()
    auto frame = base_frame;
    frame.push_back(0xFF);
    CHECK(decoder.decode(frame) == 0);
  }

  SUBCASE("Multiple Frames - Second Frame has Length Mismatch") {
    std::vector<uint8_t> multi_frame = base_frame;
    std::vector<uint8_t> frame2;
    build_mbus_frame(frame2, {0xDD, 0xEE});
    frame2[1] = 0x10; // Corrupt L1
    multi_frame.insert(multi_frame.end(), frame2.begin(), frame2.end());

    // decode() aborts entirely if ANY frame is corrupted
    CHECK(decoder.decode(multi_frame) == 0);
  }

  SUBCASE("Multiple Frames - Second Frame has Checksum Error") {
    decoder.set_skip_crc_check(false);
    std::vector<uint8_t> multi_frame = base_frame;
    std::vector<uint8_t> frame2;
    build_mbus_frame(frame2, {0xDD, 0xEE});
    frame2[10] ^= 0xFF; // Corrupt a byte
    multi_frame.insert(multi_frame.end(), frame2.begin(), frame2.end());

    // decode() aborts entirely if CRC fails on ANY frame
    CHECK(decoder.decode(multi_frame) == 0);
  }

  SUBCASE("Empty Payload Handling (Frame Size valid, but no Application Data)") {
    std::vector<uint8_t> empty_frame;
    build_mbus_frame(empty_frame, {});
    // Fails because write_offset == 0
    CHECK(decoder.decode(empty_frame) == 0);
  }

  SUBCASE("Mixed Frames - Valid Frame Followed by Empty Frame") {
    std::vector<uint8_t> multi_frame = base_frame;
    std::vector<uint8_t> empty_frame;
    build_mbus_frame(empty_frame, {});
    multi_frame.insert(multi_frame.end(), empty_frame.begin(), empty_frame.end());

    // Succeeds and returns 3, silently ignoring the second empty frame
    CHECK(decoder.decode(multi_frame) == 3);
  }

  SUBCASE("Header Size Too Large for Defined Length (Malformed L)") {
    auto frame = base_frame;
    frame[1] = 0x02;
    frame[2] = 0x02;
    frame[4+2+1] = 0x16; // Recalculate Stop Byte position

    // Fails because MBUS_HEADER > MBUS_INTRO + L
    CHECK(decoder.decode({frame.data(), 8}) == 0);
  }
}
