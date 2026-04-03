#include <doctest.h>
#include <vector>
#include <cstdint>

#include "dlms_parser/mbus_decoder.h"

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

TEST_CASE("MBus Decoder - Payload Decoding (decode)") {

  std::vector<uint8_t> base_frame;
  build_mbus_frame(base_frame, {0xAA, 0xBB, 0xCC});

  SUBCASE("Single Frame Decoding") {
    auto frame = base_frame;
    const auto result = decode_mbus_frames_in_place(frame, true);

    CHECK(result.size() == 3);
    CHECK(frame[0] == 0xAA);
    CHECK(frame[1] == 0xBB);
    CHECK(frame[2] == 0xCC);
  }

  SUBCASE("Multiple Concatenated Frames") {
    std::vector<uint8_t> multi_frame = base_frame;
    std::vector<uint8_t> frame2;
    build_mbus_frame(frame2, {0xDD, 0xEE, 0xFF});
    multi_frame.insert(multi_frame.end(), frame2.begin(), frame2.end());

    const auto result = decode_mbus_frames_in_place(multi_frame, true);

    CHECK(result.size() == 6);
    CHECK(multi_frame[0] == 0xAA);
    CHECK(multi_frame[2] == 0xCC);
    CHECK(multi_frame[3] == 0xDD);
    CHECK(multi_frame[5] == 0xFF);
  }

  SUBCASE("Strict CRC Enabled - Accepts Valid Checksum") {
    auto frame = base_frame;
    CHECK(decode_mbus_frames_in_place(frame, false).size() == 3);
  }

  SUBCASE("Strict CRC Enabled - Rejects Invalid Checksum") {
    auto frame = base_frame;
    frame[10] ^= 0xFF; // Corrupt a byte
    CHECK(decode_mbus_frames_in_place(frame, false).empty());
  }
}

TEST_CASE("MBus Decoder - Malformed Frame Handling") {

  std::vector<uint8_t> base_frame;
  build_mbus_frame(base_frame, {0xAA, 0xBB, 0xCC});

  SUBCASE("Decode returns 0 for Length < MBUS_INTRO") {
    auto frame = base_frame;
    CHECK(decode_mbus_frames_in_place({frame.data(), 3}, true).empty());
  }

  SUBCASE("Decode returns 0 for Length Mismatch") {
    auto frame = base_frame;
    frame[1] = 0x10;
    CHECK(decode_mbus_frames_in_place(frame, true).empty());
  }

  SUBCASE("Decode returns 0 for Invalid Stop Byte") {
    auto frame = base_frame;
    frame.back() = 0x17;
    CHECK(decode_mbus_frames_in_place(frame, true).empty());
  }

  SUBCASE("Decode returns 0 for Incomplete Final Frame") {
    auto frame = base_frame;
    CHECK(decode_mbus_frames_in_place({frame.data(), frame.size() - 1}, true).empty());
  }

  SUBCASE("Decode ignores trailing garbage after valid frames") {
    auto frame = base_frame;
    frame.push_back(0xFF);
    const auto result = decode_mbus_frames_in_place(frame, true);
    CHECK(result.size() == 3);
    CHECK(frame[0] == 0xAA);
    CHECK(frame[1] == 0xBB);
    CHECK(frame[2] == 0xCC);
  }

  SUBCASE("Multiple Frames - Second Frame has Length Mismatch") {
    std::vector<uint8_t> multi_frame = base_frame;
    std::vector<uint8_t> frame2;
    build_mbus_frame(frame2, {0xDD, 0xEE});
    frame2[1] = 0x10; // Corrupt L1
    multi_frame.insert(multi_frame.end(), frame2.begin(), frame2.end());

    // decode() aborts entirely if ANY frame is corrupted
    CHECK(decode_mbus_frames_in_place(multi_frame, true).empty());
  }

  SUBCASE("Multiple Frames - Second Frame has Checksum Error") {
    std::vector<uint8_t> multi_frame = base_frame;
    std::vector<uint8_t> frame2;
    build_mbus_frame(frame2, {0xDD, 0xEE});
    frame2[10] ^= 0xFF; // Corrupt a byte
    multi_frame.insert(multi_frame.end(), frame2.begin(), frame2.end());

    // decode() aborts entirely if CRC fails on ANY frame
    CHECK(decode_mbus_frames_in_place(multi_frame, false).empty());
  }

  SUBCASE("Empty Payload Handling (Frame Size valid, but no Application Data)") {
    std::vector<uint8_t> empty_frame;
    build_mbus_frame(empty_frame, {});
    // Fails because write_offset == 0
    CHECK(decode_mbus_frames_in_place(empty_frame, true).empty());
  }

  SUBCASE("Mixed Frames - Valid Frame Followed by Empty Frame") {
    std::vector<uint8_t> multi_frame = base_frame;
    std::vector<uint8_t> empty_frame;
    build_mbus_frame(empty_frame, {});
    multi_frame.insert(multi_frame.end(), empty_frame.begin(), empty_frame.end());

    // Succeeds and returns 3, silently ignoring the second empty frame
    CHECK(decode_mbus_frames_in_place(multi_frame, true).size() == 3);
  }

  SUBCASE("Header Size Too Large for Defined Length (Malformed L)") {
    auto frame = base_frame;
    frame[1] = 0x02;
    frame[2] = 0x02;
    frame[4+2+1] = 0x16; // Recalculate Stop Byte position

    // Fails because MBUS_HEADER > MBUS_INTRO + L
    CHECK(decode_mbus_frames_in_place({frame.data(), 8}, true).empty());
  }
}
