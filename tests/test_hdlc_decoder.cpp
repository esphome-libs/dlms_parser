#include <doctest.h>
#include <vector>
#include <cstdint>

#include "test_util.h"

#include "dlms_parser/hdlc_decoder.h"
#include "expected/hdlc_iskra550.h"

using namespace dlms_parser;

// Helper to easily fix up the length fields of a raw frame vector
static void update_frame_length(std::vector<uint8_t>& frame, const bool segmented = false) {
  if (frame.size() < 4) return;
  const size_t len = frame.size() - 2;
  frame[1] = static_cast<uint8_t>((frame[1] & 0xF0) | (segmented ? 0x08 : 0x00) | ((len >> 8) & 0x07));
  frame[2] = static_cast<uint8_t>(len & 0xFF);
}

// Structurally valid base frame for testing decode logic (ignoring CRC by default)
// Contains: Flag | Fmt+Len | Dst(1) | Src(1) | Ctrl | HCS(2) | LLC(3) | Payload(3) | FCS(2) | Flag
static const std::vector<uint8_t> BASE_FRAME = {
    0x7E,
    0xA0, 0x0F,
    0x03,
    0x21,
    0x93,
    0x11, 0x22,
    0xE6, 0xE6, 0x00,
    0xAA, 0xBB, 0xCC,
    0x33, 0x44,
    0x7E
};

TEST_CASE_FIXTURE(LogFixture, "HDLC Decoder - Payload Decoding (decode)") {

  SUBCASE("Single Frame with LLC Stripping (E6 E6 00)") {
    auto frame = BASE_FRAME;
    const auto result = decode_hdlc_frames_in_place(frame, true);

    CHECK(result.size() == 3);
    CHECK(frame[0] == 0xAA);
    CHECK(frame[1] == 0xBB);
    CHECK(frame[2] == 0xCC);
  }

  SUBCASE("Single Frame with Alternative LLC Stripping (E6 E7 00)") {
    auto frame = BASE_FRAME;
    frame[9] = 0xE7;
    const auto result = decode_hdlc_frames_in_place(frame, true);

    CHECK(result.size() == 3);
    CHECK(frame[0] == 0xAA);
    CHECK(frame[1] == 0xBB);
    CHECK(frame[2] == 0xCC);
  }

  SUBCASE("Single Frame without LLC") {
    auto frame = BASE_FRAME;
    frame[8] = 0x12;
    frame[9] = 0x34;
    frame[10] = 0x56;

    const auto result = decode_hdlc_frames_in_place(frame, true);
    CHECK(result.size() == 6);
    CHECK(frame[0] == 0x12);
    CHECK(frame[1] == 0x34);
    CHECK(frame[2] == 0x56);
    CHECK(frame[3] == 0xAA);
  }

  SUBCASE("Payload too short for LLC stripping but mimics partial LLC") {
    std::vector<uint8_t> frame = {
      0x7E, 0xA0, 0x00,
      0x03, 0x21, 0x93,
      0x11, 0x22, // HCS
      0xE6, 0xE6, // Only 2 bytes of data (matches partial LLC)
      0x33, 0x44, // FCS
      0x7E
    };
    update_frame_length(frame);
    const auto result = decode_hdlc_frames_in_place(frame, true);
    CHECK(result.size() == 2);
    CHECK(frame[0] == 0xE6);
    CHECK(frame[1] == 0xE6);
  }

  SUBCASE("Multi-Frame (Segmented) Concatenation") {
    std::vector<uint8_t> multi_frame;

    auto frame1 = BASE_FRAME;
    frame1.erase(frame1.begin() + 13);
    update_frame_length(frame1, true);

    std::vector<uint8_t> frame2 = {
      0x7E, 0xA0, 0x00,
      0x03, 0x21, 0x93,
      0x11, 0x22,
      0xCC, 0xDD, 0xEE,
      0x33, 0x44,
      0x7E
    };
    update_frame_length(frame2, false);

    multi_frame.insert(multi_frame.end(), frame1.begin(), frame1.end());
    multi_frame.insert(multi_frame.end(), frame2.begin(), frame2.end());

    const auto result = decode_hdlc_frames_in_place(multi_frame, true);
    CHECK(result.size() == 5);
    CHECK(multi_frame[0] == 0xAA);
    CHECK(multi_frame[1] == 0xBB);
    CHECK(multi_frame[2] == 0xCC);
    CHECK(multi_frame[3] == 0xDD);
    CHECK(multi_frame[4] == 0xEE);
  }

  SUBCASE("LLC stripping ONLY occurs on first frame of segmented payload") {
    std::vector<uint8_t> multi_frame;
    auto frame1 = BASE_FRAME;
    update_frame_length(frame1, true); // segmented

    std::vector<uint8_t> frame2 = {
      0x7E, 0xA0, 0x00,
      0x03, 0x21, 0x93, // Address + Ctrl
      0x11, 0x22,       // HCS
      0xE6, 0xE6, 0x00, // Fake LLC pattern in second frame
      0xDD, 0xEE,       // Data
      0x33, 0x44,       // FCS
      0x7E
    };
    update_frame_length(frame2, false);

    multi_frame.insert(multi_frame.end(), frame1.begin(), frame1.end());
    multi_frame.insert(multi_frame.end(), frame2.begin(), frame2.end());

    const auto result = decode_hdlc_frames_in_place(multi_frame, true);

    // Frame 1 payload: AA BB CC
    // Frame 2 payload: E6 E6 00 DD EE
    CHECK(result.size() == 8);
    CHECK(multi_frame[0] == 0xAA);
    CHECK(multi_frame[3] == 0xE6);
    CHECK(multi_frame[4] == 0xE6);
    CHECK(multi_frame[5] == 0x00);
  }

  SUBCASE("Multi-Frame with corrupted second frame") {
    std::vector<uint8_t> multi_frame;
    auto frame1 = BASE_FRAME;
    update_frame_length(frame1, true);
    auto frame2 = BASE_FRAME;
    update_frame_length(frame2, false);
    frame2.pop_back();

    multi_frame.insert(multi_frame.end(), frame1.begin(), frame1.end());
    multi_frame.insert(multi_frame.end(), frame2.begin(), frame2.end());

    CHECK(decode_hdlc_frames_in_place(multi_frame, true).empty());
  }
}

TEST_CASE_FIXTURE(LogFixture, "HDLC Decoder - Address Length Decoding") {

  SUBCASE("2-Byte Address Parsing") {
    std::vector<uint8_t> frame = {
      0x7E, 0xA0, 0x00,
      0x02, 0x03,
      0x21,
      0x93, 0x11, 0x22, 0xE6, 0xE6, 0x00, 0xAA, 0xBB, 0x33, 0x44, 0x7E
    };
    update_frame_length(frame);

    const auto result = decode_hdlc_frames_in_place(frame, true);
    CHECK(result.size() == 2);
    CHECK(frame[0] == 0xAA);
  }

  SUBCASE("4-Byte Address Parsing") {
    std::vector<uint8_t> frame = {
      0x7E, 0xA0, 0x00,
      0x03,
      0x02, 0x04, 0x06, 0x09,
      0x93, 0x11, 0x22, 0xE6, 0xE6, 0x00, 0xAA, 0xBB, 0x33, 0x44, 0x7E
    };
    update_frame_length(frame);

    const auto result = decode_hdlc_frames_in_place(frame, true);
    CHECK(result.size() == 2);
    CHECK(frame[0] == 0xAA);
  }

  SUBCASE("Invalid Destination Address Length (No LSB=1 within 4 bytes)") {
    std::vector<uint8_t> frame = {
      0x7E, 0xA0, 0x00,
      0x02, 0x02, 0x02, 0x02, 0x02, // Dst
      0x21, 0x93, 0x11, 0x22, 0xAA, 0x33, 0x44, 0x7E
    };
    update_frame_length(frame);

    CHECK(decode_hdlc_frames_in_place(frame, true).empty());
  }

  SUBCASE("Invalid Source Address Length (No LSB=1 within 4 bytes)") {
    std::vector<uint8_t> frame = {
      0x7E, 0xA0, 0x00,
      0x03, // Valid Dst
      0x02, 0x02, 0x02, 0x02, 0x02, // Invalid Src
      0x93, 0x11, 0x22, 0xAA, 0x33, 0x44, 0x7E
    };
    update_frame_length(frame);

    CHECK(decode_hdlc_frames_in_place(frame, true).empty());
  }

  SUBCASE("Truncated Address Field runs out of bounds") {
    std::vector<uint8_t> frame = {
      0x7E, 0xA0, 0x00,
      0x02, 0x02, // Address starts but buffer ends abruptly
      0x33, 0x44, 0x7E
    };
    update_frame_length(frame);
    CHECK(decode_hdlc_frames_in_place(frame, true).empty());
  }
}

TEST_CASE_FIXTURE(LogFixture, "HDLC Decoder - Malformed Frame Handling") {

  SUBCASE("Length field mismatch vs buffer boundaries") {
    auto frame = BASE_FRAME;
    frame[2] += 2;
    CHECK(decode_hdlc_frames_in_place(frame, true).empty());
  }

  SUBCASE("Frame too short inside flags (< 9 bytes)") {
    std::vector<uint8_t> short_frame = { 0x7E, 0xA0, 0x00, 0x03, 0x21, 0x93, 0x11, 0x33, 0x44, 0x7E };
    update_frame_length(short_frame);
    CHECK(decode_hdlc_frames_in_place(short_frame, true).empty());
  }

  SUBCASE("Strict CRC enabled - Rejects invalid HCS") {
    auto frame = BASE_FRAME; // BASE_FRAME has garbage for both HCS and FCS
    CHECK(decode_hdlc_frames_in_place(frame, false).empty());
  }

  SUBCASE("Strict CRC enabled - Accepts valid CRC") {
    std::vector frame(std::begin(dlms::test_data::iskra550_frame3), std::end(dlms::test_data::iskra550_frame3));
    CHECK_FALSE(decode_hdlc_frames_in_place(frame, false).empty());
  }

  SUBCASE("Strict CRC enabled - HCS valid, FCS invalid") {
    std::vector frame(std::begin(dlms::test_data::iskra550_frame3), std::end(dlms::test_data::iskra550_frame3));

    // Flip a bit in the payload area to invalidate the FCS while keeping HCS mathematically intact
    frame[16] ^= 0xFF;

    CHECK(decode_hdlc_frames_in_place(frame, false).empty());
  }

  SUBCASE("No payload extracted edge case") {
    std::vector<uint8_t> no_data_frame = {
      0x7E, 0xA0, 0x00,
      0x03, 0x21, 0x93,
      0x11, 0x22,
      0x33, 0x44,
      0x7E
    };
    update_frame_length(no_data_frame);
    CHECK(decode_hdlc_frames_in_place(no_data_frame, true).empty());
  }
}
