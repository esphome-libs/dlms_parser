#include <doctest.h>
#include <vector>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "dlms_parser/hdlc_decoder.h"
#include "dlms_parser/types.h"
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

TEST_CASE("HDLC Decoder - Frame Status Check (check)") {
  SUBCASE("Valid Complete Frame") {
    CHECK(HdlcDecoder::check(BASE_FRAME.data(), BASE_FRAME.size()) == FrameStatus::COMPLETE);
  }

  SUBCASE("Buffer Too Short") {
    constexpr uint8_t tiny[] = {0x7E};
    CHECK(HdlcDecoder::check(tiny, 1) == FrameStatus::ERROR);
  }

  SUBCASE("Missing Start Flag") {
    auto frame = BASE_FRAME;
    frame[0] = 0x00;
    CHECK(HdlcDecoder::check(frame.data(), frame.size()) == FrameStatus::ERROR);
  }

  SUBCASE("Missing End Flag") {
    auto frame = BASE_FRAME;
    frame.back() = 0x00;
    CHECK(HdlcDecoder::check(frame.data(), frame.size()) == FrameStatus::ERROR);
  }

  SUBCASE("Incomplete Frame (Cut off)") {
    CHECK(HdlcDecoder::check(BASE_FRAME.data(), BASE_FRAME.size() - 5) == FrameStatus::NEED_MORE);
  }

  SUBCASE("Header Not Fully Available") {
    CHECK(HdlcDecoder::check(BASE_FRAME.data(), 2) == FrameStatus::NEED_MORE);
  }

  SUBCASE("Segmented Frame (More Frames Follow)") {
    auto frame = BASE_FRAME;
    update_frame_length(frame, true);
    CHECK(HdlcDecoder::check(frame.data(), frame.size()) == FrameStatus::NEED_MORE);
  }

  SUBCASE("Multiple Frames Concatenated") {
    std::vector<uint8_t> multi_frame;
    auto frame1 = BASE_FRAME;
    update_frame_length(frame1, true);
    auto frame2 = BASE_FRAME;
    update_frame_length(frame2, false);

    multi_frame.insert(multi_frame.end(), frame1.begin(), frame1.end());
    multi_frame.insert(multi_frame.end(), frame2.begin(), frame2.end());

    CHECK(HdlcDecoder::check(multi_frame.data(), multi_frame.size()) == FrameStatus::COMPLETE);
  }

  SUBCASE("Multiple Frames Concatenated - Last Frame Incomplete") {
    std::vector<uint8_t> multi_frame;
    auto frame1 = BASE_FRAME;
    update_frame_length(frame1, true);
    auto frame2 = BASE_FRAME;
    update_frame_length(frame2, false);

    multi_frame.insert(multi_frame.end(), frame1.begin(), frame1.end());
    multi_frame.insert(multi_frame.end(), frame2.begin(), frame2.begin() + 5);

    CHECK(HdlcDecoder::check(multi_frame.data(), multi_frame.size()) == FrameStatus::NEED_MORE);
  }

  SUBCASE("Valid Frame followed by invalid garbage") {
    auto frame = BASE_FRAME;
    frame.push_back(0xFF);

    CHECK(HdlcDecoder::check(frame.data(), frame.size()) == FrameStatus::ERROR);
  }
}

TEST_CASE("HDLC Decoder - Payload Decoding (decode)") {
  HdlcDecoder decoder;
  decoder.set_skip_crc_check(true);

  SUBCASE("Single Frame with LLC Stripping (E6 E6 00)") {
    auto frame = BASE_FRAME;
    size_t new_len = decoder.decode(frame.data(), frame.size());

    CHECK(new_len == 3);
    CHECK(frame[0] == 0xAA);
    CHECK(frame[1] == 0xBB);
    CHECK(frame[2] == 0xCC);
  }

  SUBCASE("Single Frame with Alternative LLC Stripping (E6 E7 00)") {
    auto frame = BASE_FRAME;
    frame[9] = 0xE7;
    size_t new_len = decoder.decode(frame.data(), frame.size());

    CHECK(new_len == 3);
    CHECK(frame[0] == 0xAA);
    CHECK(frame[1] == 0xBB);
    CHECK(frame[2] == 0xCC);
  }

  SUBCASE("Single Frame without LLC") {
    auto frame = BASE_FRAME;
    frame[8] = 0x12;
    frame[9] = 0x34;
    frame[10] = 0x56;

    size_t new_len = decoder.decode(frame.data(), frame.size());

    CHECK(new_len == 6);
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
    size_t new_len = decoder.decode(frame.data(), frame.size());

    // Should NOT strip, should treat E6 E6 as data
    CHECK(new_len == 2);
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

    size_t new_len = decoder.decode(multi_frame.data(), multi_frame.size());

    CHECK(new_len == 5);
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

    size_t new_len = decoder.decode(multi_frame.data(), multi_frame.size());

    // Frame 1 payload: AA BB CC
    // Frame 2 payload: E6 E6 00 DD EE
    CHECK(new_len == 8);
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

    CHECK(decoder.decode(multi_frame.data(), multi_frame.size()) == 0);
  }
}

TEST_CASE("HDLC Decoder - Address Length Decoding") {
  HdlcDecoder decoder;
  decoder.set_skip_crc_check(true);

  SUBCASE("2-Byte Address Parsing") {
    std::vector<uint8_t> frame = {
      0x7E, 0xA0, 0x00,
      0x02, 0x03,
      0x21,
      0x93, 0x11, 0x22, 0xE6, 0xE6, 0x00, 0xAA, 0xBB, 0x33, 0x44, 0x7E
    };
    update_frame_length(frame);

    size_t new_len = decoder.decode(frame.data(), frame.size());
    CHECK(new_len == 2);
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

    size_t new_len = decoder.decode(frame.data(), frame.size());
    CHECK(new_len == 2);
    CHECK(frame[0] == 0xAA);
  }

  SUBCASE("Invalid Destination Address Length (No LSB=1 within 4 bytes)") {
    std::vector<uint8_t> frame = {
      0x7E, 0xA0, 0x00,
      0x02, 0x02, 0x02, 0x02, 0x02, // Dst
      0x21, 0x93, 0x11, 0x22, 0xAA, 0x33, 0x44, 0x7E
    };
    update_frame_length(frame);

    CHECK(decoder.decode(frame.data(), frame.size()) == 0);
  }

  SUBCASE("Invalid Source Address Length (No LSB=1 within 4 bytes)") {
    std::vector<uint8_t> frame = {
      0x7E, 0xA0, 0x00,
      0x03, // Valid Dst
      0x02, 0x02, 0x02, 0x02, 0x02, // Invalid Src
      0x93, 0x11, 0x22, 0xAA, 0x33, 0x44, 0x7E
    };
    update_frame_length(frame);

    CHECK(decoder.decode(frame.data(), frame.size()) == 0);
  }

  SUBCASE("Truncated Address Field runs out of bounds") {
    std::vector<uint8_t> frame = {
      0x7E, 0xA0, 0x00,
      0x02, 0x02, // Address starts but buffer ends abruptly
      0x33, 0x44, 0x7E
    };
    update_frame_length(frame);
    CHECK(decoder.decode(frame.data(), frame.size()) == 0);
  }
}

TEST_CASE("HDLC Decoder - Malformed Frame Handling") {
  HdlcDecoder decoder;
  decoder.set_skip_crc_check(true);

  SUBCASE("Length field mismatch vs buffer boundaries") {
    auto frame = BASE_FRAME;
    frame[2] += 2;
    CHECK(decoder.decode(frame.data(), frame.size()) == 0);
  }

  SUBCASE("Frame too short inside flags (< 9 bytes)") {
    std::vector<uint8_t> short_frame = { 0x7E, 0xA0, 0x00, 0x03, 0x21, 0x93, 0x11, 0x33, 0x44, 0x7E };
    update_frame_length(short_frame);
    CHECK(decoder.decode(short_frame.data(), short_frame.size()) == 0);
  }

  SUBCASE("Strict CRC enabled - Rejects invalid HCS") {
    decoder.set_skip_crc_check(false);
    auto frame = BASE_FRAME; // BASE_FRAME has garbage for both HCS and FCS
    CHECK(decoder.decode(frame.data(), frame.size()) == 0);
  }

  SUBCASE("Strict CRC enabled - Accepts valid CRC") {
    decoder.set_skip_crc_check(false);
    std::vector frame(std::begin(dlms::test_data::iskra550_frame3), std::end(dlms::test_data::iskra550_frame3));
    CHECK(decoder.decode(frame.data(), frame.size()) > 0);
  }

  SUBCASE("Strict CRC enabled - HCS valid, FCS invalid") {
    decoder.set_skip_crc_check(false);
    std::vector frame(std::begin(dlms::test_data::iskra550_frame3), std::end(dlms::test_data::iskra550_frame3));

    // Flip a bit in the payload area to invalidate the FCS while keeping HCS mathematically intact
    frame[16] ^= 0xFF;

    CHECK(decoder.decode(frame.data(), frame.size()) == 0);
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
    CHECK(decoder.decode(no_data_frame.data(), no_data_frame.size()) == 0);
  }
}