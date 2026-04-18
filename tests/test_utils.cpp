#include <doctest.h>
#include <array>
#include <span>
#include <string_view>
#include <ostream>

#include "test_util.h"
#include "dlms_parser/utils.h"

using namespace dlms_parser;

TEST_CASE_FIXTURE(LogFixture, "Endianness Conversions") {
  SUBCASE("be16") {
    constexpr uint8_t data[] = {0x12, 0x34};
    CHECK(be16(data) == 0x1234);
  }

  SUBCASE("be32") {
    constexpr uint8_t data[] = {0x12, 0x34, 0x56, 0x78};
    CHECK(be32(data) == 0x12345678);
  }

  SUBCASE("be64") {
    const uint8_t data[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    CHECK(be64(data) == 0x1122334455667788ULL);
  }
}

TEST_CASE_FIXTURE(LogFixture, "BER Length Decoding") {
  SUBCASE("Short form length (<= 127)") {
    constexpr uint8_t data[] = {0x7F}; // 127
    size_t pos = 0;
    CHECK(read_ber_length(data, pos) == 127);
    CHECK(pos == 1);
  }

  SUBCASE("Long form length (1 byte length)") {
    constexpr uint8_t data[] = {0x81, 0xFF}; // 0x81 means 1 byte follows
    size_t pos = 0;
    CHECK(read_ber_length(data, pos) == 255);
    CHECK(pos == 2);
  }

  SUBCASE("Long form length (2 byte length)") {
    constexpr uint8_t data[] = {0x82, 0x01, 0x00}; // 0x82 means 2 bytes follow, 0x0100 = 256
    size_t pos = 0;
    CHECK(read_ber_length(data, pos) == 256);
    CHECK(pos == 3);
  }

  SUBCASE("Long form length (4 byte length max uint32)") {
    constexpr uint8_t data[] = {0x84, 0xFF, 0xFF, 0xFF, 0xFF};
    size_t pos = 0;
    CHECK(read_ber_length(data, pos) == 0xFFFFFFFF);
    CHECK(pos == 5);
  }

  SUBCASE("Buffer overflow protection") {
    constexpr uint8_t data[] = {0x82, 0x01}; // Missing second byte
    size_t pos = 0;
    CHECK(read_ber_length(data, pos) == 0);
  }

  SUBCASE("Empty buffer protection") {
    size_t pos = 0;
    CHECK(read_ber_length({}, pos) == 0);
  }
}

TEST_CASE_FIXTURE(LogFixture, "Data Size and Type Properties") {
  SUBCASE("Data Sizes") {
    CHECK(get_data_type_size(DlmsDataType::NONE) == 0);
    CHECK(get_data_type_size(DlmsDataType::UINT8) == 1);
    CHECK(get_data_type_size(DlmsDataType::UINT16) == 2);
    CHECK(get_data_type_size(DlmsDataType::FLOAT32) == 4);
    CHECK(get_data_type_size(DlmsDataType::FLOAT64) == 8);
    CHECK(get_data_type_size(DlmsDataType::DATETIME) == 12);
    CHECK(get_data_type_size(DlmsDataType::DATE) == 5);
    CHECK(get_data_type_size(DlmsDataType::TIME) == 4);
    CHECK(get_data_type_size(DlmsDataType::OCTET_STRING) == -1); // Variable length
  }

  SUBCASE("Value Type Checks") {
    CHECK(is_value_data_type(DlmsDataType::UINT16) == true);
    CHECK(is_value_data_type(DlmsDataType::FLOAT32) == true);
    CHECK(is_value_data_type(DlmsDataType::STRING) == true);
    CHECK(is_value_data_type(DlmsDataType::ARRAY) == false);
    CHECK(is_value_data_type(DlmsDataType::STRUCTURE) == false);
  }
}

TEST_CASE_FIXTURE(LogFixture, "DLMS Datetime 12-byte Validation") {
  SUBCASE("Null pointer safety") {
    CHECK(test_if_date_time_12b({}) == false);
  }

  SUBCASE("Valid fully specified date") {
    const uint8_t valid_dt[] = {
        0x07, 0xE6, // 2022
        0x01,       // Jan
        0x0F,       // 15th
        0x06,       // Saturday
        0x0C,       // 12h
        0x1E,       // 30m
        0x00,       // 00s
        0xFF,       // Hundredths (Unspecified)
        0x80, 0x00, // Deviation (Unspecified)
        0x00        // Clock status
    };
    CHECK(test_if_date_time_12b(valid_dt) == true);
  }

  SUBCASE("Invalid year") {
    const uint8_t invalid_dt[] = {0x07, 0xB1, 0x01, 0x0F, 0x06, 0x0C, 0x1E, 0x00, 0xFF, 0x80, 0x00, 0x00}; // Year 1969
    CHECK(test_if_date_time_12b(invalid_dt) == false);
  }

  SUBCASE("Invalid month") {
    const uint8_t invalid_dt[] = {0x07, 0xE6, 0x0D, 0x0F, 0x06, 0x0C, 0x1E, 0x00, 0xFF, 0x80, 0x00, 0x00}; // Month 13
    CHECK(test_if_date_time_12b(invalid_dt) == false);
  }

  SUBCASE("Invalid day") {
    const uint8_t invalid_dt[] = {0x07, 0xE6, 0x01, 0x20, 0x06, 0x0C, 0x1E, 0x00, 0xFF, 0x80, 0x00, 0x00}; // Day 32
    CHECK(test_if_date_time_12b(invalid_dt) == false);
  }

  SUBCASE("Invalid hour") {
    const uint8_t invalid_dt[] = {0x07, 0xE6, 0x01, 0x0F, 0x06, 0x19, 0x1E, 0x00, 0xFF, 0x80, 0x00, 0x00}; // Hour 25
    CHECK(test_if_date_time_12b(invalid_dt) == false);
  }
}

TEST_CASE_FIXTURE(LogFixture, "DLMS Datetime Formatting") {
  std::array<char, 64> buffer{};

  SUBCASE("Format fully specified datetime") {
    const uint8_t valid_dt[] = {
        0x07, 0xE6, 0x01, 0x0F, 0x06, 0x0C, 0x1E, 0x00, 0xFF, 0x80, 0x00, 0x00
    };
    datetime_to_string(valid_dt, buffer);
    CHECK(std::string_view(buffer.data()) == "2022-01-15 12:30:00");
  }

  SUBCASE("Format datetime with deviation") {
    const uint8_t dev_dt[] = {
        0x07, 0xE6, 0x01, 0x0F, 0x06, 0x0C, 0x1E, 0x00, 0xFF,
        0xFF, 0xC4, // -60 minutes (-1 hour) deviation
        0x00
    };
    datetime_to_string(dev_dt, buffer);
    CHECK(std::string_view(buffer.data()) == "2022-01-15 12:30:00 -01:00");
  }

  SUBCASE("Unspecified datetime fields") {
    const uint8_t unspec_dt[] = {
        0xFF, 0xFF, // Year Unspecified
        0xFF,       // Month Unspecified
        0xFF,       // Day Unspecified
        0xFF,       // DoW
        0xFF,       // Hour Unspecified
        0xFF,       // Minute Unspecified
        0xFF,       // Second Unspecified
        0xFF,       // Hundredths
        0x80, 0x00, // Deviation (Unspecified)
        0x00        // Clock status
    };
    datetime_to_string(unspec_dt, buffer);
    CHECK(std::string_view(buffer.data()) == "\?\?\?\?-\?\?-\?\? \?\?:\?\?:\?\?");
  }
}

TEST_CASE_FIXTURE(LogFixture, "DLMS Data Type to String") {
  CHECK(std::string_view(to_string(DlmsDataType::NONE)) == "NONE");
  CHECK(std::string_view(to_string(DlmsDataType::FLOAT32)) == "FLOAT32");
  CHECK(std::string_view(to_string(DlmsDataType::DATETIME)) == "DATETIME");
  // Test fallback/default case
  CHECK(std::string_view(to_string(static_cast<DlmsDataType>(99))) == "UNKNOWN");
}
