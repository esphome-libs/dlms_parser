#include <doctest.h>
#include <array>
#include <cstring>
#include <span>
#include <string_view>
#include <ostream>

#include "dlms_parser/utils.h"

using namespace dlms_parser;

TEST_CASE("Endianness Conversions") {
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

TEST_CASE("OBIS String Formatting") {
  std::array<char, 32> buffer{};

  SUBCASE("Valid OBIS code") {
    const uint8_t obis[] = {1, 0, 96, 1, 0, 255};
    obis_to_string(obis, buffer);
    CHECK(std::string_view(buffer.data()) == "1.0.96.1.0.255");
  }

  SUBCASE("Zeroed OBIS code") {
    const uint8_t obis[] = {0, 0, 0, 0, 0, 0};
    obis_to_string(obis, buffer);
    CHECK(std::string_view(buffer.data()) == "0.0.0.0.0.0");
  }

  SUBCASE("Max length enforcement") {
    const uint8_t obis[] = {1, 0, 96, 1, 0, 255};
    obis_to_string(obis, std::span<char>{buffer.data(), 10});
    // Should safely truncate
    CHECK(std::string_view(buffer.data()) == "1.0.96.1.");
  }

  SUBCASE("Null pointer safety") {
    buffer[0] = 'X'; // Fill with dummy data
    obis_to_string({}, buffer);
    CHECK(std::string_view(buffer.data()) == ""); // Should be null-terminated at index 0
  }
}

TEST_CASE("Hex Formatting (format_hex_pretty_to)") {
  std::array<char, 64> buffer{};

  SUBCASE("Normal data") {
    constexpr uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    format_hex_pretty_to(buffer, data);
    CHECK(std::string_view(buffer.data()) == "DE.AD.BE.EF");
  }

  SUBCASE("Empty data") {
    format_hex_pretty_to(buffer, {});
    CHECK(std::string_view(buffer.data()) == "");
  }

  SUBCASE("Zero max length") {
    constexpr uint8_t data[] = {0xDE, 0xAD};
    buffer[0] = 'X';
    format_hex_pretty_to(std::span<char>{buffer.data(), 0}, data);
    CHECK(buffer[0] == 'X'); // Should not have written anything, not even \0
  }

  SUBCASE("Truncated by max length") {
    constexpr uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    // We pass 7 because it briefly needs space to write "DE.AD." + '\0' (7 bytes)
    // before the function strips the trailing dot.
    format_hex_pretty_to(std::span<char>{buffer.data(), 7}, data);
    CHECK(std::string_view(buffer.data()) == "DE.AD");
  }
}

TEST_CASE("BER Length Decoding") {
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

TEST_CASE("Data Size and Type Properties") {
  SUBCASE("Data Sizes") {
    CHECK(get_data_type_size(DLMS_DATA_TYPE_NONE) == 0);
    CHECK(get_data_type_size(DLMS_DATA_TYPE_UINT8) == 1);
    CHECK(get_data_type_size(DLMS_DATA_TYPE_UINT16) == 2);
    CHECK(get_data_type_size(DLMS_DATA_TYPE_FLOAT32) == 4);
    CHECK(get_data_type_size(DLMS_DATA_TYPE_FLOAT64) == 8);
    CHECK(get_data_type_size(DLMS_DATA_TYPE_DATETIME) == 12);
    CHECK(get_data_type_size(DLMS_DATA_TYPE_DATE) == 5);
    CHECK(get_data_type_size(DLMS_DATA_TYPE_TIME) == 4);
    CHECK(get_data_type_size(DLMS_DATA_TYPE_OCTET_STRING) == -1); // Variable length
  }

  SUBCASE("Value Type Checks") {
    CHECK(is_value_data_type(DLMS_DATA_TYPE_UINT16) == true);
    CHECK(is_value_data_type(DLMS_DATA_TYPE_FLOAT32) == true);
    CHECK(is_value_data_type(DLMS_DATA_TYPE_STRING) == true);
    CHECK(is_value_data_type(DLMS_DATA_TYPE_ARRAY) == false);
    CHECK(is_value_data_type(DLMS_DATA_TYPE_STRUCTURE) == false);
  }
}

TEST_CASE("Float Conversion (data_as_float)") {
  SUBCASE("Null pointer and zero length") {
    CHECK(data_as_float(DLMS_DATA_TYPE_UINT8, {}) == 0.0f);
    uint8_t dummy = 0;
    CHECK(data_as_float(DLMS_DATA_TYPE_UINT8, {&dummy, 0}) == 0.0f);
  }

  SUBCASE("Unsigned Integers") {
    constexpr uint8_t u8[] = {255};
    CHECK(data_as_float(DLMS_DATA_TYPE_UINT8, u8) == 255.0f);

    constexpr uint8_t u16[] = {0x01, 0x00}; // 256
    CHECK(data_as_float(DLMS_DATA_TYPE_UINT16, u16) == 256.0f);

    constexpr uint8_t u32[] = {0x00, 0x01, 0x00, 0x00}; // 65536
    CHECK(data_as_float(DLMS_DATA_TYPE_UINT32, u32) == 65536.0f);
  }

  SUBCASE("Signed Integers") {
    constexpr uint8_t i8[] = {0xFF}; // -1
    CHECK(data_as_float(DLMS_DATA_TYPE_INT8, i8) == -1.0f);

    constexpr uint8_t i16[] = {0xFF, 0xFE}; // -2
    CHECK(data_as_float(DLMS_DATA_TYPE_INT16, i16) == -2.0f);

    constexpr uint8_t i32[] = {0xFF, 0xFF, 0xFF, 0xFD}; // -3
    CHECK(data_as_float(DLMS_DATA_TYPE_INT32, i32) == -3.0f);
  }

  SUBCASE("Float32") {
    constexpr uint8_t f32_pos[] = {0x41, 0x20, 0x00, 0x00}; // 10.0f in IEEE 754
    CHECK(data_as_float(DLMS_DATA_TYPE_FLOAT32, f32_pos) == 10.0f);

    constexpr uint8_t f32_neg[] = {0xC1, 0x20, 0x00, 0x00}; // -10.0f
    CHECK(data_as_float(DLMS_DATA_TYPE_FLOAT32, f32_neg) == -10.0f);
  }

  SUBCASE("Float64") {
    const uint8_t f64[] = {0x40, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // 10.0 in IEEE 754 double
    CHECK(data_as_float(DLMS_DATA_TYPE_FLOAT64, f64) == 10.0f);
  }

  SUBCASE("Safe guarding against short lengths") {
    constexpr uint8_t f32[] = {0x41, 0x20, 0x00}; // Missing last byte
    CHECK(data_as_float(DLMS_DATA_TYPE_FLOAT32, {f32, 3}) == 0.0f);
  }
}

TEST_CASE("DLMS Datetime 12-byte Validation") {
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

TEST_CASE("DLMS Datetime Formatting") {
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

TEST_CASE("Data to String formatting") {
  std::array<char, 128> buffer{};

  SUBCASE("String types") {
    constexpr uint8_t str[] = {'H', 'e', 'l', 'l', 'o'};
    data_to_string(DLMS_DATA_TYPE_STRING, str, buffer);
    CHECK(std::string_view(buffer.data()) == "Hello");
  }

  SUBCASE("Numeric types") {
    constexpr uint8_t u32[] = {0x00, 0x00, 0x04, 0xD2}; // 1234
    data_to_string(DLMS_DATA_TYPE_UINT32, u32, buffer);
    CHECK(std::string_view(buffer.data()) == "1234");
  }

  SUBCASE("Bit strings fallback to hex") {
    constexpr uint8_t bits[] = {0xAB, 0xCD};
    data_to_string(DLMS_DATA_TYPE_BIT_STRING, bits, buffer);
    CHECK(std::string_view(buffer.data()) == "abcd"); // The function uses %02x
  }

  SUBCASE("Float32 formatting") {
    constexpr uint8_t f32[] = {0x41, 0x20, 0x00, 0x00}; // 10.0f
    data_to_string(DLMS_DATA_TYPE_FLOAT32, f32, buffer);
    // Uses %f, so it appends decimal zeros
    CHECK(std::string_view(buffer.data()).find("10.00000") == 0);
  }

  SUBCASE("Null pointer safety") {
    buffer[0] = 'X';
    data_to_string(DLMS_DATA_TYPE_STRING, {}, buffer);
    CHECK(std::string_view(buffer.data()) == "");
  }
}

TEST_CASE("DLMS Data Type to String") {
  CHECK(std::string_view(dlms_data_type_to_string(DLMS_DATA_TYPE_NONE)) == "NONE");
  CHECK(std::string_view(dlms_data_type_to_string(DLMS_DATA_TYPE_FLOAT32)) == "FLOAT32");
  CHECK(std::string_view(dlms_data_type_to_string(DLMS_DATA_TYPE_DATETIME)) == "DATETIME");
  // Test fallback/default case
  CHECK(std::string_view(dlms_data_type_to_string(static_cast<DlmsDataType>(99))) == "UNKNOWN");
}
