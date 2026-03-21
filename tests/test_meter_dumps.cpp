#include <doctest.h>
#include <map>
#include <string>
#include "dlms_parser/parser.h"
#include "tests/dumps/sagemcom_xt211.h"

void run_meter_test(const uint8_t* payload, size_t payload_size,
                    size_t expected_count,
                    const std::map<std::string, std::string>& expected_strings,
                    const std::map<std::string, float>& expected_floats) {

  dlms_parser::DlmsParser parser;
  std::map<std::string, float> captured_floats;
  std::map<std::string, std::string> captured_strings;

  auto callback = [&](const char* obis_code, const float float_val, const char* str_val, const bool is_numeric) {
    if (is_numeric) {
      captured_floats[std::string(obis_code)] = float_val;
    } else {
      captured_strings[std::string(obis_code)] = std::string(str_val);
    }
  };

  size_t objects_found = parser.parse(payload, payload_size, callback, false);

  CHECK(objects_found == expected_count);

  for (const auto& expected : expected_strings) {
    INFO("Checking string OBIS code: ", expected.first);
    REQUIRE(captured_strings.count(expected.first) > 0);
    CHECK(captured_strings[expected.first] == expected.second);
  }

  for (const auto& expected : expected_floats) {
    INFO("Checking numeric OBIS code: ", expected.first);
    REQUIRE(captured_floats.count(expected.first) > 0);
    CHECK(static_cast<double>(captured_floats[expected.first]) == doctest::Approx(static_cast<double>(expected.second)));
  }
}

// ---------------------------------------------------------
// Test Suite: Register all meter dumps here
// ---------------------------------------------------------
TEST_CASE("Integration: Real Meter Dumps") {

  SUBCASE("Sagemcom XT211") {
    run_meter_test(
      dlms::test_data::sagemcom_xt211_raw_frame,
      sizeof(dlms::test_data::sagemcom_xt211_raw_frame),
      dlms::test_data::sagemcom_xt211_expected_count,
      dlms::test_data::sagemcom_xt211_expected_strings,
      dlms::test_data::sagemcom_xt211_expected_floats
    );
  }

  // To add a new meter in the future, just add another SUBCASE:
  // SUBCASE("Future Meter X") {
  //   run_meter_test(
  //       dlms::test_data::future_meter_raw_frame,
  //       sizeof(dlms::test_data::future_meter_raw_frame),
  //       ...
  //   );
  // }
}
