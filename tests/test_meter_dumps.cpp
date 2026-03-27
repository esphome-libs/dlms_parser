#include <doctest.h>
#include <format>
#include <functional>
#include <map>
#include <string>
#include <cstdarg>
#include <vector>
#include <exception>

#include "dlms_parser/dlms_parser.h"
#include "dlms_parser/log.h"

#include "tests/expected/raw_sagemcom_xt211.h"
#include "tests/expected/hdlc_iskra550.h"
#include "tests/expected/hdlc_norway_han_1phase.h"
#include "tests/expected/hdlc_norway_han_3phase.h"
#include "tests/expected/mbus_netz_noe_p1.h"
#include "tests/expected/raw_energomera.h"
#include "tests/expected/hdlc_landis_gyr_zmf100.h"
#include "tests/expected/raw_salzburg_netz.h"

void run_meter_test(const char* name,
                    const uint8_t* payload, size_t payload_size,
                    size_t expected_count,
                    const std::map<std::string, std::string>& expected_strings,
                    const std::map<std::string, float>& expected_floats,
                    dlms_parser::FrameFormat format = dlms_parser::FrameFormat::RAW,
                    std::function<void(dlms_parser::DlmsParser&)> setup_fn = nullptr) {
  fprintf(stderr, "\n========== %s ==========\n", name);
  std::string log_messages;
  dlms_parser::Logger::set_log_function([&log_messages](const dlms_parser::LogLevel log_level, const char* fmt, va_list args) {
    std::array<char, 2000> buffer;
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif
    vsnprintf(buffer.data(), buffer.size(), fmt, args);
#ifdef __clang__
#pragma clang diagnostic pop
#endif

    const char* level_str;
    switch(log_level) {
      case dlms_parser::LogLevel::DEBUG:        level_str = "[DBG] "; break;
      case dlms_parser::LogLevel::VERY_VERBOSE: level_str = "[VV]  "; break;
      case dlms_parser::LogLevel::VERBOSE:      level_str = "[VRB] "; break;
      case dlms_parser::LogLevel::INFO:         level_str = "[INF] "; break;
      case dlms_parser::LogLevel::WARNING:      level_str = "[WRN] "; break;
      case dlms_parser::LogLevel::ERROR:        level_str = "[ERR] "; break;
      default: throw std::runtime_error("Unknown log level");
    }

    log_messages += std::format("{}{}\n", level_str, buffer.data());
    fprintf(stderr, "%s%s\n", level_str, buffer.data());
  });

  dlms_parser::DlmsParser parser;
  parser.set_frame_format(format);
  if (setup_fn) setup_fn(parser);

  std::map<std::string, float> captured_floats;
  std::map<std::string, std::string> captured_strings;

  auto callback = [&](const char* obis_code, const float float_val, const char* str_val, const bool is_numeric) {
    if (is_numeric) {
      captured_floats[std::string(obis_code)] = float_val;
    } else {
      captured_strings[std::string(obis_code)] = std::string(str_val);
    }
  };

  size_t objects_found = parser.parse(payload, payload_size, callback);
  INFO("--- Parser Execution Logs ---\n" << log_messages);
  dlms_parser::Logger::set_log_function([](dlms_parser::LogLevel, const char*, va_list){});

  CHECK(objects_found == expected_count);

  for (const auto& expected : expected_strings) {
    INFO("Checking string OBIS code: ", expected.first);
    REQUIRE(captured_strings.count(expected.first) > 0);
    INFO("Expected value: ", expected.second, " | Actual value: ", captured_strings[expected.first]);
    CHECK(captured_strings[expected.first] == expected.second);
  }

  for (const auto& expected : expected_floats) {
    INFO("Checking numeric OBIS code: ", expected.first);
    REQUIRE(captured_floats.count(expected.first) > 0);
    INFO("Expected value: ", expected.second, " | Actual value: ", captured_floats[expected.first]);
    CHECK(static_cast<double>(captured_floats[expected.first]) == doctest::Approx(static_cast<double>(expected.second)));
  }
}

// ---------------------------------------------------------
// Test Suite: Register all meter dumps here
// ---------------------------------------------------------
TEST_CASE("Integration: Real Meter Dumps") {

  SUBCASE("Sagemcom XT211") {
    run_meter_test("Sagemcom XT211",
      dlms::test_data::sagemcom_xt211_raw_frame,
      sizeof(dlms::test_data::sagemcom_xt211_raw_frame),
      dlms::test_data::sagemcom_xt211_expected_count,
      dlms::test_data::sagemcom_xt211_expected_strings,
      dlms::test_data::sagemcom_xt211_expected_floats
    );
  }

  SUBCASE("Iskra 550 (HDLC, 3 segmented frames)") {
    // Objects 1-2 are 2-element structs {OBIS, octet-string} — serial / id.
    // Pattern S(TO, TV) matches them at the outer STRUCT(16) level (count=2 check
    // ensures it does NOT fire for the 3-element structs, letting T2 handle those).
    run_meter_test("Iskra 550 (HDLC, 3 segmented frames)",
      dlms::test_data::iskra550_raw_frame,
      sizeof(dlms::test_data::iskra550_raw_frame),
      dlms::test_data::iskra550_expected_count,
      dlms::test_data::iskra550_expected_strings,
      dlms::test_data::iskra550_expected_floats,
      dlms_parser::FrameFormat::HDLC,
      [](dlms_parser::DlmsParser& p) { p.register_pattern("S(TO, TV)"); }
    );
  }

  SUBCASE("Norway HAN 1-phase (HDLC, Aidon)") {
    // ARRAY(9): 3 string objects {OBIS, string} + 6 numeric {OBIS, value, scaler-unit}.
    // S(TO, TV) captures the 2-element string structs; T2 handles the 3-element numeric ones.
    run_meter_test("Norway HAN 1-phase (HDLC, Aidon)",
      dlms::test_data::norway_han_1phase_raw_frame,
      sizeof(dlms::test_data::norway_han_1phase_raw_frame),
      dlms::test_data::norway_han_1phase_expected_count,
      dlms::test_data::norway_han_1phase_expected_strings,
      dlms::test_data::norway_han_1phase_expected_floats,
      dlms_parser::FrameFormat::HDLC,
      [](dlms_parser::DlmsParser& p) { p.register_pattern("S(TO, TV)"); }
    );
  }

  SUBCASE("Norway HAN 3-phase (HDLC, Aidon)") {
    // ARRAY(27): 1 datetime {OBIS, datetime} + 26 numeric {OBIS, value, scaler-unit}.
    // S(TO, TV) captures the datetime struct; T2 handles the numeric ones.
    run_meter_test("Norway HAN 3-phase (HDLC, Aidon)",
      dlms::test_data::norway_han_3phase_raw_frame,
      sizeof(dlms::test_data::norway_han_3phase_raw_frame),
      dlms::test_data::norway_han_3phase_expected_count,
      dlms::test_data::norway_han_3phase_expected_strings,
      dlms::test_data::norway_han_3phase_expected_floats,
      dlms_parser::FrameFormat::HDLC,
      [](dlms_parser::DlmsParser& p) { p.register_pattern("S(TO, TV)"); }
    );
  }

  SUBCASE("MBus Netz NOE P1 (encrypted)") {
    // 2 M-Bus frames, General-Glo-Ciphering (0xDB), AES-GCM encrypted.
    // Notification body has structure of 23 objects, all non tagged, one by one: DTM,T2,T2,...,T
    // 1) Timestamp as TDTM
    // 2) Plain object, no object structure, just: TO, TV, TSU
    // ..) More plain objects
    // last) Last object is Meter number, Ocstet-string, last in the structure
    run_meter_test("MBus Netz NOE P1 (encrypted)",
      dlms::test_data::mbus_netz_noe_p1_raw_frame,
      sizeof(dlms::test_data::mbus_netz_noe_p1_raw_frame),
      dlms::test_data::mbus_netz_noe_p1_expected_count,
      dlms::test_data::mbus_netz_noe_p1_expected_strings,
      dlms::test_data::mbus_netz_noe_p1_expected_floats,
      dlms_parser::FrameFormat::MBUS,
      [](dlms_parser::DlmsParser& p) {
        p.set_decryption_key(std::vector<uint8_t>(
            dlms::test_data::mbus_netz_noe_p1_key,
            dlms::test_data::mbus_netz_noe_p1_key + 16));
        p.register_pattern("L, TSTR");
      }
    );
  }

  SUBCASE("Energomera (RAW)") {
    run_meter_test("Energomera (RAW)",
      dlms::test_data::raw_energomera_frame,
      sizeof(dlms::test_data::raw_energomera_frame),
      dlms::test_data::raw_energomera_expected_count,
      dlms::test_data::raw_energomera_expected_strings,
      dlms::test_data::raw_energomera_expected_floats
    );
  }

  SUBCASE("Landis+Gyr ZMF100 (HDLC)") {
    run_meter_test("Landis+Gyr ZMF100 (HDLC)",
      dlms::test_data::hdlc_landis_gyr_zmf100_raw_frame,
      sizeof(dlms::test_data::hdlc_landis_gyr_zmf100_raw_frame),
      dlms::test_data::hdlc_landis_gyr_zmf100_expected_count,
      dlms::test_data::hdlc_landis_gyr_zmf100_expected_strings,
      dlms::test_data::hdlc_landis_gyr_zmf100_expected_floats,
      dlms_parser::FrameFormat::HDLC,
      [](dlms_parser::DlmsParser& p) {
        p.register_pattern("S(TO, TDTM)");
        p.register_pattern("S(TO, TV)");
        p.register_pattern("TOW, TV, TSU");  // Landis+Gyr firmware bug: 06 09 instead of 09 06
      }
    );
  }

  SUBCASE("Salzburg Netz (RAW)") {
    run_meter_test("Salzburg Netz (RAW)",
      dlms::test_data::raw_salzburg_netz_frame,
      sizeof(dlms::test_data::raw_salzburg_netz_frame),
      dlms::test_data::raw_salzburg_netz_expected_count,
      dlms::test_data::raw_salzburg_netz_expected_strings,
      dlms::test_data::raw_salzburg_netz_expected_floats,
      dlms_parser::FrameFormat::RAW,
      [](dlms_parser::DlmsParser& p) {
        p.register_pattern("TO, TDTM");   // flat datetime (OBIS + datetime as 2 top-level elements)
        p.register_pattern("S(TO, TV)");
      }
    );
  }

}
