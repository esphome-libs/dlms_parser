#include <doctest.h>
#include <format>
#include <functional>
#include <map>
#include <string>
#include <cstdarg>
#include <span>
#include <vector>

#include "dlms_parser/dlms_parser.h"
#include "dlms_parser/log.h"
#include "dlms_parser/decryption/aes_128_gcm_decryptor_mbedtls.h"
#include "dlms_parser/decryption/aes_128_gcm_decryptor_bearssl.h"
#include "dlms_parser/decryption/aes_128_gcm_decryptor_tfpsa.h"

#include "tests/expected/raw_sagemcom_xt211.h"
#include "tests/expected/raw_energomera.h"
#include "tests/expected/raw_salzburg_netz.h"
#include "tests/expected/raw_egd_example.h"
#include "tests/expected/hdlc_iskra550.h"
#include "tests/expected/hdlc_norway_han_1phase.h"
#include "tests/expected/hdlc_norway_han_3phase.h"
#include "tests/expected/hdlc_landis_gyr_zmf100.h"
#include "tests/expected/hdlc_landis_gyr_e450.h"
#include "tests/expected/hdlc_lgz_e450_2.h"
#include "tests/expected/hdlc_kaifa_ma304h3e.h"
#include "tests/expected/hdlc_kamstrup_omnipower.h"
#include "tests/expected/mbus_netz_noe_p1.h"

class LogCapturer : dlms_parser::NonCopyableAndNonMovable {
public:
  LogCapturer() {
    dlms_parser::Logger::set_log_function([&](const dlms_parser::LogLevel log_level, const char* fmt, va_list args) {
      std::array<char, 2000> buffer;
      vsnprintf(buffer.data(), buffer.size(), fmt, args);

      const char* level_str;
      switch (log_level) {
      case dlms_parser::LogLevel::DEBUG:        level_str = "[DBG] "; break;
      case dlms_parser::LogLevel::VERY_VERBOSE: level_str = "[VV]  "; break;
      case dlms_parser::LogLevel::VERBOSE:      level_str = "[VRB] "; break;
      case dlms_parser::LogLevel::INFO:         level_str = "[INF] "; break;
      case dlms_parser::LogLevel::WARNING:      level_str = "[WRN] "; break;
      case dlms_parser::LogLevel::ERROR:        level_str = "[ERR] "; break;
      }

      log_messages += std::format("{}{}\n", level_str, buffer.data());
      });
  }

  ~LogCapturer() {
    dlms_parser::Logger::set_log_function([](auto, auto, auto) {});
  }

  std::string get_logs() const {
    return log_messages;
  }

private:
  std::string log_messages;
};

template<typename Aes128GcmDecryptor = dlms_parser::Aes128GcmDecryptorMbedTls>
void run_meter_test(std::span<const uint8_t> payload,
                    size_t expected_count,
                    const std::map<std::string, std::string>& expected_strings,
                    const std::map<std::string, float>& expected_floats,
                    std::function<void(dlms_parser::DlmsParser&)> setup_fn = [](auto&) {}) {
  LogCapturer log_capturer;
  
  Aes128GcmDecryptor decryptor;
  dlms_parser::DlmsParser parser(&decryptor);
  parser.load_default_patterns();
  setup_fn(parser);

  std::map<std::string, float> captured_floats;
  std::map<std::string, std::string> captured_strings;

  auto callback = [&](const char* obis_code, const float float_val, const char* str_val, const bool is_numeric) {
    if (is_numeric) {
      captured_floats[std::string(obis_code)] = float_val;
    } else {
      captured_strings[std::string(obis_code)] = std::string(str_val);
    }
  };

  std::vector<uint8_t> mutable_payload(payload.begin(), payload.end());
  auto [objects_found, bytes_consumed] = parser.parse(mutable_payload, callback);

  INFO(log_capturer.get_logs());

  REQUIRE(objects_found == expected_count);

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
// RAW APDU tests (no frame transport)
// ---------------------------------------------------------
TEST_CASE("Integration: RAW APDU") {

  SUBCASE("Sagemcom XT211") {
    run_meter_test(
      dlms::test_data::sagemcom_xt211_raw_frame,
      dlms::test_data::sagemcom_xt211_expected_count,
      dlms::test_data::sagemcom_xt211_expected_strings,
      dlms::test_data::sagemcom_xt211_expected_floats
    );
  }

  SUBCASE("Sagemcom XT211. Duplicated frame at the end") {
    std::vector<uint8_t> duplicated_frame(std::begin(dlms::test_data::sagemcom_xt211_raw_frame), std::end(dlms::test_data::sagemcom_xt211_raw_frame));
    duplicated_frame.insert(duplicated_frame.end(), std::begin(dlms::test_data::sagemcom_xt211_raw_frame), std::end(dlms::test_data::sagemcom_xt211_raw_frame));
    run_meter_test(
      duplicated_frame,
      39,
      dlms::test_data::sagemcom_xt211_expected_strings,
      dlms::test_data::sagemcom_xt211_expected_floats
    );
  }

  SUBCASE("Sagemcom XT211 and the half of the same data at the end") {
    std::vector<uint8_t> duplicated_frame(std::begin(dlms::test_data::sagemcom_xt211_raw_frame), std::end(dlms::test_data::sagemcom_xt211_raw_frame));
    const auto half = std::size(dlms::test_data::sagemcom_xt211_raw_frame) / 2;
    duplicated_frame.insert(duplicated_frame.end(), std::begin(dlms::test_data::sagemcom_xt211_raw_frame), std::begin(dlms::test_data::sagemcom_xt211_raw_frame) + half);
    run_meter_test(
      duplicated_frame,
      27,
      dlms::test_data::sagemcom_xt211_expected_strings,
      dlms::test_data::sagemcom_xt211_expected_floats
    );
  }

  SUBCASE("Energomera") {
    run_meter_test(
      dlms::test_data::raw_energomera_frame,
      dlms::test_data::raw_energomera_expected_count,
      dlms::test_data::raw_energomera_expected_strings,
      dlms::test_data::raw_energomera_expected_floats
    );
  }

  SUBCASE("Salzburg Netz") {
    run_meter_test(
      dlms::test_data::raw_salzburg_netz_frame,
      dlms::test_data::raw_salzburg_netz_expected_count,
      dlms::test_data::raw_salzburg_netz_expected_strings,
      dlms::test_data::raw_salzburg_netz_expected_floats,
      [](dlms_parser::DlmsParser& p) {
        p.register_pattern("TO, TDTM");
        p.register_pattern("S(TO, TV)");
      }
    );
  }

  SUBCASE("EGD Example") {
    run_meter_test(
      dlms::test_data::egd_example_raw_frame,
      dlms::test_data::egd_example_expected_count,
      dlms::test_data::egd_example_expected_strings,
      dlms::test_data::egd_example_expected_floats
    );
  }

}

// ---------------------------------------------------------
// HDLC transport tests
// ---------------------------------------------------------
TEST_CASE("Integration: HDLC") {

  SUBCASE("Iskra 550 (3 segmented frames)") {
    run_meter_test(
      dlms::test_data::iskra550_raw_frame,
      dlms::test_data::iskra550_expected_count,
      dlms::test_data::iskra550_expected_strings,
      dlms::test_data::iskra550_expected_floats,
      [](dlms_parser::DlmsParser& p) { p.register_pattern("S(TO, TV)"); }
    );
  }

  SUBCASE("Iskra 550 (3 segmented frames) and the same data at the end. Should ignore the duplicated part") {
    std::vector<uint8_t> duplicated_frame(std::begin(dlms::test_data::iskra550_raw_frame), std::end(dlms::test_data::iskra550_raw_frame));
    duplicated_frame.insert(duplicated_frame.end(), std::begin(dlms::test_data::iskra550_raw_frame), std::end(dlms::test_data::iskra550_raw_frame));
    run_meter_test(
      duplicated_frame,
      dlms::test_data::iskra550_expected_count,
      dlms::test_data::iskra550_expected_strings,
      dlms::test_data::iskra550_expected_floats,
      [](dlms_parser::DlmsParser& p) { p.register_pattern("S(TO, TV)"); }
    );
  }

  SUBCASE("Iskra 550 (3 segmented frames) and the half of the same data at the end. Should fail") {
    std::vector<uint8_t> duplicated_frame(std::begin(dlms::test_data::iskra550_raw_frame), std::end(dlms::test_data::iskra550_raw_frame));
    const auto half = std::size(dlms::test_data::iskra550_raw_frame) / 2;
    duplicated_frame.insert(duplicated_frame.end(), std::begin(dlms::test_data::iskra550_raw_frame), std::begin(dlms::test_data::iskra550_raw_frame) + half);
    dlms_parser::Aes128GcmDecryptorMbedTls decryptor;
    dlms_parser::DlmsParser parser(&decryptor);
    auto [n, consumed] = parser.parse(duplicated_frame, [](auto, auto, auto, auto) {});
    CHECK(n == 0);
  }

  SUBCASE("Norway HAN 1-phase (Aidon)") {
    run_meter_test(
      dlms::test_data::norway_han_1phase_raw_frame,
      dlms::test_data::norway_han_1phase_expected_count,
      dlms::test_data::norway_han_1phase_expected_strings,
      dlms::test_data::norway_han_1phase_expected_floats,
      [](dlms_parser::DlmsParser& p) {
        p.register_pattern("S(TO, TV, TSU)");
        p.register_pattern("S(TO, TV)"); 
      }
    );
  }

  SUBCASE("Norway HAN 3-phase (Aidon)") {
    run_meter_test(
      dlms::test_data::norway_han_3phase_raw_frame,
      dlms::test_data::norway_han_3phase_expected_count,
      dlms::test_data::norway_han_3phase_expected_strings,
      dlms::test_data::norway_han_3phase_expected_floats,
      [](dlms_parser::DlmsParser& p) {
        p.register_pattern("DateTime", "F, S(TO, TDTM)");
        p.register_pattern("Obis-Value-Scaler-Unit", "S(TO, TV, TSU)"); 
      }
    );
  }

  SUBCASE("Landis+Gyr ZMF100") {
    run_meter_test(
      dlms::test_data::hdlc_landis_gyr_zmf100_raw_frame,
      dlms::test_data::hdlc_landis_gyr_zmf100_expected_count,
      dlms::test_data::hdlc_landis_gyr_zmf100_expected_strings,
      dlms::test_data::hdlc_landis_gyr_zmf100_expected_floats,
      [](dlms_parser::DlmsParser& p) {
        p.set_skip_crc_check(true);
        p.register_pattern("S(TO, TDTM)");
        p.register_pattern("S(TO, TV)");
        p.register_pattern("TOW, TV, TSU");
      }
    );
  }

  SUBCASE("Landis+Gyr ZMF100 - CRC check rejects bad FCS") {
    dlms_parser::Aes128GcmDecryptorMbedTls decryptor;
    dlms_parser::DlmsParser parser(&decryptor);
    std::vector<uint8_t> frame(std::begin(dlms::test_data::hdlc_landis_gyr_zmf100_raw_frame),
                                std::end(dlms::test_data::hdlc_landis_gyr_zmf100_raw_frame));
    auto [n, consumed] = parser.parse(frame, [](auto, auto, auto, auto) {});
    CHECK(n == 0);
  }

  SUBCASE("Landis+Gyr E450 (GBT + encrypted). Use MbedTls") {
    run_meter_test(
      dlms::test_data::hdlc_landis_gyr_e450_raw_frame,
      dlms::test_data::hdlc_landis_gyr_e450_expected_count,
      dlms::test_data::hdlc_landis_gyr_e450_expected_strings,
      dlms::test_data::hdlc_landis_gyr_e450_expected_floats,
      [](dlms_parser::DlmsParser& p) {
        p.set_decryption_key(dlms::test_data::hdlc_landis_gyr_e450_key);
        p.register_pattern("DateTime", "F, TDTM");
        p.register_pattern("Obis-Value Pair","TO, TV");
      }
    );
  }

  SUBCASE("Landis+Gyr E450 (GBT + encrypted). Use BearSsl") {
    run_meter_test<dlms_parser::Aes128GcmDecryptorBearSsl>(
      dlms::test_data::hdlc_landis_gyr_e450_raw_frame,
      dlms::test_data::hdlc_landis_gyr_e450_expected_count,
      dlms::test_data::hdlc_landis_gyr_e450_expected_strings,
      dlms::test_data::hdlc_landis_gyr_e450_expected_floats,
      [](dlms_parser::DlmsParser& p) {
        p.set_decryption_key(dlms::test_data::hdlc_landis_gyr_e450_key);
        p.register_pattern("DateTime", "F, TDTM");
        p.register_pattern("Obis-Value Pair", "TO, TV");
      }
    );
  }

  SUBCASE("Landis+Gyr E450 (GBT + encrypted). Use TF-PSA") {
    run_meter_test<dlms_parser::Aes128GcmDecryptorTfPsa>(
      dlms::test_data::hdlc_landis_gyr_e450_raw_frame,
      dlms::test_data::hdlc_landis_gyr_e450_expected_count,
      dlms::test_data::hdlc_landis_gyr_e450_expected_strings,
      dlms::test_data::hdlc_landis_gyr_e450_expected_floats,
      [](dlms_parser::DlmsParser& p) {
        p.set_decryption_key(dlms::test_data::hdlc_landis_gyr_e450_key);
        p.register_pattern("DateTime", "F, TDTM");
        p.register_pattern("Obis-Value Pair", "TO, TV");
      }
    );
  }

  SUBCASE("Landis+Gyr E450 #2 (GBT + encrypted)") {
    run_meter_test(
      dlms::test_data::hdlc_lgz_e450_2_raw_frame,
      dlms::test_data::hdlc_lgz_e450_2_expected_count,
      dlms::test_data::hdlc_lgz_e450_2_expected_strings,
      dlms::test_data::hdlc_lgz_e450_2_expected_floats,
      [](dlms_parser::DlmsParser& p) {
        p.set_decryption_key(dlms::test_data::hdlc_lgz_e450_2_key);
        p.register_pattern("TO, TV");
      }
    );
  }

  SUBCASE("Kamstrup Omnipower (encrypted, no auth key)") {
    run_meter_test(
      dlms::test_data::hdlc_kamstrup_omnipower_raw_frame,
      dlms::test_data::hdlc_kamstrup_omnipower_expected_count,
      dlms::test_data::hdlc_kamstrup_omnipower_expected_strings,
      dlms::test_data::hdlc_kamstrup_omnipower_expected_floats,
      [](dlms_parser::DlmsParser& p) {
        p.set_decryption_key(dlms::test_data::hdlc_kamstrup_omnipower_key);
        p.register_pattern("Obis List Ver", "F, TSTR");
        p.register_pattern("Code-Value Pair", "TO, TV");
      }
    );
  }

  SUBCASE("Kamstrup Omnipower (encrypted + authenticated)") {
    run_meter_test(
      dlms::test_data::hdlc_kamstrup_omnipower_raw_frame,
      dlms::test_data::hdlc_kamstrup_omnipower_expected_count,
      dlms::test_data::hdlc_kamstrup_omnipower_expected_strings,
      dlms::test_data::hdlc_kamstrup_omnipower_expected_floats,
      [](dlms_parser::DlmsParser& p) {
        p.set_decryption_key(dlms::test_data::hdlc_kamstrup_omnipower_key);
        p.set_authentication_key(dlms::test_data::hdlc_kamstrup_omnipower_auth_key);
        p.register_pattern("Obis List Ver", "F, TSTR");
        p.register_pattern("Code-Value Pair", "TO, TV");
      }
    );
  }

  SUBCASE("Kamstrup Omnipower (encrypted + authenticated). BearSsl") {
    run_meter_test<dlms_parser::Aes128GcmDecryptorBearSsl>(
      dlms::test_data::hdlc_kamstrup_omnipower_raw_frame,
      dlms::test_data::hdlc_kamstrup_omnipower_expected_count,
      dlms::test_data::hdlc_kamstrup_omnipower_expected_strings,
      dlms::test_data::hdlc_kamstrup_omnipower_expected_floats,
      [](dlms_parser::DlmsParser& p) {
        p.set_decryption_key(dlms::test_data::hdlc_kamstrup_omnipower_key);
        p.set_authentication_key(dlms::test_data::hdlc_kamstrup_omnipower_auth_key);
        p.register_pattern("Obis List Ver", "F, TSTR");
        p.register_pattern("Code-Value Pair", "TO, TV");
      }
    );
  }

  SUBCASE("Kamstrup Omnipower (encrypted + authenticated). Use TF-PSA") {
    run_meter_test<dlms_parser::Aes128GcmDecryptorTfPsa>(
      dlms::test_data::hdlc_kamstrup_omnipower_raw_frame,
      dlms::test_data::hdlc_kamstrup_omnipower_expected_count,
      dlms::test_data::hdlc_kamstrup_omnipower_expected_strings,
      dlms::test_data::hdlc_kamstrup_omnipower_expected_floats,
      [](dlms_parser::DlmsParser& p) {
        p.set_decryption_key(dlms::test_data::hdlc_kamstrup_omnipower_key);
        p.set_authentication_key(dlms::test_data::hdlc_kamstrup_omnipower_auth_key);
        p.register_pattern("Obis List Ver", "F, TSTR");
        p.register_pattern("Code-Value Pair", "TO, TV");
      }
    );
  }

  SUBCASE("Kaifa MA304H3E") {
    run_meter_test(
      dlms::test_data::hdlc_kaifa_ma304h3e_raw_frame,
      dlms::test_data::hdlc_kaifa_ma304h3e_expected_count,
      dlms::test_data::hdlc_kaifa_ma304h3e_expected_strings,
      dlms::test_data::hdlc_kaifa_ma304h3e_expected_floats
    );
  }

  SUBCASE("Kamstrup Omnipower - wrong auth key rejects frame") {
    const auto wrong_key = dlms_parser::Aes128GcmAuthenticationKey::from_bytes(std::array<uint8_t, 16>{0x00}).value();
    dlms_parser::Aes128GcmDecryptorMbedTls decryptor;
    dlms_parser::DlmsParser parser(&decryptor);
    parser.set_decryption_key(dlms::test_data::hdlc_kamstrup_omnipower_key);
    parser.set_authentication_key(wrong_key);
    parser.load_default_patterns();
    std::vector<uint8_t> frame(std::begin(dlms::test_data::hdlc_kamstrup_omnipower_raw_frame),
                                std::end(dlms::test_data::hdlc_kamstrup_omnipower_raw_frame));
    auto [n, consumed] = parser.parse(frame, [](auto, auto, auto, auto) {});
    CHECK(n == 0);
  }

}

// ---------------------------------------------------------
// M-Bus transport tests
// ---------------------------------------------------------
TEST_CASE("Integration: MBus") {

  SUBCASE("Netz NOE P1 (encrypted)") {
    run_meter_test(
      dlms::test_data::mbus_netz_noe_p1_raw_frame,
      dlms::test_data::mbus_netz_noe_p1_expected_count,
      dlms::test_data::mbus_netz_noe_p1_expected_strings,
      dlms::test_data::mbus_netz_noe_p1_expected_floats,
      [](dlms_parser::DlmsParser& p) {
        p.set_decryption_key(dlms::test_data::mbus_netz_noe_p1_key);
        const uint8_t meter_obis[] = {0, 0, 96, 1, 0, 255};  // 0.0.96.1.0.255
        p.register_pattern("MeterID", "L, TSTR", 0, meter_obis);
        p.register_pattern("Obis-Value-Scaler-Unit", "S(TO, TV, TSU)");
      }
    );
  }

  SUBCASE("Netz NOE P1 (encrypted) and the same data at the end. Should ignore the duplicated part") {
    std::vector<uint8_t> duplicated_frame(std::begin(dlms::test_data::mbus_netz_noe_p1_raw_frame), std::end(dlms::test_data::mbus_netz_noe_p1_raw_frame));
    duplicated_frame.insert(duplicated_frame.end(), std::begin(dlms::test_data::mbus_netz_noe_p1_raw_frame), std::end(dlms::test_data::mbus_netz_noe_p1_raw_frame));
    run_meter_test(
      duplicated_frame,
      dlms::test_data::mbus_netz_noe_p1_expected_count,
      dlms::test_data::mbus_netz_noe_p1_expected_strings,
      dlms::test_data::mbus_netz_noe_p1_expected_floats,
      [](dlms_parser::DlmsParser& p) {
        p.set_decryption_key(dlms::test_data::mbus_netz_noe_p1_key);
        const uint8_t meter_obis[] = { 0, 0, 96, 1, 0, 255 };  // 0.0.96.1.0.255
        p.register_pattern("MeterID", "L, TSTR", 0, meter_obis);
        p.register_pattern("Obis-Value-Scaler-Unit", "S(TO, TV, TSU)");
      }
    );
  }

  SUBCASE("Netz NOE P1 (encrypted) and the half of the same data at the end. Should fail") {
    std::vector<uint8_t> duplicated_frame(std::begin(dlms::test_data::mbus_netz_noe_p1_raw_frame), std::end(dlms::test_data::mbus_netz_noe_p1_raw_frame));
    const auto half = std::size(dlms::test_data::mbus_netz_noe_p1_raw_frame) / 2;
    duplicated_frame.insert(duplicated_frame.end(), std::begin(dlms::test_data::mbus_netz_noe_p1_raw_frame), std::begin(dlms::test_data::mbus_netz_noe_p1_raw_frame) + half);
    dlms_parser::Aes128GcmDecryptorMbedTls decryptor;
    dlms_parser::DlmsParser parser(&decryptor);
    auto [n, consumed] = parser.parse(duplicated_frame, [](auto, auto, auto, auto) {});
    CHECK(n == 0);
  }
}
