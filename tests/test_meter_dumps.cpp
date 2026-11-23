#include <doctest.h>
#include <algorithm>
#include <array>
#include <format>
#include <functional>
#include <map>
#include <string>
#include <cstdarg>
#include <span>
#include <vector>

#include "tests/log_fixture.h"

#include "dlms_parser/dlms_parser.h"
#include "dlms_parser/decryption/aes_128_gcm_decryptor_mbedtls.h"
#include "dlms_parser/decryption/aes_128_gcm_decryptor_bearssl.h"
#include "dlms_parser/decryption/aes_128_gcm_decryptor_tfpsa.h"

#include "tests/expected/raw_sagemcom_xt211.h"
#include "tests/expected/raw_energomera.h"
#include "tests/expected/raw_salzburg_netz.h"
#include "tests/expected/raw_egd_example.h"
#include "tests/expected/hdlc_iskra550.h"
#include "tests/expected/hdlc_iskra_am550_si.h"
#include "tests/expected/hdlc_norway_han_1phase.h"
#include "tests/expected/hdlc_norway_han_3phase.h"
#include "tests/expected/hdlc_landis_gyr_zmf100.h"
#include "tests/expected/hdlc_landis_gyr_e450.h"
#include "tests/expected/hdlc_landis_gyr_e450_cyprus.h"
#include "tests/expected/hdlc_landis_gyr_e450_cyprus_2.h"
#include "tests/expected/hdlc_lgz_e450_2.h"
#include "tests/expected/hdlc_kaifa_ma304h3e.h"
#include "tests/expected/hdlc_kamstrup_omnipower.h"
#include "tests/expected/mbus_netz_noe_p1.h"
#include "tests/expected/mbus_kaifa_ma309m.h"

template<typename Aes128GcmDecryptor = dlms_parser::Aes128GcmDecryptorMbedTls>
void run_meter_test(std::span<const uint8_t> payload,
                    size_t expected_count,
                    const std::map<std::string, std::string>& expected_strings,
                    const std::map<std::string, float>& expected_floats,
                    const std::function<void(dlms_parser::DlmsParser&)>& setup_fn = [](auto&) {}) {
  std::map<std::string, float> captured_floats;
  std::map<std::string, std::string> captured_strings;

  auto callback = [&](const dlms_parser::AxdrCapture& capture) {
    char obis_buf[32];
    const std::string obis{capture.obis.to_string(obis_buf)};

    if (capture.is_numeric()) {
      captured_floats[obis] = capture.value_as_float_with_scaler_applied();
    }
    else {
      std::array<char, 128> str_val_buf{};
      captured_strings[obis] = std::string(capture.value_as_string(str_val_buf));
    }
  };

  Aes128GcmDecryptor decryptor;
  dlms_parser::DlmsParser parser(callback, &decryptor);
  parser.load_default_patterns();
  setup_fn(parser);

  std::vector<uint8_t> mutable_payload(payload.begin(), payload.end());
  auto [objects_found, bytes_consumed] = parser.parse(mutable_payload);

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

// Iskra AM550 positional patterns: one row per element index (see tests/expected/hdlc_iskra_am550_si.h).
struct PositionalPattern {
  const char* name;  // must outlive the parser (stored by pointer)
  const char* dsl;
  dlms_parser::ObisId obis;
};

constexpr PositionalPattern iskra_am550_5s_patterns[] = {
  {"AM550 5s #0",  "CNT(18), IDX(0), TSTR", dlms_parser::ObisId(0, 0, 42, 0, 0, 255)},
  {"AM550 5s #1",  "CNT(18), IDX(1), TSTR", dlms_parser::ObisId(0, 0, 96, 1, 0, 255)},
  {"AM550 5s #2",  "CNT(18), IDX(2), TV",   dlms_parser::ObisId(1, 0, 1, 7, 0, 255)},
  {"AM550 5s #3",  "CNT(18), IDX(3), TV",   dlms_parser::ObisId(1, 0, 2, 7, 0, 255)},
  {"AM550 5s #4",  "CNT(18), IDX(4), TV",   dlms_parser::ObisId(1, 0, 3, 7, 0, 255)},
  {"AM550 5s #5",  "CNT(18), IDX(5), TV",   dlms_parser::ObisId(1, 0, 4, 7, 0, 255)},
  {"AM550 5s #6",  "CNT(18), IDX(6), TV",   dlms_parser::ObisId(1, 0, 32, 7, 0, 255)},
  {"AM550 5s #7",  "CNT(18), IDX(7), TV",   dlms_parser::ObisId(1, 0, 52, 7, 0, 255)},
  {"AM550 5s #8",  "CNT(18), IDX(8), TV",   dlms_parser::ObisId(1, 0, 72, 7, 0, 255)},
  {"AM550 5s #9",  "CNT(18), IDX(9), TV",   dlms_parser::ObisId(1, 0, 31, 7, 0, 255)},
  {"AM550 5s #10", "CNT(18), IDX(10), TV",  dlms_parser::ObisId(1, 0, 51, 7, 0, 255)},
  {"AM550 5s #11", "CNT(18), IDX(11), TV",  dlms_parser::ObisId(1, 0, 71, 7, 0, 255)},
  {"AM550 5s #12", "CNT(18), IDX(12), TV",  dlms_parser::ObisId(1, 0, 21, 7, 0, 255)},
  {"AM550 5s #13", "CNT(18), IDX(13), TV",  dlms_parser::ObisId(1, 0, 41, 7, 0, 255)},
  {"AM550 5s #14", "CNT(18), IDX(14), TV",  dlms_parser::ObisId(1, 0, 61, 7, 0, 255)},
  {"AM550 5s #15", "CNT(18), IDX(15), TV",  dlms_parser::ObisId(1, 0, 22, 7, 0, 255)},
  {"AM550 5s #16", "CNT(18), IDX(16), TV",  dlms_parser::ObisId(1, 0, 42, 7, 0, 255)},
  {"AM550 5s #17", "CNT(18), IDX(17), TV",  dlms_parser::ObisId(1, 0, 62, 7, 0, 255)},
};

constexpr PositionalPattern iskra_am550_15min_patterns[] = {
  {"AM550 15min #0", "CNT(12), IDX(0), TSTR", dlms_parser::ObisId(0, 0, 42, 0, 0, 255)},
  {"AM550 15min #4", "CNT(12), IDX(4), TV",   dlms_parser::ObisId(1, 0, 1, 8, 0, 255)},
  {"AM550 15min #5", "CNT(12), IDX(5), TV",   dlms_parser::ObisId(1, 0, 1, 8, 1, 255)},
  {"AM550 15min #6", "CNT(12), IDX(6), TV",   dlms_parser::ObisId(1, 0, 1, 8, 2, 255)},
  {"AM550 15min #7", "CNT(12), IDX(7), TV",   dlms_parser::ObisId(1, 0, 2, 8, 0, 255)},
  {"AM550 15min #8", "CNT(12), IDX(8), TV",   dlms_parser::ObisId(1, 0, 2, 8, 1, 255)},
  {"AM550 15min #9", "CNT(12), IDX(9), TV",   dlms_parser::ObisId(1, 0, 2, 8, 2, 255)},
  {"AM550 15min #10", "CNT(12), IDX(10), TV",  dlms_parser::ObisId(1, 0, 3, 8, 0, 255)},
  {"AM550 15min #11", "CNT(12), IDX(11), TV",  dlms_parser::ObisId(1, 0, 4, 8, 0, 255)},
};

// Registers the patterns of one telegram layout. Only patterns whose CNT(n) matches the frame apply.
template<size_t N>
std::function<void(dlms_parser::DlmsParser&)> am550_setup(const PositionalPattern (&patterns)[N]) {
  return [&patterns](dlms_parser::DlmsParser& parser) {
    for (const auto& p : patterns) {
      parser.register_pattern(p.name, p.dsl, 10, p.obis);
    }
  };
}

// ---------------------------------------------------------
// Test Suite: Register all meter dumps here
// ---------------------------------------------------------
// RAW APDU tests (no frame transport)
// ---------------------------------------------------------
TEST_CASE_FIXTURE(LogFixture, "Integration: RAW APDU") {

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
    constexpr auto half = std::size(dlms::test_data::sagemcom_xt211_raw_frame) / 2;
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
      dlms::test_data::raw_salzburg_netz_expected_floats
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
TEST_CASE_FIXTURE(LogFixture, "Integration: HDLC") {

  SUBCASE("Iskra 550 (3 segmented frames)") {
    run_meter_test(
      dlms::test_data::iskra550_raw_frame,
      dlms::test_data::iskra550_expected_count,
      dlms::test_data::iskra550_expected_strings,
      dlms::test_data::iskra550_expected_floats
    );
  }

  SUBCASE("Iskra 550 (3 segmented frames) with leading M-Bus short frame") {
    std::vector<uint8_t> frame{0x10, 0x40, 0x01, 0x41, 0x16};
    frame.insert(frame.end(), std::begin(dlms::test_data::iskra550_raw_frame), std::end(dlms::test_data::iskra550_raw_frame));
    run_meter_test(
      frame,
      dlms::test_data::iskra550_expected_count,
      dlms::test_data::iskra550_expected_strings,
      dlms::test_data::iskra550_expected_floats
    );
  }

  SUBCASE("Iskra 550 (3 segmented frames) and the same data at the end. Should ignore the duplicated part") {
    std::vector<uint8_t> duplicated_frame(std::begin(dlms::test_data::iskra550_raw_frame), std::end(dlms::test_data::iskra550_raw_frame));
    duplicated_frame.insert(duplicated_frame.end(), std::begin(dlms::test_data::iskra550_raw_frame), std::end(dlms::test_data::iskra550_raw_frame));
    run_meter_test(
      duplicated_frame,
      dlms::test_data::iskra550_expected_count,
      dlms::test_data::iskra550_expected_strings,
      dlms::test_data::iskra550_expected_floats
    );
  }

  SUBCASE("Iskra 550 (3 segmented frames) and the half of the same data at the end. Should fail") {
    std::vector<uint8_t> duplicated_frame(std::begin(dlms::test_data::iskra550_raw_frame), std::end(dlms::test_data::iskra550_raw_frame));
    const auto half = std::size(dlms::test_data::iskra550_raw_frame) / 2;
    duplicated_frame.insert(duplicated_frame.end(), std::begin(dlms::test_data::iskra550_raw_frame), std::begin(dlms::test_data::iskra550_raw_frame) + half);
    dlms_parser::Aes128GcmDecryptorMbedTls decryptor;
    dlms_parser::DlmsParser parser([](const auto&) {}, &decryptor);
    auto [n, consumed] = parser.parse(duplicated_frame);
    CHECK(n == 0);
  }

  SUBCASE("Iskra AM550 Slovenia 5s (positional)") {
    run_meter_test(
      dlms::test_data::iskra_am550_5s_raw_frame,
      dlms::test_data::iskra_am550_5s_expected_count,
      dlms::test_data::iskra_am550_5s_expected_strings,
      dlms::test_data::iskra_am550_5s_expected_floats,
      am550_setup(iskra_am550_5s_patterns)
    );
  }

  SUBCASE("Iskra AM550 Slovenia 15min (positional)") {
    run_meter_test(
      dlms::test_data::iskra_am550_15min_raw_frame,
      dlms::test_data::iskra_am550_15min_expected_count,
      dlms::test_data::iskra_am550_15min_expected_strings,
      dlms::test_data::iskra_am550_15min_expected_floats,
      am550_setup(iskra_am550_15min_patterns)
    );
  }

  SUBCASE("Iskra AM550 positional frames without custom patterns yield no objects") {
    run_meter_test(dlms::test_data::iskra_am550_5s_raw_frame, 0, {}, {});
    run_meter_test(dlms::test_data::iskra_am550_15min_raw_frame, 0, {}, {});
  }

  SUBCASE("Iskra AM550 15min frame with only the 5s (CNT(18)) patterns registered") {
    // The CNT(18) guard must reject the 12-element telegram.
    run_meter_test(
      dlms::test_data::iskra_am550_15min_raw_frame,
      0,
      {},
      {},
      am550_setup(iskra_am550_5s_patterns)
    );
  }

  SUBCASE("Iskra AM550: rejected and guard-only patterns never match") {
    const auto obis = dlms_parser::ObisId(1, 0, 1, 7, 0, 255);
    const auto register_guards = [obis](dlms_parser::DlmsParser& p) {
      p.register_pattern("rejected S(IDX(1))", "S(IDX(1))", 10, obis);  // IDX inside S(...) is rejected
      p.register_pattern("guard CNT(18), IDX(2)", "CNT(18), IDX(2)", 10, obis);  // consumes nothing
      p.register_pattern("guard F, L", "F, L", 10, obis);  // consumes nothing
    };
    run_meter_test(dlms::test_data::iskra_am550_5s_raw_frame, 0, {}, {}, register_guards);

    run_meter_test(
      dlms::test_data::iskra_am550_5s_raw_frame,
      1,
      {},
      {{"1.0.1.7.0.255", 3513.0f}},
      [obis, register_guards](dlms_parser::DlmsParser& p) {
        register_guards(p);
        p.register_pattern("value CNT(18), IDX(2), TV", "CNT(18), IDX(2), TV", 10, obis);
      }
    );
  }

  SUBCASE("Norway HAN 1-phase (Aidon)") {
    run_meter_test(
      dlms::test_data::norway_han_1phase_raw_frame,
      dlms::test_data::norway_han_1phase_expected_count,
      dlms::test_data::norway_han_1phase_expected_strings,
      dlms::test_data::norway_han_1phase_expected_floats
    );
  }

  SUBCASE("Norway HAN 3-phase (Aidon)") {
    run_meter_test(
      dlms::test_data::norway_han_3phase_raw_frame,
      dlms::test_data::norway_han_3phase_expected_count,
      dlms::test_data::norway_han_3phase_expected_strings,
      dlms::test_data::norway_han_3phase_expected_floats
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
      }
    );
  }

  SUBCASE("Landis+Gyr ZMF100 - CRC check rejects bad FCS") {
    dlms_parser::Aes128GcmDecryptorMbedTls decryptor;
    dlms_parser::DlmsParser parser([](const auto&) {}, &decryptor);
    std::vector<uint8_t> frame(std::begin(dlms::test_data::hdlc_landis_gyr_zmf100_raw_frame),
                                std::end(dlms::test_data::hdlc_landis_gyr_zmf100_raw_frame));
    auto [n, consumed] = parser.parse(frame);
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
        p.register_pattern("DateTime", "F, TDTM", 0, {});
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
        p.register_pattern("DateTime", "F, TDTM", 0, {});
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
        p.register_pattern("DateTime", "F, TDTM", 0, {});
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
        p.register_pattern("DateTime", "F, TDTM", 0, {});
      }
    );
  }

  SUBCASE("Landis+Gyr E450 Cyprus") {
    run_meter_test(
      dlms::test_data::hdlc_landis_gyr_e450_cyprus_raw_frame,
      dlms::test_data::hdlc_landis_gyr_e450_cyprus_expected_count,
      dlms::test_data::hdlc_landis_gyr_e450_cyprus_expected_strings,
      dlms::test_data::hdlc_landis_gyr_e450_cyprus_expected_floats
    );
  }

  SUBCASE("Landis+Gyr E450 Cyprus long packet") {
    run_meter_test(
      dlms::test_data::hdlc_landis_gyr_e450_cyprus_2_raw_frame,
      dlms::test_data::hdlc_landis_gyr_e450_cyprus_2_expected_count,
      dlms::test_data::hdlc_landis_gyr_e450_cyprus_2_expected_strings,
      dlms::test_data::hdlc_landis_gyr_e450_cyprus_2_expected_floats
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
        p.register_pattern("Obis List Ver", "F, TSTR", 0, {});
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
        p.register_pattern("Obis List Ver", "F, TSTR", 0, {});
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
        p.register_pattern("Obis List Ver", "F, TSTR", 0, {});
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
        p.register_pattern("Obis List Ver", "F, TSTR", 0, {});
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
    dlms_parser::DlmsParser parser([](const auto&) {}, &decryptor);
    parser.set_decryption_key(dlms::test_data::hdlc_kamstrup_omnipower_key);
    parser.set_authentication_key(wrong_key);
    parser.load_default_patterns();
    std::vector<uint8_t> frame(std::begin(dlms::test_data::hdlc_kamstrup_omnipower_raw_frame),
                                std::end(dlms::test_data::hdlc_kamstrup_omnipower_raw_frame));
    auto [n, consumed] = parser.parse(frame);
    CHECK(n == 0);
  }

}

// ---------------------------------------------------------
// M-Bus transport tests
// ---------------------------------------------------------
TEST_CASE_FIXTURE(LogFixture, "Integration: MBus") {

  SUBCASE("Netz NOE P1 (encrypted)") {
    run_meter_test(
      dlms::test_data::mbus_netz_noe_p1_raw_frame,
      dlms::test_data::mbus_netz_noe_p1_expected_count,
      dlms::test_data::mbus_netz_noe_p1_expected_strings,
      dlms::test_data::mbus_netz_noe_p1_expected_floats,
      [](dlms_parser::DlmsParser& p) {
        p.set_decryption_key(dlms::test_data::mbus_netz_noe_p1_key);
        const dlms_parser::ObisId default_obis(0, 0, 96, 1, 0, 255);
        p.register_pattern("MeterID", "L, TSTR", 0, default_obis);
        p.register_pattern("DateTime", "F, TDTM", 0, {});
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
        const dlms_parser::ObisId default_obis(0, 0, 96, 1, 0, 255);
        p.register_pattern("MeterID", "L, TSTR", 0, default_obis);
        p.register_pattern("DateTime", "F, TDTM", 0, {});
      }
    );
  }

  SUBCASE("Netz NOE P1 (encrypted) and the half of the same data at the end. Should fail") {
    std::vector<uint8_t> duplicated_frame(std::begin(dlms::test_data::mbus_netz_noe_p1_raw_frame), std::end(dlms::test_data::mbus_netz_noe_p1_raw_frame));
    const auto half = std::size(dlms::test_data::mbus_netz_noe_p1_raw_frame) / 2;
    duplicated_frame.insert(duplicated_frame.end(), std::begin(dlms::test_data::mbus_netz_noe_p1_raw_frame), std::begin(dlms::test_data::mbus_netz_noe_p1_raw_frame) + half);
    dlms_parser::Aes128GcmDecryptorMbedTls decryptor;
    dlms_parser::DlmsParser parser([](const auto&) {}, &decryptor);
    auto [n, consumed] = parser.parse(duplicated_frame);
    CHECK(n == 0);
  }

  SUBCASE("Kaifa MA309M (EWR, Austria)") {
    run_meter_test(
        dlms::test_data::mbus_kaifa_ma309m_raw_frame,
        dlms::test_data::mbus_kaifa_ma309m_expected_count,
        dlms::test_data::mbus_kaifa_ma309m_expected_strings,
        dlms::test_data::mbus_kaifa_ma309m_expected_floats,
        [&](dlms_parser::DlmsParser& parser) {
            parser.set_decryption_key(dlms::test_data::mbus_kaifa_ma309m_key);
        }
    );
  }
}
