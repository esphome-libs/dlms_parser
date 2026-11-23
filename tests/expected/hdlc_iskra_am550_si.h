#pragma once

#include <cstdint>
#include <cstddef>
#include <map>
#include <string>

namespace dlms::test_data {

// Iskra AM550 (Slovenia) - single HDLC frame carrying a DATA-NOTIFICATION with a flat
// STRUCTURE of values WITHOUT OBIS codes (positional). The OBIS code of each value is
// implied only by its element index, so the patterns use the IDX(n) (element index) and
// CNT(n) (element count) tokens. Identity values are anonymised (ISK1030799999999, ISK99999999).
// Sources: tests/dumps/hdlc_iskra_am550_si_5s.log, tests/dumps/hdlc_iskra_am550_si_15min.log
//
// 5 s telegram: STRUCTURE(18), element index -> OBIS (scaler not sent, raw values):
//   0 "ISK1030799999999" -> 0.0.42.0.0.255 (string)
//   1 "ISK99999999"      -> 0.0.96.1.0.255 (string)
//   2 3513 -> 1.0.1.7.0.255    3 0    -> 1.0.2.7.0.255    4 2226 -> 1.0.3.7.0.255    5 0 -> 1.0.4.7.0.255
//   6 2439 -> 1.0.32.7.0.255   7 2434 -> 1.0.52.7.0.255    8 2422 -> 1.0.72.7.0.255
//   9 485  -> 1.0.31.7.0.255  10 713  -> 1.0.51.7.0.255   11 523  -> 1.0.71.7.0.255
//  12 909  -> 1.0.21.7.0.255  13 1537 -> 1.0.41.7.0.255   14 1066 -> 1.0.61.7.0.255
//  15 0    -> 1.0.22.7.0.255  16 0    -> 1.0.42.7.0.255   17 0    -> 1.0.62.7.0.255
//
// 15 min telegram: STRUCTURE(12):
//   0 "ISK1030799999999" -> 0.0.42.0.0.255 (string)
//   1 empty octet string, 2 enum 1, 3 octet string 00 01 (no pattern)
//   4 60896257 -> 1.0.1.8.0.255    5 28592659 -> 1.0.1.8.1.255    6 32303598 -> 1.0.1.8.2.255
//   7 33 -> 1.0.2.8.0.255          8 17 -> 1.0.2.8.1.255          9 16 -> 1.0.2.8.2.255
//  10 19620794 -> 1.0.3.8.0.255   11 11234771 -> 1.0.4.8.0.255
//
// Pattern list (see am550_setup in tests/test_meter_dumps.cpp):
//   5 s:   "CNT(18), IDX(<i>), TSTR" for i=0,1;  "CNT(18), IDX(<i>), TV" for i=2..17  (default_obis = table above)
//   15 min: "CNT(12), IDX(<i>), TSTR" for i=0;   "CNT(12), IDX(<i>), TV" for i=4..11
// Float values: 60896257 and 11234771 are not exact in float32; compared with doctest::Approx.

// 5 s telegram, single HDLC frame (134 bytes)
const uint8_t iskra_am550_5s_raw_frame[] = {
    0x7E, 0xA0, 0x84, 0xCF, 0x02, 0x23, 0x13, 0xD1, 0xC7, 0xE6, 0xE7, 0x00, 0x0F, 0x00, 0x8E, 0x54,
    0xDC, 0x0C, 0x07, 0xEA, 0x0B, 0x16, 0x07, 0x14, 0x18, 0x32, 0x00, 0xFF, 0xC4, 0x00, 0x02, 0x12,
    0x09, 0x10, 0x49, 0x53, 0x4B, 0x31, 0x30, 0x33, 0x30, 0x37, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39,
    0x39, 0x39, 0x09, 0x0B, 0x49, 0x53, 0x4B, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x06,
    0x00, 0x00, 0x0D, 0xB9, 0x06, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x08, 0xB2, 0x06, 0x00,
    0x00, 0x00, 0x00, 0x12, 0x09, 0x87, 0x12, 0x09, 0x82, 0x12, 0x09, 0x76, 0x12, 0x01, 0xE5, 0x12,
    0x02, 0xC9, 0x12, 0x02, 0x0B, 0x06, 0x00, 0x00, 0x03, 0x8D, 0x06, 0x00, 0x00, 0x06, 0x01, 0x06,
    0x00, 0x00, 0x04, 0x2A, 0x06, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00,
    0x00, 0x00, 0x00, 0x1D, 0x64, 0x7E,
};

// 15 min telegram, single HDLC frame (101 bytes)
const uint8_t iskra_am550_15min_raw_frame[] = {
    0x7E, 0xA0, 0x63, 0xCF, 0x02, 0x23, 0x13, 0xEB, 0xDC, 0xE6, 0xE7, 0x00, 0x0F, 0x00, 0x8E, 0x55,
    0x1A, 0x0C, 0x07, 0xEA, 0x0B, 0x16, 0x07, 0x14, 0x1E, 0x00, 0x00, 0xFF, 0xC4, 0x00, 0x02, 0x0C,
    0x09, 0x10, 0x49, 0x53, 0x4B, 0x31, 0x30, 0x33, 0x30, 0x37, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39,
    0x39, 0x39, 0x09, 0x00, 0x16, 0x01, 0x09, 0x02, 0x00, 0x01, 0x06, 0x03, 0xA1, 0x34, 0x01, 0x06,
    0x01, 0xB4, 0x4A, 0x13, 0x06, 0x01, 0xEC, 0xE9, 0xEE, 0x06, 0x00, 0x00, 0x00, 0x21, 0x06, 0x00,
    0x00, 0x00, 0x11, 0x06, 0x00, 0x00, 0x00, 0x10, 0x06, 0x01, 0x2B, 0x63, 0xBA, 0x06, 0x00, 0xAB,
    0x6D, 0xD3, 0x44, 0x47, 0x7E,
};

// 5 s: 2 string objects + 16 numeric objects = 18 total
constexpr size_t iskra_am550_5s_expected_count = 18;

const std::map<std::string, std::string> iskra_am550_5s_expected_strings = {
    {"0.0.42.0.0.255", "ISK1030799999999"},
    {"0.0.96.1.0.255", "ISK99999999"},
};

const std::map<std::string, float> iskra_am550_5s_expected_floats = {
    {"1.0.1.7.0.255",   3513.0f},
    {"1.0.2.7.0.255",      0.0f},
    {"1.0.3.7.0.255",   2226.0f},
    {"1.0.4.7.0.255",      0.0f},
    {"1.0.32.7.0.255",  2439.0f},
    {"1.0.52.7.0.255",  2434.0f},
    {"1.0.72.7.0.255",  2422.0f},
    {"1.0.31.7.0.255",   485.0f},
    {"1.0.51.7.0.255",   713.0f},
    {"1.0.71.7.0.255",   523.0f},
    {"1.0.21.7.0.255",   909.0f},
    {"1.0.41.7.0.255",  1537.0f},
    {"1.0.61.7.0.255",  1066.0f},
    {"1.0.22.7.0.255",     0.0f},
    {"1.0.42.7.0.255",     0.0f},
    {"1.0.62.7.0.255",     0.0f},
};

// 15 min: 1 string object + 8 numeric objects = 9 total
constexpr size_t iskra_am550_15min_expected_count = 9;

const std::map<std::string, std::string> iskra_am550_15min_expected_strings = {
    {"0.0.42.0.0.255", "ISK1030799999999"},
};

const std::map<std::string, float> iskra_am550_15min_expected_floats = {
    {"1.0.1.8.0.255", 60896257.0f},
    {"1.0.1.8.1.255", 28592659.0f},
    {"1.0.1.8.2.255", 32303598.0f},
    {"1.0.2.8.0.255",       33.0f},
    {"1.0.2.8.1.255",       17.0f},
    {"1.0.2.8.2.255",       16.0f},
    {"1.0.3.8.0.255", 19620794.0f},
    {"1.0.4.8.0.255", 11234771.0f},
};

}  // namespace dlms::test_data
