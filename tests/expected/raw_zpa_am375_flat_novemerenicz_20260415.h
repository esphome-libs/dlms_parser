#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace dlms::test_data {

// ZPA AM375 (PRE Distribuce), official datasheet from April 2026. Compared to the
// real-world meter, this one has NUL-padded strings, a different format of the load
// limiter, and a different format for energy counters.

const uint8_t zpa_am375_flat_novemerenicz_20260415_raw_frame[] = {
    0x0F,                                                             // data-notification
    0x00, 0x00, 0x00, 0x03,                                           // long-invoke-id-and-priority
    0x00,                                                             // date-time = null
    0x02, 0x16,                                                       // structure(22)
    0x09, 0x11, 0x5A, 0x50, 0x41, 0x33, 0x48, 0x41, 0x4E, 0x30, 0x30, 0x32, 0x30, 0x30,
    0x00, 0x00, 0x00, 0x00, 0x00,                                     // octet-string(17) "ZPA3HAN00200" + 5 NUL pad
    0x09, 0x0C, 0x07, 0xE9, 0x06, 0x18, 0x02, 0x0D, 0x0E, 0x01, 0x00, 0x00, 0x78, 0x80,   // octet-string(12) datetime 2025-06-24 13:14:01 +02:00
    0x09, 0x11, 0x52, 0x33, 0x31, 0x33, 0x31, 0x39, 0x32,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // octet-string(17) "R313192" + 10 NUL pad
    0x16, 0x01,                                                       // enum = 1            (0.0.96.3.10.255)
    0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x27, 0x10,             // long64-unsigned = 10000    (0.0.17.0.0.255)
    0x16, 0x00,                                                       // enum = 0            (0.1.96.3.10.255)
    0x16, 0x00,                                                       // enum = 0            (0.2.96.3.10.255)
    0x16, 0x00,                                                       // enum = 0            (0.3.96.3.10.255)
    0x16, 0x01,                                                       // enum = 1            (0.4.96.3.10.255)
    0x09, 0x02, 0x54, 0x31,                                           // octet-string(2) "T1"
    0x06, 0x00, 0x00, 0x20, 0xAD,                                     // double-long-unsigned = 8365  (1.0.1.7.0.255)
    0x06, 0x00, 0x00, 0x0C, 0x0F,                                     // double-long-unsigned = 3087  (1.0.21.7.0.255)
    0x06, 0x00, 0x00, 0x0A, 0x36,                                     // double-long-unsigned = 2614  (1.0.41.7.0.255)
    0x06, 0x00, 0x00, 0x0A, 0x68,                                     // double-long-unsigned = 2664  (1.0.61.7.0.255)
    0x06, 0x00, 0x00, 0x00, 0x00,                                     // double-long-unsigned = 0     (1.0.2.7.0.255)
    0x06, 0x00, 0x00, 0x00, 0x00,                                     // double-long-unsigned = 0     (1.0.22.7.0.255)
    0x06, 0x00, 0x00, 0x00, 0x00,                                     // double-long-unsigned = 0     (1.0.42.7.0.255)
    0x06, 0x00, 0x00, 0x00, 0x00,                                     // double-long-unsigned = 0     (1.0.62.7.0.255)
    0x06, 0x00, 0x01, 0x4D, 0x2C,                                     // double-long-unsigned = 85292 (1.0.1.8.0.255)
    0x06, 0x00, 0x01, 0x4D, 0x2C,                                     // double-long-unsigned = 85292 (1.0.1.8.1.255)
    0x06, 0x00, 0x00, 0x00, 0x00,                                     // double-long-unsigned = 0     (1.0.1.8.2.255)
    0x06, 0x00, 0x00, 0x21, 0xD2                                      // double-long-unsigned = 8658  (1.0.2.8.0.255)
};

constexpr size_t zpa_am375_flat_novemerenicz_20260415_expected_count = 22;

const std::map<std::string, std::string> zpa_am375_flat_novemerenicz_20260415_expected_strings = {
    {"0.0.96.1.4.255", "ZPA3HAN00200"},
    {"0.0.1.0.0.255",  "2025-06-24 13:14:01.00 +02:00"},
    {"0.0.96.1.1.255", "R313192"},
    {"0.0.96.14.0.255", "T1"}
};

const std::map<std::string, float> zpa_am375_flat_novemerenicz_20260415_expected_floats = {
    {"0.0.96.3.10.255", 1.0f},
    {"0.0.17.0.0.255",  10000.0f},
    {"0.1.96.3.10.255", 0.0f},
    {"0.2.96.3.10.255", 0.0f},
    {"0.3.96.3.10.255", 0.0f},
    {"0.4.96.3.10.255", 1.0f},
    {"1.0.1.7.0.255",   8365.0f},
    {"1.0.21.7.0.255",  3087.0f},
    {"1.0.41.7.0.255",  2614.0f},
    {"1.0.61.7.0.255",  2664.0f},
    {"1.0.2.7.0.255",   0.0f},
    {"1.0.22.7.0.255",  0.0f},
    {"1.0.42.7.0.255",  0.0f},
    {"1.0.62.7.0.255",  0.0f},
    {"1.0.1.8.0.255",   85292.0f},
    {"1.0.1.8.1.255",   85292.0f},
    {"1.0.1.8.2.255",   0.0f},
    {"1.0.2.8.0.255",   8658.0f}
};

}
