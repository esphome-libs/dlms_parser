#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace dlms::test_data {

// ZPA AM375 (PRE Distribuce), a real meter where the utility attempted to restore
// compatibility with their published spec. Note the word "attempted".

const uint8_t zpa_am375_flat_predistribuce_20260924_raw_frame[] = {
    0x0F,                                                             // data-notification
    0x00, 0x00, 0x00, 0x03,                                           // long-invoke-id-and-priority
    0x00,                                                             // date-time = null
    0x02, 0x16,                                                       // structure(22)
    0x09, 0x0C, 0x5A, 0x50, 0x41, 0x33, 0x48, 0x41, 0x4E, 0x30, 0x30, 0x32, 0x30, 0x30,      // octet-string(12) "ZPA3HAN00200"
    0x09, 0x0C, 0x07, 0xEA, 0x09, 0x18, 0x04, 0x11, 0x2E, 0x01, 0x00, 0x00, 0x78, 0x80,      // octet-string(12) datetime 2026-09-24 17:46:01 +02:00
    0x09, 0x07, 0x47, 0x30, 0x33, 0x35, 0x34, 0x39, 0x39,                                    // octet-string(7) "G035499"
    0x16, 0x01,                                                       // enum = 1            (0.0.96.3.10.255)
    0x06, 0x00, 0x00, 0x00, 0x00,                                     // double-long-unsigned = 0   (0.0.17.0.0.255)
    0x16, 0x00,                                                       // enum = 0            (0.1.96.3.10.255)
    0x16, 0x00,                                                       // enum = 0            (0.2.96.3.10.255)
    0x16, 0x00,                                                       // enum = 0            (0.3.96.3.10.255)
    0x16, 0x00,                                                       // enum = 0            (0.4.96.3.10.255)
    0x09, 0x02, 0x54, 0x31,                                           // octet-string(2) "T1"
    0x06, 0x00, 0x00, 0x02, 0x65,                                     // double-long-unsigned = 613   (1.0.1.7.0.255)
    0x06, 0x00, 0x00, 0x00, 0x52,                                     // double-long-unsigned = 82    (1.0.21.7.0.255)
    0x06, 0x00, 0x00, 0x00, 0x32,                                     // double-long-unsigned = 50    (1.0.41.7.0.255)
    0x06, 0x00, 0x00, 0x01, 0xE1,                                     // double-long-unsigned = 481   (1.0.61.7.0.255)
    0x06, 0x00, 0x00, 0x00, 0x00,                                     // double-long-unsigned = 0     (1.0.2.7.0.255)
    0x06, 0x00, 0x00, 0x00, 0x00,                                     // double-long-unsigned = 0     (1.0.22.7.0.255)
    0x06, 0x00, 0x00, 0x00, 0x00,                                     // double-long-unsigned = 0     (1.0.42.7.0.255)
    0x06, 0x00, 0x00, 0x00, 0x00,                                     // double-long-unsigned = 0     (1.0.62.7.0.255)
    0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49, 0x65, 0xF3,             // long64-unsigned = 4810227    (1.0.1.8.0.255)
    0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49, 0x46, 0xCB,             // long64-unsigned = 4802251    (1.0.1.8.1.255)
    0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F, 0x28,             // long64-unsigned = 7976       (1.0.1.8.2.255)
    0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0xF6              // long64-unsigned = 66806      (1.0.2.8.0.255)
};

constexpr size_t zpa_am375_flat_predistribuce_20260924_expected_count = 22;

const std::map<std::string, std::string> zpa_am375_flat_predistribuce_20260924_expected_strings = {
    {"0.0.96.1.4.255", "ZPA3HAN00200"},
    {"0.0.1.0.0.255",  "2026-09-24 17:46:01.00 +02:00"},
    {"0.0.96.1.1.255", "G035499"},
    {"0.0.96.14.0.255", "T1"}
};

const std::map<std::string, float> zpa_am375_flat_predistribuce_20260924_expected_floats = {
    {"0.0.96.3.10.255", 1.0f},
    {"0.0.17.0.0.255",  0.0f},
    {"0.1.96.3.10.255", 0.0f},
    {"0.2.96.3.10.255", 0.0f},
    {"0.3.96.3.10.255", 0.0f},
    {"0.4.96.3.10.255", 0.0f},
    {"1.0.1.7.0.255",   613.0f},
    {"1.0.21.7.0.255",  82.0f},
    {"1.0.41.7.0.255",  50.0f},
    {"1.0.61.7.0.255",  481.0f},
    {"1.0.2.7.0.255",   0.0f},
    {"1.0.22.7.0.255",  0.0f},
    {"1.0.42.7.0.255",  0.0f},
    {"1.0.62.7.0.255",  0.0f},
    {"1.0.1.8.0.255",   4810227.0f},
    {"1.0.1.8.1.255",   4802251.0f},
    {"1.0.1.8.2.255",   7976.0f},
    {"1.0.2.8.0.255",   66806.0f}
};

}
