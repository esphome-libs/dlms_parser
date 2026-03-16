#pragma once

#include <cstdint>
#include <functional>

namespace dlms {
    namespace parser {

        enum DlmsDataType : uint8_t {
            DLMS_DATA_TYPE_NONE = 0,
            DLMS_DATA_TYPE_ARRAY = 1,
            DLMS_DATA_TYPE_STRUCTURE = 2,
            DLMS_DATA_TYPE_BOOLEAN = 3,
            DLMS_DATA_TYPE_BIT_STRING = 4,
            DLMS_DATA_TYPE_INT32 = 5,
            DLMS_DATA_TYPE_UINT32 = 6,
            DLMS_DATA_TYPE_OCTET_STRING = 9,
            DLMS_DATA_TYPE_STRING = 10,
            DLMS_DATA_TYPE_STRING_UTF8 = 12,
            DLMS_DATA_TYPE_BINARY_CODED_DESIMAL = 13,
            DLMS_DATA_TYPE_INT8 = 15,
            DLMS_DATA_TYPE_INT16 = 16,
            DLMS_DATA_TYPE_UINT8 = 17,
            DLMS_DATA_TYPE_UINT16 = 18,
            DLMS_DATA_TYPE_COMPACT_ARRAY = 19,
            DLMS_DATA_TYPE_INT64 = 20,
            DLMS_DATA_TYPE_UINT64 = 21,
            DLMS_DATA_TYPE_ENUM = 22,
            DLMS_DATA_TYPE_FLOAT32 = 23,
            DLMS_DATA_TYPE_FLOAT64 = 24,
            DLMS_DATA_TYPE_DATETIME = 25,
            DLMS_DATA_TYPE_DATE = 26,
            DLMS_DATA_TYPE_TIME = 27
          };

        enum class AxdrTokenType : uint8_t {
            EXPECT_TO_BE_FIRST,
            EXPECT_TYPE_EXACT,
            EXPECT_TYPE_U_I_8,
            EXPECT_CLASS_ID_UNTAGGED,
            EXPECT_OBIS6_TAGGED,
            EXPECT_OBIS6_UNTAGGED,
            EXPECT_ATTR8_UNTAGGED,
            EXPECT_VALUE_GENERIC,
            EXPECT_STRUCTURE_N,
            EXPECT_SCALER_TAGGED,
            EXPECT_UNIT_ENUM_TAGGED,
            GOING_DOWN,
            GOING_UP,
          };

        struct AxdrCaptures {
            uint32_t elem_idx{0};
            uint16_t class_id{0};
            const uint8_t *obis{nullptr};
            DlmsDataType value_type{DlmsDataType::DLMS_DATA_TYPE_NONE};
            const uint8_t *value_ptr{nullptr};
            uint8_t value_len{0};

            bool has_scaler_unit{false};
            int8_t scaler{0};
            uint8_t unit_enum{0};
        };

        // Callback: OBIS code, numeric value, string value, is_numeric flag
        using DlmsDataCallback = std::function<void(const char *obis_code, float float_val, const char *str_val, bool is_numeric)>;

    }  // namespace parser
}  // namespace dlms