#pragma once

#include <cstdint>
#include <cstddef>
#include "types.h"

namespace dlms {
    namespace parser {

        float data_as_float(DlmsDataType value_type, const uint8_t *ptr, uint8_t len);
        void data_to_string(DlmsDataType value_type, const uint8_t *ptr, uint8_t len, char *buffer, size_t max_len);
        void obis_to_string(const uint8_t *obis, char *buffer, size_t max_len);
        const char *dlms_data_type_to_string(DlmsDataType vt);

        int get_data_type_size(DlmsDataType type);
        bool is_value_data_type(DlmsDataType type);

        // Replaces esphome::format_hex_pretty_to for standalone capability
        void format_hex_pretty_to(char *out, size_t max_out, const uint8_t *data, size_t length);

    }  // namespace parser
}  // namespace dlms