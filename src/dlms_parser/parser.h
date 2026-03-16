#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include "types.h"
#include "pattern.h"

namespace dlms {
    namespace parser {

        class DlmsParser {
        public:
            DlmsParser();

            // Registers a custom parsing pattern from the YAML config
            void register_custom_pattern(const std::string &dsl);

            // Parses the buffer and fires callbacks for each found sensor value
            size_t parse(const uint8_t *buffer, size_t length, DlmsDataCallback callback, bool show_log);

        private:
            void register_pattern_dsl_(const std::string &name, const std::string &dsl, int priority);
            void load_default_patterns_();

            uint8_t read_byte_();
            uint16_t read_u16_();
            uint32_t read_u32_();

            bool test_if_date_time_12b_();

            bool skip_data_(uint8_t type);
            bool parse_element_(uint8_t type, uint8_t depth = 0);
            bool parse_sequence_(uint8_t type, uint8_t depth = 0);

            bool capture_generic_value_(AxdrCaptures &c);
            bool try_match_patterns_(uint8_t elem_idx);
            bool match_pattern_(uint8_t elem_idx, const AxdrDescriptorPattern &pat, uint8_t &elements_consumed_at_level0);
            void emit_object_(const AxdrDescriptorPattern &pat, const AxdrCaptures &c);

            const uint8_t *buffer_{nullptr};
            size_t buffer_len_{0};

            size_t pos_{0};
            DlmsDataCallback callback_;
            bool show_log_{false};
            size_t objects_found_{0};
            uint8_t last_pattern_elements_consumed_{0};

            std::vector<AxdrDescriptorPattern> patterns_;
        };

    }  // namespace parser
}  // namespace dlms