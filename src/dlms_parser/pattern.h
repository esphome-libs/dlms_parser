#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "types.h"

namespace dlms {
    namespace parser {

        struct AxdrPatternStep {
            AxdrTokenType type;
            uint8_t param_u8_a{0};
        };

        struct AxdrDescriptorPattern {
            std::string name;
            int priority{0};
            std::vector<AxdrPatternStep> steps;
            uint16_t default_class_id{0};
        };

    }  // namespace parser
}  // namespace dlms