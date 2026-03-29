#pragma once

#include "types.h"
#include <cstdint>
#include <string>
#include <vector>

namespace dlms_parser {

struct AxdrPatternStep {
  AxdrTokenType type;
  uint8_t param_u8_a{0};
};

struct AxdrDescriptorPattern {
  const char* name{nullptr};
  int priority{0};
  AxdrPatternStep steps[32]{};
  uint16_t default_class_id{0};
  bool has_default_obis{false};
  uint8_t default_obis[6]{};
};

}
