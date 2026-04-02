# dlms_parser

`dlms_parser` is a lightweight C++20 library for parsing DLMS/COSEM push telegrams from electricity meters. It handles transport decoding (`RAW`, `HDLC`, `M-Bus`), optional AES-128-GCM decryption, APDU unwrapping, and AXDR pattern matching to extract meter values in a form that is easy to consume from embedded code.

It is designed for embedded and integration-heavy environments such as ESPHome, but it also builds and tests on desktop platforms.

## Features

- Parses DLMS/COSEM push telegrams from complete frames
- Supports `RAW`, `HDLC`, and `MBUS` input formats
- Handles optional AES-128-GCM encrypted APDUs
- Extracts values through a simple callback-based API
- Includes built-in AXDR descriptor patterns for common meter layouts
- Allows custom patterns for vendor-specific structures
- Provides optional raw captures for advanced integrations

## Quick Start

```cpp
#include "dlms_parser/dlms_parser.h"
#include "dlms_parser/decryption/aes_128_gcm_decryptor_mbedtls.h" // Or your chosen backend

uint8_t work_buf[1024];  // caller-owned, no heap allocation during parse()

dlms_parser::Aes128GcmDecryptorMbedTls decryptor;
dlms_parser::DlmsParser parser(decryptor);
parser.set_work_buffer(work_buf, sizeof(work_buf));
parser.set_frame_format(dlms_parser::FrameFormat::RAW);
parser.load_default_patterns();

auto on_value = [](const char* obis, float num, const char* str, bool is_numeric) {
    if (is_numeric) {
        printf("%s = %.3f\n", obis, num);
    } else {
        printf("%s = \"%s\"\n", obis, str);
    }
};

auto [count, consumed] = parser.parse(frame_bytes, frame_len, on_value);
printf("%zu objects found\n", count);
```

If your meter uses transport framing or encryption, set those options before calling `parse()`:

```cpp
parser.set_frame_format(dlms_parser::FrameFormat::HDLC);
parser.set_decryption_key(key);
```

## Key Capabilities

- **Transport decoding**: `RAW`, `HDLC` (including multi-frame segmentation and General Block Transfer), `M-Bus`
- **Encryption**: AES-128-GCM decryption and optional authentication tag verification for `General-GLO-Ciphering` and `General-DED-Ciphering` APDUs
- **Pattern matching**: DSL-based AXDR descriptor patterns with built-in presets and custom registration
- **Callback API**: cooked callback delivers OBIS code + scaled value; raw callback gives full capture details
- **Embedded-friendly**: no heap allocation in the hot path; stack-only per-frame parsing
- **Portable**: builds on ESP32 (IDF/Arduino), ESP8266, Linux, macOS, Windows

## Typical Usage Flow

1. Create `dlms_parser::DlmsParser`
2. Provide a work buffer (`set_work_buffer`)
3. Select the frame format
4. Set the decryption key (and optionally the authentication key) if the meter is encrypted
5. Load built-in patterns and optionally register custom ones
6. Pass one complete frame to `parse()`
7. Consume extracted values in the callback

## Documentation

- [HOWTO.md](HOWTO.md): practical guide, examples, troubleshooting
- [REFERENCE.md](REFERENCE.md): public API, pattern DSL, protocol/reference notes
- [ARCHITECTURE.md](ARCHITECTURE.md): component diagram and module responsibilities

## How to add the library to your project

### PlatformIO package
TODO: add link

### ESP-IDF component
TODO: add link

### CMake
```
FetchContent_Declare(
  dlms_parser
  GIT_REPOSITORY https://github.com/esphome-libs/dlms_parser
  GIT_TAG v1.0)
FetchContent_MakeAvailable(dlms_parser)

add_executable(your_project_name main.cpp)
target_link_libraries(your_project_name PRIVATE dlms_parser)
```

## How to work with the codebase

You can open the project using any IDE that supports CMake.

## References

This library builds on work from:

- [esphome-dlms-cosem](https://github.com/latonita/esphome-dlms-cosem) -- original ESPHome DLMS/COSEM component and AXDR parser
- [xt211](https://github.com/Tomer27cz/xt211) -- Sagemcom XT211 parser, instrumental in de-Guruxing the protocol handling

## License

Apache-2.0. See [LICENSE](LICENSE).
