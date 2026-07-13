# dlms_parser

`dlms_parser` is a C++20 library for parsing DLMS/COSEM push telegrams from electricity meters.<br>
It is designed for embedded and integration-heavy environments such as ESPHome, but it also works on desktop platforms.

## Features

- **Transport decoding**: `RAW`, `HDLC`, `M-Bus`. Auto-detects the frame format based on the leading byte. Includes multi-frame segmentation and General Block Transfer
- **Encryption**: AES-128-GCM decryption and optional authentication tag verification for `General-GLO-Ciphering` and `General-DED-Ciphering` APDUs
- **Crypto Backends**: Pluggable decryption backends with built-in support for `mbedTLS`, `BearSSL`, and `TF-PSA`
- **Pattern matching**: DSL-based AXDR descriptor patterns with built-in presets and custom registration
- **Callback API**: cooked callback delivers OBIS code + scaled value
- **Embedded-friendly**: no heap allocation during parsing
- **Portable**: builds on ESP32 (IDF/Arduino), ESP8266, Linux, macOS, Windows

## How to use

* Complete example with the explanation: [test_example.cpp](https://github.com/esphome-libs/dlms_parser/blob/main/tests/test_example.cpp)
* Usage in ESPHome: [dlms_meter component](https://github.com/esphome/esphome/tree/dev/esphome/components/dlms_meter)

### Creating custom patterns to match your meter's telegram structure

The parser starts with no registered AXDR patterns. Load the built-ins first unless you want full control:
```c++
parser.load_default_patterns();
```

**Built-in patterns (available after calling `parser.load_default_patterns()`):**

| Name                                     | Pattern          | Priority |
|------------------------------------------|------------------|---------:|
| `SelfDescribing`                         | `SelfDesc`       |       10 |
| `classId-taggedObis-scaler-value`        | `TC,TO,TS,TV`    |       20 |
| `taggedObis-value-scalerUnit`            | `TO,TV,TSU`      |       30 |
| `value-classId-scalerUnit-taggedObis`    | `TV,TC,TSU,TO`   |       40 |
| `zpaAidon-untaggedLayout`                | `ADV`            |       50 |
| `structuredObis-value-scalerUnit`        | `S(TO, TV, TSU)` |       60 |
| `structuredObis-value`                   | `S(TO, TV)`      |       70 |
| `flatObis-valuePair`                     | `TO, TV`         |       80 |
| `firstElement-dateTime`                  | `F, S(TO, TDTM)` |       90 |
| `swappedTagObis-value-scalerUnit`        | `TOW, TV, TSU`   |      100 |

**Registering Custom Patterns:**

If your meter emits a layout not covered by the built-ins, you can register custom patterns. Lower priority numbers are evaluated first.
```c++
parser.register_pattern("MyPattern", "TO, TV, S(TS, TU)", 5, {});

// With default OBIS — used when the pattern captures no OBIS code
dlms_parser::ObisId meter_obis(0, 0, 96, 1, 0, 255);  // 0.0.96.1.0.255
parser.register_pattern("MeterID", "L, TSTR", 0, meter_obis);
```

Pattern priority matters:

- lower priority number is tried first
- `register_pattern(dsl)` uses priority `0`
- built-ins start at priority `10`

Common examples:

```cpp
parser.register_pattern("TC, TO, TDTM");          // datetime value
parser.register_pattern("C, O, A, V, TS, TU");    // untagged flat
parser.register_pattern("TO, TV, S(TS, TU)");     // tagged with scaler-unit
parser.register_pattern("TO, TV");                // flat OBIS + value pairs (no scaler)
parser.register_pattern("L, TSTR");               // last element as string
parser.register_pattern("TOW, TV, TSU");          // Landis+Gyr swapped OBIS
```

### Token reference
| Token          | Meaning                                        | Hex example                     |
|----------------|------------------------------------------------|---------------------------------|
| `SelfDesc`     | array of value descriptions followed by values | definitions array + values      |
| `F`            | first element guard                            | position check only             |
| `L`            | last element guard                             | position check only             |
| `C`            | class ID, 2-byte uint16 without tag            | `00 03`                         |
| `TC`           | tagged class ID                                | `12 00 03`                      |
| `O`            | OBIS code, 6-byte octet string without tag     | `01 00 01 08 00 FF`             |
| `TO`           | tagged OBIS code                               | `09 06 01 00 01 08 00 FF`       |
| `TOW`          | tagged OBIS with swapped tag bytes             | `06 09 01 00 1F 07 00 FF`       |
| `A`            | attribute index, 1-byte uint8 without tag      | `02`                            |
| `TA`           | tagged attribute                               | `11 02` or `0F 02`              |
| `V` / `TV`     | generic value                                  | `06 00 00 07 A4`                |
| `TSTR`         | tagged string-like value                       | `09 08 38 34 38 39 35 31 32 36` |
| `TDTM`         | tagged 12-byte date-time value                 | `19 ...` or `09 0C ...`         |
| `TS`           | tagged scaler                                  | `0F FF`                         |
| `TU`           | tagged unit enum                               | `16 23`                         |
| `TSU`          | tagged scaler-unit pair                        | `02 02 0F FF 16 23`             |
| `S(x, y, ...)` | inline sub-structure                           | `02 03`                         |
| `DN`           | descend into nested structure                  | control token                   |
| `UP`           | return from nested structure                   | control token                   |

## How to add the library to your project

### PlatformIO package
[https://registry.platformio.org/libraries/esphome/dlms_parser](https://registry.platformio.org/libraries/esphome/dlms_parser)

### ESP-IDF component
[https://components.espressif.com/components/esphome/dlms_parser](https://components.espressif.com/components/esphome/dlms_parser)

### CMake
```cmake
FetchContent_Declare(
  dlms_parser
  GIT_REPOSITORY https://github.com/esphome-libs/dlms_parser
  GIT_TAG v1.0)
FetchContent_MakeAvailable(dlms_parser)

add_executable(your_project_name main.cpp)
target_link_libraries(your_project_name PRIVATE dlms_parser)
```

### Acknowledgements

This library builds on foundational work and protocol insights from:
- [esphome-dlms-cosem](https://github.com/latonita/esphome-dlms-cosem) - original ESPHome DLMS/COSEM component and AXDR parser by **latonita**.
- [xt211](https://github.com/Tomer27cz/xt211) - Sagemcom XT211 parser by **Tomer27cz**, instrumental in de-Guruxing the protocol handling.

## References
- [DLMS/COSEM Architecture and Protocols. Green Book Edition 11](https://github.com/zhuyangfei/DLMS-green-book/blob/main/Green-Book-Ed-11-V1-0.pdf)
- [CONSUMER INFORMATION INTERFACE (CII) SPECIFICATION](https://wiki.weble.ch/articles/landys_e450_docs/customer_information_interface_(cii)_specification.pdf)
- [EWK Energie AG. Smart meter customer interface](https://ewk-energie.ch/wp-content/uploads/2025/08/smart-meter-kundenschnittstelle.pdf)
- [Zaehler Landis+Gyr E450/E570. Smart meter customer interface](https://www.bkw.ch/fileadmin/user_upload/03_Energie/03_01_Stromversorgung_Privat-_und_Gewerbekunden/Zaehlerablesung/BKW_faktenblatt_kundenschnittstelle_L_G_E450_E570_def_Web.pdf)
- [E450 Specification](https://assets.netzburgenland.at/Spezifikation_Kundenschnittstelle_E450_korr_2_009418889e.pdf)
- [Netz Smart Meter specification](https://netz-noe.at/getContentAsset/568bef9a-3bd1-4f2e-a710-6ba7e71cb746/0ee16eb8-9692-4f25-b8a4-d007b35915a4/218_15_Smart-Meter-Folder-Kundenschnittstelle-2025_0110.pdf?language=de)
