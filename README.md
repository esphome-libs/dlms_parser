# dlms_parser

`dlms_parser` is a C++20 library for parsing DLMS/COSEM push telegrams from electricity meters.<br>
It is designed for embedded and integration-heavy environments such as ESPHome, but it also works on desktop platforms.

## Features

- **Transport decoding**: `RAW`, `HDLC`, `M-Bus`. Including multi-frame segmentation and General Block Transfer
- **Encryption**: AES-128-GCM decryption and optional authentication tag verification for `General-GLO-Ciphering` and `General-DED-Ciphering` APDUs
- **Pattern matching**: DSL-based AXDR descriptor patterns with built-in presets and custom registration
- **Callback API**: cooked callback delivers OBIS code + scaled value; raw callback gives full capture details
- **Embedded-friendly**: no heap allocation during parsing
- **Portable**: builds on ESP32 (IDF/Arduino), ESP8266, Linux, macOS, Windows

## How to use

Complete example with the explanation: [test_example.cpp](https://github.com/esphome-libs/dlms_parser/blob/main/tests/test_example.cpp)

## How to creating custom patterns to match your meter's telegram structure

The parser starts with no registered AXDR patterns. Load the built-ins first unless you want full control:

```cpp
parser.load_default_patterns();
```

Built-in patterns

| Name    | Priority | Typical use                               |
|---------|---------:|-------------------------------------------|
| `T1`    |       10 | class ID, tagged OBIS, scaler, value      |
| `T2`    |       20 | tagged OBIS, value, scaler-unit structure |
| `T3`    |       30 | value first, class ID, scaler-unit, OBIS  |
| `U.ZPA` |       40 | untagged ZPA/Aidon-style layouts          |

Register a custom pattern when your meter emits a different structure

```cpp
// Simple — name="CUSTOM", priority=0 (tried before built-ins)
parser.register_pattern("TC, TO, TDTM");

// Named with explicit priority
parser.register_pattern("MyPattern", "TO, TV, S(TS, TU)", 5);

// With default OBIS — used when the pattern captures no OBIS code
const uint8_t meter_obis[] = {0, 0, 96, 1, 0, 255};  // 0.0.96.1.0.255
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
| Token          | Meaning                                    | Hex example                     |
|----------------|--------------------------------------------|---------------------------------|
| `F`            | first element guard                        | position check only             |
| `L`            | last element guard                         | position check only             |
| `C`            | class ID, 2-byte uint16 without tag        | `00 03`                         |
| `TC`           | tagged class ID                            | `12 00 03`                      |
| `O`            | OBIS code, 6-byte octet string without tag | `01 00 01 08 00 FF`             |
| `TO`           | tagged OBIS code                           | `09 06 01 00 01 08 00 FF`       |
| `TOW`          | tagged OBIS with swapped tag bytes         | `06 09 01 00 1F 07 00 FF`       |
| `A`            | attribute index, 1-byte uint8 without tag  | `02`                            |
| `TA`           | tagged attribute                           | `11 02` or `0F 02`              |
| `V` / `TV`     | generic value                              | `06 00 00 07 A4`                |
| `TSTR`         | tagged string-like value                   | `09 08 38 34 38 39 35 31 32 36` |
| `TDTM`         | tagged 12-byte date-time value             | `19 ...` or `09 0C ...`         |
| `TS`           | tagged scaler                              | `0F FF`                         |
| `TU`           | tagged unit enum                           | `16 23`                         |
| `TSU`          | tagged scaler-unit pair                    | `02 02 0F FF 16 23`             |
| `S(x, y, ...)` | inline sub-structure                       | `02 03`                         |
| `DN`           | descend into nested structure              | control token                   |
| `UP`           | return from nested structure               | control token                   |

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
You can open the repository using any IDE that supports CMake.

## References
- [DLMS/COSEM Architecture and Protocols. Green Book Edition 11](https://github.com/zhuyangfei/DLMS-green-book/blob/main/Green-Book-Ed-11-V1-0.pdf)
- [CONSUMER INFORMATION INTERFACE (CII) SPECIFICATION](https://wiki.weble.ch/articles/landys_e450_docs/customer_information_interface_(cii)_specification.pdf)
- [EWK Energie AG. Smart meter customer interface](https://ewk-energie.ch/wp-content/uploads/2025/08/smart-meter-kundenschnittstelle.pdf)
- [Zaehler Landis+Gyr E450/E570. Smart meter customer interface](https://www.bkw.ch/fileadmin/user_upload/03_Energie/03_01_Stromversorgung_Privat-_und_Gewerbekunden/Zaehlerablesung/BKW_faktenblatt_kundenschnittstelle_L_G_E450_E570_def_Web.pdf)
- [E450 Specification](https://assets.netzburgenland.at/Spezifikation_Kundenschnittstelle_E450_korr_2_009418889e.pdf)
- [Netz Smart Meter specification](https://netz-noe.at/getContentAsset/568bef9a-3bd1-4f2e-a710-6ba7e71cb746/0ee16eb8-9692-4f25-b8a4-d007b35915a4/218_15_Smart-Meter-Folder-Kundenschnittstelle-2025_0110.pdf?language=de)
