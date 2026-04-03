# dlms_parser

`dlms_parser` is a C++20 library for parsing DLMS/COSEM push telegrams from electricity meters.<br>
It is designed for embedded and integration-heavy environments such as ESPHome, but it also works on desktop platforms.

## Features

- **Transport decoding**: `RAW`, `HDLC`, `M-Bus`. Including multi-frame segmentation and General Block Transfer
- **Encryption**: AES-128-GCM decryption and optional authentication tag verification for `General-GLO-Ciphering` and `General-DED-Ciphering` APDUs
- **Pattern matching**: DSL-based AXDR descriptor patterns with built-in presets and custom registration
- **Callback API**: cooked callback delivers OBIS code + scaled value; raw callback gives full capture details
- **Embedded-friendly**: no heap allocation in the hot path; stack-only per-frame parsing
- **Portable**: builds on ESP32 (IDF/Arduino), ESP8266, Linux, macOS, Windows

## How to use

Complete example with the explanation: [test_example.cpp](https://github.com/esphome-libs/dlms_parser/blob/main/tests/test_example.cpp)

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

You can open the repository using any IDE that supports CMake.

## References

### This library builds on work from

- [esphome-dlms-cosem](https://github.com/latonita/esphome-dlms-cosem) - original ESPHome DLMS/COSEM component and AXDR parser
- [xt211](https://github.com/Tomer27cz/xt211) - Sagemcom XT211 parser, instrumental in de-Guruxing the protocol handling

### External References

- [DLMS/COSEM Architecture and Protocols. Green Book Edition 11](https://github.com/zhuyangfei/DLMS-green-book/blob/main/Green-Book-Ed-11-V1-0.pdf)
- [CONSUMER INFORMATION INTERFACE (CII) SPECIFICATION](https://wiki.weble.ch/articles/landys_e450_docs/customer_information_interface_(cii)_specification.pdf)
- [EWK Energie AG. Smart meter customer interface](https://ewk-energie.ch/wp-content/uploads/2025/08/smart-meter-kundenschnittstelle.pdf)
- [Zaehler Landis+Gyr E450/E570. Smart meter customer interface](https://www.bkw.ch/fileadmin/user_upload/03_Energie/03_01_Stromversorgung_Privat-_und_Gewerbekunden/Zaehlerablesung/BKW_faktenblatt_kundenschnittstelle_L_G_E450_E570_def_Web.pdf)
- [E450 Specification](https://assets.netzburgenland.at/Spezifikation_Kundenschnittstelle_E450_korr_2_009418889e.pdf)
- [Netz Smart Meter specification](https://netz-noe.at/getContentAsset/568bef9a-3bd1-4f2e-a710-6ba7e71cb746/0ee16eb8-9692-4f25-b8a4-d007b35915a4/218_15_Smart-Meter-Folder-Kundenschnittstelle-2025_0110.pdf?language=de)
