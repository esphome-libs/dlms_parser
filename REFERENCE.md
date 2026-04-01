# dlms_parser — Reference

This document collects the public API, AXDR pattern DSL, and supporting reference material for `dlms_parser`.

## Public API

### `DlmsParser`

Main facade that composes frame decoding, APDU handling, decryption, and AXDR parsing.

| Method                                                | Description                                                                           |
|-------------------------------------------------------|---------------------------------------------------------------------------------------|
| `DlmsParser(Aes128GcmDecryptor&)`                     | Constructor requiring a reference to an AES-128-GCM decryptor backend                 |
| `set_frame_format(FrameFormat)`                       | Select transport wrapper: `RAW`, `HDLC`, or `MBUS`                                    |
| `set_work_buffer(buf, capacity)`                      | Provide a caller-owned buffer for in-place transforms — **required before `parse()`** |
| `set_skip_crc_check(bool)`                            | Skip CRC/checksum validation for HDLC and M-Bus                                       |
| `set_decryption_key(Aes128GcmDecryptionKey)`          | Set AES-128-GCM decryption key (GUEK)                                                 |
| `set_authentication_key(Aes128GcmDecryptionKey)`      | Set AES-128-GCM authentication key (GAK) for GCM tag verification                     |
| `load_default_patterns()`                             | Register built-in patterns `T1`, `T2`, `T3`, `U.ZPA`                                  |
| `register_pattern(dsl)`                               | Register a custom pattern with name `CUSTOM` and priority `0`                         |
| `register_pattern(name, dsl, priority)`               | Register a named pattern with explicit priority                                       |
| `register_pattern(name, dsl, priority, default_obis)` | Register with a default 6-byte OBIS (used when pattern has no `TO`/`O`)               |
| `check_frame(buf, len)`                               | Check if buffer contains a complete message — returns `FrameStatus`                   |
| `parse(buf, len, cooked_cb, raw_cb)`                  | Parse a complete frame — returns `ParseResult{count, bytes_consumed}`                 |

### `FrameStatus`

| Value                    | Meaning                                                          |
|--------------------------|------------------------------------------------------------------|
| `FrameStatus::COMPLETE`  | buffer contains a complete message — call `parse()`              |
| `FrameStatus::NEED_MORE` | more frames needed — keep reading and call `check_frame()` again |
| `FrameStatus::ERROR`     | invalid framing — discard buffer and resync                      |

### `ParseResult`

| Field            | Type     | Description                                       |
|------------------|----------|---------------------------------------------------|
| `count`          | `size_t` | number of matched COSEM objects                   |
| `bytes_consumed` | `size_t` | how many bytes of the AXDR payload were processed |

### `FrameFormat`

| Value               | Meaning                                            |
|---------------------|----------------------------------------------------|
| `FrameFormat::RAW`  | input buffer already contains the APDU or raw AXDR |
| `FrameFormat::MBUS` | input buffer contains M-Bus transport framing      |
| `FrameFormat::HDLC` | input buffer contains HDLC transport framing       |

## Callback Types

### `DlmsDataCallback`

```cpp
void(const char* obis_code, float float_val, const char* str_val, bool is_numeric)
```

- `obis_code`: formatted OBIS string such as `1.0.1.8.0.255`
- `float_val`: numeric value with scaler already applied
- `str_val`: textual representation when the value is not numeric
- `is_numeric`: tells which of `float_val` or `str_val` is valid

### `DlmsRawCallback`

```cpp
void(const AxdrCaptures& captures, const AxdrDescriptorPattern& pattern)
```

Use this callback when you need raw bytes, precise type information, or scaler/unit fields before cooked conversion.

## `AxdrCaptures`

Raw data captured by a matched pattern.

| Field             | Type             | Description                                  |
|-------------------|------------------|----------------------------------------------|
| `elem_idx`        | `uint32_t`       | element index in the enclosing structure     |
| `class_id`        | `uint16_t`       | captured COSEM class ID                      |
| `obis`            | `const uint8_t*` | pointer to 6-byte OBIS code or `nullptr`     |
| `value_type`      | `DlmsDataType`   | DLMS type of the captured value              |
| `value_ptr`       | `const uint8_t*` | pointer to raw value bytes                   |
| `value_len`       | `uint8_t`        | byte length of the raw value                 |
| `has_scaler_unit` | `bool`           | indicates whether scaler/unit was captured   |
| `scaler`          | `int8_t`         | decimal exponent used as `value * 10^scaler` |
| `unit_enum`       | `uint8_t`        | DLMS unit enumeration value                  |

## Pattern DSL Reference

Patterns are comma-separated tokens. The token order must match the object layout in the AXDR stream.

Built-in patterns:

| Name    | DSL               | Priority |
|---------|-------------------|---------:|
| `T1`    | `TC, TO, TS, TV`  |       10 |
| `T2`    | `TO, TV, TSU`     |       20 |
| `T3`    | `TV, TC, TSU, TO` |       30 |
| `U.ZPA` | `F, C, O, A, TV`  |       40 |

Token reference:

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

Examples:

```cpp
parser.register_pattern("TC, TO, TDTM");
parser.register_pattern("C, O, A, V, TS, TU");
parser.register_pattern("TO, TV, S(TS, TU)");
parser.register_pattern("L, TSTR");
parser.register_pattern("TOW, TV, TSU");
```

Priority rules:

- lower priority is tried first
- `register_pattern(dsl)` assigns priority `0`
- first successful match wins

## Utility Functions

Helpers exposed by `dlms_parser::utils`:

| Function                                    | Description                                           |
|---------------------------------------------|-------------------------------------------------------|
| `data_as_float(type, ptr, len)`             | Convert DLMS-encoded value bytes to `float`           |
| `data_to_string(type, ptr, len, buf, max)`  | Convert a DLMS value to a textual representation      |
| `datetime_to_string(ptr, len, buf, max)`    | Format a 12-byte datetime as a string                 |
| `obis_to_string(obis, buf, max)`            | Format a 6-byte OBIS code as `A.B.C.D.E.F`            |
| `test_if_date_time_12b(ptr)`                | Heuristic check for 12-byte datetime payloads         |
| `dlms_data_type_to_string(type)`            | Convert a type enum to a readable name                |
| `get_data_type_size(type)`                  | Return fixed size, variable marker, or no-size marker |
| `is_value_data_type(type)`                  | Tell whether a type represents a scalar value         |
| `format_hex_pretty_to(out, max, data, len)` | Format bytes as dot-separated hex                     |

## Logging API

Logging is disabled until you install a handler:

| Method                               | Description                |
|--------------------------------------|----------------------------|
| `Logger::set_log_function(callback)` | Install a logging callback |
| `Logger::log(level, fmt, ...)`       | Emit a log message         |

Typical log levels:

| Level          | Typical content                            |
|----------------|--------------------------------------------|
| `DEBUG`        | pattern matching and traversal details     |
| `VERY_VERBOSE` | low-level parser diagnostics               |
| `VERBOSE`      | parsing warnings and type-specific notes   |
| `INFO`         | matched object details                     |
| `WARNING`      | frame errors and missing prerequisites     |
| `ERROR`        | decryption failures and fatal parse errors |

## Supported APDU Tags And Input Forms

Common APDU tags accepted by the parser:

| Byte   | Meaning                                                                             |
|--------|-------------------------------------------------------------------------------------|
| `0x0F` | `DATA-NOTIFICATION`                                                                 |
| `0xE0` | `General-Block-Transfer` — reassembles numbered blocks, then re-enters APDU parsing |
| `0xDB` | `General-GLO-Ciphering` — encrypted, needs decryption key                           |
| `0xDF` | `General-DED-Ciphering` — encrypted, needs decryption key                           |
| `0x01` | raw AXDR array                                                                      |
| `0x02` | raw AXDR structure                                                                  |

See also [HOWTO.md](HOWTO.md) for usage examples and [ARCHITECTURE.md](ARCHITECTURE.md) for the component diagram.

## External References

- [DLMS/COSEM Architecture and Protocols. Green Book Edition 11](https://github.com/zhuyangfei/DLMS-green-book/blob/main/Green-Book-Ed-11-V1-0.pdf)
- [CONSUMER INFORMATION INTERFACE (CII) SPECIFICATION](https://wiki.weble.ch/articles/landys_e450_docs/customer_information_interface_(cii)_specification.pdf)
- [EWK Energie AG. Smart meter customer interface](https://ewk-energie.ch/wp-content/uploads/2025/08/smart-meter-kundenschnittstelle.pdf)
- [Zaehler Landis+Gyr E450/E570. Smart meter customer interface](https://www.bkw.ch/fileadmin/user_upload/03_Energie/03_01_Stromversorgung_Privat-_und_Gewerbekunden/Zaehlerablesung/BKW_faktenblatt_kundenschnittstelle_L_G_E450_E570_def_Web.pdf)
- [E450 Specification](https://assets.netzburgenland.at/Spezifikation_Kundenschnittstelle_E450_korr_2_009418889e.pdf)
- [Netz Smart Meter specification](https://netz-noe.at/getContentAsset/568bef9a-3bd1-4f2e-a710-6ba7e71cb746/0ee16eb8-9692-4f25-b8a4-d007b35915a4/218_15_Smart-Meter-Folder-Kundenschnittstelle-2025_0110.pdf?language=de)
