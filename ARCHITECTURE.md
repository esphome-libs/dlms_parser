# dlms_parser — Architecture

## Component Diagram

```mermaid
graph TD
    UART["UART bytes"] --> CHECK["check_frame()"]
    CHECK -->|COMPLETE| PARSE["parse()"]
    CHECK -->|NEED_MORE| UART

    PARSE --> HDLC["HdlcDecoder"]
    PARSE --> MBUS["MBusDecoder"]
    PARSE --> RAW["RAW pass-through"]

    HDLC --> APDU["ApduHandler"]
    MBUS --> APDU
    RAW --> APDU

    APDU -->|"0xE0"| GBT["GBT reassembly"] --> APDU
    APDU -->|"0xDB/DF"| GCM["GcmDecryptor"] --> APDU
    APDU -->|"0x0F"| DN["DATA-NOTIFICATION"]
    APDU -->|"0x01/02"| AXDR

    DN --> AXDR["AxdrParser"]
    AXDR --> PAT["Pattern matching<br/>T1 · T2 · T3 · U.ZPA · custom"]
    PAT --> CB["cooked_cb(obis, value)<br/>raw_cb(captures, pattern)"]
    CB --> RES["ParseResult<br/>{count, bytes_consumed}"]
```

## Data Flow

```
UART → check_frame() → COMPLETE / NEED_MORE / ERROR
                          │
                          ▼
                       parse()
                          │
            ┌─────────────┼─────────────┐
            HDLC          MBUS          RAW
            │             │             │
            └──────┬──────┘             │
                   ▼                    │
              ApduHandler ◄─────────────┘
                   │
         ┌────────┼────────┬──────────┐
         0xE0     0xDB/DF  0x0F       0x01/02
         GBT      GCM      DATA-NOT   raw AXDR
         │        │        │          │
         └──►     └──►     ▼          ▼
         re-enter  re-enter AxdrParser
                           │
                    pattern matching
                           │
                    callbacks + ParseResult
```

## Module Responsibilities

| Module           | Role                                                                |
|------------------|---------------------------------------------------------------------|
| **DlmsParser**   | Facade — owns all components, exposes `check_frame()` and `parse()` |
| **HdlcDecoder**  | Strips 0x7E framing, validates CRC, reassembles segmented frames    |
| **MBusDecoder**  | Strips 0x68 framing, validates checksum, concatenates multi-frame   |
| **ApduHandler**  | Scans for APDU tag, handles GBT/encryption/DATA-NOTIFICATION        |
| **GcmDecryptor** | AES-128-GCM decryption (BearSSL / PSA / mbedTLS)                    |
| **AxdrParser**   | Walks STRUCTURE/ARRAY tree, matches DSL patterns, emits objects     |
| **Logger**       | Static logging interface, silent by default                         |
| **utils**        | Value conversion, OBIS/datetime formatting, type helpers            |

## Zero-Heap Architecture

All parsing transforms happen in a single caller-owned work buffer. **No heap
allocation occurs during `parse()`.** The caller provides the buffer at setup:

```cpp
uint8_t work_buf[1024];
parser.set_work_buffer(work_buf, sizeof(work_buf));
```

The pipeline copies input into the work buffer, then transforms in-place:

```
work_buf: [7E HDLC frames 7E]  ← memcpy from input
    ↓ HDLC decode (strip framing, concatenate payloads)
work_buf: [E0 GBT blocks]
    ↓ GBT reassembly (strip block headers)
work_buf: [DB ciphertext]
    ↓ AES-GCM decrypt in-place
work_buf: [0F DATA-NOTIFICATION AXDR...]
    ↓ strip APDU header → AxdrParser reads directly
```

Each stage produces output ≤ input, so the buffer never grows.

## Caller vs Library Responsibilities

The library is **stateless** between calls — it does not buffer or accumulate data.

| Responsibility                                | Owner                                            |
|-----------------------------------------------|--------------------------------------------------|
| Reading bytes from UART                       | Caller                                           |
| Detecting frame boundaries (0x7E / 0x16)      | Caller                                           |
| Accumulating multi-frame messages             | Caller (using `check_frame()` to know when done) |
| Providing a work buffer (`set_work_buffer()`) | Caller                                           |
| Decoding transport framing (HDLC / M-Bus)     | Library (in-place)                               |
| Reassembling GBT blocks                       | Library (in-place)                               |
| Decrypting AES-GCM                            | Library (in-place)                               |
| Walking AXDR structure and matching patterns  | Library                                          |
| Delivering parsed values via callbacks        | Library                                          |

Typical caller loop:

```
read frame from UART → append to buffer → check_frame()
  ├─ NEED_MORE → read more
  ├─ ERROR → clear buffer, resync
  └─ COMPLETE → parse() → clear buffer
```
