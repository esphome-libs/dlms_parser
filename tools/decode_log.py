#!/usr/bin/env python3
"""Decode a DLMS meter log file into annotated human-readable output.

Usage:
    python3 tools/decode_log.py tests/dumps/hdlc_kaifa_ma304h3e.log
    python3 tools/decode_log.py tests/dumps/hdlc_kaifa_ma304h3e.log > tests/dumps/hdlc_kaifa_ma304h3e_decoded.log
"""

import os
import re
import struct
import sys
from typing import Optional
from xml.etree.ElementTree import Comment, Element, SubElement, ElementTree, indent

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ---------------------------------------------------------------------------
# DLMS type tags
# ---------------------------------------------------------------------------
DLMS_TYPES = {
    0x00: "NULL",
    0x01: "ARRAY",
    0x02: "STRUCTURE",
    0x03: "BOOLEAN",
    0x04: "BIT_STRING",
    0x05: "INT32",
    0x06: "UINT32",
    0x09: "OCTET_STRING",
    0x0A: "VISIBLE_STRING",
    0x0C: "STRING_UTF8",
    0x0D: "BCD",
    0x0F: "INT8",
    0x10: "INT16",
    0x11: "UINT8",
    0x12: "UINT16",
    0x13: "COMPACT_ARRAY",
    0x14: "INT64",
    0x15: "UINT64",
    0x16: "ENUM",
    0x17: "FLOAT32",
    0x18: "FLOAT64",
    0x19: "DATETIME",
    0x1A: "DATE",
    0x1B: "TIME",
}

FIXED_SIZES = {
    0x03: 1, 0x0F: 1, 0x11: 1, 0x16: 1,  # 1-byte
    0x10: 2, 0x12: 2,                       # 2-byte
    0x05: 4, 0x06: 4, 0x17: 4,              # 4-byte
    0x14: 8, 0x15: 8, 0x18: 8,              # 8-byte
    0x19: 12, 0x1A: 5, 0x1B: 4,             # datetime/date/time
}

DLMS_UNITS = {
    1: "a", 2: "mo", 3: "wk", 4: "d", 5: "h", 6: "min", 7: "s",
    27: "W", 28: "VA", 29: "var", 30: "Wh", 31: "VAh", 32: "varh",
    33: "A", 35: "V", 44: "Hz",
}


def hex_line(data: bytes, max_bytes: int = 32) -> str:
    return " ".join(f"{b:02X}" for b in data[:max_bytes])


# ---------------------------------------------------------------------------
# CRC-16/X.25
# ---------------------------------------------------------------------------
def crc16_x25_raw(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc >> 1) ^ 0x8408) if (crc & 1) else (crc >> 1)
        crc &= 0xFFFF
    return crc


# ---------------------------------------------------------------------------
# Hex parser — handles various log file formats
# ---------------------------------------------------------------------------
def parse_hex_file(path: str) -> bytes:
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()

    # Try to find hex data by looking for known frame start patterns
    # Strategy: extract all contiguous hex regions, pick the one starting with 7E/68/0F/DB/DF/01/02
    text = text.replace("-\n", "").replace("'\n", "")  # line continuations

    # Split into lines, find hex-only lines
    hex_chunks = []
    for line in text.split("\n"):
        line = line.strip().replace("-", "").replace(",", "").replace("'", "")
        # Extract only hex chars and spaces
        clean = ""
        for ch in line:
            if ch in "0123456789abcdefABCDEF ":
                clean += ch
            else:
                clean += " "
        tokens = clean.split()
        # A line is hex data if it has tokens and all tokens are even-length hex
        line_bytes = []
        valid = True
        for tok in tokens:
            if len(tok) % 2 != 0 or not all(c in "0123456789abcdefABCDEF" for c in tok):
                valid = False
                break
            for i in range(0, len(tok), 2):
                line_bytes.append(int(tok[i : i + 2], 16))
        if valid and len(line_bytes) >= 1:
            hex_chunks.append(bytes(line_bytes))

    # Concatenate all hex chunks
    all_bytes = b"".join(hex_chunks)
    if not all_bytes:
        return b""

    # Find offset of first known frame start
    for i, b in enumerate(all_bytes):
        if b in (0x7E, 0x68, 0x0F, 0xDB, 0xDF, 0x01, 0x02):
            return all_bytes[i:]

    return all_bytes


# Valid AXDR type tags — used to confirm the byte after an attribute descriptor
# is a real typed value, not coincidental data.
AXDR_TYPE_TAGS = set(DLMS_TYPES.keys())


def looks_like_cosem_descriptor(data: bytes, pos: int, remaining: int) -> bool:
    """Check if data[pos:pos+9] looks like an untagged COSEM attribute descriptor.

    Format: class-id(2) + OBIS(6) + attr-id(1), followed by a valid AXDR type tag.
    """
    if remaining < 10:  # 9 for descriptor + at least 1 for the value tag
        return False
    if data[pos] != 0x00:  # high byte of class-id is always 0x00
        return False
    if data[pos + 1] == 0x00:  # low byte should be non-zero (class-id >= 1)
        return False
    # Byte after descriptor must be a valid AXDR type tag
    value_tag = data[pos + 9]
    return value_tag in AXDR_TYPE_TAGS


# ---------------------------------------------------------------------------
# AXDR walker
# ---------------------------------------------------------------------------
class AxdrWalker:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.lines: list[str] = []

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def peek(self) -> int:
        return self.data[self.pos] if self.pos < len(self.data) else -1

    def read(self, n: int) -> bytes:
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def read_byte(self) -> int:
        b = self.data[self.pos]
        self.pos += 1
        return b

    def emit(self, indent: int, text: str):
        self.lines.append("  " * indent + text)

    def decode_datetime(self, data: bytes) -> str:
        if len(data) < 12:
            return hex_line(data)
        year = (data[0] << 8) | data[1]
        mo, day, dow = data[2], data[3], data[4]
        h, m, s, hs = data[5], data[6], data[7], data[8]
        dev = struct.unpack(">h", data[9:11])[0]
        status = data[11]

        year_s = f"{year:04d}" if year not in (0, 0xFFFF) else "????"
        mo_s = f"{mo:02d}" if mo != 0xFF and 1 <= mo <= 12 else "??"
        day_s = f"{day:02d}" if day != 0xFF and 1 <= day <= 31 else "??"
        h_s = f"{h:02d}" if h != 0xFF and h <= 23 else "??"
        m_s = f"{m:02d}" if m != 0xFF and m <= 59 else "??"
        s_s = f"{s:02d}" if s != 0xFF and s <= 59 else "??"
        result = f"{year_s}-{mo_s}-{day_s} {h_s}:{m_s}:{s_s}"
        if hs != 0xFF and hs <= 99:
            result += f".{hs:02d}"
        if dev != -32768:
            sign = "+" if dev >= 0 else "-"
            ad = abs(dev)
            result += f" {sign}{ad // 60:02d}:{ad % 60:02d}"
        if status & 0x80:
            result += " (summer time)"
        return result

    def format_obis(self, data: bytes) -> str:
        return ".".join(str(b) for b in data[:6])

    def decode_value(self, tag: int, data: bytes) -> str:
        if tag in (0x03,):  # BOOLEAN
            return f"{'true' if data[0] else 'false'}"
        if tag in (0x0F,):  # INT8
            return f"{struct.unpack('b', data)[0]}"
        if tag in (0x11,):  # UINT8
            return f"{data[0]}"
        if tag in (0x16,):  # ENUM
            return f"{data[0]}"
        if tag in (0x10,):  # INT16
            return f"{struct.unpack('>h', data)[0]}"
        if tag in (0x12,):  # UINT16
            return f"{struct.unpack('>H', data)[0]}"
        if tag in (0x05,):  # INT32
            return f"{struct.unpack('>i', data)[0]}"
        if tag in (0x06,):  # UINT32
            v = struct.unpack(">I", data)[0]
            return f"{v} (0x{v:08X})"
        if tag in (0x14,):  # INT64
            return f"{struct.unpack('>q', data)[0]}"
        if tag in (0x15,):  # UINT64
            return f"{struct.unpack('>Q', data)[0]}"
        if tag in (0x17,):  # FLOAT32
            return f"{struct.unpack('>f', data)[0]}"
        if tag in (0x18,):  # FLOAT64
            return f"{struct.unpack('>d', data)[0]}"
        if tag in (0x19,):  # DATETIME
            return self.decode_datetime(data)
        return hex_line(data)

    def is_printable_string(self, data: bytes) -> bool:
        return all(32 <= b < 127 for b in data if b != 0)

    def looks_like_datetime(self, data: bytes) -> bool:
        """Heuristic: 12-byte OCTET_STRING that looks like a DLMS datetime."""
        if len(data) != 12:
            return False
        year = (data[0] << 8) | data[1]
        mo, day = data[2], data[3]
        h, m, s = data[5], data[6], data[7]
        if year == 0xFFFF:
            return False  # wildcard year — not a concrete datetime
        if not (2000 <= year <= 2099):
            return False
        if mo != 0xFF and not (1 <= mo <= 12):
            return False
        if day != 0xFF and not (1 <= day <= 31):
            return False
        if h != 0xFF and h > 23:
            return False
        if m != 0xFF and m > 59:
            return False
        if s != 0xFF and s > 59:
            return False
        return True

    def try_annotate_obis(self, data: bytes) -> str:
        if len(data) != 6:
            return ""
        obis = self.format_obis(data)
        # Common OBIS annotations
        known = {
            "1.0.1.7.0.255": "Active power+ (W)",
            "1.0.2.7.0.255": "Active power- (W)",
            "1.0.3.7.0.255": "Reactive power+ (var)",
            "1.0.4.7.0.255": "Reactive power- (var)",
            "1.0.1.8.0.255": "Active energy+ total (Wh)",
            "1.0.2.8.0.255": "Active energy- total (Wh)",
            "1.0.3.8.0.255": "Reactive energy+ total (varh)",
            "1.0.4.8.0.255": "Reactive energy- total (varh)",
            "1.0.1.8.1.255": "Active energy+ T1 (Wh)",
            "1.0.1.8.2.255": "Active energy+ T2 (Wh)",
            "1.0.2.8.1.255": "Active energy- T1 (Wh)",
            "1.0.2.8.2.255": "Active energy- T2 (Wh)",
            "1.0.21.7.0.255": "Active power+ L1 (W)",
            "1.0.22.7.0.255": "Active power- L1 (W)",
            "1.0.41.7.0.255": "Active power+ L2 (W)",
            "1.0.42.7.0.255": "Active power- L2 (W)",
            "1.0.61.7.0.255": "Active power+ L3 (W)",
            "1.0.62.7.0.255": "Active power- L3 (W)",
            "1.0.31.7.0.255": "Current L1 (A)",
            "1.0.51.7.0.255": "Current L2 (A)",
            "1.0.71.7.0.255": "Current L3 (A)",
            "1.0.32.7.0.255": "Voltage L1 (V)",
            "1.0.52.7.0.255": "Voltage L2 (V)",
            "1.0.72.7.0.255": "Voltage L3 (V)",
            "1.0.13.7.0.255": "Power factor",
            "0.0.1.0.0.255": "Clock / datetime",
            "0.0.96.1.0.255": "Meter serial number",
            "0.0.96.1.1.255": "Meter ID",
            "0.0.96.1.7.255": "Meter firmware",
            "0.0.42.0.0.255": "Logical device name",
            "1.1.0.2.129.255": "Meter type identifier",
        }
        ann = known.get(obis, "")
        return f"  <-- OBIS {obis}" + (f", {ann}" if ann else "")

    def walk_element(self, indent: int):
        if self.remaining() <= 0:
            return

        tag = self.read_byte()
        type_name = DLMS_TYPES.get(tag, f"UNKNOWN(0x{tag:02X})")

        if tag in (0x01, 0x02):  # ARRAY / STRUCTURE
            count = self.read_byte()
            self.emit(indent, f"{tag:02X}                                     <-- {type_name}")
            self.emit(indent + 1, f"{count:02X}                                   <-- {count} elements")

            # Detect COSEM attribute descriptor: STRUCTURE(2) where element 1
            # is an untagged 9-byte block: class-id(2) + OBIS(6) + attr-id(1)
            if tag == 0x02 and count == 2 and looks_like_cosem_descriptor(self.data, self.pos, self.remaining()):
                desc = self.data[self.pos : self.pos + 9]
                class_id = (desc[0] << 8) | desc[1]
                obis = desc[2:8]
                attr_id = desc[8]
                self.pos += 9
                obis_str = self.format_obis(obis)
                ann = OBIS_NAMES.get(obis_str, "")
                self.emit(indent + 1, f"--- element [1/2]: COSEM attribute descriptor ---")
                self.emit(indent + 2, f"{desc[0]:02X} {desc[1]:02X}                                  <-- class-id = {class_id}")
                self.emit(indent + 2, f"{hex_line(obis):<39s}  <-- OBIS {obis_str}" + (f", {ann}" if ann else ""))
                self.emit(indent + 2, f"{attr_id:02X}                                     <-- attr-id = {attr_id}")
                self.emit(indent + 1, f"--- element [2/2] ---")
                self.walk_element(indent + 1)
                return

            for i in range(count):
                if self.remaining() <= 0:
                    self.emit(indent + 1, "... (truncated)")
                    break
                self.emit(indent + 1, f"--- element [{i + 1}/{count}] ---")
                self.walk_element(indent + 1)
            return

        if tag in FIXED_SIZES:
            size = FIXED_SIZES[tag]
            data = self.read(size)

            if tag == 0x19:  # DATETIME
                self.emit(indent, f"{tag:02X}                                     <-- {type_name}")
                self.emit(indent + 1, f"{hex_line(data)}")
                self.emit(indent + 1, f"= {self.decode_datetime(data)}")
            elif tag == 0x16:  # ENUM
                unit = DLMS_UNITS.get(data[0], "")
                ann = f" ({unit})" if unit else ""
                self.emit(indent, f"{tag:02X} {hex_line(data):<38s}  <-- {type_name} = {data[0]}{ann}")
            elif tag == 0x0F:  # INT8
                val = struct.unpack("b", data)[0]
                self.emit(indent, f"{tag:02X} {hex_line(data):<38s}  <-- {type_name} = {val}")
            else:
                val_str = self.decode_value(tag, data)
                self.emit(indent, f"{tag:02X} {hex_line(data):<38s}  <-- {type_name} = {val_str}")
            return

        # Variable-length types (OCTET_STRING, VISIBLE_STRING, etc.)
        if tag in (0x09, 0x0A, 0x0C, 0x04, 0x0D):
            length = self.read_byte()
            data = self.read(length)

            # Check if it's a 6-byte OBIS
            if tag == 0x09 and length == 6:
                obis_ann = self.try_annotate_obis(data)
                self.emit(indent, f"{tag:02X} {length:02X} {hex_line(data):<35s}{obis_ann}")
                return

            self.emit(indent, f"{tag:02X}                                     <-- {type_name}")
            self.emit(indent + 1, f"{length:02X}                                   <-- length = {length}")
            self.emit(indent + 1, f"{hex_line(data)}")

            # Try to show a decoded value
            if tag == 0x09 and length == 12 and self.looks_like_datetime(data):
                self.emit(indent + 1, f"= {self.decode_datetime(data)}")
            elif self.is_printable_string(data):
                display = data.rstrip(b"\x00").decode("ascii", errors="replace")
                self.emit(indent + 1, f'= "{display}"')
            return

        # NULL
        if tag == 0x00:
            self.emit(indent, f"00                                     <-- NULL")
            return

        self.emit(indent, f"{tag:02X}                                     <-- {type_name}")


# ---------------------------------------------------------------------------
# XML AXDR walker
# ---------------------------------------------------------------------------
class AxdrXmlWalker:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read(self, n: int) -> bytes:
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def read_byte(self) -> int:
        b = self.data[self.pos]
        self.pos += 1
        return b

    def format_obis(self, data: bytes) -> str:
        return ".".join(str(b) for b in data[:6])

    def decode_datetime_str(self, data: bytes) -> str:
        if len(data) < 12:
            return hex_line(data)
        year = (data[0] << 8) | data[1]
        mo, day, dow = data[2], data[3], data[4]
        h, m, s, hs = data[5], data[6], data[7], data[8]
        dev = struct.unpack(">h", data[9:11])[0]
        year_s = f"{year:04d}" if year not in (0, 0xFFFF) else "????"
        mo_s = f"{mo:02d}" if mo != 0xFF and 1 <= mo <= 12 else "??"
        day_s = f"{day:02d}" if day != 0xFF and 1 <= day <= 31 else "??"
        h_s = f"{h:02d}" if h != 0xFF and h <= 23 else "??"
        m_s = f"{m:02d}" if m != 0xFF and m <= 59 else "??"
        s_s = f"{s:02d}" if s != 0xFF and s <= 59 else "??"
        result = f"{year_s}-{mo_s}-{day_s} {h_s}:{m_s}:{s_s}"
        if hs != 0xFF and hs <= 99:
            result += f".{hs:02d}"
        if dev != -32768:
            sign = "+" if dev >= 0 else "-"
            ad = abs(dev)
            result += f" {sign}{ad // 60:02d}:{ad % 60:02d}"
        return result

    def looks_like_datetime(self, data: bytes) -> bool:
        if len(data) != 12:
            return False
        year = (data[0] << 8) | data[1]
        if year == 0xFFFF or not (2000 <= year <= 2099):
            return False
        mo, day = data[2], data[3]
        h, m, s = data[5], data[6], data[7]
        if mo != 0xFF and not (1 <= mo <= 12):
            return False
        if day != 0xFF and not (1 <= day <= 31):
            return False
        if h != 0xFF and h > 23:
            return False
        if m != 0xFF and m > 59:
            return False
        if s != 0xFF and s > 59:
            return False
        return True

    def is_printable(self, data: bytes) -> bool:
        return all(32 <= b < 127 for b in data if b != 0)

    def format_value(self, tag: int, data: bytes) -> str:
        if tag == 0x03:
            return "true" if data[0] else "false"
        if tag == 0x0F:
            return str(struct.unpack("b", data)[0])
        if tag in (0x11,):
            return str(data[0])
        if tag in (0x16,):
            return str(data[0])
        if tag == 0x10:
            return str(struct.unpack(">h", data)[0])
        if tag == 0x12:
            return str(struct.unpack(">H", data)[0])
        if tag == 0x05:
            return str(struct.unpack(">i", data)[0])
        if tag == 0x06:
            return str(struct.unpack(">I", data)[0])
        if tag == 0x14:
            return str(struct.unpack(">q", data)[0])
        if tag == 0x15:
            return str(struct.unpack(">Q", data)[0])
        if tag == 0x17:
            return str(struct.unpack(">f", data)[0])
        if tag == 0x18:
            return str(struct.unpack(">d", data)[0])
        if tag == 0x19:
            return self.decode_datetime_str(data)
        return data.hex().upper()

    def walk_element(self, parent: Element):
        if self.remaining() <= 0:
            return

        tag = self.read_byte()
        type_name = DLMS_TYPES.get(tag, f"Unknown_0x{tag:02X}")
        xml_tag = type_name.replace("_", "")

        if tag in (0x01, 0x02):  # ARRAY / STRUCTURE
            count = self.read_byte()

            # Detect COSEM attribute descriptor: STRUCTURE(2) where element 1
            # is an untagged 9-byte block: class-id(2) + OBIS(6) + attr-id(1)
            if tag == 0x02 and count == 2 and looks_like_cosem_descriptor(self.data, self.pos, self.remaining()):
                desc = self.data[self.pos : self.pos + 9]
                class_id = (desc[0] << 8) | desc[1]
                obis = desc[2:8]
                attr_id = desc[8]
                self.pos += 9
                obis_str = self.format_obis(obis)
                wrapper = SubElement(parent, "STRUCTURE", Qty="2")
                ad = SubElement(wrapper, "AttributeDescriptor")
                SubElement(ad, "ClassId", Value=f"{class_id:04X}")
                SubElement(ad, "InstanceId", Value=obis_str)
                SubElement(ad, "AttributeId", Value=f"{attr_id:02X}")
                self.walk_element(wrapper)
                return

            el = SubElement(parent, xml_tag, Qty=str(count))
            for _ in range(count):
                if self.remaining() <= 0:
                    break
                self.walk_element(el)
            return

        if tag in FIXED_SIZES:
            size = FIXED_SIZES[tag]
            data = self.read(size)
            el = SubElement(parent, xml_tag, Value=self.format_value(tag, data))
            if tag == 0x16:
                unit = DLMS_UNITS.get(data[0])
                if unit:
                    el.set("Unit", unit)
            return

        # Variable-length types
        if tag in (0x09, 0x0A, 0x0C, 0x04, 0x0D):
            length = self.read_byte()
            data = self.read(length)
            el = SubElement(parent, xml_tag)

            if tag == 0x09 and length == 6:
                el.set("Value", self.format_obis(data))
                obis_str = self.format_obis(data)
                ann = OBIS_NAMES.get(obis_str)
                if ann:
                    el.set("Name", ann)
            elif tag == 0x09 and length == 12 and self.looks_like_datetime(data):
                el.set("Value", self.decode_datetime_str(data))
            elif self.is_printable(data):
                el.set("Value", data.rstrip(b"\x00").decode("ascii", errors="replace"))
            else:
                el.set("Value", data.hex().upper())
            return

        if tag == 0x00:
            SubElement(parent, "NullData")
            return

        SubElement(parent, xml_tag)


# OBIS name lookup shared with XML walker
OBIS_NAMES = {
    "1.0.1.7.0.255": "Active power+ (W)",
    "1.0.2.7.0.255": "Active power- (W)",
    "1.0.3.7.0.255": "Reactive power+ (var)",
    "1.0.4.7.0.255": "Reactive power- (var)",
    "1.0.1.8.0.255": "Active energy+ total (Wh)",
    "1.0.2.8.0.255": "Active energy- total (Wh)",
    "1.0.3.8.0.255": "Reactive energy+ total (varh)",
    "1.0.4.8.0.255": "Reactive energy- total (varh)",
    "1.0.1.8.1.255": "Active energy+ T1 (Wh)",
    "1.0.1.8.2.255": "Active energy+ T2 (Wh)",
    "1.0.2.8.1.255": "Active energy- T1 (Wh)",
    "1.0.2.8.2.255": "Active energy- T2 (Wh)",
    "1.0.21.7.0.255": "Active power+ L1 (W)",
    "1.0.22.7.0.255": "Active power- L1 (W)",
    "1.0.41.7.0.255": "Active power+ L2 (W)",
    "1.0.42.7.0.255": "Active power- L2 (W)",
    "1.0.61.7.0.255": "Active power+ L3 (W)",
    "1.0.62.7.0.255": "Active power- L3 (W)",
    "1.0.31.7.0.255": "Current L1 (A)",
    "1.0.51.7.0.255": "Current L2 (A)",
    "1.0.71.7.0.255": "Current L3 (A)",
    "1.0.32.7.0.255": "Voltage L1 (V)",
    "1.0.52.7.0.255": "Voltage L2 (V)",
    "1.0.72.7.0.255": "Voltage L3 (V)",
    "1.0.13.7.0.255": "Power factor",
    "0.0.1.0.0.255": "Clock / datetime",
    "0.0.96.1.0.255": "Meter serial number",
    "0.0.96.1.1.255": "Meter ID",
    "0.0.96.1.7.255": "Meter firmware",
    "0.0.42.0.0.255": "Logical device name",
    "1.1.0.2.129.255": "Meter type identifier",
}


def apdu_to_xml(apdu: bytes, key: Optional[bytes] = None) -> Optional[Element]:
    """Convert APDU bytes into an XML element tree."""
    if not apdu:
        return None

    tag = apdu[0]

    if tag == 0x0F:
        root = Element("DataNotification")
        pos = 1
        root.set("LongInvokeId", apdu[pos : pos + 4].hex().upper())
        pos += 4

        dt_byte = apdu[pos]
        pos += 1
        if dt_byte == 0x00:
            SubElement(root, "DateTime")
        elif dt_byte == 0x0C:
            dtm = apdu[pos : pos + 12]
            walker = AxdrXmlWalker(dtm)
            el = SubElement(root, "DateTime", Value=walker.decode_datetime_str(dtm))
            pos += 12
        elif dt_byte == 0x09:
            length = apdu[pos]
            pos += 1
            dtm = apdu[pos : pos + length]
            walker = AxdrXmlWalker(dtm)
            el = SubElement(root, "DateTime", Value=walker.decode_datetime_str(dtm))
            pos += length
        else:
            SubElement(root, "DateTime", Value="unknown")
            pos += 12

        axdr_data = apdu[pos:]
        if axdr_data:
            walker = AxdrXmlWalker(axdr_data)
            walker.walk_element(root)
        return root

    elif tag == 0xE0:
        # GBT reassembly
        pos = 0
        reassembled = b""
        while pos < len(apdu) and apdu[pos] == 0xE0:
            block_ctrl = apdu[pos + 1]
            is_last = (block_ctrl & 0x80) != 0
            blen = apdu[pos + 6]
            block_data = apdu[pos + 7 : pos + 7 + blen]
            reassembled += block_data
            pos += 7 + blen
            if is_last:
                break
        return apdu_to_xml(reassembled, key)

    elif tag in (0xDB, 0xDF):
        name = "GeneralGloCiphering" if tag == 0xDB else "GeneralDedCiphering"
        root = Element(name)
        pos = 1

        st_len = apdu[pos]
        pos += 1
        systitle = apdu[pos : pos + st_len]
        root.set("SystemTitle", systitle.hex().upper())
        pos += st_len

        # BER length
        len_byte = apdu[pos]
        pos += 1
        if len_byte <= 0x7F:
            cipher_len = len_byte
        else:
            num_bytes = len_byte & 0x7F
            cipher_len = 0
            for _ in range(num_bytes):
                cipher_len = (cipher_len << 8) | apdu[pos]
                pos += 1

        sec_ctrl = apdu[pos]
        pos += 1
        fc = struct.unpack(">I", apdu[pos : pos + 4])[0]
        root.set("FrameCounter", str(fc))
        pos += 4

        iv = systitle + struct.pack(">I", fc)
        has_auth = (sec_ctrl & 0x10) != 0
        gcm_tag_len = 12 if has_auth else 0
        payload_len = cipher_len - 5 - gcm_tag_len
        ciphertext = apdu[pos : pos + payload_len]

        if key:
            plain = decrypt_gcm(key, iv, ciphertext)
            if plain:
                inner = apdu_to_xml(plain, key)
                if inner is not None:
                    root.append(inner)
                    return root
        root.set("Encrypted", "true")
        root.set("Ciphertext", ciphertext.hex().upper())
        return root

    elif tag in (0x01, 0x02):
        root = Element("RawAxdr")
        walker = AxdrXmlWalker(apdu)
        walker.walk_element(root)
        return root

    else:
        root = Element("RawAxdr")
        walker = AxdrXmlWalker(apdu)
        walker.walk_element(root)
        return root


def _annotate_instance_ids(xml_text: str) -> str:
    """Add inline OBIS name comments after each InstanceId element."""
    def _replace(m):
        obis_str = m.group(1)
        ann = OBIS_NAMES.get(obis_str)
        if ann:
            return m.group(0) + f" <!-- {ann} -->"
        return m.group(0)
    return re.sub(r'<InstanceId Value="([0-9.]+)" />', _replace, xml_text)


def save_apdu_xml(apdu: bytes, log_path: str, key: Optional[bytes] = None):
    """Save APDU as XML to xxx_decoded.xml alongside the log file."""
    root = apdu_to_xml(apdu, key)
    if root is None:
        return
    indent(root, space="  ")
    tree = ElementTree(root)
    base = os.path.splitext(log_path)[0]
    xml_path = base + "_decoded.xml"
    # Write to string, annotate InstanceId lines, then save
    from io import StringIO
    buf = StringIO()
    tree.write(buf, encoding="unicode", xml_declaration=True)
    xml_text = _annotate_instance_ids(buf.getvalue())
    with open(xml_path, "w") as f:
        f.write(xml_text)
    print(f"XML:   {xml_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# HDLC decoder
# ---------------------------------------------------------------------------
def decode_hdlc(data: bytes) -> tuple[list[str], bytes]:
    lines = []
    apdu_parts = []
    offset = 0
    frame_num = 0

    while offset < len(data):
        if data[offset] != 0x7E:
            offset += 1
            continue

        # Find frame using length field
        if offset + 3 > len(data):
            break
        seg_bit = (data[offset + 1] & 0x08) != 0
        flen = ((data[offset + 1] & 0x07) << 8) | data[offset + 2]
        frame_total = flen + 2
        if offset + frame_total > len(data):
            break

        frame = data[offset : offset + frame_total]
        frame_num += 1
        content = frame[1:-1]

        lines.append(f"=== HDLC frame {frame_num} ({len(frame)} bytes){' [segmented]' if seg_bit else ''} ===")
        lines.append(f"7E                                     <-- opening flag")
        lines.append(f"{content[0]:02X} {content[1]:02X}                                  <-- format, length={flen}{', segmented' if seg_bit else ''}")

        pos = 2
        # Dst address
        dst_len = 0
        for i in range(min(4, len(content) - pos)):
            if content[pos + i] & 0x01:
                dst_len = i + 1
                break
        dst = content[pos : pos + dst_len]
        lines.append(f"{hex_line(dst):<39s}  <-- dst addr ({dst_len}B)")
        pos += dst_len

        # Src address
        src_len = 0
        for i in range(min(4, len(content) - pos)):
            if content[pos + i] & 0x01:
                src_len = i + 1
                break
        src = content[pos : pos + src_len]
        lines.append(f"{hex_line(src):<39s}  <-- src addr ({src_len}B)")
        pos += src_len

        lines.append(f"{content[pos]:02X}                                     <-- control byte")
        pos += 1

        # HCS
        hcs_check = crc16_x25_raw(content[: pos + 2])
        hcs_ok = "OK" if hcs_check == 0xF0B8 else "FAIL"
        lines.append(f"{content[pos]:02X} {content[pos+1]:02X}                                  <-- HCS ({hcs_ok})")
        pos += 2

        # FCS
        fcs_check = crc16_x25_raw(content)
        fcs_ok = "OK" if fcs_check == 0xF0B8 else "FAIL"
        lines.append(f"... FCS: {content[-2]:02X} {content[-1]:02X} ({fcs_ok})")

        data_end = len(content) - 2

        # LLC
        is_first = frame_num == 1
        if (is_first and pos + 3 <= data_end and
                content[pos] == 0xE6 and content[pos + 1] in (0xE6, 0xE7) and content[pos + 2] == 0x00):
            lines.append(f"{content[pos]:02X} {content[pos+1]:02X} {content[pos+2]:02X}                               <-- LLC header")
            pos += 3

        payload = content[pos:data_end]
        apdu_parts.append(payload)
        lines.append(f"Payload: {len(payload)} bytes")
        lines.append(f"7E                                     <-- closing flag")
        lines.append("")

        offset += frame_total

    return lines, b"".join(apdu_parts)


# ---------------------------------------------------------------------------
# M-Bus decoder
# ---------------------------------------------------------------------------
def decode_mbus(data: bytes) -> tuple[list[str], bytes]:
    lines = []
    apdu_parts = []
    offset = 0
    frame_num = 0

    while offset < len(data):
        if data[offset] != 0x68:
            break
        L = data[offset + 1]
        if data[offset + 2] != L or data[offset + 3] != 0x68:
            break
        frame_size = 4 + L + 2
        if offset + frame_size > len(data):
            break

        frame_num += 1
        lines.append(f"=== M-Bus frame {frame_num} (L={L}, {frame_size} bytes) ===")
        lines.append(f"68 {L:02X} {L:02X} 68                             <-- intro (L={L})")

        cs_calc = sum(data[offset + 4 : offset + 4 + L]) & 0xFF
        cs_stored = data[offset + 4 + L]
        cs_ok = "OK" if cs_calc == cs_stored else "FAIL"
        lines.append(f"C={data[offset+4]:02X} A={data[offset+5]:02X} CI={data[offset+6]:02X} STSAP={data[offset+7]:02X} DTSAP={data[offset+8]:02X}")
        lines.append(f"CS: {cs_stored:02X} ({cs_ok}), stop: {data[offset+4+L+1]:02X}")

        payload = data[offset + 9 : offset + 4 + L]
        apdu_parts.append(payload)
        lines.append(f"Payload: {len(payload)} bytes")
        lines.append("")

        offset += frame_size

    return lines, b"".join(apdu_parts)


# ---------------------------------------------------------------------------
# APDU decoder
# ---------------------------------------------------------------------------
def decode_apdu(apdu: bytes, key: Optional[bytes] = None) -> tuple[list[str], Optional[bytes]]:
    lines = []
    if not apdu:
        return lines, None

    tag = apdu[0]
    if tag == 0x0F:
        lines.append("=== APDU: DATA-NOTIFICATION ===")
        lines.append(f"0F                                     <-- DATA-NOTIFICATION tag")
        pos = 1
        lines.append(f"{hex_line(apdu[pos:pos+4]):<39s}  <-- Long-Invoke-ID")
        pos += 4

        dt_byte = apdu[pos]
        pos += 1
        if dt_byte == 0x00:
            lines.append(f"00                                     <-- DateTime: absent")
        elif dt_byte == 0x0C:
            dtm = apdu[pos : pos + 12]
            walker = AxdrWalker(dtm)
            dt_str = walker.decode_datetime(dtm)
            lines.append(f"0C                                     <-- DateTime: 12 raw bytes")
            lines.append(f"  {hex_line(dtm)}")
            lines.append(f"  = {dt_str}")
            pos += 12
        elif dt_byte == 0x09:
            length = apdu[pos]
            pos += 1
            dtm = apdu[pos : pos + length]
            walker = AxdrWalker(dtm)
            dt_str = walker.decode_datetime(dtm)
            lines.append(f"09                                     <-- DateTime: OCTET_STRING")
            lines.append(f"  {length:02X}                                   <-- length = {length}")
            lines.append(f"  {hex_line(dtm)}")
            lines.append(f"  = {dt_str}")
            pos += length
        else:
            lines.append(f"{dt_byte:02X}                                     <-- DateTime: unknown flag")
            pos += 12  # best guess

        lines.append("")
        return lines, apdu[pos:]

    elif tag == 0xE0:
        # General Block Transfer (GBT) — reassemble numbered blocks then recurse
        # Format per block: E0 [ctrl:1] [block_num:2] [block_num_ack:2] [BER_len] [data...]
        lines.append(f"=== APDU: General Block Transfer (0xE0) ===")
        pos = 0
        reassembled = b""
        while pos < len(apdu) and apdu[pos] == 0xE0:
            block_ctrl = apdu[pos + 1]
            is_last = (block_ctrl & 0x80) != 0
            bnum = (apdu[pos + 2] << 8) | apdu[pos + 3]
            # block_num_ack at pos+4..pos+5 (skip)
            # BER length at pos+6
            blen = apdu[pos + 6]
            block_data = apdu[pos + 7 : pos + 7 + blen]
            lines.append(f"  Block {bnum}: {blen} bytes (ctrl=0x{block_ctrl:02X}){' [last]' if is_last else ''}")
            reassembled += block_data
            pos += 7 + blen
            if is_last:
                break
        lines.append(f"  Reassembled: {len(reassembled)} bytes")
        lines.append("")
        inner_lines, axdr = decode_apdu(reassembled, key)
        lines.extend(inner_lines)
        return lines, axdr

    elif tag in (0xDB, 0xDF):
        name = "General-GLO-Ciphering" if tag == 0xDB else "General-DED-Ciphering"
        lines.append(f"=== APDU: {name} (0x{tag:02X}) ===")
        pos = 1

        # System title
        st_len = apdu[pos]
        pos += 1
        systitle = apdu[pos : pos + st_len]
        st_ascii = systitle.decode("ascii", errors="replace")
        lines.append(f"{apdu[1]:02X}                                     <-- system title length = {st_len}")
        lines.append(f"  {hex_line(systitle):<35s}  = \"{st_ascii}\"")
        pos += st_len

        # BER length
        len_byte = apdu[pos]
        pos += 1
        if len_byte <= 0x7F:
            cipher_len = len_byte
            lines.append(f"{len_byte:02X}                                     <-- cipher length = {cipher_len}")
        else:
            num_bytes = len_byte & 0x7F
            cipher_len = 0
            for i in range(num_bytes):
                cipher_len = (cipher_len << 8) | apdu[pos]
                pos += 1
            lines.append(f"{len_byte:02X} ...                                  <-- cipher length = {cipher_len} (multi-byte)")

        # Security control + frame counter
        sec_ctrl = apdu[pos]
        pos += 1
        fc = struct.unpack(">I", apdu[pos : pos + 4])[0]
        lines.append(f"{sec_ctrl:02X}                                     <-- security control")
        lines.append(f"{hex_line(apdu[pos:pos+4]):<39s}  <-- frame counter = {fc}")
        pos += 4

        # IV = systitle(8) + frame_counter(4)
        iv = systitle + struct.pack(">I", fc)

        has_auth = (sec_ctrl & 0x10) != 0
        gcm_tag_len = 12 if has_auth else 0
        payload_len = cipher_len - 5 - gcm_tag_len  # minus security_ctrl(1) + frame_counter(4) + tag
        ciphertext = apdu[pos : pos + payload_len]
        gcm_tag = apdu[pos + payload_len : pos + payload_len + gcm_tag_len] if has_auth else b""
        lines.append(f"Ciphertext: {payload_len} bytes")
        # Show encrypted payload in hex (chunked for readability)
        for i in range(0, len(ciphertext), 32):
            chunk = ciphertext[i : i + 32]
            prefix = "  " if i > 0 else "  "
            lines.append(f"{prefix}{hex_line(chunk, 32)}")
        if has_auth:
            lines.append(f"GCM auth tag: {hex_line(gcm_tag)}")

        if key:
            plain = decrypt_gcm(key, iv, ciphertext)
            if plain:
                lines.append("")
                lines.append(f"Decrypted: {len(plain)} bytes")
                for i in range(0, len(plain), 32):
                    chunk = plain[i : i + 32]
                    lines.append(f"  {hex_line(chunk, 32)}")
                lines.append("")
                # Recurse — decrypted payload is an inner APDU
                inner_lines, axdr = decode_apdu(plain, key)
                lines.extend(inner_lines)
                return lines, axdr
            else:
                lines.append(f"Decryption: FAILED (wrong key or corrupted)")
        else:
            if HAS_CRYPTO:
                lines.append(f"No key provided - place key in .key file or use -k flag")
            else:
                lines.append(f"No 'cryptography' package - pip install cryptography")
        return lines, None

    elif tag in (0x01, 0x02):
        lines.append("=== APDU: raw AXDR (no wrapper) ===")
        return lines, apdu

    else:
        lines.append(f"=== APDU: unknown tag 0x{tag:02X} ===")
        return lines, apdu


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------
def load_key(log_path: str) -> Optional[bytes]:
    """Try to load AES key from .key file with same base name, or from -k argument."""
    base = os.path.splitext(log_path)[0]
    key_path = base + ".key"
    if os.path.exists(key_path):
        with open(key_path) as f:
            text = f.read()
        hex_str = re.sub(r"[^0-9a-fA-F]", "", text)
        if len(hex_str) == 32:
            return bytes(int(hex_str[i : i + 2], 16) for i in range(0, 32, 2))
    return None


# ---------------------------------------------------------------------------
# AES-GCM decryption
# ---------------------------------------------------------------------------
def decrypt_gcm(key: bytes, iv: bytes, ciphertext: bytes) -> Optional[bytes]:
    """Decrypt using AES-GCM without tag verification (matches C++ mbedTLS behavior)."""
    if not HAS_CRYPTO:
        return None
    try:
        # GCM internally uses CTR with J0 = IV || 0x00000002 for the first data block.
        # Build the initial counter: IV (12 bytes) + counter starting at 2 (big-endian).
        # Counter 1 is used for the auth tag; counter 2+ for data encryption.
        j0 = iv + b"\x00\x00\x00\x02"
        cipher = Cipher(algorithms.AES(key), modes.CTR(j0))
        dec = cipher.decryptor()
        return dec.update(ciphertext) + dec.finalize()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <logfile> [-k <hex_key>]", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]

    # Parse optional -k key argument
    cli_key = None
    if "-k" in sys.argv:
        idx = sys.argv.index("-k")
        if idx + 1 < len(sys.argv):
            hex_str = re.sub(r"[^0-9a-fA-F]", "", sys.argv[idx + 1])
            if len(hex_str) == 32:
                cli_key = bytes(int(hex_str[i : i + 2], 16) for i in range(0, 32, 2))

    key = cli_key or load_key(path)

    raw = parse_hex_file(path)
    print(f"Input: {path} ({len(raw)} bytes)")
    if key:
        print(f"Key:   {key.hex().upper()}" + (" (from .key file)" if not cli_key else " (from -k argument)"))
    print()

    # Detect transport
    all_lines = []
    apdu = None

    if raw[0] == 0x7E:
        frame_lines, apdu = decode_hdlc(raw)
        all_lines.extend(frame_lines)
    elif raw[0] == 0x68:
        frame_lines, apdu = decode_mbus(raw)
        all_lines.extend(frame_lines)
    else:
        all_lines.append("=== Transport: RAW (no frame wrapper) ===")
        all_lines.append("")
        apdu = raw

    # Decode APDU
    if apdu:
        apdu_lines, axdr = decode_apdu(apdu, key)
        all_lines.extend(apdu_lines)

        # Decode AXDR
        if axdr and len(axdr) > 0:
            all_lines.append(f"=== AXDR payload ({len(axdr)} bytes) ===")
            walker = AxdrWalker(axdr)
            walker.walk_element(0)
            all_lines.extend(walker.lines)
            if walker.pos < len(axdr):
                remaining = axdr[walker.pos :]
                all_lines.append(f"")
                all_lines.append(f"Unparsed tail ({len(remaining)} bytes): {hex_line(remaining)}")

        # Save APDU as XML
        save_apdu_xml(apdu, path, key)

    for line in all_lines:
        print(line)


if __name__ == "__main__":
    main()
