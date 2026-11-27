"""Build EDID base blocks by hand, from the VESA E-EDID 1.4 layout. Every value is invented."""

from __future__ import annotations

import struct

_HEADER = bytes([0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00])
_DESCRIPTOR_OFFSETS = (54, 72, 90, 108)


def _vendor(code: str) -> bytes:
    letters = [ord(c) - ord("A") + 1 for c in code]
    return struct.pack(">H", (letters[0] << 10) | (letters[1] << 5) | letters[2])


def _text_descriptor(tag: int, text: str) -> bytes:
    body = text.encode("ascii")[:13]
    if len(body) < 13:
        body += b"\n" + b" " * (12 - len(body))
    return bytes([0, 0, 0, tag, 0]) + body


def edid_block(
    *,
    vendor: str = "VMW",
    product: int = 0x0001,
    serial: int = 0x01234567,
    week: int = 12,
    year: int = 2020,
    texts: dict[int, str] | None = None,
    extensions: int = 0,
) -> bytes:
    """Return one 128-byte EDID base block with a correct checksum."""
    block = bytearray(128)
    block[0:8] = _HEADER
    block[8:10] = _vendor(vendor)
    struct.pack_into("<HI", block, 10, product, serial)
    block[16] = week
    block[17] = year - 1990
    block[18:20] = bytes([1, 4])
    for offset, (tag, text) in zip(_DESCRIPTOR_OFFSETS, (texts or {}).items(), strict=False):
        block[offset : offset + 18] = _text_descriptor(tag, text)
    block[126] = extensions
    block[127] = (-sum(block[:127])) & 0xFF
    return bytes(block)
