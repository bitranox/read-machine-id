"""EDID: what a display says about itself - maker, model, serial number, name, date of manufacture.

The base block is the first 128 bytes of a display's EDID (VESA E-EDID standard, release A
revision 2, "EDID 1.4"): the fixed header, the manufacturer as three letters packed into five
bits each, a product code and a 32-bit serial number, the week and year of manufacture, and four
18-byte descriptors, three of which can carry text (``0xFF`` serial, ``0xFE`` unspecified text,
``0xFC`` display name). Extension blocks after it are not decoded.

The decoder is OS-neutral: Linux reads the bytes from ``/sys/class/drm/*/edid``, Windows from a
monitor's ``Device Parameters\\EDID`` registry value. A virtual display's EDID (or its absence)
differs between hypervisors, so it is a fingerprint.

Contents:
    * :func:`decode_edid` - decode a base block.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .json_types import JsonObject

#: The length of the base block.
BLOCK_BYTES = 128

_HEADER = bytes([0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00])
_DESCRIPTORS = (54, 72, 90, 108)
_DESCRIPTOR_TEXT = 13
_TAG_SERIAL = 0xFF
_TAG_TEXT = 0xFE
_TAG_NAME = 0xFC
_MODEL_YEAR_WEEK = 0xFF
_YEAR_BASE = 1990
_LETTER_BITS = 0x1F
_LETTERS = 26


def _letter(code: int) -> str:
    return chr(ord("A") + code - 1) if 1 <= code <= _LETTERS else "?"


def _manufacturer(block: bytes) -> str:
    packed = int.from_bytes(block[8:10], "big")
    return "".join(_letter((packed >> shift) & _LETTER_BITS) for shift in (10, 5, 0))


def _texts(block: bytes) -> dict[int, str]:
    """The text descriptors by tag; a display descriptor starts with two zero bytes."""
    found: dict[int, str] = {}
    for offset in _DESCRIPTORS:
        descriptor = block[offset : offset + 18]
        if descriptor[0:2] == b"\0\0" and descriptor[3] not in found:
            raw = descriptor[5 : 5 + _DESCRIPTOR_TEXT].split(b"\n", 1)[0]
            found[descriptor[3]] = raw.decode("ascii", errors="replace").rstrip()
    return found


def decode_edid(data: bytes) -> JsonObject:
    """Return the identifying fields of an EDID's base block.

    A wrong checksum is reported (``checksum_ok``), not refused: a display that sends one still
    says who it is.

    Raises:
        ValueError: ``data`` is shorter than a base block or does not start with the EDID header.

    Example:
        >>> decode_edid(b"")
        Traceback (most recent call last):
        ...
        ValueError: not an EDID base block (0 bytes)
    """
    if len(data) < BLOCK_BYTES or data[:8] != _HEADER:
        raise ValueError(f"not an EDID base block ({len(data)} bytes)")
    block = data[:BLOCK_BYTES]
    texts = _texts(block)
    week = block[16]
    model_year = week == _MODEL_YEAR_WEEK
    return {
        "manufacturer": _manufacturer(block),
        "product_code": f"0x{int.from_bytes(block[10:12], 'little'):04x}",
        "serial_number": int.from_bytes(block[12:16], "little"),
        "serial": texts.get(_TAG_SERIAL),
        "name": texts.get(_TAG_NAME),
        "text": texts.get(_TAG_TEXT),
        "week": None if model_year or week == 0 else week,
        "year": block[17] + _YEAR_BASE,
        "model_year": model_year,
        "version": f"{block[18]}.{block[19]}",
        "extensions": block[126],
        "checksum_ok": sum(block) % 256 == 0,
    }


__all__ = ["BLOCK_BYTES", "decode_edid"]
