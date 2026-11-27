"""Decode a raw SMBIOS structure table (DMTF DSP0134) into JSON.

Windows hands out the firmware's SMBIOS table as one block of bytes (WMI class
``MSSmBios_RawSMBiosTables``). WMI's own classes expose only part of it: no OEM strings (type 11),
no slots (type 9), no onboard devices (type 41), and on older builds not even the system family
or SKU. This module reads the block itself, so every structure is kept, and the types that carry
identity or device numbers are decoded field by field.

Every decoder reads with bounds-checked helpers: a structure shorter than its type's current
length (an older SMBIOS version, or a firmware that leaves fields out) yields None for the missing
fields rather than raising.

Contents:
    * :class:`SmbiosType` - the structure types decoded here.
    * :class:`SmbiosStructure` - one structure with bounds-checked field readers.
    * :func:`parse_smbios_structures` - split a table into its structures.
    * :func:`decode_smbios` - the whole table as JSON.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from .json_types import JsonObject, JsonValue

# Every structure starts with a 4-byte header: type, length, handle.
_HEADER = 4
_UUID_BYTES = 16
# Type 4 offset 08h: the CPUID signature and feature flags, 8 bytes.
_CPUID_BYTES = 8
# Type 9/41 device/function byte: device in bits 7:3, function in bits 2:0.
_FUNCTION_BITS = 0x07
_DEVICE_SHIFT = 3
# Type 41 device type byte: bit 7 says enabled, bits 6:0 the type. Type 3's chassis type byte
# has the same layout, its bit 7 meaning "chassis lock present".
_ENABLED_BIT = 0x80
_TYPE_BITS = 0x7F
_CHASSIS_LOCK_BIT = 0x80


class SmbiosType(IntEnum):
    """The SMBIOS structure types decoded field by field (DSP0134 section 7)."""

    BIOS = 0
    SYSTEM = 1
    BOARD = 2
    CHASSIS = 3
    PROCESSOR = 4
    SYSTEM_SLOTS = 9
    OEM_STRINGS = 11
    PHYSICAL_MEMORY_ARRAY = 16
    MEMORY_DEVICE = 17
    MEMORY_ARRAY_MAPPED_ADDRESS = 19
    ONBOARD_DEVICES_EXTENDED = 41
    END_OF_TABLE = 127


@dataclass(frozen=True)
class SmbiosStructure:
    """One SMBIOS structure: its type, the formatted area and its string set (1-based)."""

    type: int
    handle: int
    formatted: bytes
    strings: tuple[str, ...]

    def string(self, offset: int) -> str | None:
        """Return the string the byte at ``offset`` points to, or None when absent or 0.

        Examples:
            >>> s = SmbiosStructure(1, 0, bytes([1, 4, 0, 0, 1, 2]), ("A",))
            >>> s.string(4), s.string(5), s.string(9)
            ('A', None, None)
        """
        index = self.byte(offset)
        if not index or index > len(self.strings):
            return None
        return self.strings[index - 1]

    def byte(self, offset: int) -> int | None:
        """Return the byte at ``offset`` of the formatted area, or None past its end."""
        return self.formatted[offset] if offset < len(self.formatted) else None

    def word(self, offset: int) -> int | None:
        """Return the little-endian u16 at ``offset``, or None past the formatted area's end."""
        return self._unpack("<H", offset)

    def dword(self, offset: int) -> int | None:
        """Return the little-endian u32 at ``offset``, or None past the formatted area's end."""
        return self._unpack("<I", offset)

    def qword(self, offset: int) -> int | None:
        """Return the little-endian u64 at ``offset``, or None past the formatted area's end."""
        return self._unpack("<Q", offset)

    def _unpack(self, fmt: str, offset: int) -> int | None:
        if offset + struct.calcsize(fmt) > len(self.formatted):
            return None
        return int(struct.unpack_from(fmt, self.formatted, offset)[0])


def parse_smbios_structures(table: bytes) -> list[SmbiosStructure]:
    """Split a raw SMBIOS structure table into its structures, stopping at type 127.

    A structure whose length runs past the table, or whose string set has no terminator, ends
    the walk: what came before it is kept.

    Examples:
        >>> t = bytes([1, 4, 0, 0]) + b"A\\0\\0" + bytes([127, 4, 1, 0]) + b"\\0\\0"
        >>> [s.type for s in parse_smbios_structures(t)], parse_smbios_structures(t)[0].strings
        ([1, 127], ('A',))
        >>> parse_smbios_structures(bytes([1, 40, 0, 0]))
        []
    """
    out: list[SmbiosStructure] = []
    pos = 0
    while pos + _HEADER <= len(table):
        parsed = _structure_at(table, pos)
        if parsed is None:
            break
        structure, pos = parsed
        out.append(structure)
        if structure.type == SmbiosType.END_OF_TABLE:
            break
    return out


def _structure_at(table: bytes, pos: int) -> tuple[SmbiosStructure, int] | None:
    stype, length = table[pos], table[pos + 1]
    if length < _HEADER or pos + length > len(table):
        return None
    end = table.find(b"\0\0", pos + length)
    if end < 0:
        return None
    raw = table[pos + length : end]
    strings = tuple(s.decode("latin-1") for s in raw.split(b"\0")) if raw else ()
    handle = int(struct.unpack_from("<H", table, pos + 2)[0])
    return SmbiosStructure(stype, handle, table[pos : pos + length], strings), end + 2


def _smbios_uuid(raw: bytes) -> str | None:
    # SMBIOS 2.6+: the first three fields are little-endian, the rest as stored. All-zero means
    # "not set", all-FF "not present" (DSP0134 7.2.1).
    if len(raw) != _UUID_BYTES or raw in (b"\0" * _UUID_BYTES, b"\xff" * _UUID_BYTES):
        return None
    return str(uuid.UUID(bytes_le=raw)).upper()


def _bus_location(s: SmbiosStructure, segment: int, bus: int, devfn: int) -> JsonObject:
    raw = s.byte(devfn)
    return {
        "segment": s.word(segment),
        "bus": s.byte(bus),
        "device": raw >> _DEVICE_SHIFT if raw is not None else None,
        "function": raw & _FUNCTION_BITS if raw is not None else None,
    }


def _type0(s: SmbiosStructure) -> JsonObject:
    major, minor = s.byte(0x14), s.byte(0x15)
    return {
        "vendor": s.string(0x04),
        "version": s.string(0x05),
        "starting_segment": s.word(0x06),
        "release_date": s.string(0x08),
        "rom_size_64k": s.byte(0x09),
        "characteristics": s.qword(0x0A),
        "bios_revision": f"{major}.{minor}" if major is not None and minor is not None else None,
    }


def _type1(s: SmbiosStructure) -> JsonObject:
    return {
        "manufacturer": s.string(0x04),
        "product": s.string(0x05),
        "version": s.string(0x06),
        "serial": s.string(0x07),
        "uuid": _smbios_uuid(s.formatted[0x08:0x18]),
        "wakeup_type": s.byte(0x18),
        "sku": s.string(0x19),
        "family": s.string(0x1A),
    }


def _type2(s: SmbiosStructure) -> JsonObject:
    return {
        "manufacturer": s.string(0x04),
        "product": s.string(0x05),
        "version": s.string(0x06),
        "serial": s.string(0x07),
        "asset_tag": s.string(0x08),
        "feature_flags": s.byte(0x09),
        "location_in_chassis": s.string(0x0A),
        "board_type": s.byte(0x0D),
    }


def _type3(s: SmbiosStructure) -> JsonObject:
    chassis = s.byte(0x05)
    return {
        "manufacturer": s.string(0x04),
        "type": chassis & _TYPE_BITS if chassis is not None else None,
        "lock_present": bool(chassis & _CHASSIS_LOCK_BIT) if chassis is not None else None,
        "version": s.string(0x06),
        "serial": s.string(0x07),
        "asset_tag": s.string(0x08),
        "bootup_state": s.byte(0x09),
        "oem_defined": s.dword(0x0D),
    }


def _type4(s: SmbiosStructure) -> JsonObject:
    cpuid = s.formatted[0x08:0x10]
    return {
        "socket": s.string(0x04),
        "processor_type": s.byte(0x05),
        "family": s.byte(0x06),
        "manufacturer": s.string(0x07),
        "processor_id": cpuid[::-1].hex().upper() if len(cpuid) == _CPUID_BYTES else None,
        "version": s.string(0x10),
        "max_speed_mhz": s.word(0x14),
        "current_speed_mhz": s.word(0x16),
        "status": s.byte(0x18),
        "serial": s.string(0x20),
        "asset_tag": s.string(0x21),
        "part_number": s.string(0x22),
        "core_count": s.byte(0x23),
        "core_enabled": s.byte(0x24),
        "thread_count": s.byte(0x25),
        "characteristics": s.word(0x26),
    }


def _type9(s: SmbiosStructure) -> JsonObject:
    return {
        "designation": s.string(0x04),
        "slot_type": s.byte(0x05),
        "data_bus_width": s.byte(0x06),
        "current_usage": s.byte(0x07),
        "slot_length": s.byte(0x08),
        "slot_id": s.word(0x09),
        "characteristics_1": s.byte(0x0B),
        "characteristics_2": s.byte(0x0C),
        **_bus_location(s, 0x0D, 0x0F, 0x10),
    }


def _type16(s: SmbiosStructure) -> JsonObject:
    return {
        "location": s.byte(0x04),
        "use": s.byte(0x05),
        "error_correction": s.byte(0x06),
        "maximum_capacity_kib": s.dword(0x07),
        "memory_devices": s.word(0x0D),
        "extended_maximum_capacity_bytes": s.qword(0x0F),
    }


def _type17(s: SmbiosStructure) -> JsonObject:
    return {
        "locator": s.string(0x10),
        "bank": s.string(0x11),
        "size_raw": s.word(0x0C),
        "form_factor": s.byte(0x0E),
        "memory_type": s.byte(0x12),
        "speed_mts": s.word(0x15),
        "manufacturer": s.string(0x17),
        "serial": s.string(0x18),
        "asset_tag": s.string(0x19),
        "part_number": s.string(0x1A),
        "extended_size_mib": s.dword(0x1C),
        "configured_speed_mts": s.word(0x20),
    }


def _type19(s: SmbiosStructure) -> JsonObject:
    return {
        "starting_address_kib": s.dword(0x04),
        "ending_address_kib": s.dword(0x08),
        "memory_array_handle": s.word(0x0C),
        "partition_width": s.byte(0x0E),
        "extended_starting_address": s.qword(0x0F),
        "extended_ending_address": s.qword(0x17),
    }


def _type41(s: SmbiosStructure) -> JsonObject:
    raw = s.byte(0x05)
    return {
        "reference_designation": s.string(0x04),
        "device_type": raw & _TYPE_BITS if raw is not None else None,
        "enabled": bool(raw & _ENABLED_BIT) if raw is not None else None,
        "device_type_instance": s.byte(0x06),
        **_bus_location(s, 0x07, 0x09, 0x0A),
    }


def _raw(s: SmbiosStructure) -> JsonObject:
    return {
        "type": s.type,
        "handle": s.handle,
        "length": len(s.formatted),
        "formatted_hex": s.formatted.hex(),
        "strings": list(s.strings),
    }


# One decoder per type that is returned as a list (a machine may carry several of each).
_LIST_DECODERS: dict[str, tuple[SmbiosType, Callable[[SmbiosStructure], JsonObject]]] = {
    "cpu": (SmbiosType.PROCESSOR, _type4),
    "slots": (SmbiosType.SYSTEM_SLOTS, _type9),
    "memory_arrays": (SmbiosType.PHYSICAL_MEMORY_ARRAY, _type16),
    "memory": (SmbiosType.MEMORY_DEVICE, _type17),
    "memory_mapped": (SmbiosType.MEMORY_ARRAY_MAPPED_ADDRESS, _type19),
    "onboard_devices": (SmbiosType.ONBOARD_DEVICES_EXTENDED, _type41),
}
# The types the specification allows once: the first structure is decoded.
_SINGLE_DECODERS: dict[str, tuple[SmbiosType, Callable[[SmbiosStructure], JsonObject]]] = {
    "bios": (SmbiosType.BIOS, _type0),
    "system": (SmbiosType.SYSTEM, _type1),
    "board": (SmbiosType.BOARD, _type2),
    "chassis": (SmbiosType.CHASSIS, _type3),
}


def decode_smbios(table: bytes, version: str) -> JsonObject:
    """Decode the whole table: every structure raw, the identity-bearing types field by field.

    Args:
        table: the raw structure table (``MSSmBios_RawSMBiosTables.SMBiosData``).
        version: the SMBIOS version Windows reports, e.g. ``"3.1"``.

    Returns:
        ``version``, ``type_counts``, one key per decoded type, ``oem_strings``, every structure
        under ``structures`` and the whole table as ``raw_hex``.

    Examples:
        >>> t = bytes([1, 0x1B, 0, 0]) + bytes(0x17) + b"\\0\\0" + bytes([127, 4, 1, 0]) + b"\\0\\0"
        >>> d = decode_smbios(t, "3.1")
        >>> d["type_counts"], d["system"]["uuid"], len(d["structures"])
        ({'1': 1, '127': 1}, None, 2)
    """
    structures = parse_smbios_structures(table)
    by_type: dict[int, list[SmbiosStructure]] = {}
    for st in structures:
        by_type.setdefault(st.type, []).append(st)
    decoded: JsonObject = {
        "version": version,
        "type_counts": {str(t): len(v) for t, v in sorted(by_type.items())},
    }
    for key, (stype, decode) in _SINGLE_DECODERS.items():
        found = by_type.get(stype)
        decoded[key] = decode(found[0]) if found else None
    for key, (stype, decode) in _LIST_DECODERS.items():
        items: list[JsonValue] = [decode(s) for s in by_type.get(stype, [])]
        decoded[key] = items
    oem: list[JsonValue] = [x for s in by_type.get(SmbiosType.OEM_STRINGS, []) for x in s.strings]
    decoded["oem_strings"] = oem
    raw: list[JsonValue] = [_raw(s) for s in structures]
    decoded["structures"] = raw
    decoded["raw_hex"] = table.hex()
    return decoded


__all__ = ["SmbiosStructure", "SmbiosType", "decode_smbios", "parse_smbios_structures"]
