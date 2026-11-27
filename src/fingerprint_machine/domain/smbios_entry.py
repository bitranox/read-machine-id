"""Decode the SMBIOS entry point structure (DMTF DSP0134 section 5.2).

Linux hands out the firmware's SMBIOS table in two files: the structure table itself
(``/sys/firmware/dmi/tables/DMI``) and the entry point that announced it
(``/sys/firmware/dmi/tables/smbios_entry_point``). The entry point carries the SMBIOS version the
table follows, which :func:`~fingerprint_machine.domain.smbios.decode_smbios` records; Windows
reports the same version in the header of its RSMB block.

Two layouts exist: the 32-bit ``_SM_`` entry point (SMBIOS 2.1 to 2.8, with an inner ``_DMI_``
part that holds the table length, address and structure count) and the 64-bit ``_SM3_`` entry
point (SMBIOS 3.0 and later, which states a maximum table size and no structure count).

Contents:
    * :class:`SmbiosEntryPoint` - the decoded entry point.
    * :func:`decode_smbios_entry_point` - decode one.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .json_types import JsonObject

_SM3 = struct.Struct(
    "<5sBBBBBBBIQ"
)  # anchor, checksum, length, major, minor, docrev, revision, reserved, size, address
_SM2 = struct.Struct("<4sBBBBHB5s5sBHIHB")  # anchor .. structure count, BCD revision
_SM3_ANCHOR = b"_SM3_"
_SM2_ANCHOR = b"_SM_"


@dataclass(frozen=True)
class SmbiosEntryPoint:
    """What an SMBIOS entry point states about the table that follows it.

    Attributes:
        anchor: ``"_SM3_"`` or ``"_SM_"``.
        major: the SMBIOS major version.
        minor: the SMBIOS minor version.
        docrev: the specification's document revision (``_SM3_`` only; 0 for ``_SM_``).
        table_length: the table length (``_SM_``) or its maximum size (``_SM3_``), in bytes.
        table_address: the physical address the table sits at.
        structure_count: the number of structures (``_SM_`` only).
    """

    anchor: str
    major: int
    minor: int
    docrev: int
    table_length: int
    table_address: int
    structure_count: int | None

    @property
    def version(self) -> str:
        """The SMBIOS version as ``"<major>.<minor>"``, the form Windows reports it in."""
        return f"{self.major}.{self.minor}"

    def as_json(self) -> JsonObject:
        """Return the entry point as JSON, the address in hex."""
        return {
            "anchor": self.anchor,
            "version": self.version,
            "docrev": self.docrev,
            "table_length": self.table_length,
            "table_address": f"0x{self.table_address:08x}",
            "structure_count": self.structure_count,
        }


def decode_smbios_entry_point(raw: bytes) -> SmbiosEntryPoint:
    """Decode an ``_SM3_`` or ``_SM_`` entry point.

    Raises:
        ValueError: the bytes are shorter than the entry point their anchor names, or carry no
            known anchor.

    Examples:
        >>> sm3 = b"_SM3_" + bytes([0, 24, 3, 6, 0, 1, 0]) + struct.pack("<IQ", 100, 0x1000)
        >>> decode_smbios_entry_point(sm3).version
        '3.6'
        >>> decode_smbios_entry_point(b"nope")
        Traceback (most recent call last):
        ...
        ValueError: not an SMBIOS entry point: no _SM3_ or _SM_ anchor in 4 bytes
    """
    if raw.startswith(_SM3_ANCHOR):
        return _sm3(raw)
    if raw.startswith(_SM2_ANCHOR):
        return _sm2(raw)
    msg = f"not an SMBIOS entry point: no _SM3_ or _SM_ anchor in {len(raw)} bytes"
    raise ValueError(msg)


def _need(raw: bytes, layout: struct.Struct, anchor: str) -> None:
    if len(raw) < layout.size:
        msg = f"{anchor} entry point is {len(raw)} bytes, shorter than its {layout.size}"
        raise ValueError(msg)


def _sm3(raw: bytes) -> SmbiosEntryPoint:
    _need(raw, _SM3, "_SM3_")
    _anchor, _sum, _len, major, minor, docrev, _rev, _res, size, address = _SM3.unpack_from(raw)
    return SmbiosEntryPoint("_SM3_", major, minor, docrev, size, address, None)


def _sm2(raw: bytes) -> SmbiosEntryPoint:
    _need(raw, _SM2, "_SM_")
    fields = _SM2.unpack_from(raw)
    major, minor, length, address, count = fields[3], fields[4], fields[10], fields[11], fields[12]
    return SmbiosEntryPoint("_SM_", major, minor, 0, length, address, count)


__all__ = ["SmbiosEntryPoint", "decode_smbios_entry_point"]
