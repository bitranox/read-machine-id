"""SCSI Vital Product Data: the unit serial (page 0x80) and the device identifiers (page 0x83).

Linux keeps both pages as the disk returned them (``/sys/block/<disk>/device/vpd_pg80`` and
``vpd_pg83``). Page 0x83 is where a disk's world wide names live: the NAA id a hypervisor assigns
to a virtual disk, the T10 vendor id, the SAS address of the port it hangs on. Layouts follow
SPC-5 (section 7.7.3 "Device Identification VPD page" and 7.7.18 "Unit Serial Number VPD page").

Contents:
    * :class:`DesignatorType`, :class:`Association`, :class:`CodeSet` - the categorical fields.
    * :class:`Designator` - one identifier of page 0x83.
    * :func:`decode_vpd_page80` - the unit serial number.
    * :func:`decode_vpd_page83` - every designator.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .json_types import JsonObject

_HEADER = 4
_DESIGNATOR_HEADER = 4


class DesignatorType(StrEnum):
    """SPC-5 table 588: what a designator identifies by."""

    VENDOR_SPECIFIC = "vendor_specific"
    T10_VENDOR_ID = "t10_vendor_id"
    EUI64 = "eui64"
    NAA = "naa"
    RELATIVE_TARGET_PORT = "relative_target_port"
    TARGET_PORT_GROUP = "target_port_group"
    LOGICAL_UNIT_GROUP = "logical_unit_group"
    MD5_LOGICAL_UNIT = "md5_logical_unit"
    SCSI_NAME = "scsi_name"
    PROTOCOL_PORT = "protocol_port"
    UUID = "uuid"


class Association(StrEnum):
    """SPC-5 table 587: what the designator belongs to."""

    LOGICAL_UNIT = "logical_unit"
    TARGET_PORT = "target_port"
    TARGET_DEVICE = "target_device"
    RESERVED = "reserved"


class CodeSet(StrEnum):
    """SPC-5 table 586: how the designator's bytes are written."""

    BINARY = "binary"
    ASCII = "ascii"
    UTF8 = "utf8"


_TYPES = tuple(DesignatorType)
_ASSOCIATIONS = tuple(Association)
_CODE_SETS = MappingProxyType({1: CodeSet.BINARY, 2: CodeSet.ASCII, 3: CodeSet.UTF8})
# SPC-5 table 589: the protocol identifier, meaningful only when PIV is set.
_PROTOCOLS = (
    "fibre_channel", "parallel_scsi", "ssa", "ieee1394", "srp", "iscsi",
    "sas", "adt", "ata", "uas", "sop", "pcie",
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class Designator:
    """One identifier of the Device Identification page."""

    #: The kind of identifier, or ``type<N>`` for a type SPC-5 reserves.
    kind: DesignatorType | str
    association: Association
    #: How the value was written; text values are decoded, binary ones kept as hex.
    code_set: CodeSet | str
    #: The transport the identifier belongs to (``sas``, ``iscsi``, ...), when the disk says so.
    protocol: str | None
    value: str

    def as_json(self) -> JsonObject:
        """Return the designator as a reading records it."""
        return {
            "type": str(self.kind),
            "association": self.association.value,
            "code_set": str(self.code_set),
            "protocol": self.protocol,
            "value": self.value,
        }


def _body(page: bytes, code: int) -> bytes:
    if len(page) < _HEADER:
        raise ValueError(f"VPD page shorter than its {_HEADER}-byte header")
    if page[1] != code:
        raise ValueError(f"VPD page 0x{page[1]:02x}, expected 0x{code:02x}")
    length = int.from_bytes(page[2:4], "big")
    if _HEADER + length > len(page):
        raise ValueError(f"VPD page 0x{code:02x} claims {length} bytes, holds {len(page) - _HEADER}")
    return page[_HEADER : _HEADER + length]


def decode_vpd_page80(page: bytes) -> str:
    """Return the unit serial number page 0x80 carries, without its space padding.

    Raises:
        ValueError: the bytes are not a complete page 0x80.

    Example:
        >>> decode_vpd_page80(bytes([0, 0x80, 0, 6]) + b"ABC   ")
        'ABC'
    """
    return _body(page, 0x80).decode("ascii", errors="replace").strip(" \x00")


def _value(code_set: CodeSet | str, raw: bytes) -> str:
    if code_set in {CodeSet.ASCII, CodeSet.UTF8}:
        return raw.decode("utf-8", errors="replace").rstrip(" \x00")
    return raw.hex()


def _designator(head: bytes, raw: bytes) -> Designator:
    code_set: CodeSet | str = _CODE_SETS.get(head[0] & 0x0F, f"code_set{head[0] & 0x0F}")
    kind_number = head[1] & 0x0F
    kind: DesignatorType | str = _TYPES[kind_number] if kind_number < len(_TYPES) else f"type{kind_number}"
    piv = bool(head[1] & 0x80)
    protocol_number = head[0] >> 4
    known_protocol = protocol_number < len(_PROTOCOLS)
    protocol = (_PROTOCOLS[protocol_number] if known_protocol else f"protocol{protocol_number}") if piv else None
    return Designator(
        kind=kind,
        association=_ASSOCIATIONS[(head[1] >> 4) & 0x03],
        code_set=code_set,
        protocol=protocol,
        value=_value(code_set, raw),
    )


def decode_vpd_page83(page: bytes) -> list[Designator]:
    """Return every designator page 0x83 carries, in page order.

    Raises:
        ValueError: the bytes are not a complete page 0x83, or a designator runs past it.

    Example:
        >>> naa = bytes([1, 3, 0, 2, 0x60, 0x01])
        >>> decode_vpd_page83(bytes([0, 0x83, 0, len(naa)]) + naa)[0].as_json()["value"]
        '6001'
    """
    body = _body(page, 0x83)
    out: list[Designator] = []
    offset = 0
    while offset + _DESIGNATOR_HEADER <= len(body):
        head = body[offset : offset + _DESIGNATOR_HEADER]
        end = offset + _DESIGNATOR_HEADER + head[3]
        if end > len(body):
            raise ValueError(f"designator at offset {offset} runs past the page")
        out.append(_designator(head, body[offset + _DESIGNATOR_HEADER : end]))
        offset = end
    return out


__all__ = [
    "Association",
    "CodeSet",
    "Designator",
    "DesignatorType",
    "decode_vpd_page80",
    "decode_vpd_page83",
]
