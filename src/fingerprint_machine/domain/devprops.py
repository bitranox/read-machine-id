"""The Windows device properties a reading asks the configuration manager for.

Some of what Windows knows about a device is in no WMI class and in no registry key an
administrator may read (the device's ``Properties`` key belongs to SYSTEM): its parent in the
device tree, its location paths (``PCIROOT(0)#PCI(1C00)#PCI(0000)``, the topology), its bus
number and address, and the PCI driver's view of the function (link speed and width, interrupt
support). The configuration manager answers each by its property key, a format GUID and a
property id (``devpkey.h`` and ``pciprop.h`` in the Windows SDK).

Contents:
    * :class:`PropertyKey` - a format GUID and a property id.
    * :class:`DeviceProperty` - the properties read, each with its key.
    * :class:`PropertyType`, :func:`decode_property` - a property's value as JSON.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from .json_types import JsonValue

_DEVICE = "a45c254e-df1c-4efd-8020-67d146a850e0"
_RELATIONS = "4340a6c5-93fa-4706-972c-7b648008a5a7"
_PCI = "3ab22e31-8264-4b4e-9af5-a8d2d8e33e62"
_GUID_BYTES = 16


@dataclass(frozen=True, slots=True)
class PropertyKey:
    """A device property key: the property set's format GUID and the id within it."""

    fmtid: str
    pid: int


class DeviceProperty(StrEnum):
    """The device properties a reading asks for, named as the reading records them."""

    PARENT = "parent"
    LOCATION_PATHS = "location_paths"
    LOCATION_INFO = "location_info"
    BUS_NUMBER = "bus_number"
    ADDRESS = "address"
    PCI_DEVICE_TYPE = "device_type"
    PCI_CURRENT_SPEED_AND_MODE = "current_speed_and_mode"
    PCI_BASE_CLASS = "base_class"
    PCI_SUB_CLASS = "sub_class"
    PCI_PROG_IF = "prog_if"
    PCI_CURRENT_PAYLOAD_SIZE = "current_payload_size"
    PCI_MAX_PAYLOAD_SIZE = "max_payload_size"
    PCI_MAX_READ_REQUEST_SIZE = "max_read_request_size"
    PCI_CURRENT_LINK_SPEED = "current_link_speed"
    PCI_CURRENT_LINK_WIDTH = "current_link_width"
    PCI_MAX_LINK_SPEED = "max_link_speed"
    PCI_MAX_LINK_WIDTH = "max_link_width"
    PCI_EXPRESS_SPEC_VERSION = "express_spec_version"
    PCI_INTERRUPT_SUPPORT = "interrupt_support"
    PCI_INTERRUPT_MESSAGE_MAXIMUM = "interrupt_message_maximum"
    PCI_BAR_TYPES = "bar_types"

    @property
    def key(self) -> PropertyKey:
        """The property key the configuration manager answers this property by."""
        return _KEYS[self]


_KEYS: dict[DeviceProperty, PropertyKey] = {
    DeviceProperty.PARENT: PropertyKey(_RELATIONS, 8),
    DeviceProperty.LOCATION_PATHS: PropertyKey(_DEVICE, 37),
    DeviceProperty.LOCATION_INFO: PropertyKey(_DEVICE, 15),
    DeviceProperty.BUS_NUMBER: PropertyKey(_DEVICE, 23),
    DeviceProperty.ADDRESS: PropertyKey(_DEVICE, 30),
    DeviceProperty.PCI_DEVICE_TYPE: PropertyKey(_PCI, 1),
    DeviceProperty.PCI_CURRENT_SPEED_AND_MODE: PropertyKey(_PCI, 2),
    DeviceProperty.PCI_BASE_CLASS: PropertyKey(_PCI, 3),
    DeviceProperty.PCI_SUB_CLASS: PropertyKey(_PCI, 4),
    DeviceProperty.PCI_PROG_IF: PropertyKey(_PCI, 5),
    DeviceProperty.PCI_CURRENT_PAYLOAD_SIZE: PropertyKey(_PCI, 6),
    DeviceProperty.PCI_MAX_PAYLOAD_SIZE: PropertyKey(_PCI, 7),
    DeviceProperty.PCI_MAX_READ_REQUEST_SIZE: PropertyKey(_PCI, 8),
    DeviceProperty.PCI_CURRENT_LINK_SPEED: PropertyKey(_PCI, 9),
    DeviceProperty.PCI_CURRENT_LINK_WIDTH: PropertyKey(_PCI, 10),
    DeviceProperty.PCI_MAX_LINK_SPEED: PropertyKey(_PCI, 11),
    DeviceProperty.PCI_MAX_LINK_WIDTH: PropertyKey(_PCI, 12),
    DeviceProperty.PCI_EXPRESS_SPEC_VERSION: PropertyKey(_PCI, 13),
    DeviceProperty.PCI_INTERRUPT_SUPPORT: PropertyKey(_PCI, 14),
    DeviceProperty.PCI_INTERRUPT_MESSAGE_MAXIMUM: PropertyKey(_PCI, 15),
    DeviceProperty.PCI_BAR_TYPES: PropertyKey(_PCI, 16),
}

#: The PCI driver's own properties of a function, in the order a reading lists them.
PCI_PROPERTIES = tuple(p for p in DeviceProperty if p.key.fmtid == _PCI)


class PropertyType(IntEnum):
    """The ``DEVPROP_TYPE_*`` codes of the values a reading decodes (``devpropdef.h``)."""

    BYTE = 0x03
    INT16 = 0x04
    UINT16 = 0x05
    INT32 = 0x06
    UINT32 = 0x07
    INT64 = 0x08
    UINT64 = 0x09
    GUID = 0x0D
    FILETIME = 0x10
    BOOLEAN = 0x11
    STRING = 0x12
    BINARY = 0x1003
    STRING_LIST = 0x2012


_INTEGERS = {
    PropertyType.BYTE: (1, False),
    PropertyType.INT16: (2, True),
    PropertyType.UINT16: (2, False),
    PropertyType.INT32: (4, True),
    PropertyType.UINT32: (4, False),
    PropertyType.INT64: (8, True),
    PropertyType.UINT64: (8, False),
    PropertyType.FILETIME: (8, False),
}


def _strings(raw: bytes) -> list[str]:
    text = raw.decode("utf-16-le", errors="replace")
    return [s for s in text.split("\0") if s]


def _string(raw: bytes) -> JsonValue:
    found = _strings(raw)
    return found[0] if found else ""


def _string_list(raw: bytes) -> JsonValue:
    items: list[JsonValue] = list(_strings(raw))
    return items


def _boolean(raw: bytes) -> JsonValue:
    # DEVPROP_BOOLEAN is one byte: 0 is false, 0xFF (DEVPROP_TRUE) true.
    return bool(raw[:1]) and raw[:1] != b"\0"


def _guid(raw: bytes) -> JsonValue:
    if len(raw) < _GUID_BYTES:
        raise ValueError(f"a GUID property is {_GUID_BYTES} bytes, got {len(raw)}")
    return str(uuid.UUID(bytes_le=raw[:_GUID_BYTES]))


def _hex(raw: bytes) -> JsonValue:
    return raw.hex()


_DECODERS: dict[PropertyType, Callable[[bytes], JsonValue]] = {
    PropertyType.STRING: _string,
    PropertyType.STRING_LIST: _string_list,
    PropertyType.BOOLEAN: _boolean,
    PropertyType.GUID: _guid,
}


def _integer(kind: PropertyType, raw: bytes) -> int:
    size, signed = _INTEGERS[kind]
    if len(raw) < size:
        raise ValueError(f"a {kind.name} property is {size} bytes, got {len(raw)}")
    return int.from_bytes(raw[:size], "little", signed=signed)


def decode_property(type_code: int, raw: bytes) -> JsonValue:
    """Return a device property's value as JSON, by its ``DEVPROP_TYPE_*`` code.

    A string list becomes a list, a GUID its text form, a boolean True or False; an integer its
    value. A type this does not decode is kept as hex with its code, so nothing is dropped.

    Raises:
        ValueError: ``raw`` is shorter than its type.

    Examples:
        >>> decode_property(0x12, "PCI\\\\X\\0".encode("utf-16-le"))
        'PCI\\\\X'
        >>> decode_property(0x2012, "A\\0B\\0\\0".encode("utf-16-le"))
        ['A', 'B']
        >>> decode_property(0x07, bytes([5, 0, 0, 0])), decode_property(0x11, b"\\xff")
        (5, True)
        >>> decode_property(0x99, b"\\x01")
        {'type': '0x0099', 'hex': '01'}
    """
    if type_code not in PropertyType:
        return {"type": f"0x{type_code:04x}", "hex": raw.hex()}
    kind = PropertyType(type_code)
    if kind in _INTEGERS:
        return _integer(kind, raw)
    return _DECODERS.get(kind, _hex)(raw)


__all__ = ["PCI_PROPERTIES", "DeviceProperty", "PropertyKey", "PropertyType", "decode_property"]
