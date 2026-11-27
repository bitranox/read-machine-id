r"""How Windows names a PCI device: its ids, its place on the bus, its serial number, its resources.

Windows keeps no configuration space a program may read; what it tells about a PCI function is
spread over the Plug and Play data:

* the hardware and compatible ids (``PCI\VEN_15AD&DEV_07C0&SUBSYS_07C015AD&REV_02``,
  ``PCI\VEN_15AD&CC_010700``) carry the ids of the configuration header;
* the location (``PCI bus 3, device 0, function 0``, stored in the registry as an indirect
  string ending in ``(3,0,0)``) is the device's address on its bus;
* the instance id is the Device Serial Number (16 hex digits) followed by the function number
  when the device has one and says its id is unique (``CM_DEVCAP_UNIQUEID`` in the device's
  ``Capabilities``); otherwise it is a bus-relative name that no other machine shares either;
* the allocated resources are associations (``Win32_PnPAllocatedResource``) between WMI object
  paths, e.g. ``\\HOST\root\cimv2:Win32_IRQResource.IRQNumber=17``.

The functions here turn each into the values a Linux reading records under the same names
(``vendor_id`` ``0x15ad``, ``class_code`` ``0x010700``, the address ``0000:03:00.0``), so the
``pci`` sections of a Windows and a Linux reading of one machine line up.

Windows does not name the PCI segment (domain) of a device in any of these, so the address
always says domain ``0000``; a machine with a second PCI segment is rare outside large servers.

Contents:
    * :class:`PciIds`, :func:`pci_ids` - the ids from a device's hardware and compatible ids.
    * :class:`PciLocation`, :func:`pci_location` - bus, device and function.
    * :func:`unique_id_serial` - the Device Serial Number an instance id carries.
    * :func:`irq_number` - an IRQ number the same way however WMI wrote it.
    * :class:`InterruptSupport` - the interrupt kinds a device supports.
    * :class:`WmiReference`, :func:`parse_wmi_reference` - one end of a WMI association.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntFlag
from typing import TYPE_CHECKING

from .pci_config import serial_number_text

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .json_types import JsonObject, JsonValue

_VENDOR = re.compile(r"VEN_([0-9A-F]{4})", re.IGNORECASE)
_DEVICE = re.compile(r"DEV_([0-9A-F]{4})", re.IGNORECASE)
_SUBSYS = re.compile(r"SUBSYS_([0-9A-F]{4})([0-9A-F]{4})", re.IGNORECASE)
_REVISION = re.compile(r"REV_([0-9A-F]{2})", re.IGNORECASE)
_CLASS = re.compile(r"CC_([0-9A-F]{6})", re.IGNORECASE)
#: The arguments of the registry's indirect location string: ``...;(6,18,0)``.
_LOCATION_ARGS = re.compile(r"\((\d+),(\d+),(\d+)\)\s*$")
#: The resolved location text, in any language: the first three numbers are bus, device, function.
_LOCATION_TEXT = re.compile(r"(\d+)\D+(\d+)\D+(\d+)")
_SERIAL_INSTANCE = re.compile(r"^([0-9A-F]{16})[0-9A-F]{2}$", re.IGNORECASE)
_REFERENCE = re.compile(r"^(?:\\\\[^\\]*\\[^:]*:)?(?P<cls>\w+)\.(?P<keys>.*)$", re.DOTALL)
_KEY = re.compile(r'(?P<name>\w+)=(?:"(?P<quoted>(?:[^"\\]|\\.)*)"|(?P<bare>[^,]*))', re.DOTALL)
_ESCAPE = re.compile(r"\\(.)", re.DOTALL)

#: ``CM_DEVCAP_UNIQUEID``: the device's instance id is unique across machines (its serial number).
CM_DEVCAP_UNIQUEID = 0x10
_FUNCTION_BITS = 0xFFFF


def _hex(pattern: re.Pattern[str], ids: list[str], group: int = 1) -> str | None:
    for text in ids:
        if (match := pattern.search(text)) is not None:
            return f"0x{match.group(group).lower()}"
    return None


@dataclass(frozen=True, slots=True)
class PciIds:
    """The configuration header ids Windows publishes in a device's hardware and compatible ids."""

    vendor_id: str | None
    device_id: str | None
    subsystem_vendor_id: str | None
    subsystem_id: str | None
    revision: str | None
    class_code: str | None

    def as_json(self) -> JsonObject:
        """Return the ids under the names a Linux reading uses."""
        return {
            "vendor_id": self.vendor_id,
            "device_id": self.device_id,
            "subsystem_vendor_id": self.subsystem_vendor_id,
            "subsystem_id": self.subsystem_id,
            "revision": self.revision,
            "class_code": self.class_code,
        }


def pci_ids(ids: Iterable[object]) -> PciIds:
    r"""Return the ids a device's hardware and compatible ids carry; an id it lacks is None.

    ``SUBSYS_ssssvvvv`` is the subsystem id, then the subsystem vendor id.

    Example:
        >>> ids = pci_ids([r"PCI\VEN_15AD&DEV_07C0&SUBSYS_07C115AD&REV_02", r"PCI\VEN_15AD&CC_010700"])
        >>> ids.vendor_id, ids.device_id, ids.subsystem_vendor_id, ids.subsystem_id
        ('0x15ad', '0x07c0', '0x15ad', '0x07c1')
        >>> ids.revision, ids.class_code
        ('0x02', '0x010700')
    """
    texts = [i for i in ids if isinstance(i, str)]
    return PciIds(
        vendor_id=_hex(_VENDOR, texts),
        device_id=_hex(_DEVICE, texts),
        subsystem_vendor_id=_hex(_SUBSYS, texts, 2),
        subsystem_id=_hex(_SUBSYS, texts, 1),
        revision=_hex(_REVISION, texts),
        class_code=_hex(_CLASS, texts),
    )


@dataclass(frozen=True, slots=True)
class PciLocation:
    """Where a PCI function sits: its bus, device and function number."""

    bus: int
    device: int
    function: int

    @property
    def address(self) -> str:
        """The address as Linux writes it, domain ``0000`` (Windows does not name the segment)."""
        return f"0000:{self.bus:02x}:{self.device:02x}.{self.function:x}"

    def as_json(self) -> JsonObject:
        """Return the location as a reading records it."""
        return {"bus": self.bus, "device": self.device, "function": self.function}


def pci_location(text: object) -> PciLocation | None:
    """Return the bus, device and function a location string names; None when it names none.

    Takes the registry's indirect form (``@...pci.sys,#65536;PCI bus %1, ...;(6,18,0)``) and the
    resolved text in any language (``PCI bus 6, device 18, function 0``).

    Examples:
        >>> pci_location("@System32\\\\drivers\\\\pci.sys,#65536;PCI bus %1, device %2, function %3;(6,18,0)").address
        '0000:06:12.0'
        >>> pci_location("PCI-Bus 11, Geraet 0, Funktion 1").address
        '0000:0b:00.1'
        >>> pci_location("PCI Slot 1") is None
        True
    """
    if not isinstance(text, str):
        return None
    match = _LOCATION_ARGS.search(text) or _LOCATION_TEXT.search(text)
    if match is None:
        return None
    bus, device, function = (int(g) for g in match.groups())
    return PciLocation(bus=bus, device=device, function=function)


def pci_location_from_address(*, bus: int, address: int) -> PciLocation:
    """Return the location Windows' bus number and device address (``device << 16 | function``) name.

    Example:
        >>> pci_location_from_address(bus=6, address=0x120000).address
        '0000:06:12.0'
    """
    return PciLocation(bus=bus, device=address >> 16, function=address & _FUNCTION_BITS)


def unique_id_serial(instance_id: object, capabilities: object) -> str | None:
    r"""Return the Device Serial Number an instance id carries, written as a Linux reading writes it.

    Windows builds the instance id from the serial only for a device whose capabilities include
    ``CM_DEVCAP_UNIQUEID``; any other instance id is a bus-relative name, so None.

    Examples:
        >>> unique_id_serial(r"PCI\VEN_15AD&DEV_07C0\0123ABCD5005056000", 0x10 | 0x4)
        '01-23-ab-cd-50-05-05-60'
        >>> unique_id_serial(r"PCI\VEN_1AF4&DEV_1000\5&2490727A&0&9008F0", 6) is None
        True
    """
    if not isinstance(instance_id, str) or not isinstance(capabilities, int):
        return None
    if not capabilities & CM_DEVCAP_UNIQUEID:
        return None
    match = _SERIAL_INSTANCE.match(instance_id.rsplit("\\", 1)[-1])
    return None if match is None else serial_number_text(int(match.group(1), 16))


_UINT32 = 1 << 32
_INT32_MAX = (1 << 31) - 1


def irq_number(value: object) -> int | None:
    """Return an IRQ number as ``Win32_IRQResource`` writes it: a message-signaled one negative.

    WMI writes the same IRQ two ways: signed in the ``IRQNumber`` property (``-3``) and unsigned
    in the object paths of ``Win32_PnPAllocatedResource`` (``4294967293``). Both read as ``-3``.

    Examples:
        >>> irq_number("4294967293"), irq_number(-3), irq_number("17"), irq_number(17)
        (-3, -3, 17, 17)
        >>> irq_number("IRQ17") is None, irq_number(True) is None, irq_number(2**32) is None
        (True, True, True)
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text.lstrip("-").isdigit():
            return None
        value = int(text)
    if not isinstance(value, int) or not -_UINT32 // 2 <= value < _UINT32:
        return None
    return value - _UINT32 if value > _INT32_MAX else value


class InterruptSupport(IntFlag):
    """The interrupt kinds a PCI device supports (``DEVPKEY_PciDevice_InterruptSupport``)."""

    LINE_BASED = 0x1
    MSI = 0x2
    MSI_X = 0x4

    @classmethod
    def names(cls, value: object) -> JsonValue:
        """Return the kinds set in ``value`` by name; None when ``value`` is not a number.

        Example:
            >>> InterruptSupport.names(5)
            ['line_based', 'msi_x']
        """
        if not isinstance(value, int) or isinstance(value, bool):
            return None
        return [str(f.name).lower() for f in cls if value & f]


@dataclass(frozen=True, slots=True)
class WmiReference:
    """One end of a WMI association: the class it names and the key values that pick the instance."""

    class_name: str
    keys: tuple[tuple[str, str], ...]

    def key(self, name: str) -> str | None:
        """Return the value of one key, compared without regard to case; None when absent."""
        for key, found in self.keys:
            if key.casefold() == name.casefold():
                return found
        return None


def parse_wmi_reference(text: str) -> WmiReference:
    r"""Return the class and key values of a WMI object path.

    Quoted key values are unescaped (``\\`` is one backslash); the leading ``\\HOST\namespace:``
    is optional.

    Raises:
        ValueError: ``text`` is not an object path.

    Examples:
        >>> parse_wmi_reference(r'\\H\root\cimv2:Win32_PnPEntity.DeviceID="PCI\\VEN_1\\3&1"').key("DeviceID")
        'PCI\\VEN_1\\3&1'
        >>> parse_wmi_reference(r"\\H\root\cimv2:Win32_IRQResource.IRQNumber=-3").keys
        (('IRQNumber', '-3'),)
    """
    match = _REFERENCE.match(text)
    if match is None:
        raise ValueError(f"not a WMI object path: {text!r}")
    keys = tuple(
        (m.group("name"), _ESCAPE.sub(r"\1", m.group("quoted")) if m.group("quoted") is not None else m.group("bare"))
        for m in _KEY.finditer(match.group("keys"))
    )
    if not keys:
        raise ValueError(f"a WMI object path without keys: {text!r}")
    return WmiReference(class_name=match.group("cls"), keys=keys)


__all__ = [
    "CM_DEVCAP_UNIQUEID",
    "InterruptSupport",
    "PciIds",
    "PciLocation",
    "WmiReference",
    "irq_number",
    "parse_wmi_reference",
    "pci_ids",
    "pci_location",
    "pci_location_from_address",
    "unique_id_serial",
]
