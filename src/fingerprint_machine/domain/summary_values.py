"""Read values out of a reading for its summary, and write them in one form for both OSes.

The summary of a Windows and of a Linux reading of the same machine must compare equal where the
hardware is the same, but the two OSes report one value in different spellings: a MAC as
``005056000001`` or ``00:50:56:00:00:01``, a system UUID in upper or lower case, a PCI Device
Serial Number inside a PnP instance id or in the lspci form. The canonical forms below are the
one spelling the summary uses on both.

Contents:
    * :func:`node`, :func:`rows`, :func:`first`, :func:`obj` - walk a reading's JSON tree.
    * :func:`text`, :func:`integer` - a leaf as ``str`` / ``int``, or None for anything else.
    * :func:`canonical_mac` - a MAC address, lower case, colon-separated.
    * :func:`canonical_uuid` - a UUID or GUID, upper case, without braces.
    * :func:`canonical_disk_id` - a disk's VPD 0x83 identifier as Linux writes it (``naa.``/``eui.``).
    * :func:`canonical_dsn` - a Device Serial Number in the lspci form; an all-zero one is none.
    * :func:`dsn_from_instance` - the Device Serial Number in a Windows PnP instance id, lspci form.
    * :func:`pci_address` - a PCI address from segment, bus, device and function numbers.
    * :func:`split_pci_address` - bus, device and function of a ``dddd:bb:dd.f`` address.
    * :func:`pci_order` - a sort key that puts devices in PCI address order, unplaced ones last.
    * :func:`memory_device_bytes` - the size of an SMBIOS type 17 memory device.
    * :func:`processor_id` - the Windows ``ProcessorId`` built from raw CPUID leaf 1.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .pci_config import serial_number_text

if TYPE_CHECKING:
    from .json_types import JsonObject, JsonValue

_HEX_MAC = re.compile(r"[0-9a-fA-F]{12}")
_SEPARATED_MAC = re.compile(r"[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}")
# A PnP instance id carries the DSN as 16 hex digits, followed by the function number on real
# hardware (two more digits); an id without a DSN holds "&" and never matches.
_INSTANCE_DSN = re.compile(r"([0-9a-fA-F]{16})([0-9a-fA-F]{2})?")
_HEX = re.compile(r"[0-9a-fA-F]+")
# MSFT_Disk.UniqueIdFormat values naming an identifier Linux writes with a type prefix.
_DISK_ID_PREFIXES = {2: "eui.", 3: "naa."}
_PCI_ADDRESS = re.compile(r"[0-9a-fA-F]{4}:([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])")
_LEAF_1 = "0x00000001:0"
_SIZE_UNKNOWN = 0xFFFF
_SIZE_EXTENDED = 0x7FFF
_SIZE_IN_KIB = 0x8000
_KIB = 1024
_MIB = 1024 * 1024


def node(body: JsonValue, *path: str) -> JsonValue:
    """Return the value at ``path``, or None where a step is missing or not an object.

    Example:
        >>> node({"a": {"b": 1}}, "a", "b"), node({"a": 1}, "a", "b")
        (1, None)
    """
    current = body
    for key in path:
        current = current.get(key) if isinstance(current, dict) else None
    return current


def rows(body: JsonValue, *path: str) -> list[JsonObject]:
    """Return the objects of the list at ``path``; an error record or a missing list gives none.

    Example:
        >>> rows({"a": [{"x": 1}, 2]}, "a"), rows({"a": {"error": "x"}}, "a")
        ([{'x': 1}], [])
    """
    found = node(body, *path)
    return [r for r in found if isinstance(r, dict)] if isinstance(found, list) else []


def first(body: JsonValue, *path: str) -> JsonObject:
    """Return the first object of the list at ``path``, or an empty object.

    Example:
        >>> first({"a": [{"x": 1}]}, "a"), first({}, "a")
        ({'x': 1}, {})
    """
    found = rows(body, *path)
    return found[0] if found else {}


def obj(body: JsonValue, *path: str) -> JsonObject:
    """Return the object at ``path``, or an empty object (an error record counts as one).

    Example:
        >>> obj({"a": {"x": 1}}, "a"), obj({"a": [1]}, "a")
        ({'x': 1}, {})
    """
    found = node(body, *path)
    return found if isinstance(found, dict) else {}


def text(value: JsonValue) -> str | None:
    """Return a non-blank string with its edges stripped, else None (an error record included).

    Example:
        >>> text(" Model X "), text("  "), text({"error": "x"})
        ('Model X', None, None)
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def integer(value: JsonValue) -> int | None:
    """Return an int, or a decimal or ``0x`` string as one, else None (bool is not an int here).

    Example:
        >>> integer(3), integer("160"), integer("0x0b"), integer(True), integer("n/a")
        (3, 160, 11, None, None)
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 0)
        except ValueError:
            return None
    return None


def canonical_mac(value: JsonValue) -> str | None:
    """Return a MAC address lower case and colon-separated; an all-zero or unparsable one gives None.

    Examples:
        >>> canonical_mac("005056000001"), canonical_mac("00-50-56-00-00-01")
        ('00:50:56:00:00:01', '00:50:56:00:00:01')
        >>> canonical_mac("00:00:00:00:00:00") is None, canonical_mac("") is None
        (True, True)
    """
    raw = text(value)
    if raw is None:
        return None
    if _SEPARATED_MAC.fullmatch(raw):
        raw = raw.replace(":", "").replace("-", "")
    if not _HEX_MAC.fullmatch(raw) or int(raw, 16) == 0:
        return None
    raw = raw.lower()
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def canonical_uuid(value: JsonValue) -> str | None:
    """Return a UUID or GUID in upper case without braces, as SMBIOS decoders write it.

    Example:
        >>> canonical_uuid("04030201-0605-0807-090a-0b0c0d0e0f10"), canonical_uuid("{aaaa-01}")
        ('04030201-0605-0807-090A-0B0C0D0E0F10', 'AAAA-01')
    """
    raw = text(value)
    return raw.strip("{}").upper() if raw is not None else None


def canonical_disk_id(value: JsonValue, *, id_format: int | None = None) -> str | None:
    """Return a disk's VPD 0x83 identifier in the form Linux writes to ``wwid``.

    Windows (``MSFT_Disk.UniqueId``) gives an NAA or EUI-64 identifier as bare hex and says which
    in ``UniqueIdFormat`` (3 = FCPH name, the NAA form; 2 = EUI-64); Linux prefixes the type.
    Any other identifier is returned as it stands.

    Examples:
        >>> canonical_disk_id("6000C29AAAAAAAAA", id_format=3), canonical_disk_id("naa.6000C29A")
        ('naa.6000c29aaaaaaaaa', 'naa.6000c29a')
        >>> canonical_disk_id("eui.0025385B71B04B4E")
        'eui.0025385b71b04b4e'
    """
    raw = text(value)
    if raw is None:
        return None
    prefix = _DISK_ID_PREFIXES.get(id_format) if id_format is not None else None
    if prefix is not None and _HEX.fullmatch(raw):
        return prefix + raw.lower()
    kind, dot, rest = raw.partition(".")
    if dot and kind.lower() in ("naa", "eui") and _HEX.fullmatch(rest):
        return f"{kind.lower()}.{rest.lower()}"
    return raw


def canonical_dsn(value: JsonValue) -> str | None:
    """Return a Device Serial Number in the lspci form, or None for an all-zero one.

    Some devices carry the Device Serial Number capability with every byte zero; that names no
    device, so the summary treats it as no serial (the ``pci`` section keeps it as read).

    Example:
        >>> canonical_dsn("00-0C-29-FF-FF-00-00-01"), canonical_dsn("00-00-00-00-00-00-00-00")
        ('00-0c-29-ff-ff-00-00-01', None)
    """
    raw = text(value)
    if raw is None:
        return None
    digits = raw.replace("-", "")
    if not _HEX.fullmatch(digits) or int(digits, 16) == 0:
        return None
    return serial_number_text(int(digits, 16))


def dsn_from_instance(pnp_id: JsonValue) -> str | None:
    r"""Return the Device Serial Number a Windows PnP instance id carries, in the lspci form.

    Example:
        >>> dsn_from_instance("PCI\\VEN_15AD&DEV_07C0\\0123ABCD5005056000")
        '01-23-ab-cd-50-05-05-60'
        >>> dsn_from_instance("PCI\\VEN_8086&DEV_100E\\3&61AAA01&0&18") is None
        True
    """
    raw = text(pnp_id)
    if raw is None or "\\" not in raw:
        return None
    match = _INSTANCE_DSN.fullmatch(raw.rsplit("\\", 1)[1])
    return canonical_dsn(match.group(1)) if match else None


def pci_address(*, segment: int, bus: int | None, device: int | None, function: int | None) -> str | None:
    """Return a PCI address as Linux writes it, or None when a number is missing.

    Example:
        >>> pci_address(segment=0, bus=11, device=0, function=0)
        '0000:0b:00.0'
    """
    if bus is None or device is None or function is None:
        return None
    return f"{segment:04x}:{bus:02x}:{device:02x}.{function:x}"


def pci_order(address: str | None) -> tuple[bool, str]:
    """Return a sort key that orders by PCI address and puts a device with none last.

    Each OS lists devices in its own order (WMI's, the interface names'); sorting both by address
    lines up the n-th NIC or controller of a Windows and a Linux reading of one machine.

    Example:
        >>> sorted(["0000:0a:01.0", None, "0000:00:1f.2"], key=pci_order)
        ['0000:00:1f.2', '0000:0a:01.0', None]
    """
    return (address is None, address or "")


def split_pci_address(address: str | None) -> tuple[int | None, int | None, int | None]:
    """Return the bus, device and function numbers of a ``dddd:bb:dd.f`` address.

    Example:
        >>> split_pci_address("0000:0b:00.0"), split_pci_address(None)
        ((11, 0, 0), (None, None, None))
    """
    match = _PCI_ADDRESS.fullmatch(address or "")
    if match is None:
        return None, None, None
    bus, device, function = match.groups()
    return int(bus, 16), int(device, 16), int(function)


def memory_device_bytes(row: JsonObject) -> int | None:
    """Return the size of an SMBIOS type 17 memory device in bytes; 0 for an empty socket.

    The Size word holds MiB, or KiB when bit 15 is set; ``0x7FFF`` defers to the Extended Size
    in MiB and ``0xFFFF`` means unknown (SMBIOS 3.x, type 17 offsets 0Ch and 1Ch).

    Examples:
        >>> memory_device_bytes({"size_raw": 0x7FFF, "extended_size_mib": 32768})
        34359738368
        >>> memory_device_bytes({"size_raw": 4096}), memory_device_bytes({"size_raw": 0x8000 | 512})
        (4294967296, 524288)
        >>> memory_device_bytes({"size_raw": 0xFFFF}) is None
        True
    """
    size = integer(row.get("size_raw"))
    if size is None or size == _SIZE_UNKNOWN:
        return None
    if size == _SIZE_EXTENDED:
        extended = integer(row.get("extended_size_mib"))
        return extended * _MIB if extended is not None else None
    if size & _SIZE_IN_KIB:
        return (size & ~_SIZE_IN_KIB) * _KIB
    return size * _MIB


def processor_id(raw_cpuid: JsonValue) -> str | None:
    """Return CPUID leaf 1 EDX then EAX as 16 hex digits, the value Windows reports as ProcessorId.

    Example:
        >>> processor_id({"0x00000001:0": {"eax": "0x000b0671", "edx": "0xbfebfbff"}})
        'BFEBFBFF000B0671'
    """
    leaf = obj(raw_cpuid, _LEAF_1)
    eax, edx = integer(leaf.get("eax")), integer(leaf.get("edx"))
    if eax is None or edx is None:
        return None
    return f"{edx:08X}{eax:08X}"


__all__ = [
    "canonical_disk_id",
    "canonical_dsn",
    "canonical_mac",
    "canonical_uuid",
    "dsn_from_instance",
    "first",
    "integer",
    "memory_device_bytes",
    "node",
    "obj",
    "pci_address",
    "pci_order",
    "processor_id",
    "rows",
    "split_pci_address",
    "text",
]
