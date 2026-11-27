"""PCI configuration space: the header and the capability lists a device publishes.

The configuration space is what a device tells the OS about itself before any driver runs: its
ids, its class, its interrupt pin, and two linked lists of capabilities. Which capabilities a
device carries, at which offsets, and the values in them (the Device Serial Number above all) are
the same on every boot and differ between a physical device and the one a hypervisor emulates in
its place, so they are a fingerprint.

Layouts follow the PCI Local Bus Specification 3.0 (6.1 header, 6.7 capability list, 6.8 MSI and
MSI-X) and the PCI Express Base Specification (7.5.3 PCI Express capability, 7.6 extended
capabilities: 7.8.4 AER, 7.9.3 Device Serial Number, 9.3.3 SR-IOV). Capability names follow the
``PCI_CAP_ID_*`` and ``PCI_EXT_CAP_ID_*`` constants of Linux's ``include/uapi/linux/pci_regs.h``,
spelled out.

An unprivileged reader sees only the first 64 bytes (the header); the capability lists start
after it. :func:`walk_capabilities` says where the readable bytes ran out instead of guessing.

Contents:
    * :class:`PciePortType` - the device/port type a PCI Express capability names.
    * :class:`PciCapability` - one capability found by the walk.
    * :class:`CapabilityWalk` - every capability found, and where the walk ran out of bytes.
    * :func:`decode_header` - the 64-byte header.
    * :func:`walk_capabilities` - follow both capability lists.
    * :func:`decode_capabilities` - the walk, plus the fields of the capabilities that identify.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .json_types import JsonObject, JsonValue

#: The bytes every configuration space has: the header an unprivileged read returns.
HEADER_BYTES = 64
#: Where the extended capability list starts; a space this size or smaller has none.
EXTENDED_START = 0x100

_STATUS_CAP_LIST = 0x0010
_HEADER_TYPE_MASK = 0x7F
_MULTIFUNCTION = 0x80
_HEADER_BRIDGE = 1
_HEADER_CARDBUS = 2
_CAP_POINTER = 0x34
_CARDBUS_CAP_POINTER = 0x14
_POINTER_MASK = 0xFC
_EXT_POINTER_SHIFT = 20
_EXT_POINTER_MASK = 0xFFC
_EXT_VERSION_SHIFT = 16
_EXT_ID_MASK = 0xFFFF
_EXT_VERSION_MASK = 0xF
_EXT_ABSENT = (0, 0xFFFFFFFF)
#: The most capabilities each list can hold (one per dword after the header, after 0x100): a bound
#: on the walk besides the loop check, so a corrupt list ends either way.
_MAX_STANDARD = (256 - HEADER_BYTES) // 4
_MAX_EXTENDED = (4096 - EXTENDED_START) // 4
_PINS = (None, "INTA", "INTB", "INTC", "INTD")

#: Standard capability ids, as ``PCI_CAP_ID_*`` names them.
_CAP_NAMES: dict[int, str] = {
    0x01: "power_management",
    0x02: "agp",
    0x03: "vital_product_data",
    0x04: "slot_identification",
    0x05: "msi",
    0x06: "compactpci_hot_swap",
    0x07: "pci_x",
    0x08: "hypertransport",
    0x09: "vendor_specific",
    0x0A: "debug_port",
    0x0B: "compactpci_central_resource",
    0x0C: "pci_hot_plug",
    0x0D: "bridge_subsystem_vendor_id",
    0x0E: "agp_8x",
    0x0F: "secure_device",
    0x10: "pci_express",
    0x11: "msi_x",
    0x12: "sata",
    0x13: "advanced_features",
    0x14: "enhanced_allocation",
    0x15: "flattening_portal_bridge",
}

#: Extended capability ids, as ``PCI_EXT_CAP_ID_*`` names them.
_EXT_NAMES: dict[int, str] = {
    0x01: "advanced_error_reporting",
    0x02: "virtual_channel",
    0x03: "device_serial_number",
    0x04: "power_budgeting",
    0x05: "root_complex_link_declaration",
    0x06: "root_complex_internal_link_control",
    0x07: "root_complex_event_collector",
    0x08: "multi_function_virtual_channel",
    0x09: "virtual_channel_9",
    0x0A: "root_complex_register_block",
    0x0B: "vendor_specific",
    0x0C: "config_access_correlation",
    0x0D: "access_control_services",
    0x0E: "alternative_routing_id",
    0x0F: "address_translation_services",
    0x10: "sr_iov",
    0x11: "mr_iov",
    0x12: "multicast",
    0x13: "page_request",
    0x15: "resizable_bar",
    0x16: "dynamic_power_allocation",
    0x17: "tph_requester",
    0x18: "latency_tolerance_reporting",
    0x19: "secondary_pci_express",
    0x1A: "protocol_multiplexing",
    0x1B: "process_address_space_id",
    0x1C: "lane_number_receiver",
    0x1D: "downstream_port_containment",
    0x1E: "l1_pm_substates",
    0x1F: "precision_time_measurement",
    0x23: "designated_vendor_specific",
    0x25: "data_link_feature",
    0x26: "physical_layer_16gt",
    0x27: "lane_margining",
    0x29: "native_pcie_enclosure_management",
    0x2A: "physical_layer_32gt",
    0x2E: "data_object_exchange",
}

_CAP_MSI = 0x05
_CAP_EXP = 0x10
_CAP_MSIX = 0x11
_EXT_AER = 0x01
_EXT_DSN = 0x03
_EXT_SRIOV = 0x10


class PciePortType(StrEnum):
    """The device/port type field of a PCI Express capability (PCIe Base 7.5.3.2)."""

    ENDPOINT = "endpoint"
    LEGACY_ENDPOINT = "legacy_endpoint"
    ROOT_PORT = "root_port"
    UPSTREAM_PORT = "upstream_port"
    DOWNSTREAM_PORT = "downstream_port"
    PCIE_TO_PCI_BRIDGE = "pcie_to_pci_bridge"
    PCI_TO_PCIE_BRIDGE = "pci_to_pcie_bridge"
    RC_INTEGRATED_ENDPOINT = "rc_integrated_endpoint"
    RC_EVENT_COLLECTOR = "rc_event_collector"

    @classmethod
    def from_number(cls, number: int) -> PciePortType | None:
        """Return the type a field value names, or None for a reserved value.

        Example:
            >>> PciePortType.from_number(0)
            <PciePortType.ENDPOINT: 'endpoint'>
        """
        return _PORT_TYPES.get(number)


_PORT_TYPES: dict[int, PciePortType] = {
    0x0: PciePortType.ENDPOINT,
    0x1: PciePortType.LEGACY_ENDPOINT,
    0x4: PciePortType.ROOT_PORT,
    0x5: PciePortType.UPSTREAM_PORT,
    0x6: PciePortType.DOWNSTREAM_PORT,
    0x7: PciePortType.PCIE_TO_PCI_BRIDGE,
    0x8: PciePortType.PCI_TO_PCIE_BRIDGE,
    0x9: PciePortType.RC_INTEGRATED_ENDPOINT,
    0xA: PciePortType.RC_EVENT_COLLECTOR,
}


@dataclass(frozen=True, slots=True)
class PciCapability:
    """One capability: its id, where it sits, and (extended only) its version."""

    cap_id: int
    offset: int
    version: int | None = None

    @property
    def extended(self) -> bool:
        """Whether it sits in the extended list (offset 0x100 and up)."""
        return self.offset >= EXTENDED_START

    def as_json(self) -> JsonObject:
        """Return the capability as a reading records it.

        Example:
            >>> PciCapability(0x10, 0x40).as_json()
            {'id': '0x10', 'name': 'pci_express', 'offset': '0x40'}
        """
        if not self.extended:
            return {"id": f"0x{self.cap_id:02x}", "name": _CAP_NAMES.get(self.cap_id), "offset": f"0x{self.offset:02x}"}
        return {
            "id": f"0x{self.cap_id:04x}",
            "name": _EXT_NAMES.get(self.cap_id),
            "offset": f"0x{self.offset:03x}",
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class CapabilityWalk:
    """Every capability found, in list order, and the first pointer past the readable bytes."""

    capabilities: tuple[PciCapability, ...]
    extended: tuple[PciCapability, ...]
    unread_at: int | None


def _uint(cfg: bytes, offset: int, size: int) -> int | None:
    """The little-endian field at ``offset``, or None when it lies past the bytes read."""
    if offset + size > len(cfg):
        return None
    return int.from_bytes(cfg[offset : offset + size], "little")


def _int(cfg: bytes, offset: int, size: int) -> int:
    """A field inside the header, which :func:`decode_header` has checked is all there."""
    return int.from_bytes(cfg[offset : offset + size], "little")


def _hex(value: int | None, digits: int) -> str | None:
    return None if value is None else f"0x{value:0{digits}x}"


def _cap_pointer(cfg: bytes) -> int | None:
    if not _int(cfg, 0x06, 2) & _STATUS_CAP_LIST:
        return None
    kind = cfg[0x0E] & _HEADER_TYPE_MASK
    return cfg[_CARDBUS_CAP_POINTER if kind == _HEADER_CARDBUS else _CAP_POINTER] & _POINTER_MASK


def _type_fields(cfg: bytes, kind: int) -> JsonObject:
    if kind == _HEADER_BRIDGE:
        return {"primary_bus": cfg[0x18], "secondary_bus": cfg[0x19], "subordinate_bus": cfg[0x1A]}
    if kind == 0:
        return {"subsystem_vendor_id": _hex(_int(cfg, 0x2C, 2), 4), "subsystem_id": _hex(_int(cfg, 0x2E, 2), 4)}
    return {}


def decode_header(cfg: bytes) -> JsonObject:
    """Return the fields of the 64-byte header every device has.

    Raises:
        ValueError: fewer than 64 bytes were given.

    Example:
        >>> decode_header(bytes([0x86, 0x80]) + bytes(62))["vendor_id"]
        '0x8086'
    """
    if len(cfg) < HEADER_BYTES:
        raise ValueError(f"a PCI header is {HEADER_BYTES} bytes, got {len(cfg)}")
    kind = cfg[0x0E] & _HEADER_TYPE_MASK
    pin = cfg[0x3D]
    pointer = _cap_pointer(cfg)
    return {
        "vendor_id": _hex(_int(cfg, 0x00, 2), 4),
        "device_id": _hex(_int(cfg, 0x02, 2), 4),
        "command": _hex(_int(cfg, 0x04, 2), 4),
        "status": _hex(_int(cfg, 0x06, 2), 4),
        "revision": _hex(cfg[0x08], 2),
        "class_code": _hex(_int(cfg, 0x09, 3), 6),
        "header_type": kind,
        "multifunction": bool(cfg[0x0E] & _MULTIFUNCTION),
        "interrupt_line": cfg[0x3C],
        "interrupt_pin": _PINS[pin] if pin < len(_PINS) else f"unknown({pin})",
        "capabilities_pointer": _hex(pointer, 2),
        **_type_fields(cfg, kind),
    }


def _walk_standard(cfg: bytes) -> tuple[tuple[PciCapability, ...], int | None]:
    found: list[PciCapability] = []
    seen: set[int] = set()
    pointer = _cap_pointer(cfg) if len(cfg) >= HEADER_BYTES else None
    while pointer and pointer >= HEADER_BYTES and pointer not in seen and len(found) < _MAX_STANDARD:
        if pointer + 2 > len(cfg):
            return tuple(found), pointer
        seen.add(pointer)
        found.append(PciCapability(cfg[pointer], pointer))
        pointer = cfg[pointer + 1] & _POINTER_MASK
    return tuple(found), None


def _walk_extended(cfg: bytes) -> tuple[PciCapability, ...]:
    found: list[PciCapability] = []
    seen: set[int] = set()
    offset = EXTENDED_START if len(cfg) > EXTENDED_START else 0
    while offset >= EXTENDED_START and offset not in seen and len(found) < _MAX_EXTENDED:
        header = _uint(cfg, offset, 4)
        if header is None or header in _EXT_ABSENT:
            break
        seen.add(offset)
        version = (header >> _EXT_VERSION_SHIFT) & _EXT_VERSION_MASK
        found.append(PciCapability(header & _EXT_ID_MASK, offset, version))
        offset = (header >> _EXT_POINTER_SHIFT) & _EXT_POINTER_MASK
    return tuple(found)


def walk_capabilities(cfg: bytes) -> CapabilityWalk:
    """Follow the standard and the extended capability lists, ending on a loop or the last byte.

    ``unread_at`` is the first standard pointer that lies past the bytes given (an unprivileged
    read stops at 64); the extended list is read only from a space larger than 256 bytes.

    Example:
        >>> walk_capabilities(bytes(64)).capabilities
        ()
    """
    standard, unread_at = _walk_standard(cfg)
    extended = _walk_extended(cfg) if unread_at is None else ()
    return CapabilityWalk(capabilities=standard, extended=extended, unread_at=unread_at)


def _first(caps: tuple[PciCapability, ...], cap_id: int) -> int | None:
    return next((c.offset for c in caps if c.cap_id == cap_id), None)


def _dsn(cfg: bytes, offset: int | None) -> str | None:
    value = None if offset is None else _uint(cfg, offset + 4, 8)
    if value is None:
        return None
    return "-".join(f"{b:02x}" for b in value.to_bytes(8, "big"))


def _pcie(cfg: bytes, offset: int | None) -> JsonObject | None:
    flags = None if offset is None else _uint(cfg, offset + 2, 2)
    if offset is None or flags is None:
        return None
    number = (flags >> 4) & 0xF
    port_type = PciePortType.from_number(number)
    slot = bool(flags & 0x100)
    slot_caps = _uint(cfg, offset + 0x14, 4) if slot else None
    link_caps = _uint(cfg, offset + 0x0C, 4)
    return {
        "version": flags & 0xF,
        "port_type": port_type.value if port_type is not None else f"unknown({number})",
        "slot_implemented": slot,
        "physical_slot": None if slot_caps is None else slot_caps >> 19,
        "max_link_speed": None if link_caps is None else link_caps & 0xF,
        "max_link_width": None if link_caps is None else (link_caps >> 4) & 0x3F,
    }


def _msi(cfg: bytes, offset: int | None) -> JsonObject | None:
    control = None if offset is None else _uint(cfg, offset + 2, 2)
    if control is None:
        return None
    return {
        "enabled": bool(control & 0x1),
        "vectors_capable": 1 << ((control >> 1) & 0x7),
        "vectors_enabled": 1 << ((control >> 4) & 0x7),
        "address_64bit": bool(control & 0x80),
        "per_vector_masking": bool(control & 0x100),
    }


def _msix(cfg: bytes, offset: int | None) -> JsonObject | None:
    control = None if offset is None else _uint(cfg, offset + 2, 2)
    table = None if offset is None else _uint(cfg, offset + 4, 4)
    pba = None if offset is None else _uint(cfg, offset + 8, 4)
    if control is None or table is None or pba is None:
        return None
    return {
        "enabled": bool(control & 0x8000),
        "function_mask": bool(control & 0x4000),
        "table_size": (control & 0x7FF) + 1,
        "table_bar": table & 0x7,
        "table_offset": _hex(table & ~0x7, 4),
        "pba_bar": pba & 0x7,
        "pba_offset": _hex(pba & ~0x7, 4),
    }


_AER_FIELDS = (
    ("uncorrectable_status", 0x04),
    ("uncorrectable_mask", 0x08),
    ("uncorrectable_severity", 0x0C),
    ("correctable_status", 0x10),
    ("correctable_mask", 0x14),
    ("capabilities_control", 0x18),
)


def _aer(cfg: bytes, offset: int | None) -> JsonObject | None:
    if offset is None or _uint(cfg, offset + 0x18, 4) is None:
        return None
    return {name: _hex(_uint(cfg, offset + at, 4), 8) for name, at in _AER_FIELDS}


def _sriov(cfg: bytes, offset: int | None) -> JsonObject | None:
    if offset is None or _uint(cfg, offset + 0x1A, 2) is None:
        return None
    control = _int(cfg, offset + 0x08, 2)
    return {
        "vf_enabled": bool(control & 0x1),
        "initial_vfs": _int(cfg, offset + 0x0C, 2),
        "total_vfs": _int(cfg, offset + 0x0E, 2),
        "num_vfs": _int(cfg, offset + 0x10, 2),
        "first_vf_offset": _int(cfg, offset + 0x14, 2),
        "vf_stride": _int(cfg, offset + 0x16, 2),
        "vf_device_id": _hex(_int(cfg, offset + 0x1A, 2), 4),
    }


def decode_capabilities(cfg: bytes, walk: CapabilityWalk) -> JsonObject:
    """Return every capability of ``walk`` and the identifying fields of the ones that have them.

    A capability the device does not carry is None, so two readings line up key by key.

    Example:
        >>> decode_capabilities(bytes(64), walk_capabilities(bytes(64)))["msi"] is None
        True
    """
    std, ext = walk.capabilities, walk.extended
    caps_list: list[JsonValue] = [c.as_json() for c in std]
    ext_list: list[JsonValue] = [c.as_json() for c in ext]
    return {
        "list": caps_list,
        "extended": ext_list,
        "device_serial_number": _dsn(cfg, _first(ext, _EXT_DSN)),
        "pci_express": _pcie(cfg, _first(std, _CAP_EXP)),
        "msi": _msi(cfg, _first(std, _CAP_MSI)),
        "msi_x": _msix(cfg, _first(std, _CAP_MSIX)),
        "advanced_error_reporting": _aer(cfg, _first(ext, _EXT_AER)),
        "sr_iov": _sriov(cfg, _first(ext, _EXT_SRIOV)),
    }


__all__ = [
    "EXTENDED_START",
    "HEADER_BYTES",
    "CapabilityWalk",
    "PciCapability",
    "PciePortType",
    "decode_capabilities",
    "decode_header",
    "walk_capabilities",
]
