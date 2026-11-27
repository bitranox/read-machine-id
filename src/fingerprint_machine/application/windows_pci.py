r"""The ``pci`` section of a Windows reading: every PCI function, where it sits, and what it was given.

Every instance under ``HKLM\SYSTEM\CurrentControlSet\Enum\PCI`` is read one at a time, present or
not: its ids (from its hardware and compatible ids, under the names a Linux reading uses), its
address on the bus, its place in the device tree (parent and location paths, from the
configuration manager), the PCI bus Windows hangs it on, its driver service, its Device Serial
Number where Windows took the instance id from it, the PCI driver's own properties (link speed and
width, interrupt support), its MSI settings
(``Device Parameters\Interrupt Management\MessageSignaledInterruptProperties``) and the resources
Windows allocated to it (``Win32_PnPAllocatedResource``: IRQs, memory ranges, I/O ports, DMA
channels). Then the system's tables: the PCI buses, every IRQ, the I/O port and memory ranges and
the DMA channels.

Windows lists a message-signaled interrupt as an IRQ with a negative number; those are the
device's ``msi_irqs``, the others its line-based ``irq``.

Contents:
    * :func:`read_windows_pci` - read the section.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from ..domain.devprops import PCI_PROPERTIES, DeviceProperty
from ..domain.machine_errors import MissingKeyError
from ..domain.windows_pci import (
    InterruptSupport,
    PciLocation,
    WmiReference,
    irq_number,
    parse_wmi_reference,
    pci_ids,
    pci_location,
    pci_location_from_address,
    unique_id_serial,
)
from .guard import ANSWER_ERRORS, guarded
from .windows_values import optional_values, values

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import WindowsSources

_ENUM = r"HKLM\SYSTEM\CurrentControlSet\Enum"
_ENUM_PCI = rf"{_ENUM}\PCI"
_MSI = r"Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
_LINK = (
    ("current_speed", DeviceProperty.PCI_CURRENT_LINK_SPEED),
    ("current_width", DeviceProperty.PCI_CURRENT_LINK_WIDTH),
    ("max_speed", DeviceProperty.PCI_MAX_LINK_SPEED),
    ("max_width", DeviceProperty.PCI_MAX_LINK_WIDTH),
)
_INTERRUPT = frozenset({DeviceProperty.PCI_INTERRUPT_SUPPORT, DeviceProperty.PCI_INTERRUPT_MESSAGE_MAXIMUM})
#: The PCI driver's properties not already listed under ``link`` or ``interrupts``.
_OTHER_PCI = tuple(p for p in PCI_PROPERTIES if p not in {q for _, q in _LINK} | _INTERRUPT)
_WANTED = (
    DeviceProperty.PARENT,
    DeviceProperty.LOCATION_PATHS,
    DeviceProperty.LOCATION_INFO,
    DeviceProperty.BUS_NUMBER,
    DeviceProperty.ADDRESS,
    *PCI_PROPERTIES,
)
#: The resource classes ``Win32_PnPAllocatedResource`` points at: the key each is named by, the
#: name a device's ``resources`` lists them under, and the properties kept per range.
_RESOURCES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "Win32_IRQResource": ("IRQNumber", "irqs", ("IRQNumber", "TriggerType", "TriggerLevel", "Shareable")),
    "Win32_DeviceMemoryAddress": ("StartingAddress", "memory", ("StartingAddress", "EndingAddress", "MemoryType")),
    "Win32_PortResource": ("StartingAddress", "ports", ("StartingAddress", "EndingAddress")),
    "Win32_DMAChannel": ("DMAChannel", "dma", ("DMAChannel", "ChannelTiming", "TypeCTiming")),
}


def _rows(src: WindowsSources, class_name: str) -> list[JsonObject]:
    return src.platform.cim(class_name)


def _json_rows(src: WindowsSources, class_name: str) -> JsonValue:
    rows: list[JsonValue] = list(_rows(src, class_name))
    return rows


def _reference(row: JsonObject, side: str) -> WmiReference | None:
    text = row.get(side)
    if not isinstance(text, str):
        return None
    try:
        return parse_wmi_reference(text)
    except ValueError:
        return None


def _links(src: WindowsSources, class_name: str) -> dict[str, list[WmiReference]]:
    """Each device's antecedents in an association class, keyed by the device id upper-cased."""
    found: dict[str, list[WmiReference]] = defaultdict(list)
    for row in _rows(src, class_name):
        antecedent, dependent = _reference(row, "Antecedent"), _reference(row, "Dependent")
        device = dependent.key("DeviceID") if dependent is not None else None
        if antecedent is not None and device is not None:
            found[device.upper()].append(antecedent)
    return dict(found)


def _canonical(class_name: str, value: object) -> str:
    """The key a resource is joined on; an IRQ the same however WMI wrote its number."""
    if class_name == "Win32_IRQResource":
        return str(irq_number(value))
    return str(value)


def _index(build: Callable[[], dict[str, list[WmiReference]]]) -> tuple[dict[str, list[WmiReference]], JsonValue]:
    try:
        return build(), None
    except ANSWER_ERRORS as exc:
        return {}, {"error": f"{type(exc).__name__}: {exc}"}


class _Tables:
    """The system-wide answers every device is joined against, each asked once, or why not."""

    def __init__(self, src: WindowsSources) -> None:
        self.allocations, self.allocations_error = _index(lambda: _links(src, "Win32_PnPAllocatedResource"))
        self.buses, self.buses_error = _index(lambda: _links(src, "Win32_DeviceBus"))
        self.answers: dict[str, JsonValue] = {c: guarded(lambda c=c: _json_rows(src, c)) for c in _RESOURCES}
        self.ranges: dict[str, dict[str, JsonObject]] = {c: self._by_key(c) for c in _RESOURCES}

    def _by_key(self, class_name: str) -> dict[str, JsonObject]:
        answer = self.answers[class_name]
        key = _RESOURCES[class_name][0]
        rows = answer if isinstance(answer, list) else []
        return {_canonical(class_name, r.get(key)): r for r in rows if isinstance(r, dict)}

    def join_errors(self) -> JsonObject:
        """Why a join could not be made, by the association that was refused (None where it was read)."""
        return {"Win32_PnPAllocatedResource": self.allocations_error, "Win32_DeviceBus": self.buses_error}


def _subkeys(src: WindowsSources, key: str) -> JsonValue:
    names: list[JsonValue] = list(src.registry.subkeys(key))
    return names


def _instances(src: WindowsSources) -> Iterator[str]:
    """Every PCI instance id Windows has a registry key for, one device model at a time."""
    for device in src.registry.subkeys(_ENUM_PCI):
        found = guarded(lambda device=device: _subkeys(src, rf"{_ENUM_PCI}\{device}"))
        for inst in found if isinstance(found, list) else []:
            if isinstance(inst, str):
                yield rf"PCI\{device}\{inst}"


def _property(src: WindowsSources, instance_id: str, prop: DeviceProperty) -> JsonValue:
    """One device property; None when the device does not have it."""
    try:
        return src.platform.device_property(instance_id, prop)
    except MissingKeyError:
        return None


def _properties(src: WindowsSources, instance_id: str) -> JsonObject:
    return {p.value: guarded(lambda p=p: _property(src, instance_id, p)) for p in _WANTED}


def _location(registry: JsonObject, props: JsonObject) -> PciLocation | None:
    bus, address = props.get("bus_number"), props.get("address")
    if isinstance(bus, int) and isinstance(address, int):
        return pci_location_from_address(bus=bus, address=address)
    return pci_location(registry.get("LocationInformation")) or pci_location(props.get("location_info"))


def _strings(value: JsonValue) -> list[str]:
    if isinstance(value, str):
        return [value]
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _resources(tables: _Tables, refs: list[WmiReference]) -> JsonObject:
    """The ranges allocated to a device, by kind, each with the properties that describe it."""
    out: dict[str, list[JsonValue]] = {name: [] for _, name, _ in _RESOURCES.values()}
    for ref in refs:
        if ref.class_name not in _RESOURCES:
            continue
        key, name, kept = _RESOURCES[ref.class_name]
        row = tables.ranges[ref.class_name].get(_canonical(ref.class_name, ref.key(key)), {key: ref.key(key)})
        out[name].append({k: row.get(k) for k in kept})
    found: JsonObject = dict(out)
    return found


def _irq_numbers(refs: list[WmiReference]) -> list[int]:
    found = (irq_number(r.key("IRQNumber")) for r in refs if r.class_name == "Win32_IRQResource")
    return sorted(n for n in found if n is not None)


def _interrupts(src: WindowsSources, instance_id: str, *, refs: list[WmiReference], props: JsonObject) -> JsonObject:
    irqs = _irq_numbers(refs)
    line: list[JsonValue] = [n for n in irqs if n >= 0]
    message: list[JsonValue] = [n for n in irqs if n < 0]
    msi_key = rf"{_ENUM}\{instance_id}\{_MSI}"
    return {
        "irq": line,
        "msi_irqs": message,
        "msi": guarded(lambda: optional_values(src, msi_key)),
        "interrupt_support": InterruptSupport.names(props.get(DeviceProperty.PCI_INTERRUPT_SUPPORT.value)),
        "interrupt_message_maximum": props.get(DeviceProperty.PCI_INTERRUPT_MESSAGE_MAXIMUM.value),
    }


def _bus(tables: _Tables, instance_id: str) -> JsonValue:
    found = [b for r in tables.buses.get(instance_id.upper(), []) if (b := r.key("DeviceID")) is not None]
    return found[0] if found else None


def _name(row: JsonObject | None, registry: JsonObject) -> JsonValue:
    if row is not None:
        return row.get("Name")
    return registry.get("FriendlyName") or registry.get("DeviceDesc")


def _identity(registry: JsonObject, instance_id: str) -> JsonObject:
    ids = [*_strings(registry.get("HardwareID")), *_strings(registry.get("CompatibleIDs"))]
    return {
        **pci_ids(ids).as_json(),
        "hardware_ids": registry.get("HardwareID"),
        "compatible_ids": registry.get("CompatibleIDs"),
        "driver": registry.get("Service"),
        "device_serial_number": unique_id_serial(instance_id, registry.get("Capabilities")),
    }


def _device(src: WindowsSources, tables: _Tables, present: dict[str, JsonObject], instance_id: str) -> JsonObject:
    registry = values(src, rf"{_ENUM}\{instance_id}")
    props = _properties(src, instance_id)
    refs = tables.allocations.get(instance_id.upper(), [])
    location = _location(registry, props)
    return {
        "instance_id": instance_id,
        "present": instance_id.upper() in present,
        "name": _name(present.get(instance_id.upper()), registry),
        "address": location.address if location is not None else None,
        "location": location.as_json() if location is not None else None,
        "location_information": registry.get("LocationInformation"),
        "location_paths": props[DeviceProperty.LOCATION_PATHS.value],
        "parent": props[DeviceProperty.PARENT.value],
        "bus": _bus(tables, instance_id),
        **_identity(registry, instance_id),
        "link": {name: props.get(p.value) for name, p in _LINK},
        "properties": {p.value: props.get(p.value) for p in _OTHER_PCI},
        "resources": _resources(tables, refs),
        "interrupts": _interrupts(src, instance_id, refs=refs, props=props),
    }


def _present(src: WindowsSources) -> JsonValue:
    """The PCI devices present now, by their instance id upper-cased."""
    present: JsonObject = {}
    for row in _rows(src, "Win32_PnPEntity"):
        device = str(row.get("DeviceID", "")).upper()
        if device.startswith("PCI\\"):
            present[device] = row
    return present


def read_windows_pci(src: WindowsSources) -> JsonValue:
    """Read every PCI function one at a time, then the system's buses, IRQs and resource ranges."""
    tables = _Tables(src)
    answer = guarded(lambda: _present(src))
    refused = isinstance(answer, dict) and isinstance(answer.get("error"), str)
    rows = answer if isinstance(answer, dict) and not refused else {}
    present = {k: v for k, v in rows.items() if isinstance(v, dict)}
    return {
        "devices": [guarded(lambda i=inst: _device(src, tables, present, i)) for inst in _instances(src)],
        "buses": guarded(lambda: _json_rows(src, "Win32_Bus")),
        "irq_descriptors": tables.answers["Win32_IRQResource"],
        "ioports": tables.answers["Win32_PortResource"],
        "iomem": tables.answers["Win32_DeviceMemoryAddress"],
        "dma": tables.answers["Win32_DMAChannel"],
        "present_error": answer if refused else None,
        "join_errors": tables.join_errors(),
    }


__all__ = ["read_windows_pci"]
