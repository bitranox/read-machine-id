"""The ``pci`` section of a Linux reading: every PCI device, where it sits, and its interrupts.

Every device in ``/sys/bus/pci/devices`` is read one at a time: its address and its parent chain
(so the reading is a topology), ids, class, driver, IOMMU group, NUMA node, ACPI node, slot, bus
numbers, resource ranges, link speed and width, power state, the configuration space header and
capability walk, and its interrupts - legacy IRQ and pin, MSI/MSI-X vectors, their
``/proc/interrupts`` rows and their CPU affinity. Then what the system has besides devices: the
interrupt descriptors in ``/sys/kernel/irq``, the named counters of ``/proc/interrupts``, the
I/O port and memory maps and the DMA channels.

Unprivileged, the configuration space is its first 64 bytes, so the capability walk is recorded
as needing root; so are the addresses of ``/proc/iomem`` and ``/proc/ioports``, which the kernel
prints as zero for anyone else.

Contents:
    * :func:`read_pci` - read the section.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..domain.interrupts import parse_interrupts
from ..domain.kernel_tables import addresses_hidden, parse_dma, parse_resource_tree
from ..domain.machine_errors import NeedsRootError, SourceError
from ..domain.pci_config import HEADER_BYTES, decode_capabilities, decode_header, walk_capabilities
from ..domain.pci_sysfs import parse_pci_resources, pci_placement, slot_address
from .guard import ANSWER_ERRORS, guarded
from .linux_files import ATTRIBUTE_MAX_BYTES, optional_dir, text
from .linux_values import int_value, link_name, numeric_names, optional

if TYPE_CHECKING:
    from ..domain.interrupts import InterruptTable
    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import LinuxSource, LinuxSources

_DEVICES = "/sys/bus/pci/devices"
_SLOTS = "/sys/bus/pci/slots"
_KERNEL_IRQ = "/sys/kernel/irq"
_PROC_INTERRUPTS = "/proc/interrupts"
#: The full configuration space of a PCI Express device; nothing larger exists.
_CONFIG_BYTES = 4096
#: /proc/interrupts grows with CPUs times interrupts; a few MiB covers hundreds of CPUs.
_TABLE_BYTES = 8 * 1024 * 1024

#: Device files holding one id each, under the names the configuration header uses.
_ID_FILES = (
    ("vendor_id", "vendor"),
    ("device_id", "device"),
    ("subsystem_vendor_id", "subsystem_vendor"),
    ("subsystem_id", "subsystem_device"),
    ("class_code", "class"),
    ("revision", "revision"),
)
_OPTIONAL_TEXT = (
    ("label", "label"),
    ("acpi_index", "acpi_index"),
    ("power_state", "power_state"),
    ("secondary_bus", "secondary_bus_number"),
    ("subordinate_bus", "subordinate_bus_number"),
)
_LINK_FILES = (
    ("current_speed", "current_link_speed"),
    ("current_width", "current_link_width"),
    ("max_speed", "max_link_speed"),
    ("max_width", "max_link_width"),
)
_SLOT_FILES = ("max_bus_speed", "cur_bus_speed")
_IRQ_FILES = ("chip_name", "hwirq", "type", "name", "actions", "wakeup")


class _Interrupts:
    """``/proc/interrupts``, read and parsed once for every device, or the error that refused it."""

    def __init__(self, system: LinuxSource) -> None:
        self._system = system
        self._table: InterruptTable | None = None
        self._error: str | None = None

    def table(self) -> InterruptTable:
        """The parsed table; raises the reason again when it could not be read."""
        if self._error is not None:
            raise SourceError(self._error)
        if self._table is None:
            try:
                self._table = parse_interrupts(self._system.read_text(_PROC_INTERRUPTS, max_bytes=_TABLE_BYTES))
            except ANSWER_ERRORS as exc:
                self._error = f"{_PROC_INTERRUPTS}: {type(exc).__name__}: {exc}"
                raise
        return self._table


def _text(system: LinuxSource, path: str) -> JsonValue:
    return text(system, path)


def _ids(system: LinuxSource, base: str) -> JsonObject:
    return {key: guarded(lambda f=f: _text(system, f"{base}/{f}")) for key, f in _ID_FILES}


def _optional_texts(system: LinuxSource, base: str, files: tuple[tuple[str, str], ...]) -> JsonObject:
    return {key: optional(lambda f=f: _text(system, f"{base}/{f}")) for key, f in files}


def _placement(system: LinuxSource, address: str) -> JsonValue:
    return pci_placement(system.readlink(f"{_DEVICES}/{address}")).as_json()


def _resources(system: LinuxSource, base: str) -> JsonValue:
    ranges = parse_pci_resources(system.read_text(f"{base}/resource", max_bytes=ATTRIBUTE_MAX_BYTES))
    return [r.as_json() for r in ranges]


def _capabilities(cfg: bytes, path: str) -> JsonValue:
    walk = walk_capabilities(cfg)
    if walk.unread_at is None:
        return decode_capabilities(cfg, walk)
    where = f"{path}: the capability list starts at 0x{walk.unread_at:02x}, past the {len(cfg)} bytes read"
    if len(cfg) <= HEADER_BYTES:
        raise NeedsRootError(f"{where}; only root reads past the header")
    raise SourceError(where)


def _config(system: LinuxSource, base: str) -> JsonValue:
    path = f"{base}/config"
    cfg = system.read_bytes(path, max_bytes=_CONFIG_BYTES)
    return {
        "bytes_read": len(cfg),
        "header": decode_header(cfg),
        "capabilities": guarded(lambda: _capabilities(cfg, path)),
    }


def _pin(config: JsonValue) -> JsonValue:
    header = config.get("header") if isinstance(config, dict) else None
    return header.get("interrupt_pin") if isinstance(header, dict) else None


def _msi_irqs(system: LinuxSource, base: str) -> JsonValue:
    return [
        {"irq": irq, "mode": optional(lambda irq=irq: _text(system, f"{base}/msi_irqs/{irq}"))}
        for irq in numeric_names(system, f"{base}/msi_irqs")
    ]


def _irq_numbers(irq: JsonValue, msi: JsonValue) -> list[int]:
    numbers = {irq} if isinstance(irq, int) and irq > 0 else set[int]()
    for entry in msi if isinstance(msi, list) else []:
        if isinstance(entry, dict) and isinstance(number := entry.get("irq"), int):
            numbers.add(number)
    return sorted(numbers)


def _rows(interrupts: _Interrupts, irqs: list[int]) -> JsonValue:
    by_irq = interrupts.table().by_irq()
    return [by_irq[irq].as_json() for irq in irqs if irq in by_irq]


def _affinity(system: LinuxSource, irq: int) -> JsonObject:
    base = f"/proc/irq/{irq}"
    return {
        "irq": irq,
        "smp_affinity_list": optional(lambda: _text(system, f"{base}/smp_affinity_list")),
        "effective_affinity_list": optional(lambda: _text(system, f"{base}/effective_affinity_list")),
        "node": optional(lambda: int_value(system, f"{base}/node")),
    }


def _device_interrupts(system: LinuxSource, interrupts: _Interrupts, base: str, config: JsonValue) -> JsonObject:
    irq = optional(lambda: int_value(system, f"{base}/irq"))
    msi = optional(lambda: _msi_irqs(system, base))
    irqs = _irq_numbers(irq, msi)
    return {
        "irq": irq,
        "pin": _pin(config),
        "msi_irqs": msi,
        "rows": guarded(lambda: _rows(interrupts, irqs)),
        "affinity": [_affinity(system, n) for n in irqs],
    }


def _device(system: LinuxSource, interrupts: _Interrupts, slots: dict[str, str], address: str) -> JsonObject:
    base = f"{_DEVICES}/{address}"
    config = guarded(lambda: _config(system, base))
    return {
        "address": address,
        "placement": guarded(lambda: _placement(system, address)),
        **_ids(system, base),
        "driver": optional(lambda: link_name(system, f"{base}/driver")),
        "iommu_group": optional(lambda: link_name(system, f"{base}/iommu_group")),
        "numa_node": optional(lambda: int_value(system, f"{base}/numa_node")),
        "firmware_node": optional(lambda: link_name(system, f"{base}/firmware_node")),
        "acpi_path": optional(lambda: _text(system, f"{base}/firmware_node/path")),
        "slot": slots.get(slot_address(address)),
        **_optional_texts(system, base, _OPTIONAL_TEXT),
        "link": _optional_texts(system, base, _LINK_FILES),
        "resources": guarded(lambda: _resources(system, base)),
        "config": config,
        "interrupts": _device_interrupts(system, interrupts, base, config),
    }


def _slot(system: LinuxSource, name: str) -> JsonObject:
    base = f"{_SLOTS}/{name}"
    return {
        "name": name,
        "address": guarded(lambda: _text(system, f"{base}/address")),
        **{f: optional(lambda f=f: _text(system, f"{base}/{f}")) for f in _SLOT_FILES},
    }


def _slot_names(slots: JsonValue) -> dict[str, str]:
    if not isinstance(slots, list):
        return {}
    return {
        str(s["address"]): str(s["name"]) for s in slots if isinstance(s, dict) and isinstance(s.get("address"), str)
    }


def _irq_descriptor(system: LinuxSource, irq: int) -> JsonObject:
    base = f"{_KERNEL_IRQ}/{irq}"
    return {"irq": irq, **{f: optional(lambda f=f: _text(system, f"{base}/{f}")) for f in _IRQ_FILES}}


def _irq_descriptors(system: LinuxSource) -> JsonValue:
    return [_irq_descriptor(system, irq) for irq in numeric_names(system, _KERNEL_IRQ)]


def _counters(interrupts: _Interrupts) -> JsonValue:
    table = interrupts.table()
    cpus: list[JsonValue] = list(table.cpus)
    return {"cpus": cpus, "named": [row.as_json() for row in table.named()]}


def _hidden(path: str) -> JsonValue:
    raise NeedsRootError(f"{path}: the kernel shows the addresses only to root")


def _resource_tree(system: LinuxSource, path: str) -> JsonValue:
    entries = parse_resource_tree(system.read_text(path, max_bytes=_TABLE_BYTES))
    hidden = addresses_hidden(entries)
    return {
        "entries": [e.as_json(with_addresses=not hidden) for e in entries],
        "addresses": guarded(lambda: _hidden(path)) if hidden else "shown",
    }


def _dma(system: LinuxSource) -> JsonValue:
    return [c.as_json() for c in parse_dma(system.read_text("/proc/dma", max_bytes=_TABLE_BYTES))]


def read_pci(src: LinuxSources) -> JsonValue:
    """Read every PCI device one at a time, then the system's interrupts, I/O and memory maps."""
    system = src.system
    interrupts = _Interrupts(system)
    slots = guarded(lambda: [_slot(system, name) for name in optional_dir(system, _SLOTS)])
    names = _slot_names(slots)
    return {
        "devices": [
            guarded(lambda a=address: _device(system, interrupts, names, a))
            for address in optional_dir(system, _DEVICES)
        ],
        "slots": slots,
        "interrupts": guarded(lambda: _counters(interrupts)),
        "irq_descriptors": optional(lambda: _irq_descriptors(system)),
        "ioports": guarded(lambda: _resource_tree(system, "/proc/ioports")),
        "iomem": guarded(lambda: _resource_tree(system, "/proc/iomem")),
        "dma": optional(lambda: _dma(system)),
    }


__all__ = ["read_pci"]
