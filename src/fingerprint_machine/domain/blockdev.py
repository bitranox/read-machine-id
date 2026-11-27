"""The small Linux text formats a disk is described by, outside its binary VPD pages.

Contents:
    * :class:`SchedulerChoice` - the I/O schedulers a disk offers and the one in use.
    * :class:`UdevRecord` - what udev recorded about a device (``/run/udev/data/b<major>:<minor>``).
    * :func:`parse_scheduler` - a ``queue/scheduler`` line.
    * :func:`parse_udev_record` - one udev database file.
    * :func:`pci_addresses` - the PCI devices a sysfs device path runs through, root first.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .json_types import JsonObject, JsonValue

# A PCI address as sysfs writes it: domain (4 hex digits, more behind a VMD), bus, device, function.
_PCI_ADDRESS = re.compile(r"[0-9a-f]{4,8}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]")


@dataclass(frozen=True, slots=True)
class SchedulerChoice:
    """The I/O schedulers a disk's queue offers, and the one in use (``None`` when none is marked)."""

    active: str | None
    available: tuple[str, ...]

    def as_json(self) -> JsonObject:
        """Return the choice as a reading records it."""
        return {"active": self.active, "available": list(self.available)}


@dataclass(frozen=True, slots=True)
class UdevRecord:
    """The links udev made for a device and the properties it recorded (``E:`` lines)."""

    links: tuple[str, ...]
    properties: Mapping[str, str]

    def as_json(self) -> JsonObject:
        """Return the record as a reading records it."""
        properties: JsonObject = dict(self.properties)
        links: list[JsonValue] = list(self.links)
        return {"links": links, "properties": properties}


def parse_scheduler(text: str) -> SchedulerChoice:
    """Return the schedulers of a ``queue/scheduler`` line; the bracketed one is in use.

    Example:
        >>> parse_scheduler("[none] mq-deadline").active
        'none'
    """
    names = text.split()
    active = next((n[1:-1] for n in names if n.startswith("[") and n.endswith("]")), None)
    return SchedulerChoice(active=active, available=tuple(n.strip("[]") for n in names))


def parse_udev_record(text: str) -> UdevRecord:
    """Return the links (``S:``) and properties (``E:``) of one udev database file.

    Other line kinds (``I:`` init time, ``G:`` tags, ``Q:``, ``V:``) describe udev's own
    bookkeeping, not the device, and are left out.

    Example:
        >>> parse_udev_record("S:disk/by-label/root\\nE:ID_FS_TYPE=ext4\\n").properties["ID_FS_TYPE"]
        'ext4'
    """
    links: list[str] = []
    properties: dict[str, str] = {}
    for line in text.splitlines():
        kind, _, rest = line.partition(":")
        if kind == "S":
            links.append(rest)
        elif kind == "E" and "=" in rest:
            name, _, value = rest.partition("=")
            properties[name] = value
    return UdevRecord(links=tuple(links), properties=properties)


def pci_addresses(device_path: str) -> list[str]:
    """Return the PCI addresses a sysfs device path runs through, root port first, device last.

    The path is what ``/sys/block/<disk>`` or ``/sys/class/net/<interface>`` links to: the
    device's place in the kernel's device tree, which runs through every PCI bridge above it.

    Example:
        >>> pci_addresses("../../devices/pci0000:00/0000:00:03.0/virtio0/net/eth0")
        ['0000:00:03.0']
    """
    return [part for part in device_path.split("/") if _PCI_ADDRESS.fullmatch(part)]


__all__ = ["SchedulerChoice", "UdevRecord", "parse_scheduler", "parse_udev_record", "pci_addresses"]
