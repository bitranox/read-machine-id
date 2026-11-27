"""How Linux lays out a PCI device in sysfs: where it sits in the tree and which ranges it owns.

``/sys/bus/pci/devices/<address>`` is a link into ``/sys/devices``, and the path it points at is
the device's place in the topology: the root bus (``pci0000:00``), then every bridge between the
root and the device (root port, switch upstream and downstream ports), then the device itself.
:func:`pci_placement` reads that chain from the link, so a reading lists each device's parents
and the tree can be rebuilt from it.

A device's ``resource`` file (``resource_show`` in ``drivers/pci/pci-sysfs.c``) has one line per
resource slot - the six BARs, the expansion ROM, then the SR-IOV and bridge windows the kernel
build defines - each ``<start> <end> <flags>`` in hex. Unused slots are all zero and are left out.
Flags are the kernel's ``IORESOURCE_*`` bits (``include/linux/ioport.h``).

Contents:
    * :class:`PciPlacement`, :func:`pci_placement` - a device's place in the PCI tree.
    * :class:`ResourceKind`, :class:`PciResource`, :func:`parse_pci_resources` - its ranges.
    * :func:`slot_address` - the address a ``/sys/bus/pci/slots`` entry names a device by.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .json_types import JsonObject, JsonValue

_ADDRESS = re.compile(r"^[0-9a-f]{4,}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")
_ROOT = re.compile(r"^pci[0-9a-f]{4,}:[0-9a-f]{2}$")
_RESOURCE_LINE = re.compile(r"^\s*0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s*$")

_IORESOURCE_IO = 0x00000100
_IORESOURCE_MEM = 0x00000200
_IORESOURCE_PREFETCH = 0x00002000
_IORESOURCE_MEM_64 = 0x00100000


@dataclass(frozen=True, slots=True)
class PciPlacement:
    """A device's sysfs path, the root bus it hangs off, and the bridges in between."""

    sysfs_path: str
    root: str | None
    parents: tuple[str, ...]

    def as_json(self) -> JsonObject:
        """Return the placement as a reading records it."""
        parents: list[JsonValue] = list(self.parents)
        return {"sysfs_path": self.sysfs_path, "root": self.root, "parents": parents}


def pci_placement(link_target: str) -> PciPlacement:
    """Return the placement a ``/sys/bus/pci/devices/<address>`` link points at.

    The root is the last ``pci<domain>:<bus>`` component (a device under a Hyper-V VMBus or a
    Xen bus has others before it); the parents are the PCI addresses after it, the device's own
    address excluded.

    Example:
        >>> pci_placement("../../../devices/pci0000:00/0000:00:1c.0/0000:02:00.0").parents
        ('0000:00:1c.0',)
    """
    parts = [p for p in link_target.split("/") if p not in {"", ".", ".."}]
    roots = [i for i, p in enumerate(parts) if _ROOT.match(p)]
    start = roots[-1] if roots else -1
    chain = tuple(p for p in parts[start + 1 :] if _ADDRESS.match(p))
    return PciPlacement(
        sysfs_path="/sys/" + "/".join(parts),
        root=parts[start] if roots else None,
        parents=chain[:-1],
    )


class ResourceKind(StrEnum):
    """What a resource range addresses."""

    IO = "io"
    MEMORY = "memory"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class PciResource:
    """One resource slot of a device that is in use."""

    index: int
    start: int
    end: int
    flags: int

    @property
    def kind(self) -> ResourceKind:
        """I/O port range, memory range, or anything else the flags name."""
        if self.flags & _IORESOURCE_IO:
            return ResourceKind.IO
        if self.flags & _IORESOURCE_MEM:
            return ResourceKind.MEMORY
        return ResourceKind.OTHER

    def as_json(self) -> JsonObject:
        """Return the range as a reading records it."""
        return {
            "index": self.index,
            "kind": self.kind.value,
            "start": hex(self.start),
            "end": hex(self.end),
            "size": self.end - self.start + 1,
            "prefetchable": bool(self.flags & _IORESOURCE_PREFETCH),
            "address_64bit": bool(self.flags & _IORESOURCE_MEM_64),
            "flags": hex(self.flags),
        }


def parse_pci_resources(text: str) -> tuple[PciResource, ...]:
    """Parse a PCI device's ``resource`` file, keeping the slots in use (any field non-zero).

    Example:
        >>> parse_pci_resources("0x0000000000001000 0x000000000000101f 0x0000000000040101\\n")[0].kind
        <ResourceKind.IO: 'io'>
    """
    found: list[PciResource] = []
    for index, line in enumerate(text.splitlines()):
        match = _RESOURCE_LINE.match(line)
        if match is None:
            continue
        start, end, flags = (int(v, 16) for v in match.groups())
        if start or end or flags:
            found.append(PciResource(index, start, end, flags))
    return tuple(found)


def slot_address(device_address: str) -> str:
    """Return the ``domain:bus:device`` a slot names, from a device's ``domain:bus:device.function``.

    Example:
        >>> slot_address("0000:00:15.0")
        '0000:00:15'
    """
    return device_address.rsplit(".", 1)[0]


__all__ = [
    "PciPlacement",
    "PciResource",
    "ResourceKind",
    "parse_pci_resources",
    "pci_placement",
    "slot_address",
]
