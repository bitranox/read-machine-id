"""The kernel's text tables of resources and modules: ``/proc/iomem``, ``ioports``, ``dma``, ``modules``.

Each table is parsed one line at a time, in the layout the kernel prints it:

* ``/proc/iomem`` and ``/proc/ioports`` (``r_show`` in ``kernel/resource.c``): ``<start>-<end> :
  <name>``, indented two spaces per level of the resource tree. Only root sees the addresses; for
  anyone else the kernel prints every range as zero, which :func:`addresses_hidden` recognises.
* ``/proc/dma`` (``kernel/dma.c``): ``<channel>: <name>``.
* ``/proc/modules`` (``kernel/module/procfs.c``): ``<name> <size> <refcount> <used by,> <state>
  <address> [(<taints>)]``. The load address is left out: it moves with every boot (KASLR) and is
  zero for anyone but root.

Which resources the firmware hands out and which kernel modules a guest loads (``vmw_pvscsi``,
``virtio_net``, ``hv_vmbus``) identify the machine and its hypervisor.

Contents:
    * :class:`ResourceEntry`, :func:`parse_resource_tree`, :func:`addresses_hidden`.
    * :class:`DmaChannel`, :func:`parse_dma`.
    * :class:`KernelModule`, :func:`parse_modules`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .json_types import JsonObject, JsonValue

_RANGE = re.compile(r"^( *)([0-9a-fA-F]+)-([0-9a-fA-F]+) : (.*)$")
_DMA = re.compile(r"^\s*(\d+):\s*(.*)$")
_TAINTS = re.compile(r"\((\w+)\)\s*$")
_INDENT = 2
_MODULE_FIELDS = 5


@dataclass(frozen=True, slots=True)
class ResourceEntry:
    """One range of a resource tree: its depth in the tree, its bounds and its owner's name."""

    depth: int
    start: int
    end: int
    name: str

    def as_json(self, *, with_addresses: bool) -> JsonObject:
        """Return the entry, with its bounds only when they are real (not hidden as zero)."""
        entry: JsonObject = {"depth": self.depth, "name": self.name}
        if with_addresses:
            entry |= {"start": hex(self.start), "end": hex(self.end)}
        return entry


def parse_resource_tree(text: str) -> tuple[ResourceEntry, ...]:
    """Parse ``/proc/iomem`` or ``/proc/ioports``; a line that is not a range is skipped.

    Example:
        >>> parse_resource_tree("  0070-0077 : rtc0\\n")[0].depth
        1
    """
    entries: list[ResourceEntry] = []
    for line in text.splitlines():
        match = _RANGE.match(line)
        if match is not None:
            indent, start, end, name = match.groups()
            entries.append(ResourceEntry(len(indent) // _INDENT, int(start, 16), int(end, 16), name))
    return tuple(entries)


def addresses_hidden(entries: Iterable[ResourceEntry]) -> bool:
    """Whether the kernel printed every range as zero: it does so for a reader that is not root.

    Example:
        >>> addresses_hidden([ResourceEntry(0, 0, 0, "PCI Bus 0000:00")])
        True
    """
    seen = False
    for entry in entries:
        if entry.start or entry.end:
            return False
        seen = True
    return seen


@dataclass(frozen=True, slots=True)
class DmaChannel:
    """One ISA DMA channel in use and who holds it."""

    channel: int
    name: str

    def as_json(self) -> JsonObject:
        """Return the channel as a reading records it."""
        return {"channel": self.channel, "name": self.name}


def parse_dma(text: str) -> tuple[DmaChannel, ...]:
    """Parse ``/proc/dma``.

    Example:
        >>> parse_dma(" 4: cascade\\n")[0].name
        'cascade'
    """
    found = (_DMA.match(line) for line in text.splitlines())
    return tuple(DmaChannel(int(m.group(1)), m.group(2).strip()) for m in found if m is not None)


@dataclass(frozen=True, slots=True)
class KernelModule:
    """One loaded kernel module."""

    name: str
    size: int
    refcount: int | None
    used_by: tuple[str, ...]
    state: str
    taints: str | None

    def as_json(self) -> JsonObject:
        """Return the module as a reading records it."""
        used_by: list[JsonValue] = list(self.used_by)
        return {
            "name": self.name,
            "size": self.size,
            "refcount": self.refcount,
            "used_by": used_by,
            "state": self.state,
            "taints": self.taints,
        }


def _module(line: str) -> KernelModule | None:
    fields = line.split()
    if len(fields) < _MODULE_FIELDS or not fields[1].isdigit():
        return None
    name, size, refcount, users, state = fields[:_MODULE_FIELDS]
    taints = _TAINTS.search(line)
    return KernelModule(
        name=name,
        size=int(size),
        refcount=int(refcount) if refcount.isdigit() else None,
        used_by=tuple(u for u in users.split(",") if u and u != "-"),
        state=state,
        taints=taints.group(1) if taints else None,
    )


def parse_modules(text: str) -> tuple[KernelModule, ...]:
    """Parse ``/proc/modules``; a line of another shape is skipped.

    Example:
        >>> parse_modules("virtio_net 69632 0 - Live 0x0\\n")[0].name
        'virtio_net'
    """
    found = (_module(line) for line in text.splitlines())
    return tuple(m for m in found if m is not None)


__all__ = [
    "DmaChannel",
    "KernelModule",
    "ResourceEntry",
    "addresses_hidden",
    "parse_dma",
    "parse_modules",
    "parse_resource_tree",
]
