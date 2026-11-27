"""Typed sysfs leaves, and the identity of one PCI function, for the disks and network sections.

sysfs gives every value its own file, and which files exist depends on the driver: a SCSI disk
has ``vendor`` and ``vpd_pg83``, an NVMe namespace has ``nguid``, a virtio disk has neither.
:func:`read_leaves` lists a directory once and reads only the leaves it holds, each parsed as
what it is (a number, a 0/1 flag, text), so an absent leaf is simply not there while a leaf that
exists and cannot be read (root only) is a recorded error. Plain one-file reads live in
:mod:`.linux_files` and :mod:`.linux_values`; this module adds the typed parse.

Contents:
    * :class:`Leaf` - one leaf name and how to parse it.
    * :func:`stripped`, :func:`integer`, :func:`flag` - the parsers.
    * :func:`read_leaves` - every listed leaf a directory holds, each guarded.
    * :func:`pci_function` - the ids, driver and Device Serial Number of one PCI function.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..domain.machine_errors import NeedsRootError
from ..domain.pci_config import HEADER_BYTES, decode_capabilities, walk_capabilities
from .guard import guarded
from .linux_files import ATTRIBUTE_MAX_BYTES
from .linux_values import link_name, optional

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import LinuxSource

#: A PCI Express function's whole configuration space.
_CONFIG_BYTES = 4096


def stripped(raw: str) -> JsonValue:
    """Return a leaf's text without the trailing newline and padding."""
    return raw.strip()


def integer(raw: str) -> JsonValue:
    """Return a decimal leaf as a number.

    Raises:
        ValueError: the leaf is not a decimal number.
    """
    return int(raw.strip())


def flag(raw: str) -> JsonValue:
    """Return a ``0``/``1`` leaf as a boolean.

    Raises:
        ValueError: the leaf is neither.
    """
    value = raw.strip()
    if value not in {"0", "1"}:
        raise ValueError(f"not a 0/1 flag: {value!r}")
    return value == "1"


@dataclass(frozen=True, slots=True)
class Leaf:
    """One sysfs leaf: its file name and how its text becomes a value."""

    name: str
    parse: Callable[[str], JsonValue] = stripped


def read_leaves(src: LinuxSource, directory: str, leaves: Sequence[Leaf]) -> JsonObject:
    """Return every leaf of ``leaves`` that ``directory`` holds, each read guarded.

    Raises:
        SourceError: the directory itself cannot be listed.
    """
    present = set(src.list_dir(directory))
    return {
        leaf.name: guarded(
            lambda leaf=leaf: leaf.parse(src.read_text(f"{directory}/{leaf.name}", max_bytes=ATTRIBUTE_MAX_BYTES))
        )
        for leaf in leaves
        if leaf.name in present
    }


# sysfs writes PCI ids as 0x-prefixed lower-case hex, the form lspci and the PCI ID database use.
_PCI_IDS = tuple(
    Leaf(name) for name in ("vendor", "device", "subsystem_vendor", "subsystem_device", "class", "revision")
)


def _serial_number(src: LinuxSource, directory: str) -> JsonValue:
    """The DSN as the ``pci`` section writes it (``01-23-...``); None for a function without one."""
    path = f"{directory}/config"
    config = src.read_bytes(path, max_bytes=_CONFIG_BYTES)
    walk = walk_capabilities(config)
    if walk.unread_at is not None and len(config) <= HEADER_BYTES:
        raise NeedsRootError(f"{path}: the capabilities lie past the {len(config)} bytes read; only root reads them")
    return decode_capabilities(config, walk).get("device_serial_number")


def pci_function(src: LinuxSource, address: str) -> JsonObject:
    """Return the ids, class, revision, driver and Device Serial Number of a PCI function.

    The serial is written as the ``pci`` section writes it; ``None`` when the function has none.
    It lies past the first 64 bytes of the configuration space, so an unprivileged read records it
    as needing root.

    Raises:
        SourceError: the function's directory cannot be listed.
    """
    directory = f"/sys/bus/pci/devices/{address}"
    return {
        "address": address,
        **read_leaves(src, directory, _PCI_IDS),
        "driver": optional(lambda: link_name(src, f"{directory}/driver")),
        "device_serial_number": guarded(lambda: _serial_number(src, directory)),
    }


__all__ = ["Leaf", "flag", "integer", "pci_function", "read_leaves", "stripped"]
