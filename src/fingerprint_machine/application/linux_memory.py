"""The ``memory`` section of a Linux reading: how much memory, and how it is laid out.

``/proc/meminfo`` (every counter, kilobytes in bytes; the free and cached counters change from one
read to the next), the hot-pluggable memory blocks (block size and each block's state), the NUMA
nodes (CPUs, size, distances) and the huge page sizes with their configured pools. The DIMMs
themselves (size, speed, serial) are in the ``smbios`` section, types 16, 17 and 19.

Contents:
    * :func:`read_linux_memory` - the section.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..domain.procfs import parse_choice, parse_meminfo
from .guard import guarded
from .linux_files import file_values, item_section, optional_dir, optional_text, text

if TYPE_CHECKING:
    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import LinuxSource, LinuxSources

_BLOCKS = "/sys/devices/system/memory"
_NODES = "/sys/devices/system/node"
_HUGEPAGES = "/sys/kernel/mm/hugepages"
_THP = "/sys/kernel/mm/transparent_hugepage"
_HEX = 16


def _meminfo(src: LinuxSources) -> JsonValue:
    return parse_meminfo(text(src.system, "/proc/meminfo"))


def _numbered(names: list[str], prefix: str) -> list[str]:
    found = [n for n in names if n.startswith(prefix) and n[len(prefix) :].isdigit()]
    return sorted(found, key=lambda n: int(n[len(prefix) :]))


def _blocks(src: LinuxSources) -> JsonValue:
    names = optional_dir(src.system, _BLOCKS)
    if not names:
        return None
    size = guarded(lambda: int(text(src.system, f"{_BLOCKS}/block_size_bytes"), _HEX))
    states: JsonObject = {
        name: guarded(lambda name=name: text(src.system, f"{_BLOCKS}/{name}/state"))
        for name in _numbered(names, "memory")
    }
    return {
        "block_size_bytes": size,
        **file_values(src.system, _BLOCKS, ("auto_online_blocks",)),
        "states": states,
    }


def _node(src: LinuxSource, name: str) -> JsonObject:
    base = f"{_NODES}/{name}"
    number = name.removeprefix("node")
    meminfo = parse_meminfo(text(src, f"{base}/meminfo"))
    return {
        "node": int(number),
        **file_values(src, base, ("cpulist", "distance")),
        "mem_total": meminfo.get(f"Node {number} MemTotal"),
    }


def _numa(src: LinuxSources) -> JsonValue:
    nodes: list[JsonValue] = [
        guarded(lambda name=name: _node(src.system, name))
        for name in _numbered(optional_dir(src.system, _NODES), "node")
    ]
    return nodes


def _hugepages(src: LinuxSources) -> JsonValue:
    pools: JsonObject = {
        name.removeprefix("hugepages-"): file_values(
            src.system, f"{_HUGEPAGES}/{name}", ("nr_hugepages", "nr_overcommit_hugepages")
        )
        for name in optional_dir(src.system, _HUGEPAGES)
        if name.startswith("hugepages-")
    }
    thp: JsonObject = {}
    for name in ("enabled", "defrag"):
        value = guarded(lambda name=name: optional_text(src.system, f"{_THP}/{name}"))
        if isinstance(value, str):
            thp[name] = parse_choice(value)
        elif value is not None:
            thp[name] = value
    return {"pools": pools, "transparent": thp}


def read_linux_memory(src: LinuxSources) -> JsonValue:
    """Read the ``memory`` section, each item guarded."""
    return item_section(
        src,
        {"meminfo": _meminfo, "blocks": _blocks, "numa": _numa, "hugepages": _hugepages},
    )


__all__ = ["read_linux_memory"]
