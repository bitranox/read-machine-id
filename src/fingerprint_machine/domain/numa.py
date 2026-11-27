"""A NUMA node as Windows describes it: its number and the processors it holds.

Windows numbers logical processors per processor group (at most 64 in a group); a node's
processors are one group and a bit mask within it (``GetNumaNodeProcessorMaskEx``). Windows
client editions have no ``Win32_NumaNode`` class, so the reading asks kernel32 directly.

Contents:
    * :class:`NumaNode` - one node.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .json_types import JsonObject, JsonValue

_GROUP_SIZE = 64


@dataclass(frozen=True, slots=True)
class NumaNode:
    """One NUMA node: its number, its processor group and the mask of its processors in the group."""

    node: int
    group: int
    mask: int

    def as_json(self) -> JsonObject:
        """Return the node as a reading records it, the processors listed by their number in the group.

        Example:
            >>> NumaNode(node=0, group=0, mask=0b1011).as_json()["processors"]
            [0, 1, 3]
        """
        processors: list[JsonValue] = [bit for bit in range(_GROUP_SIZE) if self.mask >> bit & 1]
        return {
            "node": self.node,
            "processor_group": self.group,
            "processor_mask": f"0x{self.mask:x}",
            "processors": processors,
        }


__all__ = ["NumaNode"]
