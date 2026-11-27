"""Small reads of sysfs and procfs values that the Linux section readers share.

Sysfs publishes one value per file; whether a file exists depends on the device (a conventional
PCI device has no link speed, a device without a driver has no ``driver`` link). :func:`optional`
answers such a value with None when its file does not exist, and records any other refusal (a
file only root may read) as an error in its place, as :func:`~.guard.guarded` does.

Contents:
    * :data:`SMALL_FILE` - the size cap for one-value files.
    * :func:`optional` - read a value that may legitimately be absent.
    * :func:`text_value` - a one-value file, stripped.
    * :func:`int_value` - a one-value file holding a decimal integer.
    * :func:`link_name` - the last path component a link points at.
    * :func:`numeric_names` - the numeric names in a directory, in numeric order.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..domain.machine_errors import MissingPathError
from .guard import guarded

if TYPE_CHECKING:
    from collections.abc import Callable

    from ..domain.json_types import JsonValue
    from .machine_ports import LinuxSource

#: One-value sysfs and procfs files are far below this; it caps a file that is not.
SMALL_FILE = 64 * 1024


def optional(read: Callable[[], JsonValue]) -> JsonValue:
    """Return ``read()``, None when what it reads does not exist, or the error that refused it.

    Examples:
        >>> optional(lambda: 3)
        3
    """

    def attempt() -> JsonValue:
        try:
            return read()
        except MissingPathError:
            return None

    return guarded(attempt)


def text_value(system: LinuxSource, path: str) -> str:
    """Return a one-value file's content without its trailing newline."""
    return system.read_text(path, max_bytes=SMALL_FILE).strip()


def int_value(system: LinuxSource, path: str) -> int:
    """Return a one-value file holding a decimal integer.

    Raises:
        ValueError: the content is not an integer.
    """
    return int(text_value(system, path))


def link_name(system: LinuxSource, path: str) -> str:
    """Return the last component of the path a link points at (a driver's or a group's name)."""
    return system.readlink(path).rstrip("/").rsplit("/", 1)[-1]


def numeric_names(system: LinuxSource, path: str) -> list[int]:
    """Return the names in a directory that are numbers (IRQs, groups), in numeric order."""
    return sorted(int(name) for name in system.list_dir(path) if name.isdigit())


__all__ = ["SMALL_FILE", "int_value", "link_name", "numeric_names", "optional", "text_value"]
