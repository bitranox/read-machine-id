"""Small readers the Linux system sections share: one file, a set of files, a section of items.

Every value goes through :func:`~.guard.guarded`, so a file only root may read is one recorded
``NeedsRootError`` and its neighbours are still read. A file that does not exist is told apart:
for an attribute the kernel offers only on some machines (``cluster_id``, ``base_frequency``) its
absence is the answer, and the value is left out rather than recorded as an error.

Contents:
    * :data:`ATTRIBUTE_MAX_BYTES` - the cap on one sysfs or procfs attribute file.
    * :func:`text` - one file's text, stripped.
    * :func:`optional_text` - one file's text, or None when it does not exist.
    * :func:`optional_dir` - a directory's names, or none when it does not exist.
    * :func:`file_values` - several files of one directory, each guarded.
    * :func:`item_section` - a section of independent items, each guarded.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..domain.machine_errors import MissingPathError
from .guard import guarded

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import LinuxSource, LinuxSources

#: A sysfs attribute is at most a page; procfs text files here are small. 1 MiB bounds both.
ATTRIBUTE_MAX_BYTES = 1024 * 1024


def text(src: LinuxSource, path: str) -> str:
    """Return a text file's content with surrounding whitespace removed."""
    return src.read_text(path, max_bytes=ATTRIBUTE_MAX_BYTES).strip()


def optional_text(src: LinuxSource, path: str) -> str | None:
    """Return a text file's content stripped, or None when the file does not exist."""
    try:
        return text(src, path)
    except MissingPathError:
        return None


def optional_dir(src: LinuxSource, path: str) -> list[str]:
    """Return the names in a directory, or an empty list when it does not exist."""
    try:
        return src.list_dir(path)
    except MissingPathError:
        return []


def _present_value(src: LinuxSource, path: str) -> JsonValue:
    return guarded(lambda: optional_text(src, path))


def file_values(src: LinuxSource, directory: str, names: Iterable[str]) -> JsonObject:
    """Return each named file of ``directory`` by name, guarded; a file that does not exist is left out."""
    values: JsonObject = {}
    for name in names:
        value = _present_value(src, f"{directory}/{name}")
        if value is not None:
            values[name] = value
    return values


def item_section(src: LinuxSources, readers: Mapping[str, Callable[[LinuxSources], JsonValue]]) -> JsonObject:
    """Return a section of independent items: each reader's answer, or its error, by name."""
    return {name: guarded(lambda read=read: read(src)) for name, read in readers.items()}


__all__ = ["ATTRIBUTE_MAX_BYTES", "file_values", "item_section", "optional_dir", "optional_text", "text"]
