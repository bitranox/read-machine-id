"""Collect the sections of a Linux reading.

Each section is read on its own and guarded, as on Windows. A section this tool does not read on
Linux (yet) records a :class:`SourceError` in its place, so asking for it is visible in
``skipped`` instead of silently missing.

Contents:
    * :data:`LINUX_SECTIONS` - the sections a Linux reading holds, each with its reader.
    * :func:`read_linux_section` - read one section.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..domain.machine_errors import SourceError
from .collect_cpuid import read_cpuid
from .guard import guarded
from .sections import Section

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from ..domain.json_types import JsonValue
    from .machine_ports import LinuxSources

#: The sections of a Linux reading, in document order, each read as one piece.
LINUX_SECTIONS: Mapping[Section, Callable[[LinuxSources], JsonValue]] = {
    Section.CPUID: read_cpuid,
}


def _not_read(section: Section) -> JsonValue:
    raise SourceError(f"the {section.value} section is not read on Linux")


def read_linux_section(src: LinuxSources, section: Section) -> JsonValue:
    """Read one section of a Linux reading, guarded."""
    reader = LINUX_SECTIONS.get(section)
    if reader is None:
        return guarded(lambda: _not_read(section))
    return guarded(lambda: reader(src))


__all__ = ["LINUX_SECTIONS", "read_linux_section"]
