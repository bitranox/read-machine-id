"""``/proc/interrupts``: which interrupt controller and which handler sits behind each IRQ.

The table is what ``show_interrupts()`` in Linux's ``kernel/irq/proc.c`` prints: a header naming
the online CPUs, then one row per interrupt - ``<irq>:``, one count per CPU, the chip name
(``IO-APIC``, ``PCI-MSIX-0000:03:00.0``), ``<hwirq>-<edge|level>`` and the actions (the
drivers' handler names) - and the architecture's named counters (``NMI:``, ``LOC:``, ``ERR:``).
Kernels before 4.x print ``<chip>-<edge|level>`` with no hwirq; such a row keeps chip and actions
and leaves hwirq and trigger unknown.

The chip and action names say which interrupt controller and which drivers the machine has (an
emulated IO-APIC, MSI-X vectors of a paravirtual controller), so they are a fingerprint. The
per-CPU counts grow all the time; they are kept under ``per_cpu_counts`` so a comparison can
treat that key as volatile.

Contents:
    * :class:`InterruptRow` - one row of the table.
    * :class:`InterruptTable` - the CPUs and every row.
    * :func:`parse_interrupts` - parse the table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from .json_types import JsonObject

_ROW = re.compile(r"^\s*([^\s:]+):(.*)$")
_COUNT = re.compile(r"\s*(\d+)(?=\s|$)")
_SOURCE = re.compile(r"^(\S+)\s+(\d+)-(edge|level)\b\s*(.*)$", re.IGNORECASE)
_CHIP_ONLY = re.compile(r"^(\S+)\s*(.*)$")


@dataclass(frozen=True, slots=True)
class InterruptRow:
    """One row: a numbered interrupt (``24``) or a named counter (``NMI``)."""

    name: str
    per_cpu_counts: tuple[int, ...]
    chip: str | None = None
    hwirq: str | None = None
    trigger: str | None = None
    actions: tuple[str, ...] = ()
    description: str | None = None

    @property
    def irq(self) -> int | None:
        """The interrupt number, or None for a named counter."""
        return int(self.name) if self.name.isdigit() else None

    def as_json(self) -> JsonObject:
        """Return the row as a reading records it.

        Example:
            >>> InterruptRow("NMI", (1,), description="Non-maskable interrupts").as_json()["irq"] is None
            True
        """
        return {
            "irq": self.irq,
            "name": self.name,
            "per_cpu_counts": list(self.per_cpu_counts),
            "chip": self.chip,
            "hwirq": self.hwirq,
            "trigger": self.trigger,
            "actions": list(self.actions),
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class InterruptTable:
    """The CPUs the table counts for and every row, in file order."""

    cpus: tuple[str, ...]
    rows: tuple[InterruptRow, ...]

    def by_irq(self) -> Mapping[int, InterruptRow]:
        """Return the numbered rows by interrupt number."""
        return {row.irq: row for row in self.rows if row.irq is not None}

    def named(self) -> list[InterruptRow]:
        """Return the named counters (``NMI``, ``LOC``, ...), in file order."""
        return [row for row in self.rows if row.irq is None]


class _Counts(NamedTuple):
    """The per-CPU counts at the start of a row, and the text that follows them."""

    counts: tuple[int, ...]
    rest: str


def _counts(text: str, limit: int) -> _Counts:
    """Up to ``limit`` leading counts of ``text``, and what follows them."""
    counts: list[int] = []
    position = 0
    while len(counts) < limit and (match := _COUNT.match(text, position)) is not None:
        counts.append(int(match.group(1)))
        position = match.end()
    return _Counts(counts=tuple(counts), rest=text[position:].strip())


def _actions(text: str) -> tuple[str, ...]:
    return tuple(a.strip() for a in text.split(", ") if a.strip())


def _numbered(name: str, counts: tuple[int, ...], rest: str) -> InterruptRow:
    if (source := _SOURCE.match(rest)) is not None:
        chip, hwirq, trigger, actions = source.groups()
        return InterruptRow(name, counts, chip, hwirq, trigger.lower(), _actions(actions))
    chip_only = _CHIP_ONLY.match(rest)
    if chip_only is None:
        return InterruptRow(name, counts)
    return InterruptRow(name, counts, chip_only.group(1), actions=_actions(chip_only.group(2)))


def _rows(lines: Iterator[str], cpus: int) -> Iterator[InterruptRow]:
    for line in lines:
        match = _ROW.match(line)
        if match is None:
            continue
        name, rest = match.groups()
        row = _counts(rest, cpus)
        if name.isdigit():
            yield _numbered(name, row.counts, row.rest)
        else:
            yield InterruptRow(name, row.counts, description=row.rest or None)


def parse_interrupts(text: str) -> InterruptTable:
    """Parse ``/proc/interrupts``, one line at a time.

    Raises:
        ValueError: the first line is not the header of CPU names.

    Example:
        >>> parse_interrupts("   CPU0\\n  1:  9  IO-APIC  1-edge  i8042\\n").by_irq()[1].chip
        'IO-APIC'
    """
    lines = iter(text.splitlines())
    header = next(lines, "").split()
    if not header or not all(cpu.startswith("CPU") for cpu in header):
        raise ValueError("/proc/interrupts does not start with the header of CPU names")
    return InterruptTable(cpus=tuple(header), rows=tuple(_rows(lines, len(header))))


__all__ = ["InterruptRow", "InterruptTable", "parse_interrupts"]
