"""The ``cpuid`` section: every leaf asked, each answer recorded raw, then decoded.

The same on Windows and Linux; only the :class:`CpuidSource` behind it differs. Leaf 0 is asked
unguarded: if the CPU cannot be asked at all (not x86-64, executable memory refused), the whole
section records that one error. Every later leaf is guarded on its own, so one failing leaf is one
recorded error and the rest is still read.

Contents:
    * :func:`read_cpuid` - read the section.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..domain.cpuid import (
    HYPERVISOR_BASES,
    CpuidQuery,
    basic_queries,
    decode_cpuid,
    extended_queries,
    hypervisor_answers,
    hypervisor_queries,
    leaf7_subqueries,
)
from .guard import guarded

if TYPE_CHECKING:
    from ..domain.cpuid import CpuidRegs
    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import CpuidSource, MachineSources

_FIRST_HYPERVISOR_BASE = HYPERVISOR_BASES[0]


class _Asker:
    """Asks the CPU, keeps each answer, and records every leaf read (or its error) raw."""

    def __init__(self, cpu: CpuidSource) -> None:
        self._cpu = cpu
        self.answers: dict[CpuidQuery, CpuidRegs] = {}
        self.raw: JsonObject = {}

    def _read(self, query: CpuidQuery) -> CpuidRegs:
        regs = self._cpu.cpuid(query.leaf, subleaf=query.subleaf)
        self.answers[query] = regs
        return regs

    def first(self, query: CpuidQuery) -> CpuidRegs:
        """Ask unguarded: a failure here fails the section."""
        regs = self._read(query)
        self.raw[query.key] = regs.as_json()
        return regs

    def ask(self, query: CpuidQuery) -> CpuidRegs | None:
        """Ask guarded; record the answer or the error under the query's key."""
        self.raw[query.key] = guarded(lambda: self._read(query).as_json())
        return self.answers.get(query)

    def ask_all(self, queries: list[CpuidQuery]) -> None:
        for query in queries:
            self.ask(query)

    def probe(self, base: int) -> CpuidRegs | None:
        """Ask a hypervisor base leaf past the first; record it only if it answers (or fails)."""
        query = CpuidQuery(base)
        answer = guarded(lambda: self._read(query).as_json())
        regs = self.answers.get(query)
        if regs is None:
            self.raw[query.key] = answer
            return None
        if not hypervisor_answers(base, regs):
            del self.answers[query]
            return None
        self.raw[query.key] = answer
        return regs


def _hypervisor_leaves(asker: _Asker) -> None:
    for base in HYPERVISOR_BASES:
        regs = asker.ask(CpuidQuery(base)) if base == _FIRST_HYPERVISOR_BASE else asker.probe(base)
        if regs is not None and hypervisor_answers(base, regs):
            asker.ask_all(hypervisor_queries(base, regs))


def read_cpuid(src: MachineSources) -> JsonValue:
    """Read the CPUID leaves that identify the CPU and the hypervisor; decoded, then raw.

    Raw holds every leaf read, keyed ``0x<leaf>:<subleaf>``, except hypervisor base probes past
    ``0x40000000`` that carry no signature (on most machines all 255 of them).
    """
    asker = _Asker(src.cpuid)
    leaf0 = asker.first(CpuidQuery(0))
    asker.ask_all(basic_queries(leaf0))
    leaf7 = asker.answers.get(CpuidQuery(7))
    if leaf7 is not None:
        asker.ask_all(leaf7_subqueries(leaf7))
    ext0 = asker.ask(CpuidQuery(0x80000000))
    if ext0 is not None:
        asker.ask_all(extended_queries(ext0))
    _hypervisor_leaves(asker)
    return {**decode_cpuid(asker.answers), "raw": asker.raw}


__all__ = ["read_cpuid"]
