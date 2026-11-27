"""CPUID: which leaves to ask, and what their registers say.

The CPU's own answers (vendor, family/model/stepping, brand string, feature bits) and the
hypervisor leaves are the strongest sign of which hypervisor a guest runs under: a hypervisor
answers leaf ``0x40000000`` with its signature ("VMwareVMware", "KVMKVMKVM", "Microsoft Hv") and
sets bit 31 of leaf 1 ECX. Both can be hidden or changed, which is exactly why they are recorded.

Layouts follow the Intel SDM vol. 2A ("CPUID") and the AMD APM vol. 3 ("CPUID"). Feature bits are
named as the Linux kernel names them (``arch/x86/include/asm/cpufeatures.h``), the names
``/proc/cpuinfo`` shows, so a reading compares with that file directly. A set bit without a name
here is kept as ``bit<N>``, so nothing the CPU reports is dropped.

The hypervisor range is scanned base by base (``0x40000000``, ``0x40000100``, ... as Linux's
``hypervisor_cpuid_base`` does): a KVM guest with Hyper-V enlightenments answers "Microsoft Hv" at
the first base and its own "KVMKVMKVM" at a later one, and only that second base tells it apart
from real Hyper-V.

Contents:
    * :class:`CpuidRegs` - the four registers one CPUID returns.
    * :class:`CpuidQuery` - one leaf and sub-leaf to ask.
    * :data:`HYPERVISOR_BASES` - the hypervisor base leaves to probe.
    * :func:`basic_queries`, :func:`leaf7_subqueries`, :func:`extended_queries`,
      :func:`hypervisor_queries` - the leaves to ask next, from the answers so far.
    * :func:`hypervisor_answers` - whether a base leaf carries a hypervisor signature.
    * :func:`decode_cpuid` - the decoded view of every answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from .json_types import JsonObject, JsonValue


@dataclass(frozen=True, slots=True)
class CpuidRegs:
    """The four 32-bit registers one CPUID instruction returns."""

    eax: int
    ebx: int
    ecx: int
    edx: int

    def as_json(self) -> JsonObject:
        """Return the registers as fixed-width hex strings.

        Example:
            >>> CpuidRegs(eax=0xD, ebx=0, ecx=0, edx=1).as_json()["eax"]
            '0x0000000d'
        """
        return {"eax": _hex(self.eax), "ebx": _hex(self.ebx), "ecx": _hex(self.ecx), "edx": _hex(self.edx)}


@dataclass(frozen=True, slots=True, order=True)
class CpuidQuery:
    """One leaf (EAX) and sub-leaf (ECX) to ask CPUID."""

    leaf: int
    subleaf: int = 0

    @property
    def key(self) -> str:
        """The query as a reading names it: ``"0x<leaf>:<subleaf>"``.

        Example:
            >>> CpuidQuery(7, 1).key
            '0x00000007:1'
        """
        return f"{_hex(self.leaf)}:{self.subleaf}"


_EXTENDED = 0x80000000
_HYPERVISOR = 0x40000000
#: The highest basic and extended leaves read: the ones whose meaning is identity, not topology.
_LAST_EXTENDED = 0x80000008
#: Leaf 7 sub-leaves read at most (0 to 3 are defined today).
_LAST_LEAF7_SUBLEAF = 3
#: Leaves one hypervisor base may span (base to base + 0xFF).
_HYPERVISOR_SPAN = 0xFF
_HYPERVISOR_BIT = 31

#: Every hypervisor base leaf probed, as Linux's ``hypervisor_cpuid_base`` walks them.
HYPERVISOR_BASES: tuple[int, ...] = tuple(range(_HYPERVISOR, 0x40010000, 0x100))

#: The basic leaves read when the CPU has them, with their sub-leaves.
_BASIC: tuple[CpuidQuery, ...] = (CpuidQuery(1), CpuidQuery(7), CpuidQuery(0x0D), CpuidQuery(0x0D, 1))

_NAMES_1_ECX = (
    "pni", "pclmulqdq", "dtes64", "monitor", "ds_cpl", "vmx", "smx", "est",
    "tm2", "ssse3", "cid", "sdbg", "fma", "cx16", "xtpr", "pdcm",
    "", "pcid", "dca", "sse4_1", "sse4_2", "x2apic", "movbe", "popcnt",
    "tsc_deadline_timer", "aes", "xsave", "osxsave", "avx", "f16c", "rdrand", "hypervisor",
)  # fmt: skip
_NAMES_1_EDX = (
    "fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce",
    "cx8", "apic", "", "sep", "mtrr", "pge", "mca", "cmov",
    "pat", "pse36", "pn", "clflush", "", "dts", "acpi", "mmx",
    "fxsr", "sse", "sse2", "ss", "ht", "tm", "ia64", "pbe",
)  # fmt: skip
_NAMES_7_EBX = (
    "fsgsbase", "tsc_adjust", "sgx", "bmi1", "hle", "avx2", "fdp_excptn_only", "smep",
    "bmi2", "erms", "invpcid", "rtm", "cqm", "zero_fcs_fds", "mpx", "rdt_a",
    "avx512f", "avx512dq", "rdseed", "adx", "smap", "avx512ifma", "pcommit", "clflushopt",
    "clwb", "intel_pt", "avx512pf", "avx512er", "avx512cd", "sha_ni", "avx512bw", "avx512vl",
)  # fmt: skip
_NAMES_7_ECX = (
    "prefetchwt1", "avx512vbmi", "umip", "pku", "ospke", "waitpkg", "avx512_vbmi2", "shstk",
    "gfni", "vaes", "vpclmulqdq", "avx512_vnni", "avx512_bitalg", "tme", "avx512_vpopcntdq", "",
    "la57", "", "", "", "", "", "rdpid", "kl",
    "bus_lock_detect", "cldemote", "", "movdiri", "movdir64b", "enqcmd", "sgx_lc", "pks",
)  # fmt: skip
_NAMES_7_EDX = (
    "", "sgx_keys", "avx512_4vnniw", "avx512_4fmaps", "fsrm", "uintr", "", "",
    "avx512_vp2intersect", "srbds_ctrl", "md_clear", "rtm_always_abort",
    "", "tsx_force_abort", "serialize", "hybrid_cpu",
    "tsxldtrk", "", "pconfig", "arch_lbr", "ibt", "", "amx_bf16", "avx512_fp16",
    "amx_tile", "amx_int8", "spec_ctrl", "intel_stibp",
    "flush_l1d", "arch_capabilities", "core_capabilities", "spec_ctrl_ssbd",
)  # fmt: skip
_NAMES_E1_ECX = (
    "lahf_lm", "cmp_legacy", "svm", "extapic", "cr8_legacy", "abm", "sse4a", "misalignsse",
    "3dnowprefetch", "osvw", "ibs", "xop", "skinit", "wdt", "", "lwp",
    "fma4", "tce", "", "nodeid_msr", "", "tbm", "topoext", "perfctr_core",
    "perfctr_nb", "", "bpext", "ptsc", "perfctr_llc", "mwaitx", "", "",
)  # fmt: skip
# Bits of 0x80000001 EDX that repeat leaf 1 EDX on AMD are left unnamed, as Linux leaves them.
_NAMES_E1_EDX = (
    "", "", "", "", "", "", "", "",
    "", "", "", "syscall", "", "", "", "",
    "", "", "", "mp", "nx", "", "mmxext", "",
    "", "fxsr_opt", "pdpe1gb", "rdtscp", "", "lm", "3dnowext", "3dnow",
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class _FeatureWord:
    """One register of one leaf whose bits are feature flags."""

    name: str
    query: CpuidQuery
    register: str
    names: Sequence[str]


_FEATURE_WORDS: tuple[_FeatureWord, ...] = (
    _FeatureWord("leaf_1_ecx", CpuidQuery(1), "ecx", _NAMES_1_ECX),
    _FeatureWord("leaf_1_edx", CpuidQuery(1), "edx", _NAMES_1_EDX),
    _FeatureWord("leaf_7_ebx", CpuidQuery(7), "ebx", _NAMES_7_EBX),
    _FeatureWord("leaf_7_ecx", CpuidQuery(7), "ecx", _NAMES_7_ECX),
    _FeatureWord("leaf_7_edx", CpuidQuery(7), "edx", _NAMES_7_EDX),
    _FeatureWord("leaf_80000001_ecx", CpuidQuery(_EXTENDED + 1), "ecx", _NAMES_E1_ECX),
    _FeatureWord("leaf_80000001_edx", CpuidQuery(_EXTENDED + 1), "edx", _NAMES_E1_EDX),
)


def _hex(value: int) -> str:
    return f"0x{value:08x}"


def _bytes(*registers: int) -> bytes:
    return b"".join(r.to_bytes(4, "little") for r in registers)


def _printable(data: bytes) -> str:
    """The bytes as text: printable ASCII as is, anything else as ``\\xNN``."""
    return "".join(chr(c) if 0x20 <= c < 0x7F else f"\\x{c:02x}" for c in data)  # noqa: PLR2004 - ASCII bounds


def _signature(regs: CpuidRegs) -> bytes:
    # A hypervisor base leaf spells its signature in EBX, ECX, EDX; short ones are NUL-padded.
    return _bytes(regs.ebx, regs.ecx, regs.edx).rstrip(b"\0")


def basic_queries(leaf0: CpuidRegs) -> list[CpuidQuery]:
    """Return the basic leaves to ask, given leaf 0 (whose EAX is the highest basic leaf).

    Example:
        >>> basic_queries(CpuidRegs(eax=1, ebx=0, ecx=0, edx=0))
        [CpuidQuery(leaf=1, subleaf=0)]
    """
    return [q for q in _BASIC if q.leaf <= leaf0.eax]


def leaf7_subqueries(leaf7: CpuidRegs) -> list[CpuidQuery]:
    """Return the leaf 7 sub-leaves past 0 to ask, given sub-leaf 0 (EAX: the highest sub-leaf).

    Example:
        >>> leaf7_subqueries(CpuidRegs(eax=1, ebx=0, ecx=0, edx=0))
        [CpuidQuery(leaf=7, subleaf=1)]
    """
    return [CpuidQuery(7, n) for n in range(1, min(leaf7.eax, _LAST_LEAF7_SUBLEAF) + 1)]


def extended_queries(ext0: CpuidRegs) -> list[CpuidQuery]:
    """Return the extended leaves to ask, given leaf ``0x80000000`` (EAX: the highest one).

    A CPU without extended leaves answers with a value below ``0x80000001``: nothing to ask.

    Example:
        >>> extended_queries(CpuidRegs(eax=0x80000001, ebx=0, ecx=0, edx=0))
        [CpuidQuery(leaf=2147483649, subleaf=0)]
    """
    last = min(ext0.eax, _LAST_EXTENDED) if ext0.eax > _EXTENDED else _EXTENDED
    return [CpuidQuery(leaf) for leaf in range(_EXTENDED + 1, last + 1)]


def hypervisor_answers(base: int, regs: CpuidRegs) -> bool:
    """Return whether a hypervisor base leaf carries a signature: non-empty, printable ASCII.

    A CPU with no hypervisor answers a leaf past its maximum with some other leaf's data (Intel)
    or zeros (AMD), which never reads as a printable signature.

    Example:
        >>> hypervisor_answers(0x40000000, CpuidRegs(eax=0, ebx=0, ecx=0, edx=0))
        False
    """
    del base  # every base is judged by its signature alone
    signature = _signature(regs)
    return bool(signature) and all(0x20 <= c < 0x7F for c in signature)  # noqa: PLR2004 - ASCII bounds


def hypervisor_queries(base: int, regs: CpuidRegs) -> list[CpuidQuery]:
    """Return the leaves after a hypervisor base leaf to ask: up to its maximum, capped at base + 0xFF.

    A maximum of 0 means only the next leaf (older KVM); one at or below the base means none.

    Example:
        >>> hypervisor_queries(0x40000000, CpuidRegs(eax=0x40000002, ebx=0, ecx=0, edx=0))
        [CpuidQuery(leaf=1073741825, subleaf=0), CpuidQuery(leaf=1073741826, subleaf=0)]
    """
    if regs.eax == 0:
        return [CpuidQuery(base + 1)]
    last = min(regs.eax, base + _HYPERVISOR_SPAN)
    return [CpuidQuery(leaf) for leaf in range(base + 1, last + 1)]


def _flags(names: Sequence[str], value: int) -> list[JsonValue]:
    return [names[bit] or f"bit{bit}" for bit in range(32) if value >> bit & 1]


def _features(answers: Mapping[CpuidQuery, CpuidRegs]) -> JsonObject:
    out: JsonObject = {}
    for word in _FEATURE_WORDS:
        regs = answers.get(word.query)
        out[word.name] = None if regs is None else _flags(word.names, getattr(regs, word.register))
    return out


def _vendor(answers: Mapping[CpuidQuery, CpuidRegs]) -> JsonObject:
    leaf0 = answers.get(CpuidQuery(0))
    if leaf0 is None:
        return {"vendor": None, "max_basic_leaf": None}
    # Leaf 0 spells the vendor in EBX, EDX, ECX - not the hypervisor leaves' order.
    vendor = _printable(_bytes(leaf0.ebx, leaf0.edx, leaf0.ecx).rstrip(b"\0"))
    return {"vendor": vendor, "max_basic_leaf": _hex(leaf0.eax)}


def _signature_fields(leaf1: CpuidRegs | None) -> JsonObject:
    if leaf1 is None:
        return {"signature": None, "family": None, "model": None, "stepping": None, "logical_processor_count": None}
    eax = leaf1.eax
    base_family, base_model = eax >> 8 & 0xF, eax >> 4 & 0xF
    family = base_family + (eax >> 20 & 0xFF) if base_family == 0xF else base_family  # noqa: PLR2004 - SDM rule
    model = base_model + ((eax >> 16 & 0xF) << 4) if base_family in (6, 0xF) else base_model
    return {
        "signature": _hex(eax),
        "family": family,
        "model": model,
        "stepping": eax & 0xF,
        "logical_processor_count": leaf1.ebx >> 16 & 0xFF,
    }


def _brand(answers: Mapping[CpuidQuery, CpuidRegs]) -> str | None:
    parts = [answers.get(CpuidQuery(leaf)) for leaf in (0x80000002, 0x80000003, 0x80000004)]
    if any(p is None for p in parts):
        return None
    raw = b"".join(_bytes(p.eax, p.ebx, p.ecx, p.edx) for p in parts if p is not None)
    return _printable(raw.split(b"\0", 1)[0]).strip()


def _hypervisors(answers: Mapping[CpuidQuery, CpuidRegs]) -> list[JsonValue]:
    found: list[JsonValue] = []
    for base in HYPERVISOR_BASES:
        regs = answers.get(CpuidQuery(base))
        if regs is not None and hypervisor_answers(base, regs):
            found.append({"base": _hex(base), "vendor": _printable(_signature(regs)), "max_leaf": _hex(regs.eax)})
    return found


def decode_cpuid(answers: Mapping[CpuidQuery, CpuidRegs]) -> JsonObject:
    """Return what the answers say: vendor, signature, brand, feature names, hypervisors.

    A leaf missing from ``answers`` (not asked, or its question failed) leaves its fields None.

    Example:
        >>> leaf0 = CpuidRegs(eax=1, ebx=0x756E6547, ecx=0x6C65746E, edx=0x49656E69)
        >>> decode_cpuid({CpuidQuery(0): leaf0})["vendor"]
        'GenuineIntel'
    """
    leaf1 = answers.get(CpuidQuery(1))
    ext0 = answers.get(CpuidQuery(_EXTENDED))
    hypervisors = _hypervisors(answers)
    first = hypervisors[0] if hypervisors else None
    return {
        **_vendor(answers),
        "max_extended_leaf": _hex(ext0.eax) if ext0 is not None and ext0.eax > _EXTENDED else None,
        **_signature_fields(leaf1),
        "brand": _brand(answers),
        "features": _features(answers),
        "hypervisor_present_bit": None if leaf1 is None else bool(leaf1.ecx >> _HYPERVISOR_BIT & 1),
        "hypervisor_vendor": first.get("vendor") if isinstance(first, dict) else None,
        "hypervisors": hypervisors,
    }


__all__ = [
    "HYPERVISOR_BASES",
    "CpuidQuery",
    "CpuidRegs",
    "basic_queries",
    "decode_cpuid",
    "extended_queries",
    "hypervisor_answers",
    "hypervisor_queries",
    "leaf7_subqueries",
]
