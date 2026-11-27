"""The real CPUID adapter: machine code in an executable page, called through ctypes."""

from __future__ import annotations

import platform
from pathlib import Path

import pytest

from fingerprint_machine.adapters.cpuid import CpuidOff, NativeCpuid
from fingerprint_machine.domain.machine_errors import SourceError

_X86_64 = platform.machine().lower() in {"x86_64", "amd64"}


def _vendor(cpu: NativeCpuid) -> str:
    leaf0 = cpu.cpuid(0)
    return b"".join(r.to_bytes(4, "little") for r in (leaf0.ebx, leaf0.edx, leaf0.ecx)).decode("ascii")


@pytest.mark.os_agnostic
@pytest.mark.parametrize("machine", ["aarch64", "arm64", "i686"])
def test_a_cpu_that_is_not_x86_64_is_refused(machine: str) -> None:
    with pytest.raises(SourceError, match="x86-64"):
        NativeCpuid(machine=machine).cpuid(0)


@pytest.mark.os_agnostic
def test_an_os_without_a_page_mapper_is_refused() -> None:
    with pytest.raises(SourceError, match="Windows or Linux"):
        NativeCpuid(machine="x86_64", system="darwin").cpuid(0)


@pytest.mark.os_agnostic
def test_cpuid_off_refuses_every_leaf() -> None:
    with pytest.raises(SourceError, match="--no-cpuid"):
        CpuidOff().cpuid(0x40000000, subleaf=0)


@pytest.mark.os_linux
@pytest.mark.skipif(not _X86_64, reason="CPUID exists only on x86")
def test_leaf_0_vendor_matches_proc_cpuinfo() -> None:
    cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    expected = next(line.split(":", 1)[1].strip() for line in cpuinfo.splitlines() if line.startswith("vendor_id"))
    assert _vendor(NativeCpuid()) == expected


@pytest.mark.os_windows
@pytest.mark.skipif(not _X86_64, reason="CPUID exists only on x86")
def test_leaf_0_vendor_is_twelve_printable_characters() -> None:
    vendor = _vendor(NativeCpuid())
    assert len(vendor) == 12
    assert vendor.isprintable()


@pytest.mark.os_linux
@pytest.mark.skipif(not _X86_64, reason="CPUID exists only on x86")
def test_a_subleaf_reaches_the_cpu() -> None:
    # Leaf 0xD: sub-leaf 0 and sub-leaf 1 describe different things, so their EAX differ on any
    # CPU with XSAVE; on one without it both are zero. Either way the sub-leaf was passed in ECX
    # when sub-leaf 1's registers are not simply sub-leaf 0's again.
    cpu = NativeCpuid()
    if cpu.cpuid(0).eax < 0x0D or not cpu.cpuid(1).ecx >> 26 & 1:
        pytest.skip("no XSAVE leaf on this CPU")
    assert cpu.cpuid(0x0D) != cpu.cpuid(0x0D, subleaf=1)
