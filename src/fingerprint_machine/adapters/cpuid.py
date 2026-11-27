"""The CPUID instruction, run from Python: a few bytes of x86-64 machine code in an executable page.

Python has no CPUID. The standard way around that (py-cpuinfo does the same) is to place a tiny
function in memory, mark the page executable and call it through ctypes. The function takes the
leaf, the sub-leaf and a pointer to four 32-bit words, runs CPUID and stores EAX, EBX, ECX, EDX.
It saves RBX, which CPUID overwrites and both x86-64 calling conventions require kept.

The page is written while read-write and only then made read-execute (never writable and
executable at once), so a W^X policy that refuses the change is reported as a :class:`SourceError`
and costs only the ``cpuid`` section. Endpoint security may still notice a process that maps
executable memory; ``collect --no-cpuid`` (which wires :class:`CpuidOff`) avoids it entirely,
because the page is mapped on the first question, never at construction.

Contents:
    * :class:`NativeCpuid` - the CPU this process runs on.
    * :class:`CpuidOff` - a CPU that refuses every question (``--no-cpuid``).
"""

from __future__ import annotations

import ctypes
import mmap
import platform
import sys
from typing import TYPE_CHECKING

from ..domain.cpuid import CpuidRegs
from ..domain.machine_errors import SourceError

if TYPE_CHECKING:
    from collections.abc import Callable

# Arguments arrive in EDI, ESI, RDX (System V: Linux) or ECX, EDX, R8 (Windows x64). Each stub
# moves them to EAX (leaf), ECX (sub-leaf) and R8 (output), runs CPUID and stores the registers.
_PROLOGUE_SYSV = bytes.fromhex(
    "53"  # push rbx
    "89f8"  # mov eax, edi
    "89f1"  # mov ecx, esi
    "4989d0"  # mov r8, rdx
)
_PROLOGUE_WIN64 = bytes.fromhex(
    "53"  # push rbx
    "89c8"  # mov eax, ecx
    "89d1"  # mov ecx, edx
)
_BODY = bytes.fromhex(
    "0fa2"  # cpuid
    "418900"  # mov [r8], eax
    "41895804"  # mov [r8+4], ebx
    "41894808"  # mov [r8+8], ecx
    "4189500c"  # mov [r8+12], edx
    "5b"  # pop rbx
    "c3"  # ret
)
_X86_64 = frozenset({"x86_64", "amd64"})
_PAGE = 4096

_Words = ctypes.c_uint32 * 4
_STUB_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(_Words))


def _linux_page(code: bytes) -> int:
    if sys.platform == "win32":  # narrows the POSIX-only mmap constants for the type checker
        raise SourceError("cpuid: mmap pages are mapped on Linux")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
    address = libc.mmap(None, _PAGE, mmap.PROT_READ | mmap.PROT_WRITE, flags, -1, 0)
    if address is None or address == ctypes.c_void_p(-1).value:
        raise SourceError(f"cpuid: mmap refused a page, errno {ctypes.get_errno()}")
    ctypes.memmove(address, code, len(code))
    if libc.mprotect(address, _PAGE, mmap.PROT_READ | mmap.PROT_EXEC) != 0:
        raise SourceError(f"cpuid: making the page executable was refused, errno {ctypes.get_errno()}")
    return int(address)


def _windows_page(code: bytes) -> int:
    if sys.platform != "win32":  # narrows ctypes.WinDLL for the type checker
        raise SourceError("cpuid: VirtualAlloc needs Windows")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
    kernel32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p]
    kernel32.FlushInstructionCache.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    mem_commit_reserve, page_readwrite, page_execute_read = 0x3000, 0x04, 0x20
    address = kernel32.VirtualAlloc(None, _PAGE, mem_commit_reserve, page_readwrite)
    if not address:
        raise SourceError(f"cpuid: VirtualAlloc refused a page, Windows error {ctypes.get_last_error()}")
    ctypes.memmove(address, code, len(code))
    old = ctypes.c_uint32(0)
    if not kernel32.VirtualProtect(address, _PAGE, page_execute_read, ctypes.byref(old)):
        raise SourceError(f"cpuid: making the page executable was refused, Windows error {ctypes.get_last_error()}")
    kernel32.FlushInstructionCache(kernel32.GetCurrentProcess(), address, _PAGE)
    return int(address)


class NativeCpuid:
    """The CPUID of the CPU this process runs on.

    The executable page is mapped on the first question and kept for the life of the process.
    ``machine`` and ``system`` default to this machine; they exist so the refusals can be tested
    anywhere.
    """

    def __init__(self, *, machine: str | None = None, system: str | None = None) -> None:
        """Remember which CPU and OS to expect; nothing is mapped yet."""
        self._machine = (machine if machine is not None else platform.machine()).lower()
        self._system = system if system is not None else sys.platform
        self._stub: Callable[..., None] | None = None

    def _build(self) -> Callable[..., None]:
        if self._machine not in _X86_64:
            raise SourceError(f"cpuid needs an x86-64 CPU; this is {self._machine}")
        if self._system.startswith("linux"):
            address = _linux_page(_PROLOGUE_SYSV + _BODY)
        elif self._system == "win32":
            address = _windows_page(_PROLOGUE_WIN64 + _BODY)
        else:
            raise SourceError(f"cpuid is read on Windows or Linux only; this is {self._system}")
        stub: Callable[..., None] = _STUB_TYPE(address)
        return stub

    def cpuid(self, leaf: int, *, subleaf: int = 0) -> CpuidRegs:
        """Run CPUID for ``leaf`` and ``subleaf`` on the CPU this thread is on.

        Raises:
            SourceError: not x86-64, not Windows or Linux, or the executable page was refused.
        """
        if self._stub is None:
            self._stub = self._build()
        words = _Words()
        self._stub(leaf, subleaf, ctypes.byref(words))
        return CpuidRegs(eax=words[0], ebx=words[1], ecx=words[2], edx=words[3])


class CpuidOff:
    """A CPU that refuses every question: ``collect --no-cpuid`` maps no executable memory."""

    def cpuid(self, leaf: int, *, subleaf: int = 0) -> CpuidRegs:
        """Refuse.

        Raises:
            SourceError: always.
        """
        del leaf, subleaf
        raise SourceError("cpuid is turned off (--no-cpuid)")


__all__ = ["CpuidOff", "NativeCpuid"]
