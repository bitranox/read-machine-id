"""Kernel questions no WMI class answers on every edition: the NUMA topology and the DMA guard.

``Win32_NumaNode`` does not exist on Windows client editions, so the NUMA nodes come from
kernel32 (``GetNumaHighestNodeNumber``, ``GetNumaNodeProcessorMaskEx``). Kernel DMA Protection
is the kernel's DMA guard policy, which ``NtQuerySystemInformation`` reports
(``SystemDmaGuardPolicyInformation``, one boolean); msinfo32 shows the same value.

Off Windows every function raises :class:`SourceError`; the module still imports.

Contents:
    * :func:`numa_nodes` - every NUMA node with its processors.
    * :func:`kernel_dma_protection` - whether the DMA guard policy is enabled.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from ...domain.machine_errors import SourceError
from ...domain.numa import NumaNode

_SYSTEM_DMA_GUARD_POLICY_INFORMATION = 202
_STATUS_SUCCESS = 0


class _GroupAffinity(ctypes.Structure):
    _fields_ = (("mask", ctypes.c_size_t), ("group", wintypes.WORD), ("reserved", wintypes.WORD * 3))


def _not_windows(what: str) -> SourceError:
    return SourceError(f"{what} needs Windows, this is {sys.platform}")


def _last_error() -> int:
    if sys.platform == "win32":
        return ctypes.get_last_error()
    return 0


def _node(kernel32: ctypes.CDLL, number: int) -> NumaNode:
    affinity = _GroupAffinity()
    if not kernel32.GetNumaNodeProcessorMaskEx(wintypes.USHORT(number), ctypes.byref(affinity)):
        raise SourceError(f"GetNumaNodeProcessorMaskEx({number}) failed, Windows error {_last_error()}")
    return NumaNode(node=number, group=int(affinity.group), mask=int(affinity.mask))


def numa_nodes() -> list[NumaNode]:
    """Return every NUMA node, node 0 first, each with its processor group and mask.

    Raises:
        SourceError: not on Windows, or kernel32 refused.
    """
    if sys.platform != "win32":
        raise _not_windows("the NUMA topology")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    highest = wintypes.ULONG()
    if not kernel32.GetNumaHighestNodeNumber(ctypes.byref(highest)):
        raise SourceError(f"GetNumaHighestNodeNumber failed, Windows error {_last_error()}")
    return [_node(kernel32, number) for number in range(highest.value + 1)]


def kernel_dma_protection() -> bool:
    """Return whether the kernel's DMA guard policy (Kernel DMA Protection) is enabled.

    Raises:
        SourceError: not on Windows, or the kernel refused the query.
    """
    if sys.platform != "win32":
        raise _not_windows("the DMA guard policy")
    ntdll = ctypes.WinDLL("ntdll")
    enabled = ctypes.c_ubyte(0)
    status = (
        int(ntdll.NtQuerySystemInformation(_SYSTEM_DMA_GUARD_POLICY_INFORMATION, ctypes.byref(enabled), 1, None))
        & 0xFFFFFFFF
    )
    if status != _STATUS_SUCCESS:
        raise SourceError(f"NtQuerySystemInformation(SystemDmaGuardPolicyInformation) returned 0x{status:08X}")
    return bool(enabled.value)


__all__ = ["kernel_dma_protection", "numa_nodes"]
