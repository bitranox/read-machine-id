"""Summary fields read the same way on both OSes: the decoded SMBIOS table and the CPUID section.

Windows (``GetSystemFirmwareTable``) and Linux (``/sys/firmware/dmi/tables/DMI``, root only) hand
the same SMBIOS bytes to one decoder, and both read CPUID with one adapter, so these sections
have the same keys on both OSes. Reading the summary from them first is what makes a Windows and
a Linux reading of one machine agree; each OS fills the rest from its own sources.

Contents:
    * :func:`smbios_system` - system, BIOS, baseboard and chassis from SMBIOS types 0-3.
    * :func:`smbios_memory` - the installed memory modules from SMBIOS type 17.
    * :func:`cpuid_cpu` - vendor, brand, ProcessorId and hypervisors from the ``cpuid`` section.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .summary_model import CpuSummary, MemorySummary, SystemSummary
from .summary_values import canonical_uuid, integer, memory_device_bytes, obj, processor_id, rows, text

if TYPE_CHECKING:
    from .json_types import JsonObject


def smbios_system(body: JsonObject) -> SystemSummary:
    """Return the system identity the decoded SMBIOS table holds; None where it holds nothing.

    Example:
        >>> smbios_system({"smbios": {"system": {"uuid": "a-b"}, "board": {"serial": "B1"}}}).uuid
        'A-B'
    """
    system = obj(body, "smbios", "system")
    bios = obj(body, "smbios", "bios")
    board = obj(body, "smbios", "board")
    chassis = obj(body, "smbios", "chassis")
    return SystemSummary(
        manufacturer=text(system.get("manufacturer")),
        product=text(system.get("product")),
        serial=text(system.get("serial")),
        uuid=canonical_uuid(system.get("uuid")),
        sku=text(system.get("sku")),
        family=text(system.get("family")),
        bios_vendor=text(bios.get("vendor")),
        bios_version=text(bios.get("version")),
        bios_date=text(bios.get("release_date")),
        board_manufacturer=text(board.get("manufacturer")),
        board_product=text(board.get("product")),
        board_serial=text(board.get("serial")),
        chassis_type=integer(chassis.get("type")),
        chassis_serial=text(chassis.get("serial")),
    )


def smbios_memory(body: JsonObject, *, total_bytes: int | None) -> MemorySummary:
    """Return the installed modules (empty sockets left out) with the OS's ``total_bytes``.

    Example:
        >>> m = smbios_memory({"smbios": {"memory": [{"size_raw": 4096}, {"size_raw": 0}]}}, total_bytes=1)
        >>> m.modules, m.module_sizes
        (1, (4294967296,))
    """
    sizes = tuple(memory_device_bytes(r) for r in rows(body, "smbios", "memory"))
    installed = tuple(s for s in sizes if s != 0)
    return MemorySummary(total_bytes=total_bytes, modules=len(installed), module_sizes=installed)


def cpuid_cpu(body: JsonObject, *, counts: CpuSummary) -> CpuSummary:
    """Return what the ``cpuid`` section says about the processor, with the socket counts given.

    CPUID describes the CPU that ran the read, not how many there are, so the counts come from
    the OS (``counts``).

    Example:
        >>> c = cpuid_cpu({"cpuid": {"vendor": "GenuineIntel", "hypervisors": [{"vendor": "KVMKVMKVM"}]}},
        ...               counts=CpuSummary(sockets=1))
        >>> c.vendor, c.sockets, c.hypervisors
        ('GenuineIntel', 1, ('KVMKVMKVM',))
    """
    cpuid = obj(body, "cpuid")
    names = tuple(v for h in rows(cpuid, "hypervisors") if (v := text(h.get("vendor"))) is not None)
    return CpuSummary(
        vendor=text(cpuid.get("vendor")),
        name=text(cpuid.get("brand")),
        processor_id=processor_id(cpuid.get("raw")),
        sockets=counts.sockets,
        cores=counts.cores,
        logical_processors=counts.logical_processors,
        hypervisor=text(cpuid.get("hypervisor_vendor")),
        hypervisors=names,
    )


__all__ = ["cpuid_cpu", "smbios_memory", "smbios_system"]
