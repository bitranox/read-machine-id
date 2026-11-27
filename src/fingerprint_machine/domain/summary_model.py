"""The summary of a reading as typed records: the same fields on Windows and on Linux.

Each OS fills the records from its own sections (see :mod:`.summary_windows` and
:mod:`.summary_linux`); a value the reading does not hold is None. Hardware values are written in
one canonical form on both OSes (see :mod:`.summary_values`), so the summaries of one machine read
under Windows and under Linux compare equal where the hardware is the same. Operating-system
facts (computer name, interface names, the ``windows`` group) differ by nature.

Contents:
    * :class:`SystemSummary`, :class:`CpuSummary`, :class:`MemorySummary` - firmware and board.
    * :class:`NicSummary`, :class:`ScsiControllerSummary`, :class:`DiskSummary` - devices.
    * :class:`OsSummary`, :class:`WindowsSummary`, :class:`SecuritySummary` - OS and posture.
    * :class:`Summary` - all of them, with :meth:`Summary.as_json`.
    * :func:`fill_missing` - a record with its None fields taken from a fallback record.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass, replace
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from _typeshed import DataclassInstance

    from .json_types import JsonObject, JsonValue


@dataclass(frozen=True, slots=True, kw_only=True)
class SystemSummary:
    """SMBIOS system, BIOS, baseboard and chassis identity (types 0-3)."""

    manufacturer: str | None = None
    product: str | None = None
    serial: str | None = None
    uuid: str | None = None
    sku: str | None = None
    family: str | None = None
    bios_vendor: str | None = None
    bios_version: str | None = None
    bios_date: str | None = None
    board_manufacturer: str | None = None
    board_product: str | None = None
    board_serial: str | None = None
    chassis_type: int | None = None
    chassis_serial: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class CpuSummary:
    """The processor as CPUID reports it, with the socket, core and thread counts."""

    vendor: str | None = None
    name: str | None = None
    processor_id: str | None = None
    sockets: int | None = None
    cores: int | None = None
    logical_processors: int | None = None
    hypervisor: str | None = None
    hypervisors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class MemorySummary:
    """Memory the OS sees (``total_bytes``) and the installed modules (SMBIOS type 17)."""

    total_bytes: int | None = None
    modules: int = 0
    module_sizes: tuple[int | None, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class NicSummary:
    """One physical network adapter."""

    name: str | None = None
    description: str | None = None
    mac: str | None = None
    interface_index: int | None = None
    pci_serial: str | None = None
    pci_address: str | None = None
    driver: str | None = None
    bus: int | None = None
    device: int | None = None
    function: int | None = None
    slot: int | None = None
    class_key: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ScsiControllerSummary:
    """One storage controller."""

    name: str | None = None
    pci_serial: str | None = None
    pci_address: str | None = None
    driver: str | None = None
    sas_wwid: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class DiskSummary:
    """One physical disk."""

    model: str | None = None
    serial: str | None = None
    size: int | None = None
    mbr_signature: int | None = None
    gpt_guid: str | None = None
    unique_id: str | None = None
    controller: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class OsSummary:
    """The operating system and the identifiers it gives the machine."""

    name: str | None = None
    version: str | None = None
    hostname: str | None = None
    machine_id: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class WindowsSummary:
    """Windows identity and licensing; every field is None on Linux."""

    computer_name: str | None = None
    edition: str | None = None
    build: str | None = None
    product_id: str | None = None
    device_id: str | None = None
    machine_guid: str | None = None
    machine_sid: str | None = None
    license_status: int | None = None
    partial_product_key: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class SecuritySummary:
    """Firmware type, Secure Boot, TPM and (Windows) virtualization-based security."""

    firmware_type: str | None = None
    secure_boot: int | None = None
    tpm_version: str | None = None
    tpm_manufacturer: str | None = None
    tpm_spec_version: str | None = None
    vbs_status: int | None = None


def _value(value: object) -> JsonValue:
    if isinstance(value, tuple):
        # isinstance leaves the item type unknown; every tuple here holds model values.
        return [_value(v) for v in cast("tuple[object, ...]", value)]
    if is_dataclass(value) and not isinstance(value, type):
        return _record(value)
    return value if isinstance(value, (str, int, float, bool)) or value is None else str(value)


def _record(record: DataclassInstance) -> JsonObject:
    return {f.name: _value(getattr(record, f.name)) for f in fields(record)}


def fill_missing[R: DataclassInstance](primary: R, fallback: R) -> R:
    """Return ``primary`` with each None field taken from ``fallback``.

    Example:
        >>> fill_missing(OsSummary(name="A"), OsSummary(name="B", version="1"))
        OsSummary(name='A', version='1', hostname=None, machine_id=None)
    """
    missing = {f.name: getattr(fallback, f.name) for f in fields(primary) if getattr(primary, f.name) is None}
    return replace(primary, **missing)


@dataclass(frozen=True, slots=True, kw_only=True)
class Summary:
    """The identity values of a reading, the same fields on both OSes."""

    system: SystemSummary = field(default_factory=SystemSummary)
    cpu: CpuSummary = field(default_factory=CpuSummary)
    memory: MemorySummary = field(default_factory=MemorySummary)
    nics: tuple[NicSummary, ...] = ()
    scsi_controllers: tuple[ScsiControllerSummary, ...] = ()
    disks: tuple[DiskSummary, ...] = ()
    os: OsSummary = field(default_factory=OsSummary)
    windows: WindowsSummary = field(default_factory=WindowsSummary)
    security: SecuritySummary = field(default_factory=SecuritySummary)

    def as_json(self) -> JsonObject:
        """Return the summary as a reading records it.

        Example:
            >>> Summary(nics=(NicSummary(name="eth0"),)).as_json()["nics"][0]["name"]
            'eth0'
        """
        return _record(self)


__all__ = [
    "CpuSummary",
    "DiskSummary",
    "MemorySummary",
    "NicSummary",
    "OsSummary",
    "ScsiControllerSummary",
    "SecuritySummary",
    "Summary",
    "SystemSummary",
    "WindowsSummary",
    "fill_missing",
]
