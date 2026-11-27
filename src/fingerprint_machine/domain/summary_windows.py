"""The summary of a Windows reading: SMBIOS and CPUID first, WMI and the registry where they miss.

The SMBIOS and CPUID sections are decoded the same way on Linux, so taking them first keeps the
two OSes' summaries in step; WMI fills what they leave None (an older reading without a ``cpuid``
section, a table that failed to read).

Contents:
    * :func:`summarize_windows` - the summary of a Windows reading's sections.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .identity import vmware_pvscsi_sas_wwid
from .summary_model import (
    CpuSummary,
    DiskSummary,
    MemorySummary,
    NicSummary,
    OsSummary,
    ScsiControllerSummary,
    SecuritySummary,
    Summary,
    SystemSummary,
    WindowsSummary,
    fill_missing,
)
from .summary_shared import cpuid_cpu, smbios_memory, smbios_system
from .summary_values import (
    canonical_disk_id,
    canonical_mac,
    canonical_uuid,
    dsn_from_instance,
    first,
    integer,
    node,
    obj,
    pci_address,
    rows,
    text,
)

if TYPE_CHECKING:
    from .json_types import JsonObject

_DRIVER_SUFFIX = ".sys"


def _system(body: JsonObject) -> SystemSummary:
    bios = first(body, "platform", "bios")
    wmi = SystemSummary(
        uuid=canonical_uuid(first(body, "platform", "product").get("UUID")),
        bios_vendor=text(bios.get("Manufacturer")),
        bios_version=text(bios.get("SMBIOSBIOSVersion")),
    )
    return fill_missing(smbios_system(body), wmi)


def _total(cpus: list[JsonObject], key: str) -> int | None:
    values = [v for r in cpus if (v := integer(r.get(key))) is not None]
    return sum(values) if values else None


def _cpu(body: JsonObject) -> CpuSummary:
    cpus = rows(body, "cpu", "wmi")
    head = cpus[0] if cpus else {}
    wmi = CpuSummary(
        vendor=text(head.get("Manufacturer")),
        name=text(head.get("Name")),
        processor_id=text(head.get("ProcessorId")),
        sockets=len(cpus) or None,
        cores=_total(cpus, "NumberOfCores"),
        logical_processors=_total(cpus, "NumberOfLogicalProcessors"),
    )
    return fill_missing(cpuid_cpu(body, counts=wmi), wmi)


def _memory(body: JsonObject) -> MemorySummary:
    total = integer(first(body, "platform", "computer_system").get("TotalPhysicalMemory"))
    smbios = smbios_memory(body, total_bytes=total)
    if smbios.modules:
        return smbios
    sizes = tuple(integer(m.get("Capacity")) for m in rows(body, "memory", "modules"))
    return MemorySummary(total_bytes=total, modules=len(sizes), module_sizes=sizes)


def _driver(adapter: JsonObject) -> str | None:
    name = text(adapter.get("DriverFileName"))
    if name is None:
        return None
    name = name.lower()
    return name.removesuffix(_DRIVER_SUFFIX)


def _nic(record: JsonObject) -> NicSummary:
    adapter = obj(record, "adapter")
    hardware = first(record, "hardware")
    bus, device, function = (integer(hardware.get(k)) for k in ("BusNumber", "DeviceNumber", "FunctionNumber"))
    return NicSummary(
        name=text(adapter.get("Name")),
        description=text(adapter.get("InterfaceDescription")),
        mac=canonical_mac(adapter.get("PermanentAddress")),
        interface_index=integer(adapter.get("InterfaceIndex")),
        pci_serial=dsn_from_instance(adapter.get("PnPDeviceID")),
        # Windows reports no PCI segment here; every adapter a guest sees sits in segment 0.
        pci_address=pci_address(segment=0, bus=bus, device=device, function=function),
        driver=_driver(adapter),
        bus=bus,
        device=device,
        function=function,
        slot=integer(hardware.get("SlotNumber")),
        class_key=text(obj(record, "class_key").get("number")),
    )


def _pci_by_instance(body: JsonObject) -> dict[str, JsonObject]:
    return {key.upper(): d for d in rows(body, "pci", "devices") if (key := text(d.get("instance_id"))) is not None}


def _scsi(row: JsonObject, pci: dict[str, JsonObject]) -> ScsiControllerSummary:
    pnp = row.get("PNPDeviceID")
    function = pci.get((text(pnp) or "").upper(), {})
    return ScsiControllerSummary(
        name=text(row.get("Name")),
        pci_serial=dsn_from_instance(pnp),
        pci_address=text(function.get("address")),
        driver=text(row.get("DriverName")) or text(function.get("driver")),
        sas_wwid=vmware_pvscsi_sas_wwid(pnp),
    )


def _disks(body: JsonObject) -> tuple[DiskSummary, ...]:
    storage = {integer(r.get("Number")): r for r in rows(body, "disks", "storage")}
    out: list[DiskSummary] = []
    for d in rows(body, "disks", "wmi"):
        msft = storage.get(integer(d.get("Index")), {})
        out.append(
            DiskSummary(
                model=text(d.get("Model")),
                serial=text(d.get("SerialNumber")),
                size=integer(d.get("Size")),
                mbr_signature=integer(d.get("Signature")),
                gpt_guid=canonical_uuid(msft.get("Guid")),
                unique_id=canonical_disk_id(msft.get("UniqueId"), id_format=integer(msft.get("UniqueIdFormat"))),
            )
        )
    return tuple(out)


def _os(body: JsonObject) -> OsSummary:
    os_row = first(body, "windows", "operating_system")
    return OsSummary(
        name=text(os_row.get("Caption")),
        version=text(os_row.get("Version")),
        hostname=text(os_row.get("CSName")),
        machine_id=text(node(body, "windows", "machine_guid")),
    )


def _windows(body: JsonObject) -> WindowsSummary:
    version = obj(body, "windows", "current_version")
    os_row = first(body, "windows", "operating_system")
    licence = first(body, "windows", "licensing_products")
    return WindowsSummary(
        computer_name=text(os_row.get("CSName")),
        edition=text(version.get("EditionID")),
        build=f"{version.get('CurrentBuild')}.{version.get('UBR')}" if version else None,
        product_id=text(version.get("ProductId")) or text(os_row.get("SerialNumber")),
        device_id=text(node(body, "windows", "device_id")),
        machine_guid=text(node(body, "windows", "machine_guid")),
        machine_sid=text(node(body, "windows", "machine_sid")),
        license_status=integer(licence.get("LicenseStatus")),
        partial_product_key=text(licence.get("PartialProductKey")),
    )


def _security(body: JsonObject) -> SecuritySummary:
    tpm = first(body, "security", "tpm")
    return SecuritySummary(
        firmware_type=text(node(body, "security", "firmware_type")),
        secure_boot=integer(obj(body, "security", "secure_boot").get("UEFISecureBootEnabled")),
        tpm_version=text(obj(body, "security", "tbs").get("tpm_version")),
        tpm_manufacturer=text(tpm.get("ManufacturerIdTxt")),
        tpm_spec_version=text(tpm.get("SpecVersion")),
        vbs_status=integer(first(body, "security", "device_guard").get("VirtualizationBasedSecurityStatus")),
    )


def summarize_windows(body: JsonObject) -> Summary:
    """Return the summary of a Windows reading's sections; a section not read leaves its fields None.

    Example:
        >>> s = summarize_windows({"cpu": {"wmi": [{"Name": "Xeon", "NumberOfCores": 4}]}})
        >>> s.cpu.name, s.cpu.cores, s.cpu.logical_processors, s.nics, s.system.uuid
        ('Xeon', 4, None, (), None)
    """
    pci = _pci_by_instance(body)
    return Summary(
        system=_system(body),
        cpu=_cpu(body),
        memory=_memory(body),
        nics=tuple(_nic(r) for r in rows(body, "network", "adapters")),
        scsi_controllers=tuple(_scsi(r, pci) for r in rows(body, "hardware", "scsi_controllers")),
        disks=_disks(body),
        os=_os(body),
        windows=_windows(body),
        security=_security(body),
    )


__all__ = ["summarize_windows"]
