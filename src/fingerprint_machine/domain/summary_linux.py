"""The summary of a Linux reading: SMBIOS and CPUID first, then sysfs and procfs.

An unprivileged reading cannot open the raw SMBIOS table, so the system fields fall back to
``/sys/class/dmi/id`` (whose serial and UUID files are root-only too: those stay None). Devices
under ``/sys/devices/virtual`` (loopback, bridges, veth, loop and device-mapper disks) are left
out: the summary lists hardware, as the Windows one lists physical adapters and disk drives.

Contents:
    * :func:`summarize_linux` - the summary of a Linux reading's sections.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .identity import vmware_pvscsi_sas_wwid_from_dsn
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
    fill_missing,
)
from .summary_shared import cpuid_cpu, smbios_memory, smbios_system
from .summary_values import (
    canonical_disk_id,
    canonical_dsn,
    canonical_mac,
    canonical_uuid,
    first,
    integer,
    node,
    obj,
    rows,
    split_pci_address,
    text,
)

if TYPE_CHECKING:
    from .json_types import JsonObject, JsonValue

_VIRTUAL = "/virtual/"
# tpm_version_major as the TPM Base Services name the version on Windows.
_TPM_VERSIONS = {"1": "1.2", "2": "2.0"}


def _system(body: JsonObject) -> SystemSummary:
    dmi = obj(body, "smbios", "dmi_id")
    fallback = SystemSummary(
        manufacturer=text(dmi.get("sys_vendor")),
        product=text(dmi.get("product_name")),
        serial=text(dmi.get("product_serial")),
        uuid=canonical_uuid(dmi.get("product_uuid")),
        sku=text(dmi.get("product_sku")),
        family=text(dmi.get("product_family")),
        bios_vendor=text(dmi.get("bios_vendor")),
        bios_version=text(dmi.get("bios_version")),
        bios_date=text(dmi.get("bios_date")),
        board_manufacturer=text(dmi.get("board_vendor")),
        board_product=text(dmi.get("board_name")),
        board_serial=text(dmi.get("board_serial")),
        chassis_type=integer(dmi.get("chassis_type")),
        chassis_serial=text(dmi.get("chassis_serial")),
    )
    return fill_missing(smbios_system(body), fallback)


def _topology(body: JsonObject) -> list[tuple[str, str]]:
    """Package and core id of each logical CPU, from sysfs; empty when any CPU lacks them."""
    pairs: list[tuple[str, str]] = []
    for cpu in rows(body, "cpu", "cpus"):
        topology = obj(cpu, "topology")
        package, core = text(topology.get("physical_package_id")), text(topology.get("core_id"))
        if package is None or core is None:
            return []
        pairs.append((package, core))
    return pairs


def _cpu(body: JsonObject) -> CpuSummary:
    cpuinfo = rows(body, "cpu", "cpuinfo")
    head = cpuinfo[0] if cpuinfo else {}
    topology = _topology(body)
    procfs = CpuSummary(
        vendor=text(head.get("vendor_id")),
        name=text(head.get("model_name")),
        sockets=len({p for p, _ in topology}) or None,
        cores=len(set(topology)) or None,
        # Counted from the same sysfs list as the cores: inside a container /proc/cpuinfo can
        # show only the CPUs it may use, which would give fewer threads than cores.
        logical_processors=len(topology) or len(cpuinfo) or None,
    )
    return fill_missing(cpuid_cpu(body, counts=procfs), procfs)


def _memory(body: JsonObject) -> MemorySummary:
    return smbios_memory(body, total_bytes=integer(obj(body, "memory", "meminfo").get("MemTotal")))


def _hardware(records: list[JsonObject]) -> list[JsonObject]:
    # A record whose sysfs link could not be read cannot be placed on a bus, so it is not
    # listed as hardware either; the full section still holds it with its error.
    return [r for r in records if isinstance(path := r.get("device_path"), str) and _VIRTUAL not in path]


def _slots(body: JsonObject) -> dict[str, int | None]:
    return {str(d.get("address")): integer(d.get("slot")) for d in rows(body, "pci", "devices")}


def _nic(record: JsonObject, slots: dict[str, int | None]) -> NicSummary:
    pci = obj(record, "pci")
    address = text(pci.get("address"))
    bus, device, function = split_pci_address(address)
    return NicSummary(
        name=text(record.get("name")),
        mac=canonical_mac(record.get("permanent_address")) or canonical_mac(obj(record, "sysfs").get("address")),
        interface_index=integer(record.get("index")),
        pci_serial=canonical_dsn(pci.get("device_serial_number")),
        pci_address=address,
        driver=text(obj(record, "driver").get("driver")) or text(pci.get("driver")),
        bus=bus,
        device=device,
        function=function,
        slot=slots.get(address) if address is not None else None,
    )


def _dsn_number(dsn: str | None) -> int | None:
    return int(dsn.replace("-", ""), 16) if dsn is not None else None


def _sas_wwid(row: JsonObject, dsn: str | None) -> str | None:
    vendor, device, number = integer(row.get("vendor")), integer(row.get("device")), _dsn_number(dsn)
    if vendor is None or device is None or number is None:
        return None
    return vmware_pvscsi_sas_wwid_from_dsn(vendor=vendor, device=device, dsn=number)


def _controller(row: JsonObject) -> ScsiControllerSummary:
    dsn = canonical_dsn(row.get("device_serial_number"))
    return ScsiControllerSummary(
        pci_serial=dsn,
        pci_address=text(row.get("address")),
        driver=text(row.get("driver")),
        sas_wwid=_sas_wwid(row, dsn),
    )


def _partition_table(record: JsonObject) -> tuple[int | None, str | None]:
    """The MBR disk signature or the GPT disk GUID udev read from the partition table."""
    table = obj(record, "udev", "properties")
    kind, uid = text(table.get("ID_PART_TABLE_TYPE")), text(table.get("ID_PART_TABLE_UUID"))
    if kind == "dos" and uid is not None:
        return integer(f"0x{uid}"), None
    if kind == "gpt":
        return None, canonical_uuid(uid)
    return None, None


def _disk(record: JsonObject) -> DiskSummary:
    device = obj(record, "device")
    signature, guid = _partition_table(record)
    return DiskSummary(
        model=text(device.get("model")),
        # NVMe names its serial in sysfs; a SCSI disk only through VPD page 0x80.
        serial=text(device.get("serial")) or text(device.get("vpd_serial")),
        size=integer(record.get("size_bytes")),
        mbr_signature=signature,
        gpt_guid=guid,
        # An NVMe namespace has its own wwid; a SCSI disk's is on its device.
        unique_id=canonical_disk_id(record.get("wwid")) or canonical_disk_id(device.get("wwid")),
        controller=text(record.get("controller")),
    )


def _os(body: JsonObject) -> OsSummary:
    release = obj(body, "platform", "os_release")
    return OsSummary(
        name=text(release.get("PRETTY_NAME")) or text(release.get("NAME")),
        version=text(release.get("VERSION_ID")),
        hostname=text(node(body, "platform", "hostname")),
        machine_id=text(node(body, "platform", "machine_id")),
    )


def _tpm_version(major: JsonValue) -> str | None:
    value = text(major)
    return _TPM_VERSIONS.get(value, value) if value is not None else None


def _security(body: JsonObject) -> SecuritySummary:
    tpm = first(body, "security", "tpm")
    return SecuritySummary(
        firmware_type=text(node(body, "security", "firmware_type")),
        secure_boot=integer(obj(body, "security", "secure_boot").get("UEFISecureBootEnabled")),
        # sysfs names no TPM 2.0 manufacturer or spec version, so those two stay None on Linux.
        tpm_version=_tpm_version(tpm.get("tpm_version_major")),
    )


def summarize_linux(body: JsonObject) -> Summary:
    """Return the summary of a Linux reading's sections; a section not read leaves its fields None.

    Example:
        >>> s = summarize_linux({"network": {"adapters": [
        ...     {"name": "lo", "device_path": "../../devices/virtual/net/lo"},
        ...     {"name": "ens192", "device_path": "../../devices/pci0000:00/0000:0b:00.0/net/ens192",
        ...      "permanent_address": "00:50:56:00:00:01"}]}})
        >>> [(n.name, n.mac) for n in s.nics], s.windows.edition
        ([('ens192', '00:50:56:00:00:01')], None)
    """
    slots = _slots(body)
    return Summary(
        system=_system(body),
        cpu=_cpu(body),
        memory=_memory(body),
        nics=tuple(_nic(r, slots) for r in _hardware(rows(body, "network", "adapters"))),
        scsi_controllers=tuple(_controller(r) for r in rows(body, "disks", "controllers")),
        disks=tuple(_disk(r) for r in _hardware(rows(body, "disks", "block_devices"))),
        os=_os(body),
        security=_security(body),
    )


__all__ = ["summarize_linux"]
