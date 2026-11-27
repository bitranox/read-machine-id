"""Where a compared value comes from, in hardware terms, so a difference reads as a thing to adjust.

Comparing two machines (a VMware VM and the same guest moved to another hypervisor, say) lists
the paths that differ. A path names where the tool stored a value, not what the value is: the
same SMBIOS UUID sits at ``smbios.system.uuid`` on Windows, ``smbios.dmi_id.product_uuid`` on an
unprivileged Linux reading and ``summary.system.uuid`` in both summaries. This table names the
hardware or firmware field behind each, in generic terms only.

A path is matched by its SHAPE (list indexes stripped, ``[0]`` becomes ``[]``) against the
prefixes below, longest first, so a more specific entry wins over the branch it sits in.

Contents:
    * :func:`path_shape` - a path with its list indexes stripped.
    * :func:`source_of` - the hardware field a compared path comes from, or None.
"""

from __future__ import annotations

import re

_INDEX = re.compile(r"\[\d+\]")

_SYSTEM_UUID = "smbios type 1 system uuid"
_SYSTEM_SERIAL = "smbios type 1 system serial number"
_SYSTEM_MANUFACTURER = "smbios type 1 system manufacturer"
_SYSTEM_PRODUCT = "smbios type 1 product name"
_BIOS_VERSION = "smbios type 0 bios version"
_BIOS_VENDOR = "smbios type 0 bios vendor"
_BIOS_DATE = "smbios type 0 bios release date"
_HYPERVISOR = "cpuid 0x40000000 hypervisor signature"
_NIC_MAC = "nic permanent mac address"
_PCI_DSN = "pci device serial number"

# shape prefix -> source. A prefix matches that key and everything below it; one ending in "*"
# matches any shape that starts with the text before the star (a family of keys).
_SOURCES: dict[str, str] = {
    "smbios.system.uuid": _SYSTEM_UUID,
    "smbios.dmi_id.product_uuid": _SYSTEM_UUID,
    "summary.system.uuid": _SYSTEM_UUID,
    "smbios.system.serial": _SYSTEM_SERIAL,
    "smbios.dmi_id.product_serial": _SYSTEM_SERIAL,
    "summary.system.serial": _SYSTEM_SERIAL,
    "smbios.system.manufacturer": _SYSTEM_MANUFACTURER,
    "smbios.dmi_id.sys_vendor": _SYSTEM_MANUFACTURER,
    "summary.system.manufacturer": _SYSTEM_MANUFACTURER,
    "smbios.system.product": _SYSTEM_PRODUCT,
    "smbios.dmi_id.product_name": _SYSTEM_PRODUCT,
    "summary.system.product": _SYSTEM_PRODUCT,
    "smbios.system.sku": "smbios type 1 sku number",
    "summary.system.sku": "smbios type 1 sku number",
    "smbios.system.family": "smbios type 1 family",
    "summary.system.family": "smbios type 1 family",
    "smbios.bios.version": _BIOS_VERSION,
    "smbios.dmi_id.bios_version": _BIOS_VERSION,
    "summary.system.bios_version": _BIOS_VERSION,
    "smbios.bios.vendor": _BIOS_VENDOR,
    "smbios.dmi_id.bios_vendor": _BIOS_VENDOR,
    "summary.system.bios_vendor": _BIOS_VENDOR,
    "smbios.bios.release_date": _BIOS_DATE,
    "smbios.dmi_id.bios_date": _BIOS_DATE,
    "summary.system.bios_date": _BIOS_DATE,
    "smbios.board": "smbios type 2 baseboard",
    "summary.system.board_*": "smbios type 2 baseboard",
    "smbios.dmi_id.board_*": "smbios type 2 baseboard",
    "smbios.chassis": "smbios type 3 chassis",
    "summary.system.chassis_*": "smbios type 3 chassis",
    "smbios.dmi_id.chassis_*": "smbios type 3 chassis",
    "smbios.cpu": "smbios type 4 processor",
    "smbios.slots": "smbios type 9 system slots",
    "smbios.memory": "smbios type 17 memory device",
    "summary.memory.module*": "smbios type 17 memory device",
    "smbios.oem_strings": "smbios type 11 oem strings",
    "smbios": "smbios table",
    "acpi.tables[].oem_id": "acpi table header oem id",
    "acpi.tables[].oem_table_id": "acpi table header oem table id",
    "acpi.tables[].creator_id": "acpi table header creator id",
    "acpi.tables[].oem_revision": "acpi table header oem revision",
    "acpi": "acpi table header",
    "cpuid.hypervisor_vendor": _HYPERVISOR,
    "cpuid.hypervisors": _HYPERVISOR,
    "summary.cpu.hypervisor": _HYPERVISOR,
    "cpuid.features": "cpuid feature flags",
    "cpuid.raw.0x4*": _HYPERVISOR,
    "cpuid": "cpuid",
    "summary.cpu.processor_id": "cpuid leaf 1 processor signature and features",
    "summary.nics[].mac": _NIC_MAC,
    "summary.nics[].pci_serial": _PCI_DSN,
    "summary.nics[].pci_address": "pci address",
    "summary.nics[].slot": "pci slot number",
    "summary.scsi_controllers[].pci_serial": _PCI_DSN,
    "summary.scsi_controllers[].sas_wwid": "storage controller sas wwid",
    "summary.disks[].serial": "disk serial number (vpd 0x80)",
    "summary.disks[].unique_id": "disk identifier (vpd 0x83)",
    "pci.devices[].config.capabilities": "pci configuration space capability",
    "pci.devices[].dsn": _PCI_DSN,
    "pci.devices[]": "pci device",
    "summary.security.tpm_*": "tpm",
    "security.tpm": "tpm",
    "security.ek_certificates": "tpm endorsement key certificate",
}
_PREFIXES = sorted(_SOURCES, key=len, reverse=True)


def path_shape(path: str) -> str:
    """Return a compared path with its list indexes stripped.

    Example:
        >>> path_shape("pci.devices[12].interrupts.rows[0].per_cpu_counts")
        'pci.devices[].interrupts.rows[].per_cpu_counts'
    """
    return _INDEX.sub("[]", path)


def _matches(shape: str, prefix: str) -> bool:
    if prefix.endswith("*"):
        return shape.startswith(prefix[:-1])
    # A plain prefix must end on a key boundary, so "smbios.system.uuid" never claims "...uuid2".
    return shape.startswith(prefix) and (len(shape) == len(prefix) or shape[len(prefix)] in ".[")


def source_of(path: str) -> str | None:
    """Return the hardware or firmware field a compared path comes from, or None for an OS value.

    Examples:
        >>> source_of("summary.nics[3].mac")
        'nic permanent mac address'
        >>> source_of("smbios.dmi_id.board_serial")
        'smbios type 2 baseboard'
        >>> source_of("platform.hostname") is None
        True
    """
    shape = path_shape(path)
    return next((_SOURCES[p] for p in _PREFIXES if _matches(shape, p)), None)


__all__ = ["path_shape", "source_of"]
