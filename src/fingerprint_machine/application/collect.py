"""Collect a machine reading: every section, each question asked through the machine's sources.

A reading is one JSON document. Each section is read independently and each question inside a
section is guarded: a source that cannot answer one question (:class:`SourceError`, or a missing
row or value) records ``{"error": ...}`` in that place and the reading goes on. Anything else is
a defect in this tool and is left to surface.

:func:`collect` takes either OS's sources: :class:`WindowsSources` are read by the readers in this
module, :class:`LinuxSources` by :mod:`.collect_linux`. ``meta.os`` says which.

The last step masks every product key in the whole document, so no reader added later can leak
one by forgetting to.

Contents:
    * :class:`Section` - the sections a reading holds.
    * :data:`SCHEMA_VERSION` - the layout version recorded in every reading.
    * :func:`collect` - read the machine.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..domain.enums import MachineOs
from ..domain.identity import (
    decode_acpi_header,
    machine_sid,
    mask_product_keys,
    msdm_product_key,
    withhold_registry_values,
)
from ..domain.machine_errors import SourceError
from ..domain.network import BY_INDEX, BY_NAME, join_adapters
from ..domain.smbios import decode_smbios
from ..domain.summary import summarize
from .collect_cpuid import read_cpuid
from .collect_linux import LINUX_SECTIONS, read_linux_section
from .guard import guarded
from .machine_ports import WindowsSources
from .sections import Section
from .windows_hardware import read_cpus, read_displays, read_numa, read_scsi_map
from .windows_pci import read_windows_pci
from .windows_security import SECURITY_READERS
from .windows_values import CIMV2, Reader, cim, optional_subkeys, reg, reg_value, registry_json, values

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import MachineSources

#: The reading layout version. 1 was the predecessor script's layout (``probe_version``); 3 added
#: ``meta.os``, Linux readings and the ``cpuid`` section.
SCHEMA_VERSION = 3

_STORAGE = "root/Microsoft/Windows/Storage"
_STANDARD = "root/StandardCimv2"
_WMI = "root/wmi"

_ENUM = r"HKLM\SYSTEM\CurrentControlSet\Enum"
_NET_CLASS = r"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
_CURRENT_VERSION = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
_CLOUD_JOIN = r"HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
_WINDOWS_PRODUCT = "55c92734-d682-4d71-983e-d6ec3f16059f"

#: ``Win32_OperatingSystem``'s memory figures (KiB), the counterpart of Linux ``meminfo`` totals.
_MEMORY_TOTALS = (
    "TotalVisibleMemorySize",
    "FreePhysicalMemory",
    "TotalVirtualMemorySize",
    "FreeVirtualMemory",
    "SizeStoredInPagingFiles",
    "FreeSpaceInPagingFiles",
    "MaxProcessMemorySize",
)

# --------------------------------------------------------------------------------------------
# Readers that do more than one question.
# --------------------------------------------------------------------------------------------


def read_smbios(src: WindowsSources) -> JsonValue:
    """Decode the firmware's SMBIOS table."""
    table, version = src.platform.smbios_table()
    return decode_smbios(table, version)


def _acpi_headers(src: WindowsSources) -> JsonValue:
    headers: list[JsonValue] = [decode_acpi_header(t) for t in src.platform.acpi_tables()]
    return headers


def _msdm(src: WindowsSources) -> JsonValue:
    for table in src.platform.acpi_tables():
        if table[:4] == b"MSDM":
            return msdm_product_key(table)
    return {"present": False, "product_key": None}


def _acpi_registry(src: WindowsSources) -> JsonValue:
    # HKLM\HARDWARE\ACPI\<table>\<OEM id>\<table id>\<revision>: what Windows recorded at boot.
    out: JsonObject = {}
    base = r"HKLM\HARDWARE\ACPI"
    for table in src.registry.subkeys(base):
        oems = src.registry.subkeys(rf"{base}\{table}")
        out[table] = [_acpi_oem(src, rf"{base}\{table}", oem) for oem in oems]
    return out


def _acpi_oem(src: WindowsSources, table_key: str, oem: str) -> JsonValue:
    ids = src.registry.subkeys(rf"{table_key}\{oem}")
    revisions: list[JsonValue] = [r for i in ids for r in src.registry.subkeys(rf"{table_key}\{oem}\{i}")]
    table_ids: list[JsonValue] = list(ids)
    return {"oem_id": oem, "table_id": table_ids, "revision": revisions}


def _class_keys(src: WindowsSources) -> dict[str, JsonObject]:
    keys: dict[str, JsonObject] = {}
    for number in src.registry.subkeys(_NET_CLASS):
        if not number.isdigit():
            continue
        found = guarded(lambda number=number: values(src, rf"{_NET_CLASS}\{number}"))
        if not isinstance(found, dict):
            continue
        guid = found.get("NetCfgInstanceId")
        if isinstance(guid, str):
            keys[guid.upper()] = {"number": number, "values": found}
    return keys


def _category_rows(src: WindowsSources, class_name: str) -> list[JsonObject]:
    namespace = CIMV2 if class_name.startswith("Win32_") else _STANDARD
    return src.platform.cim(class_name, namespace=namespace)


def _category_json(src: WindowsSources, class_name: str) -> JsonValue:
    rows: list[JsonValue] = list(_category_rows(src, class_name))
    return rows


def _class_keys_json(src: WindowsSources) -> JsonValue:
    keys: JsonObject = dict(_class_keys(src))
    return keys


def _subkeys_json(src: WindowsSources, key: str) -> JsonValue:
    names: list[JsonValue] = list(src.registry.subkeys(key))
    return names


def read_network(src: WindowsSources) -> JsonValue:
    """Read every adapter with every per-adapter class joined to it."""
    adapters = src.platform.cim("MSFT_NetAdapter", namespace=_STANDARD)
    categories: dict[str, Sequence[JsonObject]] = {}
    errors: JsonObject = {}
    for category, class_name in {**BY_NAME, **BY_INDEX}.items():
        answer = guarded(lambda class_name=class_name: _category_json(src, class_name))
        if isinstance(answer, list):
            categories[category] = [r for r in answer if isinstance(r, dict)]
        else:
            errors[category] = answer
    class_keys = guarded(lambda: _class_keys_json(src))
    joined = join_adapters(adapters, categories, _as_class_keys(class_keys))
    joined["errors"] = errors
    if not isinstance(class_keys, dict) or "error" in class_keys:
        joined["class_keys_error"] = class_keys
    return joined


def _as_class_keys(value: JsonValue) -> dict[str, JsonObject]:
    if not isinstance(value, dict) or "error" in value:
        return {}
    return {k: v for k, v in value.items() if isinstance(v, dict)}


def _instances(src: WindowsSources) -> Iterable[str]:
    # Enum\<bus>\<device>\<instance>: one key per device instance Windows has ever seen.
    for bus in src.registry.subkeys(_ENUM):
        devices = guarded(lambda bus=bus: _subkeys_json(src, rf"{_ENUM}\{bus}"))
        for device in devices if isinstance(devices, list) else []:
            path = rf"{bus}\{device}"
            found = guarded(lambda path=path: _subkeys_json(src, rf"{_ENUM}\{path}"))
            yield from (rf"{path}\{inst}" for inst in (found if isinstance(found, list) else []))


def _upper_id(row: JsonObject, key: str) -> str:
    value = row.get(key)
    return value.upper() if isinstance(value, str) else ""


def read_devices(src: WindowsSources) -> JsonValue:
    """Read every device instance in the registry, present or not, with its driver if present."""
    present = {_upper_id(r, "DeviceID"): r for r in src.platform.cim("Win32_PnPEntity")}
    drivers_answer = guarded(lambda: cim("Win32_PnPSignedDriver")(src))
    driver_rows = drivers_answer if isinstance(drivers_answer, list) else []
    drivers = {_upper_id(r, "DeviceID"): r for r in driver_rows if isinstance(r, dict)}
    rows: list[JsonValue] = []
    for inst in sorted(_instances(src), key=str.upper):
        p = present.get(inst.upper())
        rows.append(
            {
                "instance_id": inst,
                "present": p is not None,
                "name": p.get("Name") if p else None,
                "registry": guarded(lambda inst=inst: values(src, rf"{_ENUM}\{inst}")),
                "driver": drivers.get(inst.upper()),
            }
        )
    acpi: list[JsonValue] = []
    acpi.extend(sorted({k.split("\\")[1] for k in present if k.startswith("ACPI\\")}))
    drivers_error = drivers_answer if isinstance(drivers_answer, dict) else None
    return {
        "instances": rows,
        "acpi_ids": acpi,
        "drivers_error": drivers_error,
        # Every kernel driver installed, loaded or not: Linux lists only the loaded ones (modules).
        "system_drivers": guarded(lambda: cim("Win32_SystemDriver")(src)),
        "displays": guarded(lambda: read_displays(src)),
    }


def _memory_totals(src: WindowsSources) -> JsonValue:
    rows: list[JsonValue] = [
        {name: row.get(name) for name in _MEMORY_TOTALS} for row in src.platform.cim("Win32_OperatingSystem")
    ]
    return rows


def _local_sids(src: WindowsSources) -> JsonValue:
    accounts = src.platform.cim("Win32_UserAccount", where="LocalAccount = TRUE")
    return machine_sid(a.get("SID") for a in accounts)


def _cloud_join(src: WindowsSources) -> JsonValue:
    # The JoinInfo key exists only on a machine joined to Entra ID: absent means not joined.
    return {
        thumb: guarded(lambda t=thumb: values(src, rf"{_CLOUD_JOIN}\{t}"))
        for thumb in optional_subkeys(src, _CLOUD_JOIN)
    }


def _current_version(src: WindowsSources) -> JsonValue:
    return withhold_registry_values(values(src, _CURRENT_VERSION))


# --------------------------------------------------------------------------------------------
# The sections.
# --------------------------------------------------------------------------------------------

#: Sections whose questions are independent: one guarded answer per item.
ITEM_SECTIONS: Mapping[Section, Mapping[str, Reader]] = {
    Section.ACPI: {"tables": _acpi_headers, "msdm": _msdm, "registry": _acpi_registry},
    Section.PLATFORM: {
        "bios": cim("Win32_BIOS"),
        "computer_system": cim("Win32_ComputerSystem"),
        "product": cim("Win32_ComputerSystemProduct"),
        "baseboard": cim("Win32_BaseBoard"),
        "enclosure": cim("Win32_SystemEnclosure"),
        "registry_bios": reg(r"HKLM\HARDWARE\DESCRIPTION\System\BIOS"),
        "registry_system": reg(r"HKLM\HARDWARE\DESCRIPTION\System"),
    },
    Section.CPU: {
        "wmi": cim("Win32_Processor"),
        "caches": cim("Win32_CacheMemory"),
        "cpus": read_cpus,
    },
    Section.MEMORY: {
        "modules": cim("Win32_PhysicalMemory"),
        "arrays": cim("Win32_PhysicalMemoryArray"),
        "totals": _memory_totals,
        "page_files": cim("Win32_PageFileUsage"),
        "page_file_settings": cim("Win32_PageFileSetting"),
        "numa": read_numa,
    },
    Section.DISKS: {
        "wmi": cim("Win32_DiskDrive"),
        "storage": cim("MSFT_Disk", _STORAGE),
        "physical": cim("MSFT_PhysicalDisk", _STORAGE),
        "partitions": cim("MSFT_Partition", _STORAGE),
        "volumes": cim("Win32_Volume"),
        "initiator_ports": cim("MSFT_InitiatorPort", _STORAGE),
        "scsi": read_scsi_map,
    },
    Section.HARDWARE: {
        "scsi_controllers": cim("Win32_SCSIController"),
        "ide_controllers": cim("Win32_IDEController"),
        "usb_controllers": cim("Win32_USBController"),
        "cdrom": cim("Win32_CDROMDrive"),
        "keyboards": cim("Win32_Keyboard"),
        "pointing": cim("Win32_PointingDevice"),
        "sound": cim("Win32_SoundDevice"),
        "monitors": cim("Win32_DesktopMonitor"),
        "monitor_ids": cim("WmiMonitorID", _WMI),
        "serial_ports": cim("Win32_SerialPort"),
        "video": cim("Win32_VideoController"),
    },
    Section.WINDOWS: {
        "operating_system": cim("Win32_OperatingSystem"),
        "current_version": _current_version,
        "machine_guid": reg_value(r"HKLM\SOFTWARE\Microsoft\Cryptography", "MachineGuid"),
        "device_id": reg_value(r"HKLM\SOFTWARE\Microsoft\SQMClient", "MachineId"),
        "sus_client_id": reg_value(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "SusClientId"),
        "machine_sid": _local_sids,
        "computer_name": reg(r"HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"),
        "tcpip": reg(r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"),
        "time_zone": cim("Win32_TimeZone"),
        "licensing_service": cim("SoftwareLicensingService"),
        "licensing_products": cim(
            "SoftwareLicensingProduct",
            where=f"ApplicationID = '{_WINDOWS_PRODUCT}' AND PartialProductKey IS NOT NULL",
        ),
        "hotfixes": cim("Win32_QuickFixEngineering"),
        "cloud_join": _cloud_join,
    },
    Section.SECURITY: SECURITY_READERS,
    Section.SERVICES: {"all": cim("Win32_Service")},
}

#: Sections read as one piece (their questions depend on each other).
WHOLE_SECTIONS: Mapping[Section, Reader] = {
    Section.CPUID: read_cpuid,
    Section.SMBIOS: read_smbios,
    Section.NETWORK: read_network,
    Section.DEVICES: read_devices,
    Section.PCI: read_windows_pci,
}


def read_section(src: WindowsSources, section: Section) -> JsonValue:
    """Read one section of a Windows reading, each of its questions guarded."""
    whole = WHOLE_SECTIONS.get(section)
    if whole is not None:
        return guarded(lambda: whole(src))
    items = ITEM_SECTIONS.get(section)
    if items is None:
        return guarded(lambda: _not_read_on_windows(section))
    return {name: guarded(lambda read=read: read(src)) for name, read in items.items()}


def _not_read_on_windows(section: Section) -> JsonValue:
    raise SourceError(f"the {section.value} section is not read on Windows yet")


def default_sections(src: MachineSources) -> list[Section]:
    """Return the sections a reading of this machine holds when none are named, in document order."""
    if isinstance(src, WindowsSources):
        return [s for s in Section if s in WHOLE_SECTIONS or s in ITEM_SECTIONS]
    return [s for s in Section if s in LINUX_SECTIONS]


def _read_body(src: MachineSources, chosen: Sequence[Section]) -> tuple[MachineOs, JsonObject]:
    if isinstance(src, WindowsSources):
        return MachineOs.WINDOWS, {s.value: read_section(src, s) for s in chosen}
    return MachineOs.LINUX, {s.value: read_linux_section(src, s) for s in chosen}


def collect(
    src: MachineSources,
    *,
    label: str,
    collected_at: str,
    tool_version: str,
    sections: Sequence[Section] | None = None,
) -> JsonObject:
    """Read the machine and return the reading, product keys masked.

    Args:
        src: the machine's sources; their type decides the OS the reading is taken as.
        label: a name for this reading, shown when comparing.
        collected_at: when the reading was taken (ISO 8601, UTC).
        tool_version: the version of this tool.
        sections: the sections to read; this OS's sections (:func:`default_sections`) when None.

    Returns:
        ``meta``, ``summary`` and one key per section read.
    """
    chosen = default_sections(src) if sections is None else list(sections)
    machine_os, body = _read_body(src, chosen)
    reading: JsonObject = {
        "meta": {
            "label": label,
            "tool": "fingerprint-machine",
            "tool_version": tool_version,
            "schema_version": SCHEMA_VERSION,
            "os": machine_os.value,
            "collected_at": collected_at,
            "sections": [s.value for s in chosen],
        },
        "summary": summarize(body, machine_os=machine_os),
        **body,
    }
    masked = mask_product_keys(reading)
    return masked if isinstance(masked, dict) else reading


__all__ = [
    "ITEM_SECTIONS",
    "SCHEMA_VERSION",
    "WHOLE_SECTIONS",
    "Reader",
    "Section",
    "cim",
    "collect",
    "default_sections",
    "read_devices",
    "read_network",
    "read_section",
    "read_smbios",
    "reg",
    "reg_value",
    "registry_json",
]
