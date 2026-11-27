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

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING

from ..domain.certificates import der_from_store_blob, describe_certificate
from ..domain.enums import MachineOs
from ..domain.identity import (
    decode_acpi_header,
    decode_tbs_device_info,
    machine_sid,
    mask_product_keys,
    msdm_product_key,
    withhold_registry_values,
)
from ..domain.machine_errors import MissingKeyError, SourceError
from ..domain.network import BY_INDEX, BY_NAME, join_adapters
from ..domain.smbios import decode_smbios
from ..domain.summary import summarize
from .collect_cpuid import read_cpuid
from .collect_linux import LINUX_SECTIONS, read_linux_section
from .guard import guarded
from .machine_ports import WindowsSources
from .sections import Section

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import MachineSources, RegistryData

#: The reading layout version. 1 was the predecessor script's layout (``probe_version``); 3 added
#: ``meta.os``, Linux readings and the ``cpuid`` section.
SCHEMA_VERSION = 3

_CIMV2 = "root/cimv2"
_STORAGE = "root/Microsoft/Windows/Storage"
_STANDARD = "root/StandardCimv2"
_TPM = "root/cimv2/Security/MicrosoftTpm"
_BITLOCKER = "root/cimv2/Security/MicrosoftVolumeEncryption"
_DEVICE_GUARD = "root/Microsoft/Windows/DeviceGuard"
_WMI = "root/wmi"

_ENUM = r"HKLM\SYSTEM\CurrentControlSet\Enum"
_NET_CLASS = r"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
_EK_STORE = r"HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI\Endorsement\EKCertStore\Certificates"
_CURRENT_VERSION = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
_CLOUD_JOIN = r"HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
_WINDOWS_PRODUCT = "55c92734-d682-4d71-983e-d6ec3f16059f"

Reader = Callable[[WindowsSources], "JsonValue"]


def registry_json(data: RegistryData) -> JsonValue:
    """Return one registry value's data as JSON: binary as hex, everything else as is.

    Examples:
        >>> registry_json(b"\\x01\\xff"), registry_json(["a"]), registry_json(5)
        ('01ff', ['a'], 5)
    """
    if isinstance(data, bytes):
        return data.hex()
    if isinstance(data, list):
        items: list[JsonValue] = list(data)
        return items
    return data


def _values(src: WindowsSources, key: str) -> JsonObject:
    return {name: registry_json(data) for name, data in src.registry.values(key).items()}


def _value(src: WindowsSources, key: str, name: str) -> JsonValue:
    return registry_json(src.registry.values(key)[name])


def cim(class_name: str, namespace: str = _CIMV2, where: str | None = None) -> Reader:
    """Return a reader for every instance of a CIM class."""

    def read(src: WindowsSources) -> JsonValue:
        rows: list[JsonValue] = list(src.platform.cim(class_name, namespace=namespace, where=where))
        return rows

    return read


def reg(key: str) -> Reader:
    """Return a reader for every value of a registry key."""
    return lambda src: _values(src, key)


def reg_value(key: str, name: str) -> Reader:
    """Return a reader for one registry value."""
    return lambda src: _value(src, key, name)


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
        values = guarded(lambda number=number: _values(src, rf"{_NET_CLASS}\{number}"))
        if not isinstance(values, dict):
            continue
        guid = values.get("NetCfgInstanceId")
        if isinstance(guid, str):
            keys[guid.upper()] = {"number": number, "values": values}
    return keys


def _category_rows(src: WindowsSources, class_name: str) -> list[JsonObject]:
    namespace = _CIMV2 if class_name.startswith("Win32_") else _STANDARD
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
                "registry": guarded(lambda inst=inst: _values(src, rf"{_ENUM}\{inst}")),
                "driver": drivers.get(inst.upper()),
            }
        )
    acpi: list[JsonValue] = []
    acpi.extend(sorted({k.split("\\")[1] for k in present if k.startswith("ACPI\\")}))
    drivers_error = drivers_answer if isinstance(drivers_answer, dict) else None
    return {"instances": rows, "acpi_ids": acpi, "drivers_error": drivers_error}


def _local_sids(src: WindowsSources) -> JsonValue:
    accounts = src.platform.cim("Win32_UserAccount", where="LocalAccount = TRUE")
    return machine_sid(a.get("SID") for a in accounts)


def _optional_subkeys(src: WindowsSources, key: str) -> list[str]:
    """Subkeys of a key that only exists on some machines: none when it is absent."""
    try:
        return src.registry.subkeys(key)
    except MissingKeyError:
        return []


def _cloud_join(src: WindowsSources) -> JsonValue:
    # The JoinInfo key exists only on a machine joined to Entra ID: absent means not joined.
    return {
        thumb: guarded(lambda t=thumb: _values(src, rf"{_CLOUD_JOIN}\{t}"))
        for thumb in _optional_subkeys(src, _CLOUD_JOIN)
    }


def _current_version(src: WindowsSources) -> JsonValue:
    return withhold_registry_values(_values(src, _CURRENT_VERSION))


def _ek_certificates(src: WindowsSources) -> JsonValue:
    out: list[JsonValue] = []
    # The store exists only once Windows has cached an EK certificate (a TPM that has one).
    for thumb in _optional_subkeys(src, _EK_STORE):
        blob = src.registry.values(rf"{_EK_STORE}\{thumb}").get("Blob")
        der = der_from_store_blob(blob) if isinstance(blob, bytes) else None
        detail = describe_certificate(der) if der is not None else {"error": "no certificate in the store blob"}
        out.append({"store_thumbprint": thumb, **detail})
    return out


def _tbs(src: WindowsSources) -> JsonValue:
    return decode_tbs_device_info(src.platform.tbs_device_info())


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
        "registry": reg(r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0"),
    },
    Section.MEMORY: {
        "modules": cim("Win32_PhysicalMemory"),
        "arrays": cim("Win32_PhysicalMemoryArray"),
    },
    Section.DISKS: {
        "wmi": cim("Win32_DiskDrive"),
        "storage": cim("MSFT_Disk", _STORAGE),
        "physical": cim("MSFT_PhysicalDisk", _STORAGE),
        "partitions": cim("MSFT_Partition", _STORAGE),
        "volumes": cim("Win32_Volume"),
        "initiator_ports": cim("MSFT_InitiatorPort", _STORAGE),
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
    Section.SECURITY: {
        "firmware_type": lambda src: src.platform.firmware_type(),
        "secure_boot": reg(r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State"),
        "tpm": cim("Win32_Tpm", _TPM),
        "tbs": _tbs,
        "ek_certificates": _ek_certificates,
        "device_guard": cim("Win32_DeviceGuard", _DEVICE_GUARD),
        "bitlocker": cim("Win32_EncryptableVolume", _BITLOCKER),
    },
    Section.SERVICES: {"all": cim("Win32_Service")},
}

#: Sections read as one piece (their questions depend on each other).
WHOLE_SECTIONS: Mapping[Section, Reader] = {
    Section.CPUID: read_cpuid,
    Section.SMBIOS: read_smbios,
    Section.NETWORK: read_network,
    Section.DEVICES: read_devices,
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
        "summary": summarize(body),
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
