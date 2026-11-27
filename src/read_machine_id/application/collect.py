"""Collect a machine reading: every section, each question asked through the two sources.

A reading is one JSON document. Each section is read independently and each question inside a
section is guarded: a source that cannot answer one question (:class:`SourceError`, or a missing
row or value) records ``{"error": ...}`` in that place and the reading goes on. Anything else is
a defect in this tool and is left to surface.

The last step masks every product key in the whole document, so no reader added later can leak
one by forgetting to.

Contents:
    * :class:`Section` - the sections a reading holds.
    * :data:`SCHEMA_VERSION` - the layout version recorded in every reading.
    * :func:`collect` - read the machine.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from enum import Enum
from typing import TYPE_CHECKING

from ..domain.certificates import der_from_store_blob, describe_certificate
from ..domain.identity import (
    decode_acpi_header,
    decode_tbs_device_info,
    machine_sid,
    mask_product_keys,
    msdm_product_key,
    withhold_registry_values,
)
from ..domain.machine_errors import SourceError
from ..domain.network import BY_INDEX, BY_NAME, join_adapters
from ..domain.smbios import decode_smbios
from ..domain.summary import summarize

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import RegistryData, Sources

#: The reading layout version. 1 was the predecessor script's layout (``probe_version``).
SCHEMA_VERSION = 2

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

# What a guarded question may raise besides SourceError: a missing row, value or key, or a value
# of the wrong shape. Anything else is a defect and surfaces.
_ANSWER_ERRORS: tuple[type[Exception], ...] = (SourceError, KeyError, IndexError, ValueError, TypeError)

Reader = Callable[["Sources"], "JsonValue"]


class Section(str, Enum):
    """The sections of a reading, in document order after ``meta`` and ``summary``."""

    SMBIOS = "smbios"
    ACPI = "acpi"
    PLATFORM = "platform"
    CPU = "cpu"
    MEMORY = "memory"
    DISKS = "disks"
    NETWORK = "network"
    HARDWARE = "hardware"
    DEVICES = "devices"
    WINDOWS = "windows"
    SECURITY = "security"
    SERVICES = "services"


def _guarded(read: Callable[[], JsonValue]) -> JsonValue:
    try:
        return read()
    except _ANSWER_ERRORS as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


def registry_json(data: RegistryData) -> JsonValue:
    """Return one registry value's data as JSON: binary as hex, everything else as is.

    Examples:
        >>> registry_json(b"\\x01\\xff"), registry_json(["a"]), registry_json(5)
        ('01ff', ['a'], 5)
    """
    if isinstance(data, bytes):
        return data.hex()
    if isinstance(data, list):
        return list[JsonValue](data)
    return data


def _values(src: Sources, key: str) -> JsonObject:
    return {name: registry_json(data) for name, data in src.registry.values(key).items()}


def _value(src: Sources, key: str, name: str) -> JsonValue:
    return registry_json(src.registry.values(key)[name])


def cim(class_name: str, namespace: str = _CIMV2, where: str | None = None) -> Reader:
    """Return a reader for every instance of a CIM class."""

    def read(src: Sources) -> JsonValue:
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


def read_smbios(src: Sources) -> JsonValue:
    """Decode the firmware's SMBIOS table."""
    table, version = src.platform.smbios_table()
    return decode_smbios(table, version)


def _acpi_headers(src: Sources) -> JsonValue:
    headers: list[JsonValue] = [decode_acpi_header(t) for t in src.platform.acpi_tables()]
    return headers


def _msdm(src: Sources) -> JsonValue:
    for table in src.platform.acpi_tables():
        if table[:4] == b"MSDM":
            return msdm_product_key(table)
    return {"present": False, "product_key": None}


def _acpi_registry(src: Sources) -> JsonValue:
    # HKLM\HARDWARE\ACPI\<table>\<OEM id>\<table id>\<revision>: what Windows recorded at boot.
    out: JsonObject = {}
    base = r"HKLM\HARDWARE\ACPI"
    for table in src.registry.subkeys(base):
        oems = src.registry.subkeys(rf"{base}\{table}")
        out[table] = [_acpi_oem(src, rf"{base}\{table}", oem) for oem in oems]
    return out


def _acpi_oem(src: Sources, table_key: str, oem: str) -> JsonValue:
    ids = src.registry.subkeys(rf"{table_key}\{oem}")
    revisions: list[JsonValue] = [r for i in ids for r in src.registry.subkeys(rf"{table_key}\{oem}\{i}")]
    table_ids: list[JsonValue] = list(ids)
    return {"oem_id": oem, "table_id": table_ids, "revision": revisions}


def _class_keys(src: Sources) -> dict[str, JsonObject]:
    keys: dict[str, JsonObject] = {}
    for number in src.registry.subkeys(_NET_CLASS):
        if not number.isdigit():
            continue
        values = _guarded(lambda number=number: _values(src, rf"{_NET_CLASS}\{number}"))
        if not isinstance(values, dict):
            continue
        guid = values.get("NetCfgInstanceId")
        if isinstance(guid, str):
            keys[guid.upper()] = {"number": number, "values": values}
    return keys


def _category_rows(src: Sources, class_name: str) -> list[JsonObject]:
    namespace = _CIMV2 if class_name.startswith("Win32_") else _STANDARD
    return src.platform.cim(class_name, namespace=namespace)


def read_network(src: Sources) -> JsonValue:
    """Read every adapter with every per-adapter class joined to it."""
    adapters = src.platform.cim("MSFT_NetAdapter", namespace=_STANDARD)
    categories: dict[str, Sequence[JsonObject]] = {}
    errors: JsonObject = {}
    for category, class_name in {**BY_NAME, **BY_INDEX}.items():
        try:
            categories[category] = _category_rows(src, class_name)
        except _ANSWER_ERRORS as exc:
            errors[category] = f"{type(exc).__name__}: {exc}"
    class_keys = _guarded(lambda: dict[str, JsonValue](_class_keys(src)))
    joined = join_adapters(adapters, categories, _as_class_keys(class_keys))
    joined["errors"] = errors
    if not isinstance(class_keys, dict) or "error" in class_keys:
        joined["class_keys_error"] = class_keys
    return joined


def _as_class_keys(value: JsonValue) -> dict[str, JsonObject]:
    if not isinstance(value, dict) or "error" in value:
        return {}
    return {k: v for k, v in value.items() if isinstance(v, dict)}


def _instances(src: Sources) -> Iterable[str]:
    # Enum\<bus>\<device>\<instance>: one key per device instance Windows has ever seen.
    for bus in src.registry.subkeys(_ENUM):
        devices = _guarded(lambda bus=bus: list[JsonValue](src.registry.subkeys(rf"{_ENUM}\{bus}")))
        for device in devices if isinstance(devices, list) else []:
            path = rf"{bus}\{device}"
            found = _guarded(lambda path=path: list[JsonValue](src.registry.subkeys(rf"{_ENUM}\{path}")))
            yield from (rf"{path}\{inst}" for inst in (found if isinstance(found, list) else []))


def _upper_id(row: JsonObject, key: str) -> str:
    value = row.get(key)
    return value.upper() if isinstance(value, str) else ""


def read_devices(src: Sources) -> JsonValue:
    """Read every device instance in the registry, present or not, with its driver if present."""
    present = {_upper_id(r, "DeviceID"): r for r in src.platform.cim("Win32_PnPEntity")}
    drivers_answer = _guarded(lambda: cim("Win32_PnPSignedDriver")(src))
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
                "registry": _guarded(lambda inst=inst: _values(src, rf"{_ENUM}\{inst}")),
                "driver": drivers.get(inst.upper()),
            }
        )
    acpi: list[JsonValue] = sorted({k.split("\\")[1] for k in present if k.startswith("ACPI\\")})
    drivers_error = drivers_answer if isinstance(drivers_answer, dict) else None
    return {"instances": rows, "acpi_ids": acpi, "drivers_error": drivers_error}


def _local_sids(src: Sources) -> JsonValue:
    accounts = src.platform.cim("Win32_UserAccount", where="LocalAccount = TRUE")
    return machine_sid(a.get("SID") for a in accounts)


def _cloud_join(src: Sources) -> JsonValue:
    return {thumb: _guarded(lambda t=thumb: _values(src, rf"{_CLOUD_JOIN}\{t}")) for thumb in src.registry.subkeys(_CLOUD_JOIN)}


def _current_version(src: Sources) -> JsonValue:
    return withhold_registry_values(_values(src, _CURRENT_VERSION))


def _ek_certificates(src: Sources) -> JsonValue:
    out: list[JsonValue] = []
    for thumb in src.registry.subkeys(_EK_STORE):
        blob = src.registry.values(rf"{_EK_STORE}\{thumb}").get("Blob")
        der = der_from_store_blob(blob) if isinstance(blob, bytes) else None
        detail = describe_certificate(der) if der is not None else {"error": "no certificate in the store blob"}
        out.append({"store_thumbprint": thumb, **detail})
    return out


def _tbs(src: Sources) -> JsonValue:
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
    Section.SMBIOS: read_smbios,
    Section.NETWORK: read_network,
    Section.DEVICES: read_devices,
}


def read_section(src: Sources, section: Section) -> JsonValue:
    """Read one section, each of its questions guarded."""
    whole = WHOLE_SECTIONS.get(section)
    if whole is not None:
        return _guarded(lambda: whole(src))
    return {name: _guarded(lambda read=read: read(src)) for name, read in ITEM_SECTIONS[section].items()}


def collect(
    src: Sources,
    *,
    label: str,
    collected_at: str,
    tool_version: str,
    sections: Sequence[Section] | None = None,
) -> JsonObject:
    """Read the machine and return the reading, product keys masked.

    Args:
        src: the platform and registry sources.
        label: a name for this reading, shown when comparing.
        collected_at: when the reading was taken (ISO 8601, UTC).
        tool_version: the version of this tool.
        sections: the sections to read; all of them when None.

    Returns:
        ``meta``, ``summary`` and one key per section read.
    """
    chosen = list(Section) if sections is None else list(sections)
    body: JsonObject = {s.value: read_section(src, s) for s in chosen}
    reading: JsonObject = {
        "meta": {
            "label": label,
            "tool": "read-machine-id",
            "tool_version": tool_version,
            "schema_version": SCHEMA_VERSION,
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
    "read_devices",
    "read_network",
    "read_section",
    "read_smbios",
    "reg",
    "reg_value",
    "registry_json",
]
