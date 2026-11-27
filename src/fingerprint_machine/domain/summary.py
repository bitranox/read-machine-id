"""The fingerprint at a glance: the identity values of a reading, pulled from its sections.

Built only from sections already read, so it asks the machine nothing and cannot disagree with
them. A section that was not read, or failed, leaves its summary fields None.

Contents:
    * :func:`summarize` - the summary of a reading's sections.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .identity import instance_serial, vmware_pvscsi_sas_wwid

if TYPE_CHECKING:
    from .json_types import JsonObject, JsonValue


def _node(body: JsonValue, *path: str) -> JsonValue:
    node = body
    for key in path:
        node = node.get(key) if isinstance(node, dict) else None
    return node


def _rows(body: JsonValue, *path: str) -> list[JsonObject]:
    node = _node(body, *path)
    return [r for r in node if isinstance(r, dict)] if isinstance(node, list) else []


def _first(body: JsonValue, *path: str) -> JsonObject:
    rows = _rows(body, *path)
    return rows[0] if rows else {}


def _obj(body: JsonValue, *path: str) -> JsonObject:
    node = _node(body, *path)
    return node if isinstance(node, dict) else {}


def _int_sum(rows: list[JsonObject], key: str) -> int:
    return sum(v for r in rows if isinstance(v := r.get(key), int))


def _system(body: JsonObject) -> JsonObject:
    smbios = _obj(body, "smbios", "system")
    return {
        "manufacturer": smbios.get("manufacturer"),
        "product": smbios.get("product"),
        "serial": smbios.get("serial"),
        "uuid": smbios.get("uuid") or _first(body, "platform", "product").get("UUID"),
        "sku": smbios.get("sku"),
        "family": smbios.get("family"),
        "bios_version": _first(body, "platform", "bios").get("SMBIOSBIOSVersion"),
    }


def _cpu(body: JsonObject) -> JsonObject:
    cpus = _rows(body, "cpu", "wmi")
    first = cpus[0] if cpus else {}
    return {
        "sockets": len(cpus),
        "name": first.get("Name"),
        "processor_id": first.get("ProcessorId"),
        "cores": _int_sum(cpus, "NumberOfCores"),
        "logical_processors": _int_sum(cpus, "NumberOfLogicalProcessors"),
    }


def _memory(body: JsonObject) -> JsonObject:
    modules = _rows(body, "memory", "modules")
    sizes: list[JsonValue] = [m.get("Capacity") for m in modules]
    return {
        "total_bytes": _first(body, "platform", "computer_system").get("TotalPhysicalMemory"),
        "modules": len(modules),
        "module_sizes": sizes,
    }


def _nic(record: JsonObject) -> JsonValue:
    adapter = _obj(record, "adapter")
    hardware = _first(record, "hardware")
    return {
        "name": adapter.get("Name"),
        "description": adapter.get("InterfaceDescription"),
        "mac": adapter.get("PermanentAddress"),
        "interface_index": adapter.get("InterfaceIndex"),
        "pci_serial": instance_serial(adapter.get("PnPDeviceID")),
        "bus": hardware.get("BusNumber"),
        "device": hardware.get("DeviceNumber"),
        "function": hardware.get("FunctionNumber"),
        "slot": hardware.get("SlotNumber"),
        "class_key": _obj(record, "class_key").get("number"),
    }


def _scsi(row: JsonObject) -> JsonValue:
    pnp = row.get("PNPDeviceID")
    return {"name": row.get("Name"), "pci_serial": instance_serial(pnp), "sas_wwid": vmware_pvscsi_sas_wwid(pnp)}


def _disks(body: JsonObject) -> list[JsonValue]:
    storage = {r.get("Number"): r for r in _rows(body, "disks", "storage")}
    out: list[JsonValue] = []
    for d in _rows(body, "disks", "wmi"):
        msft = storage.get(d.get("Index"), {})
        out.append(
            {
                "model": d.get("Model"),
                "serial": d.get("SerialNumber"),
                "size": d.get("Size"),
                "mbr_signature": d.get("Signature"),
                "gpt_guid": msft.get("Guid"),
                "unique_id": msft.get("UniqueId"),
            }
        )
    return out


def _windows(body: JsonObject) -> JsonObject:
    version = _obj(body, "windows", "current_version")
    os_row = _first(body, "windows", "operating_system")
    licence = _first(body, "windows", "licensing_products")
    return {
        "computer_name": os_row.get("CSName"),
        "edition": version.get("EditionID"),
        "build": f"{version.get('CurrentBuild')}.{version.get('UBR')}" if version else None,
        "product_id": version.get("ProductId") or os_row.get("SerialNumber"),
        "device_id": _node(body, "windows", "device_id"),
        "machine_guid": _node(body, "windows", "machine_guid"),
        "machine_sid": _node(body, "windows", "machine_sid"),
        "license_status": licence.get("LicenseStatus"),
        "partial_product_key": licence.get("PartialProductKey"),
    }


def _security(body: JsonObject) -> JsonObject:
    tpm = _first(body, "security", "tpm")
    return {
        "firmware_type": _node(body, "security", "firmware_type"),
        "secure_boot": _obj(body, "security", "secure_boot").get("UEFISecureBootEnabled"),
        "tpm_version": _obj(body, "security", "tbs").get("tpm_version"),
        "tpm_manufacturer": tpm.get("ManufacturerIdTxt"),
        "tpm_spec_version": tpm.get("SpecVersion"),
        "vbs_status": _first(body, "security", "device_guard").get("VirtualizationBasedSecurityStatus"),
    }


def summarize(body: JsonObject) -> JsonObject:
    """Return the identity values of a reading's sections.

    Examples:
        >>> s = summarize({"cpu": {"wmi": [{"Name": "Xeon", "NumberOfCores": 4, "NumberOfLogicalProcessors": 8}]}})
        >>> s["cpu"]["sockets"], s["cpu"]["cores"], s["nics"], s["system"]["uuid"]
        (1, 4, [], None)
    """
    nics: list[JsonValue] = [_nic(r) for r in _rows(body, "network", "adapters")]
    scsi: list[JsonValue] = [_scsi(r) for r in _rows(body, "hardware", "scsi_controllers")]
    return {
        "system": _system(body),
        "cpu": _cpu(body),
        "memory": _memory(body),
        "nics": nics,
        "scsi_controllers": scsi,
        "disks": _disks(body),
        "windows": _windows(body),
        "security": _security(body),
    }


__all__ = ["summarize"]
