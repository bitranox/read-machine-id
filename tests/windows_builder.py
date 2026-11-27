r"""The parts of a recorded Windows machine the pci, cpu, memory, disks, devices and security sections read.

:func:`windows_extras` returns what :func:`machine_builder.machine_document` merges into its
recording: CIM rows, registry keys, configuration-manager device properties and the kernel
answers (NUMA, DMA guard). Every value is invented; the machine is VMware-like, with a PVSCSI
controller whose instance id is its Device Serial Number and a vmxnet3 NIC whose is not.
"""

from __future__ import annotations

from edid_bytes import edid_block

from fingerprint_machine.domain.json_types import JsonObject, JsonValue

#: The host name in the recorded WMI object paths.
HOST = "TESTBOX"
PVSCSI_PARENT = r"PCI\VEN_15AD&DEV_07A0&SUBSYS_07A015AD&REV_01\3&61AAA01&0&A8"
PVSCSI_LOCATION_PATHS = ["PCIROOT(0)#PCI(1500)#PCI(0000)", r"ACPI(_SB_)#ACPI(PCI0)#ACPI(P2P0)#PCI(0000)"]
#: A TPM owner authorization the registry might cache; planted to prove a reading never carries it.
PLANTED_OWNER_AUTH = "c3ludGhldGljLW93bmVyLWF1dGg="
MONITOR = r"DISPLAY\VMW0001\5&2B3C4D5E&0&UID4352"

_ENUM = r"HKLM\SYSTEM\CurrentControlSet\Enum"
_SCSI = r"HKLM\HARDWARE\DEVICEMAP\Scsi"
_MSI = r"Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"


def _key(values: dict[str, JsonValue] | None = None, subkeys: list[str] | None = None) -> JsonValue:
    entry: JsonObject = {"values": values or {}, "subkeys": list[JsonValue](subkeys or [])}
    return entry


def _path(class_name: str, key: str, value: str | int) -> str:
    text = f'"{value}"' if isinstance(value, str) else str(value)
    return rf"\\{HOST}\root\cimv2:{class_name}.{key}={text}"


def _entity(instance_id: str) -> str:
    return _path("Win32_PnPEntity", "DeviceID", instance_id.replace("\\", "\\\\"))


def _allocated(instance_id: str, class_name: str, key: str, value: str | int) -> JsonValue:
    return {"Antecedent": _path(class_name, key, value), "Dependent": _entity(instance_id)}


def _inquiry(vendor: str, product: str, rev: str) -> str:
    data = bytes([0, 0, 6, 0x12, 31, 0, 0, 0x32]) + vendor.ljust(8).encode() + product.ljust(16).encode()
    return (data + rev.ljust(4).encode()).hex()


def _naa_page(naa: str) -> str:
    value = bytes.fromhex(naa)
    designator = bytes([0x01, 0x03, 0x00, len(value)]) + value
    return (bytes([0x00, 0x83, 0x00, len(designator)]) + designator).hex()


def _cim(*, nic: str, scsi: str) -> JsonObject:
    return {
        "root/cimv2:Win32_PnPAllocatedResource": [
            # An object path writes a message-signaled IRQ unsigned; Win32_IRQResource signed (-3).
            _allocated(scsi, "Win32_IRQResource", "IRQNumber", 2**32 - 3),
            _allocated(scsi, "Win32_IRQResource", "IRQNumber", -4),
            _allocated(scsi, "Win32_DeviceMemoryAddress", "StartingAddress", "4271898624"),
            _allocated(scsi, "Win32_PortResource", "StartingAddress", "4096"),
            _allocated(nic, "Win32_IRQResource", "IRQNumber", 18),
            {"Antecedent": "not an object path", "Dependent": _entity(nic)},
        ],
        "root/cimv2:Win32_IRQResource": [
            {"IRQNumber": 18, "TriggerType": 2, "TriggerLevel": 2, "Shareable": True, "Vector": 18},
            {"IRQNumber": -3, "TriggerType": 2, "TriggerLevel": 2, "Shareable": None, "Vector": -1},
            {"IRQNumber": -4, "TriggerType": 2, "TriggerLevel": 2, "Shareable": None, "Vector": -1},
        ],
        "root/cimv2:Win32_DeviceMemoryAddress": [
            {"StartingAddress": "4271898624", "EndingAddress": "4271931391", "MemoryType": "ReadWrite"}
        ],
        "root/cimv2:Win32_PortResource": [{"StartingAddress": "4096", "EndingAddress": "4103"}],
        "root/cimv2:Win32_DMAChannel": [],
        "root/cimv2:Win32_Bus": [{"DeviceID": "PCI_BUS_3", "BusNum": 3, "BusType": 5}],
        "root/cimv2:Win32_DeviceBus": [
            {
                "Antecedent": _path("Win32_Bus", "DeviceID", "PCI_BUS_3"),
                "Dependent": _entity(scsi),
            }
        ],
        "root/cimv2:Win32_SystemDriver": [
            {"Name": "pvscsi", "PathName": r"C:\Windows\system32\drivers\pvscsi.sys", "State": "Running"},
            {"Name": "floppy", "PathName": r"C:\Windows\system32\drivers\flpydisk.sys", "State": "Stopped"},
        ],
        "root/cimv2:Win32_PageFileUsage": [{"Name": r"C:\pagefile.sys", "AllocatedBaseSize": 2048}],
        "root/cimv2:Win32_PageFileSetting": [],
        "root/Microsoft/Windows/Defender:MSFT_MpComputerStatus": [
            {"AMServiceEnabled": True, "RealTimeProtectionEnabled": True, "IsTamperProtected": True}
        ],
        "root/StandardCimv2:MSFT_NetFirewallProfile": [
            {"Name": "Domain", "Enabled": 1},
            {"Name": "Private", "Enabled": 1},
            {"Name": "Public", "Enabled": 1},
        ],
        "root/cimv2/Security/MicrosoftVolumeEncryption:Win32_EncryptableVolume": [
            {"DriveLetter": "C:", "ProtectionStatus": 0, "ConversionStatus": 0, "EncryptionMethod": 0}
        ],
    }


def _pci_keys(*, nic: str, scsi: str) -> JsonObject:
    nic_ids: list[JsonValue] = [
        r"PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01",
        r"PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD",
    ]
    scsi_ids: list[JsonValue] = [
        r"PCI\VEN_15AD&DEV_07C0&SUBSYS_07C015AD&REV_02",
        r"PCI\VEN_15AD&DEV_07C0&SUBSYS_07C015AD",
    ]
    return {
        rf"{_ENUM}\{nic}": _key(
            {
                "UINumber": 160,
                "LocationInformation": "PCI bus 11, device 0, function 0",
                "HardwareID": nic_ids,
                "CompatibleIDs": [r"PCI\VEN_15AD&DEV_07B0&REV_01", r"PCI\VEN_15AD&CC_020000"],
                "Service": "vmxnet3ndis6",
                "Capabilities": 6,
            },
            ["Device Parameters"],
        ),
        rf"{_ENUM}\{scsi}": _key(
            {
                "UINumber": 160,
                "LocationInformation": r"@System32\drivers\pci.sys,#65536;PCI bus %1, device %2, function %3;(3,0,0)",
                "HardwareID": scsi_ids,
                "CompatibleIDs": [r"PCI\VEN_15AD&DEV_07C0&REV_02", r"PCI\VEN_15AD&CC_010700"],
                "Service": "pvscsi",
                "Capabilities": 0x10 | 0x4,
            },
            ["Device Parameters"],
        ),
        rf"{_ENUM}\{scsi}\{_MSI}": _key({"MSISupported": 1, "MessageNumberLimit": 2}),
    }


def _scsi_keys() -> JsonObject:
    port = rf"{_SCSI}\Scsi Port 0"
    unit = rf"{port}\Scsi Bus 0\Target Id 0\Logical Unit Id 0"
    return {
        _SCSI: _key(subkeys=["Scsi Port 0"]),
        port: _key({"Driver": "pvscsi", "Interrupt": 0}, ["Scsi Bus 0"]),
        rf"{port}\Scsi Bus 0": _key(subkeys=["Initiator Id 7", "Target Id 0"]),
        rf"{port}\Scsi Bus 0\Initiator Id 7": _key(),
        rf"{port}\Scsi Bus 0\Target Id 0": _key(subkeys=["Logical Unit Id 0"]),
        unit: _key(
            {
                "Identifier": "VMware  Virtual disk    2.0 ",
                "InquiryData": {"hex": _inquiry("VMware", "Virtual disk", "2.0")},
                "DeviceIdentifierPage": {"hex": _naa_page("6000c29abcdef0123456789abcdef012")},
                "DeviceType": "DiskPeripheral",
            }
        ),
    }


def _cpu_and_display_keys() -> JsonObject:
    processors = r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor"
    monitor = rf"{_ENUM}\{MONITOR}"
    edid = edid_block(vendor="VMW", product=0x0001, serial=0x01234567, year=2020, texts={0xFC: "VMware SVGA"})
    return {
        # The registry lists subkeys in text order, so processor 10 comes before processor 2.
        processors: _key(subkeys=["0", "1", "10", "2"]),
        rf"{processors}\0": _key({"ProcessorNameString": "Example CPU", "~MHz": 2700}),
        rf"{processors}\1": _key({"ProcessorNameString": "Example CPU", "~MHz": 2700}),
        rf"{processors}\10": _key({"ProcessorNameString": "Example CPU", "~MHz": 3100}),
        rf"{processors}\2": _key({"ProcessorNameString": "Example CPU", "~MHz": 2700}),
        rf"{_ENUM}\DISPLAY": _key(subkeys=["VMW0001"]),
        rf"{_ENUM}\DISPLAY\VMW0001": _key(subkeys=["5&2B3C4D5E&0&UID4352"]),
        monitor: _key({"DeviceDesc": "Generic PnP Monitor", "Driver": "{4d36e96e-e325-11ce-bfc1-08002be10318}\\0000"}),
        rf"{monitor}\Device Parameters": _key({"EDID": {"hex": edid.hex()}}),
    }


def _security_keys() -> JsonObject:
    control = r"HKLM\SYSTEM\CurrentControlSet\Control"
    providers = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"
    password = "{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}"
    return {
        rf"{control}\Lsa": _key({"RunAsPPL": 2, "RunAsPPLBoot": 2, "LimitBlankPasswordUse": 1}),
        rf"{control}\SecureBoot": _key({"AvailableUpdates": 0}, ["Servicing", "State"]),
        rf"{control}\SecureBoot\Servicing": _key({"UEFICA2023Status": "NotStarted"}),
        rf"{control}\DeviceGuard": _key({"EnableVirtualizationBasedSecurity": 1}),
        r"HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI": _key(
            {"OwnerAuthFull": PLANTED_OWNER_AUTH, "OSManagedAuthLevel": 4, "TaskReadyForAttestation": 1},
            ["Admin", "Endorsement"],
        ),
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System": _key(
            {"EnableLUA": 1, "ConsentPromptBehaviorAdmin": 5}
        ),
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer": _key({"SmartScreenEnabled": "Warn"}),
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU": _key({"NoAutoUpdate": 0, "AUOptions": 2}),
        providers: _key(subkeys=[password]),
        rf"{providers}\{password}": _key({"": "PasswordProvider"}),
    }


def windows_extras(*, nic: str, scsi: str) -> JsonObject:
    """Return the recorded answers the Windows gap-fill readers ask for.

    ``nic`` and ``scsi`` are the instance ids of the two PCI functions the recording already has.
    """
    registry: JsonObject = {
        **_pci_keys(nic=nic, scsi=scsi),
        **_scsi_keys(),
        **_cpu_and_display_keys(),
        **_security_keys(),
    }
    properties: JsonObject = {
        scsi: {
            "parent": PVSCSI_PARENT,
            "location_paths": list[JsonValue](PVSCSI_LOCATION_PATHS),
            "bus_number": 3,
            "address": 0,
            "current_link_speed": 1,
            "current_link_width": 32,
            "max_link_speed": 1,
            "max_link_width": 32,
            "base_class": 1,
            "sub_class": 7,
            "interrupt_support": 0x2 | 0x4,
            "interrupt_message_maximum": 32,
        },
    }
    system: JsonObject = {"numa_nodes": [{"node": 0, "group": 0, "mask": "0xf"}], "kernel_dma_protection": False}
    return {"cim": _cim(nic=nic, scsi=scsi), "registry": registry, "device_properties": properties, "system": system}


__all__ = ["HOST", "MONITOR", "PLANTED_OWNER_AUTH", "PVSCSI_LOCATION_PATHS", "PVSCSI_PARENT", "windows_extras"]
