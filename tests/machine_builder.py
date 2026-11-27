"""Build synthetic machines for the tests: SMBIOS structures and a whole recorded machine.

Every value here is invented. The serial numbers, UUIDs, MACs and the product key below belong to
no real machine.
"""

from __future__ import annotations

import datetime as dt
import functools
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from windows_builder import windows_extras

from fingerprint_machine.domain.json_types import JsonObject, JsonValue

#: A product key in the shape Windows uses; planted to prove that no full key is ever printed.
PLANTED_KEY = "QW3ER-TY4UI-OP5AS-DF6GH-JK7LZ"
#: A synthetic VMware PVSCSI pair: the instance serial and the sasWWID it encodes.
PVSCSI_SERIAL = "0123ABCD5005056000"
PVSCSI_WWID = "500505600123abcd"
SYSTEM_UUID_BYTES = bytes(range(1, 17))
NIC_GUID = "{11111111-2222-3333-4444-555555555555}"


def structure(stype: int, handle: int, length: int, fields: dict[int, bytes], strings: list[str]) -> bytes:
    """Return one SMBIOS structure: header, formatted area of ``length`` bytes, string set."""
    area = bytearray(length)
    area[0:4] = struct.pack("<BBH", stype, length, handle)
    for offset, data in fields.items():
        area[offset : offset + len(data)] = data
    tail = b"".join(s.encode() + b"\0" for s in strings) + b"\0" if strings else b"\0\0"
    return bytes(area) + tail


def b(value: int) -> bytes:
    """One byte."""
    return bytes([value])


def w(value: int) -> bytes:
    """One little-endian word."""
    return struct.pack("<H", value)


def d(value: int) -> bytes:
    """One little-endian dword."""
    return struct.pack("<I", value)


def q(value: int) -> bytes:
    """One little-endian qword."""
    return struct.pack("<Q", value)


def smbios_table(*, serial: str = "SER-0001") -> bytes:
    """Return a table with types 0, 1, 2, 3, 9, 11, 16, 17, 19, 41 and the end marker."""
    return b"".join(
        [
            structure(
                0,
                0,
                0x1A,
                {4: b(1), 5: b(2), 6: w(0xE800), 8: b(3), 0x14: b(1), 0x15: b(2)},
                ["Vendor Inc.", "V1.2", "01/02/2024"],
            ),
            structure(
                1,
                1,
                0x1B,
                {4: b(1), 5: b(2), 6: b(3), 7: b(4), 8: SYSTEM_UUID_BYTES, 0x18: b(6), 0x19: b(5), 0x1A: b(6)},
                ["Example Systems", "Model X", "1.0", serial, "SKU-9", "Family Y"],
            ),
            structure(2, 2, 0x0F, {4: b(1), 5: b(2), 7: b(3), 0x0D: b(0x0A)}, ["Board Co", "Board Z", "BRD-77"]),
            structure(3, 3, 0x15, {4: b(1), 5: b(0x81), 7: b(2), 9: b(3)}, ["Chassis Co", "CH-5"]),
            structure(
                9,
                4,
                0x11,
                {4: b(1), 5: b(0xA5), 9: w(7), 0x0D: w(0), 0x0F: b(3), 0x10: b((2 << 3) | 1)},
                ["PCIe Slot 7"],
            ),
            structure(11, 5, 0x05, {4: b(2)}, ["oem one", "oem two"]),
            structure(16, 6, 0x17, {4: b(3), 5: b(3), 6: b(3), 7: d(0x100000), 0x0D: w(2)}, []),
            structure(
                17,
                7,
                0x22,
                {0x0C: w(0x2000), 0x10: b(1), 0x11: b(2), 0x15: w(3200), 0x18: b(3)},
                ["DIMM 0", "BANK 0", "MEMSER-1"],
            ),
            structure(19, 8, 0x1F, {4: d(0), 8: d(0x7FFFFF), 0x0C: w(6), 0x0E: b(1)}, []),
            structure(
                41,
                9,
                0x0B,
                {4: b(1), 5: b(0x80 | 0x05), 6: b(1), 7: w(1), 9: b(0x0B), 0x0A: b((0 << 3) | 0)},
                ["Onboard NIC"],
            ),
            structure(127, 10, 0x04, {}, []),
        ]
    )


def acpi_table(signature: bytes, body: bytes = b"") -> bytes:
    """Return an ACPI table: the 36-byte header and ``body``."""
    header = struct.pack("<4sIBB6s8sI4sI", signature, 36 + len(body), 1, 0, b"OEMID ", b"TABLEID ", 1, b"TOOL", 1)
    return header + body


@functools.cache
def ek_certificate_der() -> bytes:
    """Return a self-signed DER certificate standing in for a TPM EK certificate.

    Made once per run: the key and the ECDSA signature are random, and two recordings of one
    machine must carry the same certificate.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic EK")])
    start = dt.datetime(2024, 1, 1, tzinfo=dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x1234ABCD)
        .not_valid_before(start)
        .not_valid_after(start + dt.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


def store_blob(der: bytes) -> bytes:
    """Return a registry certificate store blob holding ``der`` after one unrelated property."""
    return struct.pack("<III", 3, 1, 4) + b"junk" + struct.pack("<III", 32, 1, len(der)) + der


def _regs(eax: int, ebx: int, ecx: int, edx: int) -> JsonValue:
    return {"eax": f"0x{eax:08x}", "ebx": f"0x{ebx:08x}", "ecx": f"0x{ecx:08x}", "edx": f"0x{edx:08x}"}


def _words(text: bytes) -> list[int]:
    return [int.from_bytes(text[i : i + 4], "little") for i in range(0, len(text), 4)]


def cpuid_document(*, hypervisor: bytes = b"VMwareVMware", vendor: bytes = b"GenuineIntel") -> JsonObject:
    """Return recorded CPUID answers, keyed as a reading's ``cpuid.raw`` keys them.

    Leaf 0 spells ``vendor`` (EBX, EDX, ECX), leaf 1 sets the hypervisor bit, and leaf
    0x40000000 spells ``hypervisor`` (EBX, ECX, EDX) with 0x40000001 as its highest leaf.
    """
    v_ebx, v_edx, v_ecx = _words(vendor)
    h_ebx, h_ecx, h_edx = _words(hypervisor.ljust(12, b"\0"))
    return {
        "0x00000000:0": _regs(1, v_ebx, v_ecx, v_edx),
        "0x00000001:0": _regs(0x000306E4, 0, 1 << 31, 1),
        "0x80000000:0": _regs(0x80000001, 0, 0, 0),
        "0x80000001:0": _regs(0, 0, 0, 1 << 29),
        "0x40000000:0": _regs(0x40000001, h_ebx, h_ecx, h_edx),
        "0x40000001:0": _regs(0, 0, 0, 0),
    }


def _key(values: dict[str, JsonValue] | None = None, subkeys: list[str] | None = None) -> JsonValue:
    entry: JsonObject = {"values": values or {}, "subkeys": list[JsonValue](subkeys or [])}
    return entry


_ENUM = r"HKLM\SYSTEM\CurrentControlSet\Enum"
_NET_CLASS = r"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
_EK = r"HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI\Endorsement\EKCertStore\Certificates"
_PVSCSI = r"PCI\VEN_15AD&DEV_07C0&SUBSYS_07C015AD&REV_02"
_NIC = r"PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01"


def machine_document(*, product_id: str = "00330-80000-00000-AA111", serial: str = "SER-0001") -> JsonObject:
    """Return a recorded VMware-like machine for :class:`FixtureSources`."""
    table = smbios_table(serial=serial)
    der = ek_certificate_der()
    msdm = acpi_table(b"MSDM", bytes(20) + PLANTED_KEY.encode())
    nic_pnp = f"{_NIC}\\000C29FFFF000001"
    scsi_pnp = f"{_PVSCSI}\\{PVSCSI_SERIAL}"
    cim: JsonObject = {
        "root/cimv2:Win32_Processor": [
            {
                "Name": "Example CPU",
                "ProcessorId": "0000ABCD",
                "NumberOfCores": 2,
                "NumberOfLogicalProcessors": 4,
                "LoadPercentage": 3,
            }
        ],
        "root/cimv2:Win32_ComputerSystem": [{"TotalPhysicalMemory": "8589934592", "PartOfDomain": False}],
        "root/cimv2:Win32_ComputerSystemProduct": [{"UUID": "04030201-0605-0807-090A-0B0C0D0E0F10"}],
        "root/cimv2:Win32_BIOS": [{"SMBIOSBIOSVersion": "V1.2"}],
        "root/cimv2:Win32_PhysicalMemory": [{"Capacity": "8589934592"}],
        "root/cimv2:Win32_OperatingSystem": [
            {"CSName": "TESTBOX", "SerialNumber": product_id, "FreePhysicalMemory": "123456"}
        ],
        "root/cimv2:Win32_DiskDrive": [
            {"Index": 0, "Model": "Virtual disk", "SerialNumber": "DISK-1", "Size": "1000", "Signature": 42}
        ],
        "root/Microsoft/Windows/Storage:MSFT_Disk": [
            {"Number": 0, "Guid": "{aaaaaaaa-0000-0000-0000-000000000001}", "UniqueId": "UID-1"}
        ],
        "root/cimv2:Win32_SCSIController": [{"Name": "VMware PVSCSI Controller", "PNPDeviceID": scsi_pnp}],
        "root/cimv2:Win32_PnPEntity": [
            {"DeviceID": nic_pnp, "Name": "vmxnet3 Ethernet Adapter"},
            {"DeviceID": scsi_pnp, "Name": "VMware PVSCSI Controller"},
            {"DeviceID": r"ACPI\PNP0A03\0", "Name": "PCI Bus"},
        ],
        "root/cimv2:Win32_PnPSignedDriver": [{"DeviceID": nic_pnp, "DriverVersion": "1.9.19.0"}],
        "root/StandardCimv2:MSFT_NetAdapter": [
            {
                "Name": "Ethernet0",
                "InterfaceIndex": 6,
                "DeviceID": NIC_GUID,
                "PermanentAddress": "005056000001",
                "PnPDeviceID": nic_pnp,
                "InterfaceDescription": "vmxnet3 Ethernet Adapter",
            }
        ],
        "root/StandardCimv2:MSFT_NetAdapterHardwareInfoSettingData": [
            {"Name": "Ethernet0", "BusNumber": 11, "DeviceNumber": 0, "FunctionNumber": 0, "SlotNumber": 160}
        ],
        "root/StandardCimv2:MSFT_NetAdapterAdvancedPropertySettingData": [
            {"Name": "Ethernet0", "RegistryKeyword": "*JumboPacket", "DisplayValue": "1514"},
            {"Name": "Ethernet0", "RegistryKeyword": "*RSS", "DisplayValue": "Enabled"},
        ],
        "root/StandardCimv2:MSFT_NetIPAddress": [{"InterfaceIndex": 6, "IPAddress": "192.0.2.10"}],
        "root/cimv2:Win32_NetworkAdapterConfiguration": [
            {"InterfaceIndex": 6, "DHCPLeaseExpires": "20260101000000.000000+000"}
        ],
        "root/cimv2:Win32_UserAccount": [{"SID": "S-1-5-21-1000-2000-3000-500"}],
        "root/cimv2:SoftwareLicensingProduct": [
            {"LicenseStatus": 1, "PartialProductKey": PLANTED_KEY[-5:], "Description": f"retail {PLANTED_KEY}"}
        ],
        "root/cimv2/Security/MicrosoftTpm:Win32_Tpm": [{"ManufacturerIdTxt": "VMW", "SpecVersion": "2.0, 0, 1.59"}],
        "root/Microsoft/Windows/DeviceGuard:Win32_DeviceGuard": [{"VirtualizationBasedSecurityStatus": 0}],
    }
    registry: JsonObject = {
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion": _key(
            {
                "ProductId": product_id,
                "EditionID": "Professional",
                "CurrentBuild": "26100",
                "UBR": 1000,
                "DigitalProductId": {"hex": "a4000000" + PLANTED_KEY.encode().hex()},
                "OA3xOriginalProductKey": PLANTED_KEY,
            }
        ),
        r"HKLM\SOFTWARE\Microsoft\Cryptography": _key({"MachineGuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}),
        r"HKLM\SOFTWARE\Microsoft\SQMClient": _key({"MachineId": "{DDDDDDDD-0000-0000-0000-000000000001}"}),
        r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State": _key({"UEFISecureBootEnabled": 1}),
        _NET_CLASS: _key(subkeys=["0007", "Properties"]),
        _NET_CLASS + r"\0007": _key({"NetCfgInstanceId": NIC_GUID, "DriverDesc": "vmxnet3 Ethernet Adapter"}),
        _ENUM: _key(subkeys=["PCI"]),
        _ENUM + r"\PCI": _key(
            subkeys=["VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01", "VEN_15AD&DEV_07C0&SUBSYS_07C015AD&REV_02"]
        ),
        _ENUM + r"\PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01": _key(
            subkeys=["000C29FFFF000001", "000C29FFFF000002"]
        ),
        _ENUM + r"\PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\000C29FFFF000001": _key(
            {"UINumber": 160, "LocationInformation": "PCI bus 11, device 0, function 0"}
        ),
        _ENUM + r"\PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\000C29FFFF000002": _key({"UINumber": 192}),
        _ENUM + r"\PCI\VEN_15AD&DEV_07C0&SUBSYS_07C015AD&REV_02": _key(subkeys=[PVSCSI_SERIAL]),
        _ENUM + rf"\PCI\VEN_15AD&DEV_07C0&SUBSYS_07C015AD&REV_02\{PVSCSI_SERIAL}": _key({"UINumber": 160}),
        _EK: _key(subkeys=["ABCDEF"]),
        _EK + r"\ABCDEF": _key({"Blob": {"hex": store_blob(der).hex()}}),
    }
    firmware: JsonObject = {
        "smbios_hex": table.hex(),
        "smbios_version": "3.1",
        "acpi_hex": [acpi_table(b"FACP").hex(), msdm.hex()],
        "tbs_hex": struct.pack("<IIII", 1, 2, 4, 0x4D).hex(),
        "firmware_type": "UEFI",
    }
    extras = windows_extras(nic=nic_pnp, scsi=scsi_pnp)
    return {
        "cim": {**cim, **_obj(extras["cim"])},
        "registry": {**registry, **_obj(extras["registry"])},
        "firmware": firmware,
        "cpuid": cpuid_document(),
        "device_properties": extras["device_properties"],
        "system": extras["system"],
    }


def _obj(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict)
    return value


__all__ = [
    "NIC_GUID",
    "PLANTED_KEY",
    "PVSCSI_SERIAL",
    "PVSCSI_WWID",
    "acpi_table",
    "cpuid_document",
    "ek_certificate_der",
    "machine_document",
    "smbios_table",
    "store_blob",
    "structure",
]
