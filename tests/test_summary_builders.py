"""The per-OS summary builders on the inputs the cross-OS fixture does not reach."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from fingerprint_machine.domain.summary_linux import summarize_linux
from fingerprint_machine.domain.summary_windows import summarize_windows

if TYPE_CHECKING:
    from fingerprint_machine.domain.json_types import JsonObject, JsonValue

_PCI_NIC = "../../devices/pci0000:00/0000:00:03.0/virtio0/net/eth0"


@pytest.mark.os_agnostic
def test_a_nic_whose_permanent_address_reads_zero_takes_the_interface_address() -> None:
    nic: JsonObject = {"name": "eth0", "device_path": _PCI_NIC, "permanent_address": "00:00:00:00:00:00",
           "sysfs": {"address": "52:54:00:12:34:56"}}  # fmt: skip
    (summary_nic,) = summarize_linux({"network": {"adapters": [nic]}}).nics
    assert summary_nic.mac == "52:54:00:12:34:56"


@pytest.mark.os_agnostic
def test_the_dmi_fallback_writes_the_uuid_as_smbios_does_and_smbios_wins_over_it() -> None:
    dmi: JsonObject = {"product_uuid": "04030201-0605-0807-090a-0b0c0d0e0f10", "sys_vendor": "Vendor From DMI"}
    fallback = summarize_linux({"smbios": {"dmi_id": dmi}}).system
    assert (fallback.uuid, fallback.manufacturer) == ("04030201-0605-0807-090A-0B0C0D0E0F10", "Vendor From DMI")
    both = summarize_linux({"smbios": {"dmi_id": dmi, "system": {"manufacturer": "Vendor From Table"}}}).system
    assert (both.manufacturer, both.uuid) == ("Vendor From Table", "04030201-0605-0807-090A-0B0C0D0E0F10")


@pytest.mark.os_agnostic
def test_a_gpt_disk_gives_its_guid_and_no_mbr_signature_on_both_oses() -> None:
    guid = "aaaaaaaa-0000-0000-0000-000000000001"
    disk: JsonObject = {"name": "vda", "device_path": "../devices/pci0000:00/0000:00:04.0/virtio1/block/vda",
            "udev": {"properties": {"ID_PART_TABLE_TYPE": "gpt", "ID_PART_TABLE_UUID": guid}}}  # fmt: skip
    (linux,) = summarize_linux({"disks": {"block_devices": [disk]}}).disks
    windows_body: JsonObject = {
        "disks": {"wmi": [{"Index": 0}], "storage": [{"Number": 0, "Guid": "{" + guid.upper() + "}"}]}
    }
    (windows,) = summarize_windows(windows_body).disks
    assert (linux.gpt_guid, linux.mbr_signature) == (guid.upper(), None)
    assert (windows.gpt_guid, windows.mbr_signature) == (guid.upper(), None)


@pytest.mark.os_agnostic
def test_cpu_counts_stay_unknown_when_the_reading_cannot_tell_them() -> None:
    # cpuinfo without topology ids (common off x86) must not read as one socket with one core.
    body: JsonObject = {"cpu": {"cpuinfo": [{"vendor_id": "X"}, {"vendor_id": "X"}], "cpus": [{"cpu": 0}]}}
    linux = summarize_linux(body).cpu
    windows = summarize_windows({}).cpu
    assert (linux.sockets, linux.cores, linux.logical_processors) == (None, None, 2)
    assert (windows.sockets, windows.cores, windows.logical_processors) == (None, None, None)


@pytest.mark.os_agnostic
def test_linux_counts_sockets_and_cores_from_the_sysfs_topology() -> None:
    cpus: list[JsonValue] = [
        {"topology": {"physical_package_id": p, "core_id": c}}
        for p, c in (("0", "0"), ("0", "0"), ("0", "1"), ("1", "0"))
    ]
    cpuinfo: list[JsonValue] = [{}, {}, {}, {}]
    body: JsonObject = {"cpu": {"cpus": cpus, "cpuinfo": cpuinfo}}
    cpu = summarize_linux(body).cpu
    assert (cpu.sockets, cpu.cores, cpu.logical_processors) == (2, 3, 4)


@pytest.mark.os_agnostic
def test_logical_processors_follow_the_topology_when_cpuinfo_shows_fewer() -> None:
    # A container's /proc/cpuinfo can list only the CPUs it may use; sysfs still lists them all.
    cpus: list[JsonValue] = [{"topology": {"physical_package_id": "0", "core_id": str(n // 2)}} for n in range(8)]
    cpuinfo: list[JsonValue] = [{}, {}]
    body: JsonObject = {"cpu": {"cpus": cpus, "cpuinfo": cpuinfo}}
    cpu = summarize_linux(body).cpu
    assert (cpu.sockets, cpu.cores, cpu.logical_processors) == (1, 4, 8)


@pytest.mark.os_agnostic
def test_an_nvme_namespace_gives_its_own_identifier() -> None:
    disk: JsonObject = {
        "name": "nvme0n1",
        "device_path": "../devices/pci0000:00/0000:00:1a.0/0000:04:00.0/nvme/nvme0/nvme0n1",
        "wwid": "eui.00a0b0c0d0e0f001",
        "device": {"model": "Example NVMe", "serial": "NV-0001"},
    }
    (summary_disk,) = summarize_linux({"disks": {"block_devices": [disk]}}).disks
    assert (summary_disk.unique_id, summary_disk.serial) == ("eui.00a0b0c0d0e0f001", "NV-0001")


@pytest.mark.os_agnostic
def test_an_all_zero_device_serial_number_is_no_serial_on_both_oses() -> None:
    linux_body: JsonObject = {
        "disks": {"controllers": [{"address": "0000:04:00.0", "device_serial_number": "00-00-00-00-00-00-00-00"}]}
    }
    windows_body: JsonObject = {
        "hardware": {"scsi_controllers": [{"PNPDeviceID": "PCI\\VEN_1BB1&DEV_5018\\000000000000000000"}]}
    }
    (linux,) = summarize_linux(linux_body).scsi_controllers
    (windows,) = summarize_windows(windows_body).scsi_controllers
    assert (linux.pci_serial, windows.pci_serial) == (None, None)


@pytest.mark.os_agnostic
def test_windows_lists_hardware_adapters_and_pci_storage_controllers_only() -> None:
    # A tunnel adapter and the Storage Spaces controller are software, as Linux's /sys/devices/virtual is.
    tunnel: JsonObject = {
        "adapter": {
            "Name": "Tunnel",
            "HardwareInterface": False,
            "Virtual": True,
            "PnPDeviceID": "SWD\\Wintun\\{00000000-0000-0000-0000-000000000001}",
        }
    }
    nic: JsonObject = {
        "adapter": {
            "Name": "Ethernet0",
            "HardwareInterface": True,
            "Virtual": False,
            "PnPDeviceID": "PCI\\VEN_1AF4&DEV_1000&SUBSYS_00011AF4&REV_00\\3&0&0&90",
        }
    }
    body: JsonObject = {
        "network": {"adapters": [tunnel, nic]},
        "hardware": {"scsi_controllers": [
            {"Name": "Example SCSI", "PNPDeviceID": "PCI\\VEN_1AF4&DEV_1004&SUBSYS_00081AF4&REV_00\\3&0&0&08"},
            {"Name": "Storage Spaces", "PNPDeviceID": "ROOT\\SPACEPORT\\0000"},
        ]},
    }  # fmt: skip
    summary = summarize_windows(body)
    assert [n.name for n in summary.nics] == ["Ethernet0"]
    assert [c.name for c in summary.scsi_controllers] == ["Example SCSI"]


@pytest.mark.os_agnostic
def test_a_windows_adapter_without_a_driver_file_name_takes_it_from_the_driver_path() -> None:
    path = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\netkvm.inf_amd64_0001\\NetKVM.sys"
    record: JsonObject = {"adapter": {"Name": "Ethernet0", "HardwareInterface": True, "DriverName": path}}
    (nic,) = summarize_windows({"network": {"adapters": [record]}}).nics
    assert nic.driver == "netkvm"
