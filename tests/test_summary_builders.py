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


_SCSI_PATH = "../devices/pci0000:00/0000:00:1c.0/0000:0a:01.0/virtio2/host0/target0:0:0/0:0:0:0/block/sda"


@pytest.mark.os_agnostic
def test_linux_leaves_optical_drives_out_as_windows_lists_disk_drives_only() -> None:
    dvd: JsonObject = {"name": "sr0", "device_path": "../devices/pci0000:00/0000:00:1f.2/ata1/host1/block/sr0",
                       "device": {"model": "Example DVD", "type": 5}}  # fmt: skip
    disk: JsonObject = {"name": "sda", "device_path": _SCSI_PATH, "device": {"model": "Example Disk", "type": 0}}
    summary = summarize_linux({"disks": {"block_devices": [dvd, disk]}})
    assert [d.model for d in summary.disks] == ["Example Disk"]


@pytest.mark.os_agnostic
def test_a_disk_with_only_a_vendor_specific_designator_gives_it_as_its_id_on_both_oses() -> None:
    # A virtual SCSI disk with no serial has no wwid; Windows reports that designator as its
    # UniqueId (format 0, vendor specific), so Linux takes it from VPD page 0x83 too.
    designator: JsonObject = {"type": "vendor_specific", "association": "logical_unit", "value": "drive-scsi0"}
    port: JsonObject = {"type": "vendor_specific", "association": "target_port", "value": "port-1"}
    disk: JsonObject = {"name": "sda", "device_path": _SCSI_PATH,
                        "device": {"wwid": {"error": "EINVAL"}, "vpd_identifiers": [port, designator]}}  # fmt: skip
    (linux,) = summarize_linux({"disks": {"block_devices": [disk]}}).disks
    windows_body: JsonObject = {"disks": {"wmi": [{"Index": 0}], "storage": [
        {"Number": 0, "UniqueId": "drive-scsi0", "UniqueIdFormat": 0}]}}  # fmt: skip
    (windows,) = summarize_windows(windows_body).disks
    assert (linux.unique_id, windows.unique_id) == ("drive-scsi0", "drive-scsi0")


@pytest.mark.os_agnostic
def test_a_linux_controller_names_the_scsi_driver_behind_a_generic_pci_driver() -> None:
    controller: JsonObject = {"address": "0000:0a:01.0", "driver": "virtio-pci"}
    host: JsonObject = {"name": "host0", "proc_name": "virtio_scsi", "controller": "0000:0a:01.0"}
    body: JsonObject = {"disks": {"controllers": [controller], "scsi_hosts": [host]}}
    (summary_controller,) = summarize_linux(body).scsi_controllers
    assert summary_controller.driver == "virtio_scsi"


@pytest.mark.os_agnostic
def test_windows_lists_pci_ahci_controllers_and_both_oses_order_by_pci_address() -> None:
    ahci_pnp = "PCI\\VEN_8086&DEV_2922&SUBSYS_11001AF4&REV_02\\3&0&0&FA"
    scsi_pnp = "PCI\\VEN_1AF4&DEV_1004&SUBSYS_00081AF4&REV_00\\3&0&0&08"
    windows_body: JsonObject = {
        "hardware": {
            "scsi_controllers": [{"Name": "Example SCSI", "PNPDeviceID": scsi_pnp}],
            "ide_controllers": [{"Name": "Example AHCI", "PNPDeviceID": ahci_pnp},
                                {"Name": "Example IDE", "PNPDeviceID": "ROOT\\IDE\\0000"}],
        },
        "pci": {"devices": [{"instance_id": scsi_pnp, "address": "0000:0a:01.0"},
                            {"instance_id": ahci_pnp, "address": "0000:00:1f.2"}]},
    }  # fmt: skip
    linux_body: JsonObject = {"disks": {"controllers": [{"address": "0000:0a:01.0"}, {"address": "0000:00:1f.2"}]}}
    windows = [c.pci_address for c in summarize_windows(windows_body).scsi_controllers]
    linux = [c.pci_address for c in summarize_linux(linux_body).scsi_controllers]
    assert windows == linux == ["0000:00:1f.2", "0000:0a:01.0"]


@pytest.mark.os_agnostic
def test_a_windows_disk_model_is_the_inquiry_product_as_linux_reads_it() -> None:
    # Win32_DiskDrive appends the vendor and "SCSI Disk Device"; MSFT_Disk keeps the INQUIRY product.
    windows_body: JsonObject = {"disks": {
        "wmi": [{"Index": 0, "Model": "Example Example Disk SCSI Disk Device"}],
        "storage": [{"Number": 0, "Model": "Example Disk    "}],
    }}  # fmt: skip
    linux_disk: JsonObject = {"name": "sda", "device_path": _SCSI_PATH, "device": {"model": "Example Disk    "}}
    (windows,) = summarize_windows(windows_body).disks
    (linux,) = summarize_linux({"disks": {"block_devices": [linux_disk]}}).disks
    assert windows.model == linux.model == "Example Disk"


@pytest.mark.os_agnostic
def test_a_windows_disk_names_its_controller_by_pci_address_as_linux_does() -> None:
    # MSFT_Disk.Location writes the controller's bus, device and function in decimal.
    location = "PCI Slot 1 : Bus 10 : Device 1 : Function 0 : Adapter 1 : Port 0 : Target 0 : LUN 0"
    windows_body: JsonObject = {"disks": {
        "wmi": [{"Index": 0}, {"Index": 1}],
        "storage": [{"Number": 0, "Location": location}, {"Number": 1, "Location": "Integrated : Adapter 0"}],
    }}  # fmt: skip
    linux_disk: JsonObject = {"name": "sda", "device_path": _SCSI_PATH, "controller": "0000:0a:01.0"}
    windows, unplaced = summarize_windows(windows_body).disks
    (linux,) = summarize_linux({"disks": {"block_devices": [linux_disk]}}).disks
    assert windows.controller == linux.controller == "0000:0a:01.0"
    assert unplaced.controller is None
