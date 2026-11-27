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
    dmi: JsonObject = {"product_uuid": "acda9b46-caae-a71b-a527-d8bbc1d07065", "sys_vendor": "Vendor From DMI"}
    fallback = summarize_linux({"smbios": {"dmi_id": dmi}}).system
    assert (fallback.uuid, fallback.manufacturer) == ("ACDA9B46-CAAE-A71B-A527-D8BBC1D07065", "Vendor From DMI")
    both = summarize_linux({"smbios": {"dmi_id": dmi, "system": {"manufacturer": "Vendor From Table"}}}).system
    assert (both.manufacturer, both.uuid) == ("Vendor From Table", "ACDA9B46-CAAE-A71B-A527-D8BBC1D07065")


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
