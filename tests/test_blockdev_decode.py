"""The small Linux text formats the disks section reads: scheduler line, udev database, sysfs paths."""

from __future__ import annotations

import pytest

from fingerprint_machine.domain.blockdev import parse_scheduler, parse_udev_record, pci_addresses


@pytest.mark.os_agnostic
def test_the_bracketed_scheduler_is_the_active_one() -> None:
    choice = parse_scheduler("mq-deadline kyber [bfq] none\n")
    assert choice.as_json() == {"active": "bfq", "available": ["mq-deadline", "kyber", "bfq", "none"]}


@pytest.mark.os_agnostic
def test_a_scheduler_line_without_brackets_has_no_active_one() -> None:
    assert parse_scheduler("none\n").as_json() == {"active": None, "available": ["none"]}


@pytest.mark.os_agnostic
def test_the_udev_record_keeps_links_and_properties() -> None:
    text = (
        "S:disk/by-uuid/0000aaaa-1111-2222-3333-444455556666\n"
        "S:disk/by-partuuid/0000bbbb-01\n"
        "I:12345\n"
        "E:ID_FS_UUID=0000aaaa-1111-2222-3333-444455556666\n"
        "E:ID_FS_LABEL=root=fs\n"
        "E:ID_PART_ENTRY_UUID=0000bbbb-01\n"
        "G:systemd\n"
    )
    record = parse_udev_record(text).as_json()
    assert record == {
        "links": ["disk/by-uuid/0000aaaa-1111-2222-3333-444455556666", "disk/by-partuuid/0000bbbb-01"],
        "properties": {
            "ID_FS_UUID": "0000aaaa-1111-2222-3333-444455556666",
            "ID_FS_LABEL": "root=fs",
            "ID_PART_ENTRY_UUID": "0000bbbb-01",
        },
    }


@pytest.mark.os_agnostic
def test_the_pci_chain_reads_root_first_from_a_sysfs_device_path() -> None:
    path = "../devices/pci0000:00/0000:00:15.0/0000:03:00.0/host2/target2:0:0/2:0:0:0/block/sda"
    assert pci_addresses(path) == ["0000:00:15.0", "0000:03:00.0"]


@pytest.mark.os_agnostic
def test_a_virtual_device_path_has_no_pci_chain() -> None:
    assert pci_addresses("../devices/virtual/block/loop0") == []


@pytest.mark.os_agnostic
def test_a_part_that_only_contains_an_address_is_not_a_pci_function() -> None:
    # An NVMe-over-fabrics or bridge device may carry the address inside a longer name.
    path = "../devices/pci0000:00/0000:00:1d.0/nvme-fabrics-0000:00:1d.0/block/nvme0n1"
    assert pci_addresses(path) == ["0000:00:1d.0"]
