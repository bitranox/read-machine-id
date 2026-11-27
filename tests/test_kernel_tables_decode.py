"""The pure parsers of the kernel's text tables and of the PCI sysfs layout.

Every table is written in the layout the kernel prints it in: ``/proc/iomem`` and
``/proc/ioports`` (``kernel/resource.c`` ``r_show``), ``/proc/dma`` (``kernel/dma.c``),
``/proc/modules`` (``kernel/module/procfs.c``), a PCI device's ``resource`` file
(``drivers/pci/pci-sysfs.c`` ``resource_show``) and the target of a ``/sys/bus/pci/devices`` link.
"""

from __future__ import annotations

import pytest

from fingerprint_machine.domain.kernel_tables import (
    addresses_hidden,
    parse_dma,
    parse_modules,
    parse_resource_tree,
)
from fingerprint_machine.domain.pci_sysfs import (
    ResourceKind,
    parse_pci_resources,
    pci_placement,
    slot_address,
)

_IOMEM = "00000000-00000fff : Reserved\n00100000-bfffffff : System RAM\n  01000000-01ffffff : Kernel code\n"


@pytest.mark.os_agnostic
def test_a_resource_tree_keeps_each_range_its_name_and_its_depth() -> None:
    entries = parse_resource_tree(_IOMEM)
    assert [e.as_json(with_addresses=True) for e in entries] == [
        {"depth": 0, "name": "Reserved", "start": "0x0", "end": "0xfff"},
        {"depth": 0, "name": "System RAM", "start": "0x100000", "end": "0xbfffffff"},
        {"depth": 1, "name": "Kernel code", "start": "0x1000000", "end": "0x1ffffff"},
    ]
    assert not addresses_hidden(entries)


@pytest.mark.os_agnostic
def test_a_tree_of_zero_ranges_is_one_whose_addresses_are_hidden() -> None:
    entries = parse_resource_tree("0000-0000 : PCI Bus 0000:00\n  0000-0000 : dma1\n")
    assert addresses_hidden(entries)
    assert entries[1].as_json(with_addresses=False) == {"depth": 1, "name": "dma1"}
    assert not addresses_hidden(())


@pytest.mark.os_agnostic
def test_a_range_from_address_zero_is_not_a_hidden_one() -> None:
    assert not addresses_hidden(parse_resource_tree("00000000-00000fff : Reserved\n"))


@pytest.mark.os_agnostic
def test_a_line_that_is_not_a_range_is_skipped() -> None:
    assert parse_resource_tree("garbage\n0070-0077 : rtc0\n")[0].name == "rtc0"


@pytest.mark.os_agnostic
def test_dma_channels_are_numbered_and_named() -> None:
    assert [c.as_json() for c in parse_dma(" 4: cascade\n")] == [{"channel": 4, "name": "cascade"}]


@pytest.mark.os_agnostic
def test_a_module_line_gives_name_size_users_and_state_but_not_its_address() -> None:
    modules = parse_modules(
        "vmw_pvscsi 28672 2 - Live 0xffffffffc0400000\n"
        "kvm 1404928 1 kvm_intel, Live 0x0000000000000000 (OE)\n"
        "static_one 4096 - - Live 0x0\n"
    )
    assert [m.as_json() for m in modules] == [
        {"name": "vmw_pvscsi", "size": 28672, "refcount": 2, "used_by": [], "state": "Live", "taints": None},
        {"name": "kvm", "size": 1404928, "refcount": 1, "used_by": ["kvm_intel"], "state": "Live", "taints": "OE"},
        {"name": "static_one", "size": 4096, "refcount": None, "used_by": [], "state": "Live", "taints": None},
    ]


@pytest.mark.os_agnostic
def test_a_pci_resource_file_lists_only_the_ranges_in_use() -> None:
    text = (
        "0x00000000fd000000 0x00000000fdffffff 0x0000000000040200\n"
        "0x0000000000000000 0x0000000000000000 0x0000000000000000\n"
        "0x0000000000004000 0x000000000000401f 0x0000000000040101\n"
        "0x0000006000000000 0x000000600fffffff 0x000000000014220c\n"
    )
    resources = parse_pci_resources(text)
    assert [r.as_json() for r in resources] == [
        {
            "index": 0,
            "kind": "memory",
            "start": "0xfd000000",
            "end": "0xfdffffff",
            "size": 0x1000000,
            "prefetchable": False,
            "address_64bit": False,
            "flags": "0x40200",
        },
        {
            "index": 2,
            "kind": "io",
            "start": "0x4000",
            "end": "0x401f",
            "size": 0x20,
            "prefetchable": False,
            "address_64bit": False,
            "flags": "0x40101",
        },
        {
            "index": 3,
            "kind": "memory",
            "start": "0x6000000000",
            "end": "0x600fffffff",
            "size": 0x10000000,
            "prefetchable": True,
            "address_64bit": True,
            "flags": "0x14220c",
        },
    ]
    assert resources[0].kind is ResourceKind.MEMORY


@pytest.mark.os_agnostic
def test_a_pci_link_target_gives_the_sysfs_path_root_and_parent_chain() -> None:
    placement = pci_placement("../../../devices/pci0000:00/0000:00:15.0/0000:03:00.0")
    assert placement.as_json() == {
        "sysfs_path": "/sys/devices/pci0000:00/0000:00:15.0/0000:03:00.0",
        "root": "pci0000:00",
        "parents": ["0000:00:15.0"],
    }


@pytest.mark.os_agnostic
def test_a_device_behind_a_switch_lists_every_bridge_from_the_root_down() -> None:
    target = "../../../devices/pci0000:00/0000:00:1c.0/0000:01:00.0/0000:02:01.0/0000:03:00.0"
    assert pci_placement(target).parents == ("0000:00:1c.0", "0000:01:00.0", "0000:02:01.0")


@pytest.mark.os_agnostic
def test_a_device_on_a_root_bus_under_another_bus_takes_the_last_pci_root() -> None:
    target = "../../../devices/LNXSYSTM:00/LNXSYBUS:00/VMBUS:00/abcd/pci1a2b:00/1a2b:00:00.0"
    placement = pci_placement(target)
    assert (placement.root, placement.parents) == ("pci1a2b:00", ())


@pytest.mark.os_agnostic
def test_a_slot_address_is_the_device_address_without_its_function() -> None:
    assert slot_address("0000:00:15.0") == "0000:00:15"
