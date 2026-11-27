"""The ``pci`` and ``devices`` sections of a Linux reading, end to end through the CLI.

The synthetic guests (:mod:`linux_pci_builder`) use symbolic links and colons in file names, as
sysfs does, so those tests need a POSIX filesystem. The last tests read this machine for real.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner
from linux_builder import linux_answers, write_linux_tree
from linux_pci_builder import (
    KVM_ROOT_PORT,
    PVSCSI_ADDRESS,
    VIRTIO_NET_ADDRESS,
    VMWARE_ROOT_PORT,
    Flavour,
    write_pci_tree,
)
from machine_builder import machine_document
from pci_bytes import DSN_TEXT

from fingerprint_machine.adapters.cli.root import cli
from fingerprint_machine.adapters.fixture import FixtureLinuxSource, FixtureSources
from fingerprint_machine.application.machine_ports import LinuxSources, WindowsSources
from fingerprint_machine.composition import build_production, build_testing

if TYPE_CHECKING:
    from collections.abc import Callable

    from fingerprint_machine.composition import AppServices
    from fingerprint_machine.domain.json_types import JsonObject, JsonValue


def _obj(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict), value
    return value


def _list(value: JsonValue) -> list[JsonValue]:
    assert isinstance(value, list), value
    return value


def _guest(root: Path, flavour: Flavour, *, privileged: bool = True) -> Callable[[], AppServices]:
    write_pci_tree(write_linux_tree(root), flavour, privileged=privileged)
    source = FixtureLinuxSource(root, linux_answers())
    return lambda: build_testing(sources=LinuxSources(system=source, cpuid=source))


def _collect(args: list[str], factory: Callable[[], AppServices]) -> JsonObject:
    result = CliRunner().invoke(cli, ["collect", "--json", *args], obj=factory)
    assert result.exit_code == 0, result.stdout
    return _obj(json.loads(result.stdout))


def _skipped(envelope: JsonObject) -> list[JsonValue]:
    return [_obj(s)["path"] for s in _list(envelope["skipped"])]


def _device(pci: JsonObject, address: str) -> JsonObject:
    return next(_obj(d) for d in _list(pci["devices"]) if _obj(d)["address"] == address)


def _pci(envelope: JsonObject) -> JsonObject:
    return _obj(_obj(envelope["data"])["pci"])


@pytest.mark.os_posix
def test_a_vmware_like_guest_lists_every_device_with_its_parent_chain(tmp_path: Path) -> None:
    envelope = _collect(["--section", "pci"], _guest(tmp_path, Flavour.VMWARE))
    assert _skipped(envelope) == []
    pci = _pci(envelope)
    assert [_obj(d)["address"] for d in _list(pci["devices"])] == ["0000:00:00.0", VMWARE_ROOT_PORT, PVSCSI_ADDRESS]
    pvscsi = _device(pci, PVSCSI_ADDRESS)
    assert pvscsi["placement"] == {
        "sysfs_path": f"/sys/devices/pci0000:00/{VMWARE_ROOT_PORT}/{PVSCSI_ADDRESS}",
        "root": "pci0000:00",
        "parents": [VMWARE_ROOT_PORT],
    }
    assert (pvscsi["vendor_id"], pvscsi["device_id"], pvscsi["class_code"]) == ("0x15ad", "0x07c0", "0x010700")
    assert (pvscsi["driver"], pvscsi["slot"], pvscsi["iommu_group"]) == ("vmw_pvscsi", "160", None)
    assert pvscsi["acpi_path"] == r"\_SB_.PCI0.PE40.S1F0"
    assert pvscsi["link"] == {
        "current_speed": "5.0 GT/s PCIe",
        "current_width": "32",
        "max_speed": "5.0 GT/s PCIe",
        "max_width": "32",
    }
    assert [_obj(r)["kind"] for r in _list(pvscsi["resources"])] == ["io", "memory"]


@pytest.mark.os_posix
def test_as_root_the_capability_walk_gives_the_device_serial_number_and_msi_x(tmp_path: Path) -> None:
    pvscsi = _device(_pci(_collect(["--section", "pci"], _guest(tmp_path, Flavour.VMWARE))), PVSCSI_ADDRESS)
    config = _obj(pvscsi["config"])
    assert config["bytes_read"] == 4096
    assert _obj(config["header"])["interrupt_pin"] == "INTA"
    capabilities = _obj(config["capabilities"])
    assert capabilities["device_serial_number"] == DSN_TEXT
    assert _obj(capabilities["msi_x"])["table_size"] == 32
    assert _obj(capabilities["pci_express"])["port_type"] == "endpoint"


@pytest.mark.os_posix
def test_a_device_lists_its_interrupts_rows_and_affinity(tmp_path: Path) -> None:
    pvscsi = _device(_pci(_collect(["--section", "pci"], _guest(tmp_path, Flavour.VMWARE))), PVSCSI_ADDRESS)
    interrupts = _obj(pvscsi["interrupts"])
    assert (interrupts["irq"], interrupts["pin"]) == (56, "INTA")
    assert interrupts["msi_irqs"] == [{"irq": 56, "mode": "msix"}, {"irq": 57, "mode": "msix"}]
    rows = [_obj(r) for r in _list(interrupts["rows"])]
    assert [(r["irq"], r["chip"], r["actions"]) for r in rows] == [
        (56, f"PCI-MSIX-{PVSCSI_ADDRESS}", ["vmw_pvscsi"]),
        (57, f"PCI-MSIX-{PVSCSI_ADDRESS}", ["vmw_pvscsi"]),
    ]
    assert rows[0]["per_cpu_counts"] == [5, 700]
    assert _list(interrupts["affinity"])[0] == {
        "irq": 56,
        "smp_affinity_list": "0-1",
        "effective_affinity_list": "1",
        "node": 0,
    }


@pytest.mark.os_posix
def test_the_system_interrupts_maps_and_dma_channels_are_listed(tmp_path: Path) -> None:
    pci = _pci(_collect(["--section", "pci"], _guest(tmp_path, Flavour.VMWARE)))
    assert _obj(pci["interrupts"])["cpus"] == ["CPU0", "CPU1"]
    assert [_obj(r)["name"] for r in _list(_obj(pci["interrupts"])["named"])] == ["NMI", "ERR"]
    descriptors = [_obj(d) for d in _list(pci["irq_descriptors"])]
    assert [(d["irq"], d["chip_name"]) for d in descriptors] == [
        (0, "IO-APIC"),
        (24, "PCI-MSI"),
        (56, "PCI-MSI"),
        (57, "PCI-MSI"),
    ]
    iomem = _obj(pci["iomem"])
    assert (iomem["addresses"], _obj(_list(iomem["entries"])[1])["end"]) == ("shown", "0xbfffffff")
    assert pci["dma"] == [{"channel": 4, "name": "cascade"}]
    assert pci["slots"] == [{"name": "160", "address": "0000:03:00", "max_bus_speed": None, "cur_bus_speed": None}]


@pytest.mark.os_posix
def test_unprivileged_the_capabilities_and_map_addresses_are_marked_as_needing_root(tmp_path: Path) -> None:
    envelope = _collect(["--section", "pci"], _guest(tmp_path, Flavour.VMWARE, privileged=False))
    pci = _pci(envelope)
    config = _obj(_device(pci, PVSCSI_ADDRESS)["config"])
    assert config["bytes_read"] == 64
    assert _obj(config["header"])["device_id"] == "0x07c0"
    assert str(_obj(config["capabilities"])["error"]).startswith("NeedsRootError:")
    assert str(_obj(_obj(pci["iomem"])["addresses"])["error"]).startswith("NeedsRootError:")
    assert "start" not in _obj(_list(_obj(pci["iomem"])["entries"])[0])
    assert sorted(str(p) for p in _skipped(envelope)) == [
        "pci.devices[1].config.capabilities",
        "pci.devices[2].config.capabilities",
        "pci.iomem.addresses",
        "pci.ioports.addresses",
    ]


@pytest.mark.os_posix
def test_a_kvm_like_guest_shows_its_virtio_device_without_a_serial_number(tmp_path: Path) -> None:
    envelope = _collect(["--section", "pci"], _guest(tmp_path, Flavour.KVM))
    assert _skipped(envelope) == []
    virtio = _device(_pci(envelope), VIRTIO_NET_ADDRESS)
    assert _obj(virtio["placement"])["parents"] == [KVM_ROOT_PORT]
    assert (virtio["vendor_id"], virtio["driver"], virtio["slot"]) == ("0x1af4", "virtio-pci", "0")
    capabilities = _obj(_obj(virtio["config"])["capabilities"])
    assert capabilities["device_serial_number"] is None
    assert [_obj(c)["name"] for c in _list(capabilities["list"])] == ["vendor_specific", "msi_x", "pci_express"]
    assert _obj(capabilities["msi_x"])["table_size"] == 3
    interrupts = _obj(virtio["interrupts"])
    assert [_obj(r)["irq"] for r in _list(interrupts["rows"])] == [25, 26, 27]


@pytest.mark.os_posix
def test_a_vmware_like_guest_lists_its_devices_modules_and_display(tmp_path: Path) -> None:
    envelope = _collect(["--section", "devices"], _guest(tmp_path, Flavour.VMWARE))
    assert _skipped(envelope) == []
    devices = _obj(_obj(envelope["data"])["devices"])
    instances = {str(_obj(i)["instance_id"]): _obj(i) for i in _list(devices["instances"])}
    assert sorted(instances) == [
        "input/input2",
        "pci/0000:00:00.0",
        f"pci/{VMWARE_ROOT_PORT}",
        f"pci/{PVSCSI_ADDRESS}",
        "scsi/2:0:0:0",
    ]
    disk = instances["scsi/2:0:0:0"]
    assert (disk["driver"], disk["modalias"], disk["ids"]) == (
        "sd",
        "scsi:t-0x00",
        {"vendor": "VMware", "model": "Virtual disk"},
    )
    assert _obj(instances["input/input2"]["ids"])["name"] == "VMware VMware Virtual USB Mouse"
    assert _obj(instances[f"pci/{PVSCSI_ADDRESS}"]["ids"])["vendor"] == "0x15ad"
    assert [_obj(m)["name"] for m in _list(devices["modules"])] == ["vmw_pvscsi", "vmxnet3"]
    (display,) = _list(devices["displays"])
    edid = _obj(_obj(display)["edid"])
    assert (_obj(display)["connector"], edid["manufacturer"], edid["name"]) == ("card0-Virtual-1", "VMW", "VMware SVGA")


@pytest.mark.os_posix
def test_a_kvm_like_guest_lists_virtio_acpi_and_a_display_without_edid(tmp_path: Path) -> None:
    envelope = _collect(["--section", "devices"], _guest(tmp_path, Flavour.KVM))
    devices = _obj(_obj(envelope["data"])["devices"])
    instances = {str(_obj(i)["instance_id"]): _obj(i) for i in _list(devices["instances"])}
    virtio = instances["virtio/virtio0"]
    assert (virtio["driver"], _obj(virtio["ids"])["device"]) == ("virtio_net", "0x0001")
    assert _obj(instances["acpi/PNP0A08:00"]["ids"]) == {"path": r"\_SB_.PCI0", "hid": "PNP0A08"}
    assert devices["displays"] == [
        {"connector": "card0-Virtual-1", "status": "connected", "enabled": None, "edid": None}
    ]
    used_by = [_obj(m)["used_by"] for m in _list(devices["modules"])]
    assert used_by == [[], ["virtio_net"]]


@pytest.mark.os_agnostic
def test_a_machine_without_a_pci_bus_has_no_devices_rather_than_an_error(tmp_path: Path) -> None:
    source = FixtureLinuxSource(write_linux_tree(tmp_path), linux_answers())
    factory = lambda: build_testing(sources=LinuxSources(system=source, cpuid=source))  # noqa: E731
    pci = _pci(_collect(["--section", "pci"], factory))
    assert (pci["devices"], pci["slots"]) == ([], [])
    assert str(_obj(pci["interrupts"])["error"]).startswith("MissingPathError:")


@pytest.mark.os_agnostic
def test_windows_does_not_read_the_pci_section_yet_and_says_so_when_asked() -> None:
    recorded = FixtureSources(machine_document())
    factory = lambda: build_testing(sources=WindowsSources(platform=recorded, registry=recorded, cpuid=recorded))  # noqa: E731
    reading = _obj(_collect([], factory)["data"])
    assert "pci" not in reading
    assert "pci" not in _list(_obj(reading["meta"])["sections"])
    asked = _obj(_collect(["--section", "pci"], factory)["data"])
    assert str(_obj(asked["pci"])["error"]).startswith("SourceError:")


def _not_wholly_an_error(section: JsonValue) -> JsonObject:
    body = _obj(section)
    assert set(body) != {"error"}, body
    return body


@pytest.mark.os_linux
def test_collect_reads_the_pci_section_of_this_linux_machine() -> None:
    pci = _not_wholly_an_error(_obj(_collect(["--section", "pci"], build_production)["data"])["pci"])
    devices = _list(pci["devices"])
    assert len(devices) == len(list(Path("/sys/bus/pci/devices").glob("*")))
    if devices:
        first = _obj(devices[0])
        assert str(first["vendor_id"]).startswith("0x")
        assert isinstance(_obj(first["placement"])["parents"], list)


@pytest.mark.os_linux
def test_collect_reads_the_devices_section_of_this_linux_machine() -> None:
    devices = _not_wholly_an_error(_obj(_collect(["--section", "devices"], build_production)["data"])["devices"])
    assert isinstance(devices["instances"], list)
    modules = devices["modules"]
    assert isinstance(modules, list) or set(_obj(modules)) == {"error"}
