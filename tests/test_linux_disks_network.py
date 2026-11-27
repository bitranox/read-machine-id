"""The disks and network sections of a Linux reading: synthetic VMware and KVM guests, and this machine."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner
from linux_storage_net_builder import FS_UUID, PVSCSI_WWID, Flavour, storage_net_answers, write_storage_net_tree
from netlink_messages import route

from fingerprint_machine.adapters.cli.root import cli
from fingerprint_machine.adapters.fixture import FixtureLinuxSource
from fingerprint_machine.application.linux_network import MAX_TABLE_ENTRIES, read_linux_network
from fingerprint_machine.application.machine_ports import LinuxSources
from fingerprint_machine.composition import build_production, build_testing

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from fingerprint_machine.composition import AppServices
    from fingerprint_machine.domain.json_types import JsonObject, JsonValue


def _obj(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict), value
    return value


def _list(value: JsonValue) -> list[JsonValue]:
    assert isinstance(value, list), value
    return value


def _guest(root: Path, flavour: Flavour) -> Callable[[], AppServices]:
    source = FixtureLinuxSource(write_storage_net_tree(root, flavour), storage_net_answers(flavour))
    return lambda: build_testing(sources=LinuxSources(system=source, cpuid=source))


def _section(section: str, factory: Callable[[], AppServices]) -> tuple[JsonObject, list[str]]:
    result = CliRunner().invoke(cli, ["collect", "--json", "--section", section], obj=factory)
    assert result.exit_code == 0, result.stdout
    envelope = _obj(json.loads(result.stdout))
    skipped = [str(_obj(s)["path"]) for s in _list(envelope["skipped"])]
    return _obj(_obj(envelope["data"])[section]), skipped


def _by_name(items: JsonValue, name: str) -> JsonObject:
    return next(_obj(i) for i in _list(items) if _obj(i).get("name") == name)


@pytest.mark.os_agnostic
def test_a_vmware_disk_names_its_pvscsi_controller_and_the_sas_wwid(tmp_path: Path) -> None:
    disks, _ = _section("disks", _guest(tmp_path, Flavour.VMWARE))
    sda = _by_name(disks["block_devices"], "sda")
    assert (sda["controller"], sda["size_bytes"], sda["pci_chain"]) == (
        "0000:03:00.0", 41943040 * 512, ["0000:00:15.0", "0000:03:00.0"],
    )  # fmt: skip
    assert _obj(sda["queue"])["scheduler"] == {"active": "mq-deadline", "available": ["mq-deadline", "none"]}
    device = _obj(sda["device"])
    assert (device["vendor"], device["model"], device["driver"]) == ("VMware", "Virtual disk", "sd")
    assert device["vpd_serial"] == "VMW-DISK-0001"
    assert _obj(_list(device["vpd_identifiers"])[0])["value"] == "6000c29aaaaaaaaaaaaaaaaaaaaaaaaa"
    partition = _obj(_list(sda["partitions"])[0])
    assert (partition["name"], partition["start"]) == ("sda1", 2048)
    assert _obj(_obj(partition["udev"])["properties"])["ID_FS_UUID"] == FS_UUID
    assert _obj(_obj(disks["disk_links"])["by-uuid"])[FS_UUID] == "sda1"
    host = _by_name(disks["scsi_hosts"], "host2")
    assert (host["proc_name"], host["controller"]) == ("vmw_pvscsi", "0000:03:00.0")
    controller = _obj(_list(disks["controllers"])[0])
    assert (controller["vendor"], controller["device"], controller["driver"]) == ("0x15ad", "0x07c0", "vmw_pvscsi")
    assert controller.get("sas_wwid") == PVSCSI_WWID


@pytest.mark.os_agnostic
def test_a_kvm_guest_reads_virtio_and_nvme_and_marks_the_dsn_as_needing_root(tmp_path: Path) -> None:
    disks, skipped = _section("disks", _guest(tmp_path, Flavour.KVM))
    vda = _by_name(disks["block_devices"], "vda")
    assert (vda["serial"], vda["controller"], _obj(vda["device"])["driver"]) == (
        "KVM-DISK-0001", "0000:00:05.0", "virtio_blk",
    )  # fmt: skip
    nvme = _by_name(disks["nvme_controllers"], "nvme0")
    assert (nvme["serial"], nvme["controller"]) == ("NVME-SER-0001", "0000:00:06.0")
    assert _obj(_list(nvme["namespaces"])[0])["wwid"] == "eui.0000000000000001"
    controllers = {str(_obj(c)["address"]): _obj(c) for c in _list(disks["controllers"])}
    assert controllers["0000:00:06.0"]["device_serial_number"] is None  # a full space without the capability
    assert str(_obj(controllers["0000:00:05.0"]["device_serial_number"])["error"]).startswith("NeedsRootError:")
    assert "sas_wwid" not in controllers["0000:00:05.0"]
    assert "disks.controllers[1].device_serial_number" in skipped


@pytest.mark.os_agnostic
def test_a_vmware_nic_joins_sysfs_ethtool_and_netlink_by_interface(tmp_path: Path) -> None:
    network, skipped = _section("network", _guest(tmp_path, Flavour.VMWARE))
    assert [_obj(a).get("name") for a in _list(network["adapters"])] == ["ens192", "lo"]  # bonding_masters skipped
    nic = _by_name(network["adapters"], "ens192")
    assert (nic["index"], _obj(nic["sysfs"])["flags"], nic["queues"]) == (2, ["up", "broadcast", "multicast"], {
        "rx": 2, "tx": 2,
    })  # fmt: skip
    pci = _obj(nic["pci"])
    assert (pci["vendor"], pci["device"], pci["driver"], pci["device_serial_number"]) == (
        "0x15ad", "0x07b0", "vmxnet3", "00-0c-29-ff-ff-00-00-01",
    )  # fmt: skip
    assert _obj(nic["driver"])["driver"] == "vmxnet3"
    assert nic["permanent_address"] == "00:50:56:00:00:01"
    features = _obj(nic["features"])
    assert features["rx-checksum"] == {"active": True, "requested": True, "fixed": True}
    assert features["tx-tcp-segmentation"] == {"active": True, "requested": True, "fixed": False}
    assert _obj(nic["link_settings"])["speed_mbps"] == 10000
    assert _obj(nic["rings"])["rx_max_pending"] == 4096
    assert _obj(nic["netlink"])["address"] == "00:50:56:00:00:01"
    assert [_obj(a)["address"] for a in _list(nic["ip_addresses"])] == ["192.0.2.10"]
    assert [_obj(r)["gateway"] for r in _list(nic["routes"])] == ["192.0.2.1"]
    assert [_obj(n)["address"] for n in _list(nic["neighbours"])] == ["192.0.2.1"]
    assert [_obj(r)["output_index"] for r in _list(_obj(network["unmatched"])["routes"])] == [9]
    assert _obj(_obj(network["dns"])["resolv_conf"])["nameservers"] == ["192.0.2.53"]
    assert "network.adapters[0].channels" in skipped  # not recorded for this NIC: one error, the rest read


@pytest.mark.os_agnostic
def test_a_kvm_nic_and_the_resolver_behind_the_stub(tmp_path: Path) -> None:
    network, _ = _section("network", _guest(tmp_path, Flavour.KVM))
    nic = _by_name(network["adapters"], "eth0")
    assert (_obj(nic["pci"])["device"], nic["pci_chain"]) == ("0x1041", ["0000:00:03.0"])
    assert _obj(_obj(network["dns"])["systemd_resolved"])["nameservers"] == ["192.0.2.53"]
    assert _obj(network["tables"])["routes"] == {"rows": 2, "truncated": False}


def _not_wholly_an_error(section: JsonObject) -> None:
    assert set(section) != {"error"}, section


@pytest.mark.os_linux
def test_collect_reads_the_disks_of_this_linux_machine() -> None:
    disks, _ = _section("disks", build_production)
    _not_wholly_an_error(disks)
    for device in _list(disks["block_devices"]):
        assert "error" not in _obj(device), device


@pytest.mark.os_linux
def test_collect_reads_the_network_of_this_linux_machine() -> None:
    network, _ = _section("network", build_production)
    _not_wholly_an_error(network)
    loopback = _by_name(network["adapters"], "lo")
    assert _obj(loopback["sysfs"])["type"] == "loopback"
    assert any(_obj(a).get("address") == "127.0.0.1" for a in _list(loopback["ip_addresses"]))


@pytest.mark.os_agnostic
def test_a_netlink_table_is_kept_to_its_cap_and_a_bad_message_is_one_error(tmp_path: Path) -> None:
    answers = storage_net_answers(Flavour.KVM)
    tables = _obj(answers["netlink"])
    one_route = route(destination="203.0.113.0", gateway=None, out_index=9, prefix=24).hex()
    routes: list[JsonValue] = [one_route] * (MAX_TABLE_ENTRIES + 1)
    tables["routes"] = routes
    tables["neighbours"] = ["00"]  # shorter than a header
    source = FixtureLinuxSource(write_storage_net_tree(tmp_path, Flavour.KVM), answers)
    network = _obj(read_linux_network(LinuxSources(system=source, cpuid=source)))
    status = _obj(network["tables"])
    assert status["routes"] == {"rows": MAX_TABLE_ENTRIES, "truncated": True}
    assert status["neighbours"] == {"rows": 1, "truncated": False}
    unmatched = _obj(network["unmatched"])
    assert len(_list(unmatched["routes"])) == MAX_TABLE_ENTRIES
    assert str(_obj(_list(unmatched["neighbours"])[0])["error"]).startswith("ValueError:")
