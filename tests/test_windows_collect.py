"""A real collection on a real Windows machine (the CI Windows runner, or a developer's box).

A runner is a VM whose TPM, BitLocker and licensing answers vary, so this asserts only what every
Windows machine has: SMBIOS, the operating system, at least one network adapter, and on x86-64 a
CPU vendor read through CPUID. A cloud runner may have no PCI function at all (a VMBus-only VM),
so the pci section is checked for shape, and the configuration-manager adapter is checked on a
device every machine has.
"""

from __future__ import annotations

import json
import platform
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from fingerprint_machine.adapters.cli.root import cli
from fingerprint_machine.adapters.windows import devnode, kernel
from fingerprint_machine.adapters.windows.platform import PwshpyPlatformSource
from fingerprint_machine.composition import build_production
from fingerprint_machine.domain.devprops import DeviceProperty

if TYPE_CHECKING:
    from fingerprint_machine.domain.json_types import JsonObject, JsonValue


def _obj(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict), value
    assert set(value) != {"error"}, value
    return value


def _list(value: JsonValue) -> list[JsonValue]:
    assert isinstance(value, list), value
    return value


@pytest.fixture(scope="module")
def reading() -> JsonObject:
    """One real collection, shared by the tests below (a full reading takes about a minute)."""
    result = CliRunner().invoke(cli, ["collect", "--json"], obj=build_production)
    assert result.exit_code == 0, result.stdout
    envelope = _obj(json.loads(result.stdout))
    assert envelope["ok"] is True
    return _obj(envelope["data"])


@pytest.mark.os_windows
def test_collect_reads_this_windows_machine(reading: JsonObject) -> None:
    smbios = _obj(reading["smbios"])
    assert smbios["type_counts"]
    assert _obj(_list(_obj(reading["windows"])["operating_system"])[0])["Caption"]
    assert _list(_obj(reading["network"])["adapters"])
    assert _obj(reading["meta"])["os"] == "windows"
    if platform.machine().lower() in {"amd64", "x86_64"}:
        assert len(str(_obj(reading["cpuid"])["vendor"])) == 12


@pytest.mark.os_windows
def test_collect_reads_the_windows_hardware_sections(reading: JsonObject) -> None:
    pci = _obj(reading["pci"])
    for device in _list(pci["devices"]):
        assert str(_obj(device)["instance_id"]).upper().startswith("PCI\\")
    _list(pci["irq_descriptors"])
    assert _obj(_list(_obj(reading["cpu"])["cpus"])[0])["cpu"] == 0
    memory = _obj(reading["memory"])
    assert _obj(_list(memory["totals"])[0])["TotalVisibleMemorySize"]
    assert _obj(_list(memory["numa"])[0])["processors"]
    _list(_obj(reading["disks"])["scsi"])
    devices = _obj(reading["devices"])
    assert _list(devices["system_drivers"])
    _list(devices["displays"])


@pytest.mark.os_windows
def test_collect_reads_the_windows_security_posture(reading: JsonObject) -> None:
    security = _obj(reading["security"])
    assert isinstance(_obj(security["kernel_dma_protection"])["enabled"], bool)
    assert _obj(security["lsa"])
    assert _obj(security["uac"])
    assert _list(security["firewall"])
    assert _list(security["credential_providers"])


@pytest.mark.os_windows
def test_the_configuration_manager_answers_a_device_s_parent() -> None:
    ids = (str(r.get("DeviceID", "")) for r in PwshpyPlatformSource().cim("Win32_PnPEntity"))
    device = next(i for i in ids if i.upper().startswith(("ACPI\\", "PCI\\")))
    assert isinstance(devnode.device_property(device, DeviceProperty.PARENT), str)


@pytest.mark.os_windows
def test_the_kernel_answers_the_numa_topology_and_the_dma_guard() -> None:
    nodes = kernel.numa_nodes()
    assert (nodes[0].node, bool(nodes[0].mask)) == (0, True)
    assert isinstance(kernel.kernel_dma_protection(), bool)
