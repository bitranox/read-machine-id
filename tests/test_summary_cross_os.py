"""One VMware guest read under Windows and under Linux: the summaries agree on the hardware."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner
from linux_builder import write_linux_tree
from linux_storage_net_builder import Flavour, storage_net_answers, write_storage_net_tree
from linux_system_tree import Guest, system_answers, write_system_tree
from machine_builder import machine_document

from fingerprint_machine.adapters.cli.root import cli
from fingerprint_machine.adapters.fixture import FixtureLinuxSource, FixtureSources
from fingerprint_machine.application.machine_ports import LinuxSources, WindowsSources
from fingerprint_machine.composition import build_testing
from fingerprint_machine.domain.compare import FieldRow, compare_readings

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from fingerprint_machine.composition import AppServices
    from fingerprint_machine.domain.json_types import JsonObject, JsonValue


def _obj(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict)
    return value


def _reading(factory: Callable[[], AppServices]) -> JsonObject:
    result = CliRunner().invoke(cli, ["collect", "--json"], obj=factory)
    assert result.exit_code == 0, result.stdout
    return _obj(_obj(json.loads(result.stdout))["data"])


def _windows() -> JsonObject:
    recorded = FixtureSources(machine_document())
    return _reading(lambda: build_testing(sources=WindowsSources(platform=recorded, registry=recorded, cpuid=recorded)))


def _linux(root: Path) -> JsonObject:
    write_storage_net_tree(write_system_tree(write_linux_tree(root), Guest.VMWARE), Flavour.VMWARE)
    source = FixtureLinuxSource(root, {**storage_net_answers(Flavour.VMWARE), **system_answers(Guest.VMWARE)})
    return _reading(lambda: build_testing(sources=LinuxSources(system=source, cpuid=source)))


# The Linux reading comes from a synthetic sysfs tree whose file names hold PCI addresses
# (0000:03:00.0) as Linux does; Windows refuses ':' in a file name, so these tests run on POSIX.
# The per-OS builders are tested on every OS in test_summary_builders.py.
COLON_FILE_NAMES = pytest.mark.os_posix

#: Hardware identity values a spoofing comparison turns on; each must be read on both OSes.
_IDENTITY = (
    "summary.system.uuid",
    "summary.system.serial",
    "summary.system.manufacturer",
    "summary.system.bios_version",
    "summary.cpu.vendor",
    "summary.cpu.processor_id",
    "summary.cpu.hypervisor",
    "summary.nics[0].mac",
    "summary.nics[0].pci_serial",
    "summary.nics[0].pci_address",
    "summary.scsi_controllers[0].pci_serial",
    "summary.scsi_controllers[0].pci_address",
    "summary.scsi_controllers[0].sas_wwid",
    "summary.disks[0].serial",
    "summary.disks[0].unique_id",
    "summary.disks[0].mbr_signature",
)

#: Fields that differ between the two readings of one machine, and why. Anything else that
#: differs is a defect in one of the two builders.
_EXPECTED_DIFFERENCES = {
    # Operating-system facts: each OS names, numbers and counts these itself.
    "summary.memory.total_bytes",  # memory the OS sees, after its own reservations
    "summary.nics[0].name",
    "summary.nics[0].description",
    "summary.nics[0].interface_index",
    "summary.nics[0].class_key",  # a Windows registry key number
    "summary.scsi_controllers[0].name",  # a Windows device name
    "summary.scsi_controllers[0].driver",  # pvscsi on Windows, vmw_pvscsi on Linux
    "summary.os.name",
    "summary.os.version",
    "summary.os.hostname",
    "summary.os.machine_id",
    # Read from a Windows-only source (WMI); sysfs has no counterpart.
    "summary.security.tpm_manufacturer",
    "summary.security.tpm_spec_version",
    "summary.security.vbs_status",
    # Read from a Linux-only source: Windows links no disk to its controller in these sections.
    "summary.disks[0].controller",
    # The Linux fixture writes no PCI slot table (the Windows one names slot 160).
    "summary.nics[0].slot",
}


def _summary_reading(reading: JsonObject) -> JsonObject:
    return {"meta": {"schema_version": 3}, "summary": reading["summary"]}


def _rows(root: Path) -> dict[str, FieldRow]:
    windows, linux = _summary_reading(_windows()), _summary_reading(_linux(root))
    return {r.path: r for r in compare_readings(windows, linux).rows}


@COLON_FILE_NAMES
def test_both_oses_give_the_summary_the_same_fields(tmp_path: Path) -> None:
    windows, linux = _obj(_windows()["summary"]), _obj(_linux(tmp_path)["summary"])
    assert list(windows) == list(linux)
    for group in ("system", "cpu", "memory", "os", "windows", "security"):
        assert list(_obj(windows[group])) == list(_obj(linux[group]))
    for group in ("nics", "scsi_controllers", "disks"):
        win, lin = windows[group], linux[group]
        assert isinstance(win, list) and isinstance(lin, list) and win and lin
        assert list(_obj(win[0])) == list(_obj(lin[0]))


@COLON_FILE_NAMES
def test_one_guest_read_under_both_oses_agrees_on_every_hardware_identity_value(tmp_path: Path) -> None:
    rows = _rows(tmp_path)
    for path in _IDENTITY:
        row = rows[path]
        # A value both readings left empty would compare "same" and prove nothing.
        assert row.original is not None, path
        assert (path, row.status) == (path, "same"), (row.original, row.actual)


@COLON_FILE_NAMES
def test_only_operating_system_facts_differ_between_the_two_readings(tmp_path: Path) -> None:
    differing = {
        path for path, row in _rows(tmp_path).items()
        if row.status not in ("same", "volatile") and not path.startswith("summary.windows.")
    }  # fmt: skip
    assert differing == _EXPECTED_DIFFERENCES


@COLON_FILE_NAMES
def test_a_changed_system_uuid_is_reported_with_where_it_comes_from(tmp_path: Path) -> None:
    linux = _linux(tmp_path)
    _obj(_obj(linux["summary"])["system"])["uuid"] = "00000000-0000-0000-0000-000000000001"
    rows = {r.path: r for r in compare_readings(_summary_reading(_windows()), _summary_reading(linux)).rows}
    row = rows["summary.system.uuid"]
    assert (row.status, row.source) == ("diff", "smbios type 1 system uuid")
