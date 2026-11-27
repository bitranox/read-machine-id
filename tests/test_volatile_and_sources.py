"""Counters that change between two readings of one machine, and where each compared value comes from."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from fingerprint_machine.domain.compare import FieldStatus, compare_readings, comparison_document
from fingerprint_machine.domain.sources import source_of

if TYPE_CHECKING:
    from fingerprint_machine.domain.json_types import JsonObject

_META: JsonObject = {"schema_version": 3}


def _status(path: str, a: JsonObject, b: JsonObject) -> FieldStatus:
    rows = {r.path: r.status for r in compare_readings({"meta": _META, **a}, {"meta": _META, **b}).rows}
    return rows[path]


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("path", "a", "b"),
    [
        (
            "pci.devices[0].interrupts.rows[1].per_cpu_counts",
            {"pci": {"devices": [{"interrupts": {"rows": [{}, {"per_cpu_counts": [1, 2]}]}}]}},
            {"pci": {"devices": [{"interrupts": {"rows": [{}, {"per_cpu_counts": [3, 9]}]}}]}},
        ),
        (
            "cpu.cpuinfo[2].cpu_mhz",
            {"cpu": {"cpuinfo": [{}, {}, {"cpu_mhz": 800.0}]}},
            {"cpu": {"cpuinfo": [{}, {}, {"cpu_mhz": 5300.1}]}},
        ),
        ("memory.meminfo.MemFree", {"memory": {"meminfo": {"MemFree": 1}}}, {"memory": {"meminfo": {"MemFree": 2}}}),
        (
            "memory.meminfo.Active(anon)",
            {"memory": {"meminfo": {"Active(anon)": 1}}},
            {"memory": {"meminfo": {"Active(anon)": 2}}},
        ),
        (
            "cpuid.raw.0x00000001:0.ebx",
            {"cpuid": {"raw": {"0x00000001:0": {"ebx": "0x04"}}}},
            {"cpuid": {"raw": {"0x00000001:0": {"ebx": "0x1c"}}}},
        ),
        (
            "pci.devices[3].power_state",
            {"pci": {"devices": [{}, {}, {}, {"power_state": "D0"}]}},
            {"pci": {"devices": [{}, {}, {}, {"power_state": "D3hot"}]}},
        ),
        ("platform.boot_id", {"platform": {"boot_id": "a"}}, {"platform": {"boot_id": "b"}}),
        (
            "devices.modules[0].refcount",
            {"devices": {"modules": [{"refcount": 1}]}},
            {"devices": {"modules": [{"refcount": 4}]}},
        ),
        (
            "security.defender[0].AntivirusSignatureAge",
            {"security": {"defender": [{"AntivirusSignatureAge": 0}]}},
            {"security": {"defender": [{"AntivirusSignatureAge": 1}]}},
        ),
        (
            "memory.page_file_usage[0].CurrentUsage",
            {"memory": {"page_file_usage": [{"CurrentUsage": 10}]}},
            {"memory": {"page_file_usage": [{"CurrentUsage": 90}]}},
        ),
    ],
)
def test_a_counter_that_moves_between_reads_is_volatile(path: str, a: JsonObject, b: JsonObject) -> None:
    assert _status(path, a, b) is FieldStatus.VOLATILE


@pytest.mark.os_agnostic
def test_the_stable_parts_next_to_a_counter_stay_scored() -> None:
    a: JsonObject = {"memory": {"meminfo": {"MemTotal": 8}}, "cpuid": {"raw": {"0x00000001:0": {"eax": "0x906a3"}}}}
    b: JsonObject = {"memory": {"meminfo": {"MemTotal": 16}}, "cpuid": {"raw": {"0x00000001:0": {"eax": "0x906a4"}}}}
    assert _status("memory.meminfo.MemTotal", a, b) is FieldStatus.DIFF
    assert _status("cpuid.raw.0x00000001:0.eax", a, b) is FieldStatus.DIFF


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("path", "source"),
    [
        ("smbios.system.uuid", "smbios type 1 system uuid"),
        ("summary.system.uuid", "smbios type 1 system uuid"),
        ("smbios.dmi_id.product_uuid", "smbios type 1 system uuid"),
        ("cpuid.hypervisor_vendor", "cpuid 0x40000000 hypervisor signature"),
        ("acpi.tables[2].oem_id", "acpi table header oem id"),
        ("summary.nics[0].mac", "nic permanent mac address"),
        ("summary.nics[1].pci_serial", "pci device serial number"),
        ("smbios.board.serial", "smbios type 2 baseboard"),
        ("summary.system.board_serial", "smbios type 2 baseboard"),
        ("smbios.memory[1].serial", "smbios type 17 memory device"),
        ("summary.memory.module_sizes", "smbios type 17 memory device"),
        ("smbios.system.uuid2", "smbios table"),
    ],
)
def test_a_compared_value_names_where_it_comes_from(path: str, source: str) -> None:
    assert source_of(path) == source


@pytest.mark.os_agnostic
def test_a_path_with_no_known_source_names_none() -> None:
    assert source_of("platform.kernel.release") is None


@pytest.mark.os_agnostic
def test_the_comparison_document_carries_the_source_of_each_row() -> None:
    a: JsonObject = {"meta": _META, "smbios": {"system": {"uuid": "1"}}}
    b: JsonObject = {"meta": _META, "smbios": {"system": {"uuid": "2"}}}
    rows = comparison_document(compare_readings(a, b), ("a", "b"))["rows"]
    assert isinstance(rows, list)
    (row,) = [r for r in rows if isinstance(r, dict) and r["field"] == "smbios.system.uuid"]
    assert (row["status"], row["source"]) == ("diff", "smbios type 1 system uuid")
