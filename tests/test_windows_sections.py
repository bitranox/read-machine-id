"""The Windows pci, cpu, memory, disks, devices and security readings, end to end through the CLI.

Each test collects a recorded VMware-like machine (:mod:`machine_builder`, :mod:`windows_builder`)
and checks the reading under the key names a Linux reading uses where the value is the same.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner
from machine_builder import PVSCSI_SERIAL, machine_document
from windows_builder import PLANTED_OWNER_AUTH, PVSCSI_LOCATION_PATHS, PVSCSI_PARENT

from fingerprint_machine.adapters.cli.root import cli
from fingerprint_machine.adapters.fixture import FixtureSources
from fingerprint_machine.application.machine_ports import WindowsSources
from fingerprint_machine.composition import build_testing

if TYPE_CHECKING:
    from fingerprint_machine.domain.json_types import JsonObject, JsonValue

_PVSCSI = rf"PCI\VEN_15AD&DEV_07C0&SUBSYS_07C015AD&REV_02\{PVSCSI_SERIAL}"
_NIC = r"PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\000C29FFFF000001"
_GONE_NIC = r"PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\000C29FFFF000002"


def _obj(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict), value
    return value


def _list(value: JsonValue) -> list[JsonValue]:
    assert isinstance(value, list), value
    return value


def _reading(document: JsonObject | None = None, *sections: str) -> JsonObject:
    recorded = FixtureSources(document if document is not None else machine_document())
    sources = WindowsSources(platform=recorded, registry=recorded, cpuid=recorded)
    args = ["collect", "--json", *(a for s in sections for a in ("--section", s))]
    result = CliRunner().invoke(cli, args, obj=lambda: build_testing(sources=sources))
    assert result.exit_code == 0, result.stdout
    return _obj(_obj(json.loads(result.stdout))["data"])


def _section(name: str, document: JsonObject | None = None) -> JsonObject:
    return _obj(_reading(document, name)[name])


def _devices_by_id(pci: JsonObject) -> dict[str, JsonObject]:
    return {str(_obj(d)["instance_id"]): _obj(d) for d in _list(pci["devices"])}


@pytest.mark.os_agnostic
def test_a_windows_reading_now_holds_the_pci_section() -> None:
    reading = _reading()
    assert "pci" in _list(_obj(reading["meta"])["sections"])
    assert set(_obj(reading["pci"])) >= {"devices", "buses", "irq_descriptors", "ioports", "iomem", "dma"}


@pytest.mark.os_agnostic
def test_a_pci_function_carries_its_ids_and_address_under_the_linux_names() -> None:
    pvscsi = _devices_by_id(_section("pci"))[_PVSCSI]
    ids = {k: pvscsi[k] for k in ("vendor_id", "device_id", "subsystem_vendor_id", "subsystem_id", "revision")}
    assert ids == {
        "vendor_id": "0x15ad",
        "device_id": "0x07c0",
        "subsystem_vendor_id": "0x15ad",
        "subsystem_id": "0x07c0",
        "revision": "0x02",
    }
    assert (pvscsi["class_code"], pvscsi["address"], pvscsi["driver"]) == ("0x010700", "0000:03:00.0", "pvscsi")


@pytest.mark.os_agnostic
def test_a_pci_function_carries_its_place_in_the_device_tree() -> None:
    pvscsi = _devices_by_id(_section("pci"))[_PVSCSI]
    assert (pvscsi["parent"], pvscsi["location_paths"], pvscsi["bus"]) == (
        PVSCSI_PARENT,
        PVSCSI_LOCATION_PATHS,
        "PCI_BUS_3",
    )
    assert _obj(pvscsi["link"]) == {"current_speed": 1, "current_width": 32, "max_speed": 1, "max_width": 32}


@pytest.mark.os_agnostic
def test_the_device_serial_number_comes_from_a_unique_instance_id_only() -> None:
    devices = _devices_by_id(_section("pci"))
    assert devices[_PVSCSI]["device_serial_number"] == "01-23-ab-cd-50-05-05-60"
    assert devices[_NIC]["device_serial_number"] is None


@pytest.mark.os_agnostic
def test_message_signaled_interrupts_are_told_apart_from_line_based_ones() -> None:
    devices = _devices_by_id(_section("pci"))
    pvscsi = _obj(devices[_PVSCSI]["interrupts"])
    assert (pvscsi["irq"], pvscsi["msi_irqs"], pvscsi["interrupt_support"]) == ([], [-4, -3], ["msi", "msi_x"])
    assert pvscsi["msi"] == {"MSISupported": 1, "MessageNumberLimit": 2}
    nic = _obj(devices[_NIC]["interrupts"])
    assert (nic["irq"], nic["msi_irqs"], nic["msi"]) == ([18], [], None)


@pytest.mark.os_agnostic
def test_a_pci_function_lists_the_ranges_windows_allocated_to_it() -> None:
    resources = _obj(_devices_by_id(_section("pci"))[_PVSCSI]["resources"])
    assert resources["memory"] == [
        {"StartingAddress": "4271898624", "EndingAddress": "4271931391", "MemoryType": "ReadWrite"}
    ]
    assert resources["ports"] == [{"StartingAddress": "4096", "EndingAddress": "4103"}]
    assert [_obj(i)["IRQNumber"] for i in _list(resources["irqs"])] == [-3, -4]


@pytest.mark.os_agnostic
def test_a_location_written_out_in_text_still_gives_the_address() -> None:
    assert _devices_by_id(_section("pci"))[_NIC]["address"] == "0000:0b:00.0"


@pytest.mark.os_agnostic
def test_a_pci_function_seen_before_but_absent_now_is_still_listed() -> None:
    gone = _devices_by_id(_section("pci"))[_GONE_NIC]
    assert (gone["present"], gone["address"], gone["vendor_id"]) == (False, None, None)


@pytest.mark.os_agnostic
def test_a_refused_allocation_list_leaves_the_devices_and_says_why() -> None:
    document = machine_document()
    cim = _obj(document["cim"])
    del cim["root/cimv2:Win32_PnPAllocatedResource"]
    pci = _section("pci", document)
    assert set(pci) != {"error"}, pci
    assert str(_obj(_obj(pci["join_errors"])["Win32_PnPAllocatedResource"])["error"]).startswith("SourceError:")
    pvscsi = _devices_by_id(pci)[_PVSCSI]
    assert (pvscsi["address"], _obj(pvscsi["interrupts"])["msi_irqs"]) == ("0000:03:00.0", [])


@pytest.mark.os_agnostic
def test_the_system_tables_list_every_irq_and_bus() -> None:
    pci = _section("pci")
    assert [_obj(r)["IRQNumber"] for r in _list(pci["irq_descriptors"])] == [18, -3, -4]
    assert [_obj(r)["DeviceID"] for r in _list(pci["buses"])] == ["PCI_BUS_3"]
    assert pci["dma"] == []
    assert _obj(pci["join_errors"]) == {"Win32_PnPAllocatedResource": None, "Win32_DeviceBus": None}


@pytest.mark.os_agnostic
def test_every_logical_processor_is_listed_in_processor_order() -> None:
    cpu = _section("cpu")
    assert [_obj(c)["cpu"] for c in _list(cpu["cpus"])] == [0, 1, 2, 10]
    assert _obj(_obj(_list(cpu["cpus"])[3])["registry"])["~MHz"] == 3100


@pytest.mark.os_agnostic
def test_memory_holds_the_totals_the_page_files_and_the_numa_nodes() -> None:
    memory = _section("memory")
    assert _obj(_list(memory["totals"])[0])["FreePhysicalMemory"] == "123456"
    assert _obj(_list(memory["page_files"])[0])["Name"] == r"C:\pagefile.sys"
    assert memory["numa"] == [{"node": 0, "processor_group": 0, "processor_mask": "0xf", "processors": [0, 1, 2, 3]}]


@pytest.mark.os_agnostic
def test_the_scsi_map_decodes_each_logical_unit_under_the_linux_names() -> None:
    (port,) = _list(_section("disks")["scsi"])
    (bus,) = _list(_obj(port)["buses"])
    targets = _list(_obj(bus)["targets"])
    assert [_obj(t)["target"] for t in targets] == [0], "the bus's own initiator is no target"
    (unit,) = _list(_obj(targets[0])["units"])
    inquiry = _obj(_obj(unit)["inquiry"])
    assert (_obj(port)["port"], _obj(_obj(port)["values"])["Driver"]) == (0, "pvscsi")
    assert (inquiry["vendor"], inquiry["model"], inquiry["rev"], inquiry["type"]) == (
        "VMware",
        "Virtual disk",
        "2.0",
        0,
    )
    (designator,) = _list(_obj(unit)["vpd_identifiers"])
    assert (_obj(designator)["type"], _obj(designator)["value"]) == ("naa", "6000c29abcdef0123456789abcdef012")


@pytest.mark.os_agnostic
def test_devices_list_the_installed_drivers_and_decode_the_monitor_edid() -> None:
    devices = _section("devices")
    assert [_obj(d)["Name"] for d in _list(devices["system_drivers"])] == ["pvscsi", "floppy"]
    (display,) = _list(devices["displays"])
    edid = _obj(_obj(display)["edid"])
    assert (edid["manufacturer"], edid["name"], edid["year"]) == ("VMW", "VMware SVGA", 2020)


@pytest.mark.os_agnostic
def test_security_records_the_protections_by_item() -> None:
    security = _section("security")
    assert _obj(security["lsa"])["RunAsPPL"] == 2
    assert security["kernel_dma_protection"] == {"enabled": False, "policy": None}
    assert [_obj(p)["Name"] for p in _list(security["firewall"])] == ["Domain", "Private", "Public"]
    assert _obj(_list(security["defender"])[0])["RealTimeProtectionEnabled"] is True
    assert _obj(security["uac"])["EnableLUA"] == 1
    assert _obj(security["smartscreen"])["explorer"] == "Warn"
    assert security["credential_providers"] == [
        {"clsid": "{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}", "name": "PasswordProvider"}
    ]


@pytest.mark.os_agnostic
def test_a_policy_nobody_set_reads_as_none_not_as_an_error() -> None:
    security = _section("security")
    update = _obj(security["windows_update"])
    assert (update["policy"], _obj(update["policy_au"])["AUOptions"]) == (None, 2)
    assert _obj(update["results"]) == {"Detect": None, "Download": None, "Install": None}
    assert (security["windows_hello"], security["bitlocker_policy"]) == (None, None)


@pytest.mark.os_agnostic
def test_a_cached_tpm_authorization_never_reaches_the_reading() -> None:
    reading = _reading()
    service = _obj(_obj(reading["security"])["tpm_service"])
    assert service["OwnerAuthFull"] == "<withheld: a TPM authorization value>"
    assert service["OSManagedAuthLevel"] == 4
    assert PLANTED_OWNER_AUTH not in json.dumps(reading)


@pytest.mark.os_agnostic
def test_an_unanswered_kernel_question_costs_only_its_own_item() -> None:
    document = machine_document()
    del document["system"]
    security, memory = _section("security", document), _section("memory", document)
    assert str(_obj(security["kernel_dma_protection"])["error"]).startswith("SourceError:")
    assert str(_obj(memory["numa"])["error"]).startswith("SourceError:")
    assert _obj(security["lsa"])["RunAsPPL"] == 2
