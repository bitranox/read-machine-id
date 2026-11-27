"""SMBIOS decoding from hand-built DSP0134 bytes: every decoded type, truncation, raw round trip."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest
from machine_builder import SYSTEM_UUID_BYTES, smbios_table, structure

from fingerprint_machine.domain.smbios import decode_smbios, parse_smbios_structures, split_raw_smbios

if TYPE_CHECKING:
    from fingerprint_machine.domain.json_types import JsonObject, JsonValue


def _first(rows: JsonValue) -> JsonObject:
    assert isinstance(rows, list) and rows and isinstance(rows[0], dict)
    return rows[0]


@pytest.mark.os_agnostic
def test_system_keeps_the_keys_a_baseline_reader_expects() -> None:
    system = decode_smbios(smbios_table(), "3.1")["system"]
    assert isinstance(system, dict)
    assert {k: system[k] for k in ("manufacturer", "product", "serial", "sku", "family")} == {
        "manufacturer": "Example Systems",
        "product": "Model X",
        "serial": "SER-0001",
        "sku": "SKU-9",
        "family": "Family Y",
    }
    # SMBIOS stores the first three UUID fields little-endian: bytes 01..10 read back swapped.
    # Upper case, as the predecessor script wrote it, so its baselines still compare equal.
    assert bytes(range(1, 17)) == SYSTEM_UUID_BYTES
    assert system["uuid"] == "04030201-0605-0807-090A-0B0C0D0E0F10"


@pytest.mark.os_agnostic
def test_slot_and_onboard_device_carry_their_pci_location() -> None:
    decoded = decode_smbios(smbios_table(), "3.1")
    assert decoded["slots"] == [
        {
            "designation": "PCIe Slot 7",
            "slot_type": 0xA5,
            "data_bus_width": 0,
            "current_usage": 0,
            "slot_length": 0,
            "slot_id": 7,
            "characteristics_1": 0,
            "characteristics_2": 0,
            "segment": 0,
            "bus": 3,
            "device": 2,
            "function": 1,
        }
    ]
    assert _first(decoded["onboard_devices"]) == {
        "reference_designation": "Onboard NIC",
        "device_type": 5,
        "enabled": True,
        "device_type_instance": 1,
        "segment": 1,
        "bus": 0x0B,
        "device": 0,
        "function": 0,
    }


@pytest.mark.os_agnostic
def test_memory_array_device_and_mapping_are_decoded() -> None:
    decoded = decode_smbios(smbios_table(), "3.1")
    array, module, mapped = (_first(decoded[k]) for k in ("memory_arrays", "memory", "memory_mapped"))
    assert (array["maximum_capacity_kib"], array["memory_devices"]) == (0x100000, 2)
    assert (module["locator"], module["serial"], module["speed_mts"]) == ("DIMM 0", "MEMSER-1", 3200)
    assert (mapped["ending_address_kib"], mapped["memory_array_handle"]) == (0x7FFFFF, 6)


@pytest.mark.os_agnostic
def test_every_structure_is_kept_raw_and_counted() -> None:
    table = smbios_table()
    decoded = decode_smbios(table, "3.1")
    counts = decoded["type_counts"]
    structures = decoded["structures"]
    assert isinstance(counts, dict) and isinstance(structures, list)
    assert sum(v for v in counts.values() if isinstance(v, int)) == len(structures) == 11
    assert decoded["oem_strings"] == ["oem one", "oem two"]
    assert bytes.fromhex(str(decoded["raw_hex"])) == table


@pytest.mark.os_agnostic
def test_a_structure_cut_short_stops_the_walk_without_raising() -> None:
    first = structure(0, 0, 0x1A, {}, ["A"])
    second = structure(1, 1, 0x1B, {}, ["B"])
    cut = (first + second)[: len(first) + 10]
    assert len(parse_smbios_structures(cut)) == 1


@pytest.mark.os_agnostic
def test_a_short_structure_yields_none_for_missing_fields() -> None:
    old_system = structure(1, 1, 0x08, {4: bytes([1])}, ["Old Vendor"])
    system = decode_smbios(old_system, "2.0")["system"]
    assert isinstance(system, dict)
    assert system["manufacturer"] == "Old Vendor"
    assert system["uuid"] is None
    assert system["sku"] is None


@pytest.mark.os_agnostic
def test_rsmb_block_is_split_into_table_and_version() -> None:
    table = smbios_table()
    raw = struct.pack("<BBBBI", 0, 3, 4, 0, len(table)) + table
    assert split_raw_smbios(raw) == (table, "3.4")


@pytest.mark.os_agnostic
def test_rsmb_block_shorter_than_its_stated_length_is_refused() -> None:
    raw = struct.pack("<BBBBI", 0, 3, 1, 0, 100) + b"short"
    with pytest.raises(ValueError, match="states 100 table bytes, holds 5"):
        split_raw_smbios(raw)
