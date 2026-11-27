"""Comparing readings and joining network adapter rows."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from read_machine_id.domain.compare import FieldStatus, compare_readings, score
from read_machine_id.domain.network import join_adapters

if TYPE_CHECKING:
    from read_machine_id.domain.json_types import JsonObject, JsonValue


def _statuses(a: JsonObject, b: JsonObject) -> dict[str, FieldStatus]:
    return {r.path: r.status for r in compare_readings(a, b).rows}


def _obj(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict)
    return value


@pytest.mark.os_agnostic
def test_a_counter_property_is_shown_but_not_scored() -> None:
    a: JsonObject = {"meta": {"schema_version": 2}, "cpu": {"wmi": [{"LoadPercentage": 3, "Name": "X"}]}}
    b: JsonObject = {"meta": {"schema_version": 2}, "cpu": {"wmi": [{"LoadPercentage": 97, "Name": "X"}]}}
    cmp = compare_readings(a, b)
    assert _statuses(a, b)["cpu.wmi[0].LoadPercentage"] is FieldStatus.VOLATILE
    assert cmp.differences() == []
    assert score(cmp)["identical_pct"] == 100.0


@pytest.mark.os_agnostic
def test_a_field_only_the_newer_schema_collects_is_not_a_difference() -> None:
    old: JsonObject = {"meta": {"probe_version": 1}, "smbios": {"system": {"serial": "S"}}}
    new: JsonObject = {"meta": {"schema_version": 2}, "smbios": {"system": {"serial": "S"}, "slots": [{"bus": 1}]}}
    assert _statuses(old, new)["smbios.slots[0].bus"] is FieldStatus.NEWER_PROBE_ONLY
    assert compare_readings(old, new).differences() == []


@pytest.mark.os_agnostic
def test_within_one_schema_a_missing_field_is_a_difference() -> None:
    a: JsonObject = {"meta": {"schema_version": 2}, "x": 1}
    b: JsonObject = {"meta": {"schema_version": 2}, "x": 1, "y": 2}
    assert _statuses(a, b)["y"] is FieldStatus.ONLY_ACTUAL
    assert compare_readings(a, b).differences() == ["y"]


@pytest.mark.os_agnostic
def test_rows_join_their_adapter_by_name_by_index_and_by_class_key() -> None:
    adapters: list[JsonObject] = [
        {"Name": "A", "InterfaceIndex": 1, "DeviceID": "{aa}"},
        {"Name": "B", "InterfaceIndex": 2, "DeviceID": "{bb}"},
    ]
    categories: dict[str, list[JsonObject]] = {
        "hardware": [{"Name": "B", "BusNumber": 5}, {"Name": "A", "BusNumber": 4}],
        "advanced_properties": [{"Name": "A", "RegistryKeyword": "*RSS"}, {"Name": "Hidden", "RegistryKeyword": "*X"}],
        "ip_addresses": [{"InterfaceIndex": 2, "IPAddress": "192.0.2.2"}],
    }
    out = join_adapters(adapters, categories, {"{BB}": {"number": "0003", "values": {}}})
    records = out["adapters"]
    assert isinstance(records, list)
    first, second = _obj(records[0]), _obj(records[1])
    assert first["hardware"] == [{"Name": "A", "BusNumber": 4}]
    assert first["ip_addresses"] == []
    assert first["class_key"] is None
    assert second["ip_addresses"] == [{"InterfaceIndex": 2, "IPAddress": "192.0.2.2"}]
    assert second["class_key"] == {"number": "0003", "values": {}}
    assert "rss" not in first  # a category not read is left out, never shown as empty
    assert out["unmatched"] == {"advanced_properties": [{"Name": "Hidden", "RegistryKeyword": "*X"}]}
