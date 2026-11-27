"""collect, compare and check end to end, through the CLI, on a recorded machine."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner
from machine_builder import NIC_GUID, PLANTED_KEY, PVSCSI_WWID, machine_document

from fingerprint_machine.adapters.cli.root import cli
from fingerprint_machine.adapters.fixture import FixtureSources
from fingerprint_machine.application.machine_ports import WindowsSources
from fingerprint_machine.composition import build_production, build_testing
from fingerprint_machine.domain.cpuid import CpuidRegs

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from fingerprint_machine.composition import AppServices
    from fingerprint_machine.domain.json_types import JsonObject, JsonValue


def _replay(document: JsonObject) -> Callable[[], AppServices]:
    recorded = FixtureSources(document)
    return lambda: build_testing(sources=WindowsSources(platform=recorded, registry=recorded, cpuid=recorded))


def _machine(**kwargs: str) -> Callable[[], AppServices]:
    return _replay(machine_document(**kwargs))


def _run(args: list[str], factory: Callable[[], AppServices]) -> tuple[int, str]:
    result = CliRunner().invoke(cli, args, obj=factory)
    return result.exit_code, result.stdout


def _obj(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict)
    return value


def _collect(factory: Callable[[], AppServices]) -> JsonObject:
    code, out = _run(["collect", "--json"], factory)
    assert code == 0, out
    return _obj(json.loads(out))


@pytest.mark.os_agnostic
def test_collect_json_is_an_envelope_with_every_section() -> None:
    envelope = _collect(_machine())
    assert (envelope["ok"], envelope["command"]) == (True, "collect")
    reading = _obj(envelope["data"])
    assert list(reading)[:2] == ["meta", "summary"]
    for section in (
        "smbios",
        "acpi",
        "platform",
        "cpu",
        "cpuid",
        "memory",
        "disks",
        "network",
        "hardware",
        "devices",
        "windows",
        "security",
        "services",
    ):
        assert section in reading, section
    meta = _obj(reading["meta"])
    assert (meta["schema_version"], meta["os"]) == (3, "windows")


@pytest.mark.os_agnostic
def test_the_cpuid_section_names_the_hypervisor() -> None:
    cpuid = _obj(_obj(_collect(_machine())["data"])["cpuid"])
    assert (cpuid["vendor"], cpuid["hypervisor_vendor"], cpuid["hypervisor_present_bit"]) == (
        "GenuineIntel",
        "VMwareVMware",
        True,
    )
    raw = _obj(cpuid["raw"])
    assert sorted(raw) == [
        "0x00000000:0",
        "0x00000001:0",
        "0x40000000:0",
        "0x40000001:0",
        "0x80000000:0",
        "0x80000001:0",
    ]


@dataclass
class _CountingCpuid:
    """A CPU that answers zeros and counts every question."""

    calls: list[int] = field(default_factory=list[int])

    def cpuid(self, leaf: int, *, subleaf: int = 0) -> CpuidRegs:
        del subleaf
        self.calls.append(leaf)
        return CpuidRegs(eax=0, ebx=0, ecx=0, edx=0)


def _counted(cpu: _CountingCpuid) -> Callable[[], AppServices]:
    recorded = FixtureSources(machine_document())
    return lambda: build_testing(sources=WindowsSources(platform=recorded, registry=recorded, cpuid=cpu))


@pytest.mark.os_agnostic
def test_no_cpuid_asks_the_cpu_nothing_and_leaves_the_section_out() -> None:
    cpu = _CountingCpuid()
    code, out = _run(["collect", "--no-cpuid", "--json-bare"], _counted(cpu))
    assert code == 0, out
    reading = _obj(json.loads(out))
    assert "cpuid" not in reading
    sections = _obj(reading["meta"])["sections"]
    assert isinstance(sections, list)
    assert "cpuid" not in sections
    assert cpu.calls == []


@pytest.mark.os_agnostic
def test_no_cpuid_wins_over_asking_for_the_cpuid_section() -> None:
    cpu = _CountingCpuid()
    code, out = _run(["collect", "--section", "cpuid", "--no-cpuid", "--json-bare"], _counted(cpu))
    assert code == 0, out
    assert _obj(_obj(json.loads(out))["meta"])["sections"] == []
    assert cpu.calls == []


@pytest.mark.os_agnostic
def test_collect_asks_the_cpu_by_default() -> None:
    cpu = _CountingCpuid()
    assert _run(["collect", "--section", "cpuid", "--json-bare"], _counted(cpu))[0] == 0
    assert cpu.calls[0] == 0


@pytest.mark.os_agnostic
def test_summary_names_the_identity_values() -> None:
    summary = _obj(_obj(_collect(_machine())["data"])["summary"])
    system, windows, security = _obj(summary["system"]), _obj(summary["windows"]), _obj(summary["security"])
    assert (system["serial"], system["product"], system["sku"]) == ("SER-0001", "Model X", "SKU-9")
    nics = summary["nics"]
    assert isinstance(nics, list)
    assert _obj(nics[0]) == {
        "name": "Ethernet0",
        "description": "vmxnet3 Ethernet Adapter",
        "mac": "00:50:56:00:00:01",
        "interface_index": 6,
        "pci_serial": "00-0c-29-ff-ff-00-00-01",
        "pci_address": "0000:0b:00.0",
        "driver": "vmxnet3",
        "bus": 11,
        "device": 0,
        "function": 0,
        "slot": 160,
        "class_key": "0007",
    }
    scsi = summary["scsi_controllers"]
    assert isinstance(scsi, list)
    assert _obj(scsi[0])["sas_wwid"] == PVSCSI_WWID
    assert (windows["product_id"], windows["machine_sid"], windows["edition"]) == (
        "00330-80000-00000-AA111",
        "S-1-5-21-1000-2000-3000",
        "Professional",
    )
    assert (security["firmware_type"], security["secure_boot"], security["tpm_version"]) == ("UEFI", 1, "2.0")


@pytest.mark.os_agnostic
def test_network_adapter_carries_its_settings_and_class_key() -> None:
    network = _obj(_obj(_collect(_machine())["data"])["network"])
    adapters = network["adapters"]
    assert isinstance(adapters, list)
    adapter = _obj(adapters[0])
    properties = adapter["advanced_properties"]
    assert isinstance(properties, list)
    keywords = [_obj(p)["RegistryKeyword"] for p in properties]
    assert keywords == ["*JumboPacket", "*RSS"]
    assert _obj(_obj(adapter["class_key"])["values"])["NetCfgInstanceId"] == NIC_GUID


@pytest.mark.os_agnostic
def test_no_full_product_key_reaches_the_output() -> None:
    code, out = _run(["collect", "--json"], _machine())
    assert code == 0
    assert PLANTED_KEY in json.dumps(machine_document())  # the recording does hold it
    assert PLANTED_KEY not in out
    assert PLANTED_KEY.encode().hex() not in out  # nor its DigitalProductId encoding
    assert "*****-*****-*****-*****-" + PLANTED_KEY[-5:] in out


@pytest.mark.os_agnostic
def test_an_unrecorded_question_is_skipped_not_fatal() -> None:
    envelope = _collect(_machine())
    skipped = envelope["skipped"]
    assert isinstance(skipped, list)
    paths = [_obj(s)["path"] for s in skipped]
    assert "services.all" in paths  # Win32_Service is not in the recording
    assert "smbios" not in paths


@pytest.mark.os_agnostic
def test_an_absent_optional_key_is_an_empty_answer_not_a_skip() -> None:
    # The recording has no CloudDomainJoin key: the machine is simply not joined.
    envelope = _collect(_machine())
    reading = _obj(envelope["data"])
    assert _obj(reading["windows"])["cloud_join"] == {}
    skipped = envelope["skipped"]
    assert isinstance(skipped, list)
    assert "windows.cloud_join" not in [_obj(s)["path"] for s in skipped]


@pytest.mark.os_agnostic
def test_an_absent_key_a_machine_always_has_is_still_skipped() -> None:
    document = machine_document()
    registry = document["registry"]
    assert isinstance(registry, dict)
    del registry[r"HKLM\SOFTWARE\Microsoft\Cryptography"]
    skipped = _collect(_replay(document))["skipped"]
    assert isinstance(skipped, list)
    assert "windows.machine_guid" in [_obj(s)["path"] for s in skipped]


@pytest.mark.os_agnostic
def test_collect_out_saves_the_bare_reading(tmp_path: Path) -> None:
    target = tmp_path / "reading.json"
    code, _ = _run(["collect", "--section", "smbios", "--label", "vm-a", "--out", str(target)], _machine())
    assert code == 0
    saved = _obj(json.loads(target.read_text(encoding="utf-8")))
    assert _obj(saved["meta"])["label"] == "vm-a"
    assert _obj(saved["meta"])["sections"] == ["smbios"]
    assert "network" not in saved


@pytest.mark.os_agnostic
def test_collect_out_writes_lf_line_endings_on_every_os(tmp_path: Path) -> None:
    # On Windows a descriptor opened without O_BINARY turns each newline into CRLF.
    target = tmp_path / "reading.json"
    assert _run(["collect", "--section", "smbios", "--out", str(target)], _machine())[0] == 0
    data = target.read_bytes()
    assert b"\n" in data
    assert b"\r\n" not in data


@pytest.mark.os_posix
def test_collect_out_creates_the_file_with_the_umask_mode_as_a_plain_write_does(tmp_path: Path) -> None:
    # A temporary file is always created 0600; the saved reading must follow the umask instead,
    # or a reading taken under sudo is unreadable to the user who asked for it.
    target = tmp_path / "reading.json"
    previous = os.umask(0o027)
    try:
        code, _ = _run(["collect", "--section", "smbios", "--out", str(target)], _machine())
    finally:
        os.umask(previous)
    assert code == 0
    assert stat.S_IMODE(target.stat().st_mode) == 0o640


@pytest.mark.os_agnostic
def test_compare_exits_0_for_the_same_machine_and_1_for_another(tmp_path: Path) -> None:
    a, b, c = tmp_path / "a.json", tmp_path / "b.json", tmp_path / "c.json"
    assert _run(["collect", "--out", str(a)], _machine())[0] == 0
    assert _run(["collect", "--out", str(b)], _machine())[0] == 0
    assert _run(["collect", "--out", str(c)], _machine(serial="SER-0002"))[0] == 0

    code, out = _run(["compare", str(a), str(b), "--json"], _machine())
    assert code == 0, out
    assert _obj(json.loads(out)["data"])["differences"] == []

    code, out = _run(["compare", str(a), str(c), "--json-bare"], _machine())
    assert code == 1
    differences = _obj(json.loads(out))["differences"]
    assert isinstance(differences, list)
    assert "smbios.system.serial" in differences
    assert "summary.system.serial" in differences


@pytest.mark.os_agnostic
def test_check_saves_the_fresh_reading_and_the_comparison(tmp_path: Path) -> None:
    baseline, fresh, report = tmp_path / "base.json", tmp_path / "fresh.json", tmp_path / "report.json"
    assert _run(["collect", "--out", str(baseline)], _machine())[0] == 0
    code, _ = _run(
        ["check", str(baseline), "--save", str(fresh), "--out", str(report)],
        _machine(product_id="00330-80000-00000-BB222"),
    )
    assert code == 1
    assert _obj(_obj(json.loads(fresh.read_text(encoding="utf-8")))["summary"])["windows"]
    differences = _obj(json.loads(report.read_text(encoding="utf-8")))["differences"]
    assert isinstance(differences, list)
    assert "windows.current_version.ProductId" in differences


@pytest.mark.os_agnostic
def test_every_envelope_names_its_command_as_the_plain_word(tmp_path: Path) -> None:
    saved, junk = tmp_path / "saved.json", tmp_path / "junk.json"
    assert _run(["collect", "--out", str(saved)], _machine())[0] == 0
    junk.write_text('{"hello": 1}', encoding="utf-8")
    runs = {
        ("compare", True): ["compare", str(saved), str(saved), "--json"],
        ("check", True): ["check", str(saved), "--json"],
        ("compare", False): ["compare", str(junk), str(junk), "--json"],
        ("check", False): ["check", str(junk), "--json"],
    }
    for (verb, ok), args in runs.items():
        _, out = _run(args, _machine())
        envelope = _obj(json.loads(out))
        assert (envelope["ok"], envelope["command"]) == (ok, verb), out
        assert f'"command": "{verb}"' in out


@pytest.mark.os_agnostic
def test_a_file_that_is_not_a_reading_is_refused_as_json(tmp_path: Path) -> None:
    junk = tmp_path / "junk.json"
    junk.write_text('{"hello": 1}', encoding="utf-8")
    code, out = _run(["compare", str(junk), str(junk), "--json-bare"], _machine())
    assert code == 2
    failure = _obj(json.loads(out))
    assert (failure["ok"], _obj(failure["error"])["type"]) == (False, "NotAReadingError")


@pytest.mark.os_agnostic
@pytest.mark.parametrize("verb", ["collect", "check"])
def test_reading_a_machine_on_an_unsupported_os_is_refused_with_exit_2(verb: str, tmp_path: Path) -> None:
    """Production wiring for an OS that is neither Windows nor Linux refuses, wherever the test runs."""
    baseline = tmp_path / "base.json"
    assert _run(["collect", "--out", str(baseline)], _machine())[0] == 0
    args = ["collect"] if verb == "collect" else ["check", str(baseline)]
    code, out = _run([*args, "--json-bare"], lambda: build_production(platform="darwin"))
    assert code == 2
    error = _obj(_obj(json.loads(out))["error"])
    assert error["type"] == "UnsupportedPlatformError"
    assert "Windows or Linux" in str(error["message"])
    assert "darwin" in str(error["message"])
