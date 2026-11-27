"""Collecting a Linux machine: a synthetic tree on every OS, and this machine where it is Linux."""

from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner
from linux_builder import linux_answers, write_linux_tree

from fingerprint_machine.adapters.cli.root import cli
from fingerprint_machine.adapters.fixture import FixtureLinuxSource
from fingerprint_machine.application.machine_ports import LinuxSources
from fingerprint_machine.composition import build_production, build_testing

if TYPE_CHECKING:
    from collections.abc import Callable

    from fingerprint_machine.composition import AppServices
    from fingerprint_machine.domain.json_types import JsonObject, JsonValue

_X86_64 = platform.machine().lower() in {"x86_64", "amd64"}


def _obj(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict)
    return value


def _guest(root: Path) -> Callable[[], AppServices]:
    source = FixtureLinuxSource(write_linux_tree(root), linux_answers())
    return lambda: build_testing(sources=LinuxSources(system=source, cpuid=source))


def _collect(args: list[str], factory: Callable[[], AppServices]) -> JsonObject:
    result = CliRunner().invoke(cli, ["collect", "--json", *args], obj=factory)
    assert result.exit_code == 0, result.stdout
    return _obj(json.loads(result.stdout))


@pytest.mark.os_agnostic
def test_a_linux_reading_says_linux_and_holds_the_cpuid_section(tmp_path: Path) -> None:
    reading = _obj(_collect([], _guest(tmp_path))["data"])
    meta = _obj(reading["meta"])
    assert (meta["os"], meta["schema_version"]) == ("linux", 3)
    sections = meta["sections"]
    assert isinstance(sections, list)
    assert "cpuid" in sections
    assert "windows" not in sections
    assert list(reading) == ["meta", "summary", *sections]
    cpuid = _obj(reading["cpuid"])
    assert (cpuid["vendor"], cpuid["hypervisor_vendor"]) == ("GenuineIntel", "KVMKVMKVM")
    assert _obj(cpuid["raw"])["0x00000000:0"] == {
        "eax": "0x00000001",
        "ebx": "0x756e6547",
        "ecx": "0x6c65746e",
        "edx": "0x49656e69",
    }


@pytest.mark.os_agnostic
def test_a_section_linux_does_not_read_yet_is_recorded_as_skipped(tmp_path: Path) -> None:
    envelope = _collect(["--section", "windows"], _guest(tmp_path))
    reading = _obj(envelope["data"])
    assert str(_obj(reading["windows"])["error"]).startswith("SourceError:")
    skipped = envelope["skipped"]
    assert isinstance(skipped, list)
    assert [_obj(s)["path"] for s in skipped] == ["windows"]


@pytest.mark.os_agnostic
def test_a_failing_leaf_is_one_recorded_error_and_the_rest_is_read(tmp_path: Path) -> None:
    answers = linux_answers()
    recorded = _obj(answers["cpuid"])
    recorded["0x80000001:0"] = {"error": "refused by the test"}
    source = FixtureLinuxSource(write_linux_tree(tmp_path), answers)
    envelope = _collect(
        ["--section", "cpuid"], lambda: build_testing(sources=LinuxSources(system=source, cpuid=source))
    )
    cpuid = _obj(_obj(envelope["data"])["cpuid"])
    assert _obj(_obj(cpuid["raw"])["0x80000001:0"])["error"] == "SourceError: refused by the test"
    assert cpuid["hypervisor_vendor"] == "KVMKVMKVM"
    skipped = envelope["skipped"]
    assert isinstance(skipped, list)
    assert [_obj(s)["path"] for s in skipped] == ["cpuid.raw.0x80000001:0"]


@pytest.mark.os_linux
def test_collect_reads_the_cpuid_of_this_linux_machine() -> None:
    reading = _obj(_collect(["--section", "cpuid"], build_production)["data"])
    assert _obj(reading["meta"])["os"] == "linux"
    cpuid = _obj(reading["cpuid"])
    if not _X86_64:
        assert "x86-64" in str(cpuid["error"])
        return
    cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    vendor = next(line.split(":", 1)[1].strip() for line in cpuinfo.splitlines() if line.startswith("vendor_id"))
    assert cpuid["vendor"] == vendor
