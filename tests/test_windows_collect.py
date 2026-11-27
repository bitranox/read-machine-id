"""A real collection on a real Windows machine (the CI Windows runner, or a developer's box).

A runner is a VM whose TPM, BitLocker and licensing answers vary, so this asserts only what every
Windows machine has: SMBIOS, the operating system, at least one network adapter, and on x86-64 a
CPU vendor read through CPUID.
"""

from __future__ import annotations

import json
import platform

import pytest
from click.testing import CliRunner

from fingerprint_machine.adapters.cli.root import cli
from fingerprint_machine.composition import build_production


@pytest.mark.os_windows
def test_collect_reads_this_windows_machine() -> None:
    result = CliRunner().invoke(cli, ["collect", "--json"], obj=build_production)
    assert result.exit_code == 0, result.stdout
    envelope = json.loads(result.stdout)
    reading = envelope["data"]
    assert envelope["ok"] is True
    assert "error" not in reading["smbios"]
    assert reading["smbios"]["type_counts"]
    assert reading["windows"]["operating_system"][0]["Caption"]
    assert reading["network"]["adapters"]
    assert reading["meta"]["os"] == "windows"
    if platform.machine().lower() in {"amd64", "x86_64"}:
        assert len(reading["cpuid"]["vendor"]) == 12
