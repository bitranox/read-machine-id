"""The Linux system sections end to end: ``collect --json --section X`` over a synthetic guest.

smbios, acpi, platform, cpu, memory, security and services, each read through the CLI from a
VMware-like and a KVM-like tree, then (where this is Linux) from this machine.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner
from linux_builder import write_linux_tree
from linux_system_tree import EK_INDEX, LUKS_UUID, MACHINE_ID, Guest, system_answers, write_system_tree
from machine_builder import PLANTED_KEY

from fingerprint_machine.adapters.cli.root import cli
from fingerprint_machine.adapters.fixture import FixtureLinuxSource
from fingerprint_machine.application.linux_platform import read_linux_platform
from fingerprint_machine.application.machine_ports import LinuxSources
from fingerprint_machine.composition import build_production, build_testing
from fingerprint_machine.domain.cpuid import CpuidRegs

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from fingerprint_machine.composition import AppServices
    from fingerprint_machine.domain.json_types import JsonObject, JsonValue

_SYSTEM_SECTIONS = ("smbios", "acpi", "platform", "cpu", "memory", "security", "services")


def _obj(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict), value
    return value


def _list(value: JsonValue) -> list[JsonValue]:
    assert isinstance(value, list), value
    return value


def _source(root: Path, guest: Guest) -> FixtureLinuxSource:
    return FixtureLinuxSource(write_system_tree(write_linux_tree(root), guest), system_answers(guest))


def _factory(root: Path, guest: Guest) -> Callable[[], AppServices]:
    source = _source(root, guest)
    return lambda: build_testing(sources=LinuxSources(system=source, cpuid=source))


def _run(args: list[str], factory: Callable[[], AppServices]) -> str:
    result = CliRunner().invoke(cli, ["collect", "--json", *args], obj=factory)
    assert result.exit_code == 0, result.stdout
    return result.stdout


def _section(name: str, factory: Callable[[], AppServices]) -> JsonObject:
    reading = _obj(_obj(json.loads(_run(["--section", name], factory)))["data"])
    assert _obj(reading["meta"])["sections"] == [name]
    return _obj(reading[name])


@pytest.mark.os_agnostic
def test_smbios_decodes_the_dmi_table_with_the_entry_point_version(tmp_path: Path) -> None:
    smbios = _section("smbios", _factory(tmp_path, Guest.VMWARE))
    assert smbios["version"] == "3.1"
    system = _obj(smbios["system"])
    assert (system["serial"], system["uuid"]) == ("SER-0001", "04030201-0605-0807-090A-0B0C0D0E0F10")
    assert _obj(smbios["entry_point"])["anchor"] == "_SM3_"
    dmi = _obj(smbios["dmi_id"])
    assert (dmi["sys_vendor"], dmi["product_serial"]) == ("VMware, Inc.", "SER-0001")
    assert "modalias" not in dmi
    assert "table" not in smbios


@pytest.mark.os_agnostic
def test_acpi_lists_every_table_header_and_masks_the_msdm_key(tmp_path: Path) -> None:
    out = _run(["--section", "acpi"], _factory(tmp_path, Guest.VMWARE))
    assert PLANTED_KEY not in out
    acpi = _obj(_obj(_obj(json.loads(out))["data"])["acpi"])
    files = [_obj(t)["file"] for t in _list(acpi["tables"])]
    assert files == ["APIC", "FACP", "MSDM", "dynamic/SSDT1"]
    assert _obj(_list(acpi["tables"])[0])["oem_id"] == "OEMID"
    assert acpi["msdm"] == {"present": True, "product_key": "*****-*****-*****-*****-" + PLANTED_KEY[-5:]}


@pytest.mark.os_agnostic
def test_a_guest_without_msdm_says_so(tmp_path: Path) -> None:
    acpi = _section("acpi", _factory(tmp_path, Guest.KVM))
    assert acpi["msdm"] == {"present": False, "product_key": None}


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("guest", "kind", "clock"), [(Guest.VMWARE, "vmware", "tsc"), (Guest.KVM, "kvm", "kvm-clock")])
def test_platform_names_the_kernel_os_ids_and_hypervisor(tmp_path: Path, guest: Guest, kind: str, clock: str) -> None:
    platform = _section("platform", _factory(tmp_path, guest))
    assert _obj(platform["kernel"])["release"] == "6.1.0-synthetic"
    assert _obj(platform["os_release"])["ID"] == "example"
    assert (platform["machine_id"], platform["dbus_machine_id"]) == (MACHINE_ID, MACHINE_ID)
    assert platform["hostname"] == f"{guest.value}-guest"
    assert platform["container"] is None
    assert platform["hypervisor"] == {}
    assert _obj(platform["clocksource"])["current_clocksource"] == clock
    virt = _obj(platform["virtualization"])
    assert (virt["kind"], virt["source"]) == (kind, "cpuid 0x40000000")
    assert _obj(virt["cpuid"])["hypervisor_present_bit"] is True


@dataclass
class _CountingCpu:
    """A CPU that answers zeros and counts every question."""

    calls: list[int] = field(default_factory=list[int])

    def cpuid(self, leaf: int, *, subleaf: int = 0) -> CpuidRegs:
        del subleaf
        self.calls.append(leaf)
        return CpuidRegs(eax=0, ebx=0, ecx=0, edx=0)


@pytest.mark.os_agnostic
def test_no_cpuid_reaches_the_platform_section_and_the_verdict_falls_back_to_dmi(tmp_path: Path) -> None:
    source = _source(tmp_path, Guest.VMWARE)
    cpu = _CountingCpu()

    def factory() -> AppServices:
        return build_testing(sources=LinuxSources(system=source, cpuid=cpu))

    out = CliRunner().invoke(cli, ["collect", "--section", "platform", "--no-cpuid", "--json-bare"], obj=factory)
    assert out.exit_code == 0, out.stdout
    virt = _obj(_obj(_obj(json.loads(out.stdout))["platform"])["virtualization"])
    assert cpu.calls == []
    assert "--no-cpuid" in str(_obj(virt["cpuid"])["error"])
    assert (virt["kind"], virt["source"]) == ("vmware", "dmi product_name")


@pytest.mark.os_agnostic
def test_without_no_cpuid_the_platform_section_asks_the_cpu(tmp_path: Path) -> None:
    source = _source(tmp_path, Guest.VMWARE)
    cpu = _CountingCpu()
    platform = _obj(read_linux_platform(LinuxSources(system=source, cpuid=cpu)))
    assert cpu.calls == [1]
    assert _obj(_obj(platform["virtualization"])["cpuid"])["hypervisor_present_bit"] is False


@pytest.mark.os_agnostic
def test_a_xen_style_hypervisor_directory_is_read_as_a_tree(tmp_path: Path) -> None:
    root = write_system_tree(write_linux_tree(tmp_path), Guest.KVM)
    (root / "sys/hypervisor/properties").mkdir(parents=True)
    (root / "sys/hypervisor/type").write_bytes(b"xen\n")
    (root / "sys/hypervisor/properties/features").write_bytes(b"0000\n")
    source = FixtureLinuxSource(root, system_answers(Guest.KVM))
    platform = _obj(read_linux_platform(LinuxSources(system=source, cpuid=source)))
    assert platform["hypervisor"] == {"properties": {"features": "0000"}, "type": "xen"}


@pytest.mark.os_agnostic
def test_cpu_holds_cpuinfo_topology_caches_and_vulnerabilities(tmp_path: Path) -> None:
    cpu = _section("cpu", _factory(tmp_path, Guest.KVM))
    cpuinfo = _list(cpu["cpuinfo"])
    assert len(cpuinfo) == 2
    assert _obj(cpuinfo[0])["flags"] == ["fpu", "sse2", "hypervisor"]
    first = _obj(_list(cpu["cpus"])[0])
    assert (first["cpu"], _obj(first["topology"])["core_id"]) == (0, "0")
    assert [_obj(c)["size"] for c in _list(first["cache"])] == ["48K", "2048K"]
    assert "cpufreq" not in first
    assert _obj(_list(cpu["cpus"])[1])["online"] == "1"
    assert _obj(cpu["system"])["possible"] == "0-1"
    assert _obj(cpu["vulnerabilities"])["spectre_v2"] == "Mitigation: Enhanced IBRS"


@pytest.mark.os_agnostic
def test_memory_holds_totals_blocks_numa_and_hugepages(tmp_path: Path) -> None:
    memory = _section("memory", _factory(tmp_path, Guest.KVM))
    assert _obj(memory["meminfo"])["MemTotal"] == 4096000 * 1024
    blocks = _obj(memory["blocks"])
    assert (blocks["block_size_bytes"], blocks["states"]) == (0x8000000, {"memory0": "online", "memory1": "online"})
    assert memory["numa"] == [{"node": 0, "cpulist": "0-1", "distance": "10", "mem_total": 4096000 * 1024}]
    hugepages = _obj(memory["hugepages"])
    assert _obj(hugepages["pools"])["2048kB"] == {"nr_hugepages": "0", "nr_overcommit_hugepages": "0"}
    assert _obj(_obj(hugepages["transparent"])["enabled"])["selected"] == "madvise"


@pytest.mark.os_agnostic
def test_security_on_the_vmware_guest_reads_secure_boot_tpm_ek_and_luks(tmp_path: Path) -> None:
    security = _section("security", _factory(tmp_path, Guest.VMWARE))
    assert security["firmware_type"] == "UEFI"
    assert security["secure_boot"] == {"UEFISecureBootEnabled": 1, "SetupMode": 0}
    assert security["mok"] == {"validation_disabled": False, "mok_list_present": True}
    tpm = _obj(_list(security["tpm"])[0])
    assert (tpm["tpm_version_major"], tpm["hid"], tpm["driver"]) == ("2", "MSFT0101", None)
    ek = _obj(_list(security["ek_certificates"])[0])
    assert (ek["nv_index"], ek["subject"], ek["serial"]) == (EK_INDEX, "CN=Synthetic EK", "1234ABCD")
    assert len(_list(security["ek_certificates"])) == 1
    assert _obj(security["apparmor"])["profiles_by_mode"] == {"complain": 1, "enforce": 2}
    assert security["selinux"] is None
    assert _obj(security["lockdown"])["selected"] == "none"


@pytest.mark.os_agnostic
def test_uefi_without_visible_efivars_records_why_instead_of_reporting_secure_boot_off(tmp_path: Path) -> None:
    root = write_system_tree(write_linux_tree(tmp_path), Guest.VMWARE)
    for var in (root / "sys/firmware/efi/efivars").iterdir():
        var.unlink()
    source = FixtureLinuxSource(root, system_answers(Guest.VMWARE))
    security = _section("security", lambda: build_testing(sources=LinuxSources(system=source, cpuid=source)))
    for item in ("secure_boot", "mok"):
        assert "efivarfs is not mounted" in str(_obj(security[item])["error"])


@pytest.mark.os_agnostic
def test_security_reads_luks_and_lvm_from_device_mapper_and_never_key_material(tmp_path: Path) -> None:
    out = _run(["--section", "security"], _factory(tmp_path, Guest.KVM))
    assert "SYNTHETICDIGEST" not in out and "keyslots" not in out
    security = _obj(_obj(_obj(json.loads(out))["data"])["security"])
    crypt, lvm = (_obj(d) for d in _list(security["device_mapper"]))
    assert (crypt["kind"], crypt["subtype"], crypt["volume_uuid"], crypt["slaves"]) == (
        "crypt",
        "LUKS2",
        LUKS_UUID,
        ["sda3"],
    )
    luks = _obj(crypt["luks"])
    assert (luks["version"], luks["uuid"]) == (2, LUKS_UUID)
    assert _obj(_list(luks["segments"])[0])["encryption"] == "aes-xts-plain64"
    assert (lvm["kind"], lvm["group_uuid"], lvm["name"]) == ("lvm", "A" * 32, "vg0-swap")
    assert "luks" not in lvm


@pytest.mark.os_agnostic
def test_security_on_the_bios_kvm_guest_has_no_secure_boot_and_no_tpm(tmp_path: Path) -> None:
    security = _section("security", _factory(tmp_path, Guest.KVM))
    assert (security["firmware_type"], security["secure_boot"], security["mok"]) == ("BIOS", None, None)
    assert (security["tpm"], security["ek_certificates"]) == ([], [])
    assert security["selinux"] == {"enforce": "1", "policyvers": "33"}
    assert security["apparmor"] is None
    assert security["lsm"] == ["lockdown", "capability", "yama", "selinux"]
    assert security["firewall"] == {"modules": ["nf_tables", "x_tables"], "nftables": True, "iptables": False}


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("guest", "running"),
    [(Guest.VMWARE, {"open-vm-tools"}), (Guest.KVM, {"qemu-guest-agent", "cloud-init"})],
)
def test_services_name_the_guest_agents_installed_enabled_and_running(
    tmp_path: Path, guest: Guest, running: set[str]
) -> None:
    services = _section("services", _factory(tmp_path, guest))
    agents = _obj(services["guest_agents"])
    assert {name for name, a in agents.items() if _obj(a)["running"]} == running
    if guest is Guest.VMWARE:
        vmtools = _obj(agents["open-vm-tools"])
        assert (vmtools["units"], vmtools["enabled"]) == (
            ["open-vm-tools.service", "vgauth.service"],
            ["open-vm-tools.service"],
        )
        assert services["cloud_init_instance_id"] is None
    else:
        assert services["cloud_init_instance_id"] == "i-synthetic01"
        assert _obj(agents["qemu-guest-agent"])["installed"] is True


@pytest.mark.os_posix
@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="root reads every file")
def test_a_root_only_file_is_recorded_as_needs_root_and_its_neighbours_are_read(tmp_path: Path) -> None:
    factory = _factory(tmp_path, Guest.VMWARE)
    for name in ("sys/class/dmi/id/product_serial", "sys/firmware/dmi/tables/DMI"):
        (tmp_path / name).chmod(0)
    smbios = _section("smbios", factory)
    assert str(_obj(smbios["table"])["error"]).startswith("NeedsRootError:")
    dmi = _obj(smbios["dmi_id"])
    assert str(_obj(dmi["product_serial"])["error"]).startswith("NeedsRootError:")
    assert dmi["sys_vendor"] == "VMware, Inc."


@pytest.mark.os_agnostic
def test_a_full_linux_reading_holds_every_system_section(tmp_path: Path) -> None:
    reading = _obj(_obj(json.loads(_run([], _factory(tmp_path, Guest.KVM))))["data"])
    sections = _list(_obj(reading["meta"])["sections"])
    assert set(_SYSTEM_SECTIONS) <= set(sections)
    summary = _obj(_obj(reading["summary"])["system"])
    assert summary["serial"] == "SER-0001"


@pytest.mark.os_linux
@pytest.mark.parametrize("section", _SYSTEM_SECTIONS)
def test_collect_reads_each_system_section_of_this_linux_machine(section: str) -> None:
    result = CliRunner().invoke(cli, ["collect", "--json", "--section", section], obj=build_production)
    assert result.exit_code == 0, result.stdout
    body = _obj(_obj(json.loads(result.stdout))["data"])[section]
    assert isinstance(body, dict) and "error" not in body, body
    assert any(not (isinstance(v, dict) and set(v) == {"error"}) for v in body.values()), body
