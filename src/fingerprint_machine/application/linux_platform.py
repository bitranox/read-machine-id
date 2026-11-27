"""The ``platform`` section of a Linux reading: the kernel, the OS and the machine's own ids.

What Windows keeps in its registry and WMI (OS version, computer name, machine GUID) Linux keeps
in files: the kernel's release and command line under ``/proc``, the distribution in
``/etc/os-release``, the machine id systemd and D-Bus share, the boot id the kernel draws at each
boot. Plus what the machine runs on: the clock source the kernel chose, ``/sys/hypervisor`` (Xen),
the DMI modalias, and a verdict like ``systemd-detect-virt``'s, decided from CPUID and DMI without
running anything.

This is the second section that asks the CPU (after ``cpuid``): the verdict reads CPUID leaf 1 and,
when its hypervisor bit is set, leaf ``0x40000000``. ``collect --no-cpuid`` hands it a CPU that
refuses, so the verdict then rests on DMI alone and records why.

Contents:
    * :func:`read_linux_platform` - the section.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..domain.cpuid import CpuidQuery, decode_cpuid
from ..domain.machine_errors import MissingPathError
from ..domain.procfs import parse_os_release
from ..domain.virt import DMI_FIELDS, detect_virt
from .guard import guarded
from .linux_files import file_values, item_section, optional_dir, optional_text, text
from .linux_firmware_tables import dmi_id_values

if TYPE_CHECKING:
    from collections.abc import Callable

    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import CpuidSource, LinuxSource, LinuxSources

_HYPERVISOR_LEAF = 0x40000000
_CLOCKSOURCE = "/sys/devices/system/clocksource/clocksource0"
_HYPERVISOR_DIR = "/sys/hypervisor"
# /sys/hypervisor nests one level (Xen: properties/, version/, compilation/).
_HYPERVISOR_DEPTH = 2


def _kernel(src: LinuxSources) -> JsonValue:
    return {
        "release": guarded(lambda: text(src.system, "/proc/sys/kernel/osrelease")),
        "version": guarded(lambda: text(src.system, "/proc/sys/kernel/version")),
        "cmdline": guarded(lambda: text(src.system, "/proc/cmdline")),
    }


def _os_release(src: LinuxSources) -> JsonValue:
    # os-release(5): /etc/os-release, else the vendor copy in /usr/lib.
    try:
        return parse_os_release(src.system.read_text("/etc/os-release"))
    except MissingPathError:
        return parse_os_release(src.system.read_text("/usr/lib/os-release"))


def _file(path: str) -> Callable[[LinuxSources], JsonValue]:
    def read(src: LinuxSources) -> JsonValue:
        return text(src.system, path)

    return read


def _optional_file(path: str) -> Callable[[LinuxSources], JsonValue]:
    def read(src: LinuxSources) -> JsonValue:
        return optional_text(src.system, path)

    return read


def _tree(src: LinuxSource, path: str, depth: int) -> JsonValue:
    # An entry is a directory when it lists; one that came from a listing yet does not list is a file.
    try:
        names = src.list_dir(path)
    except MissingPathError:
        return guarded(lambda: text(src, path))
    if depth == 0:
        listed: list[JsonValue] = list(names)
        return listed
    return {name: _tree(src, f"{path}/{name}", depth - 1) for name in names}


def _hypervisor(src: LinuxSources) -> JsonValue:
    if not optional_dir(src.system, _HYPERVISOR_DIR):
        return {}
    return _tree(src.system, _HYPERVISOR_DIR, _HYPERVISOR_DEPTH)


def _clocksource(src: LinuxSources) -> JsonValue:
    return file_values(src.system, _CLOCKSOURCE, ("current_clocksource", "available_clocksource"))


def _cpuid_signals(cpu: CpuidSource) -> JsonObject:
    leaf1 = cpu.cpuid(1)
    answers = {CpuidQuery(1): leaf1}
    decoded = decode_cpuid(answers)
    if decoded["hypervisor_present_bit"]:
        answers[CpuidQuery(_HYPERVISOR_LEAF)] = cpu.cpuid(_HYPERVISOR_LEAF)
        decoded = decode_cpuid(answers)
    return {
        "hypervisor_present_bit": decoded["hypervisor_present_bit"],
        "hypervisor_vendor": decoded["hypervisor_vendor"],
    }


def _virtualization(src: LinuxSources) -> JsonValue:
    signals = guarded(lambda: _cpuid_signals(src.cpuid))
    dmi_values = dmi_id_values(src.system)
    dmi = {k: v for k in DMI_FIELDS if isinstance(v := dmi_values.get(k), str)}
    vendor = signals.get("hypervisor_vendor") if isinstance(signals, dict) else None
    bit = signals.get("hypervisor_present_bit") if isinstance(signals, dict) else None
    verdict = detect_virt(
        cpuid_vendor=vendor if isinstance(vendor, str) else None,
        hypervisor_bit=bit if isinstance(bit, bool) else None,
        dmi=dmi,
    )
    dmi_json: JsonObject = dict(dmi)
    return {**verdict.as_json(), "cpuid": signals, "dmi": dmi_json}


def read_linux_platform(src: LinuxSources) -> JsonValue:
    """Read the ``platform`` section, each item guarded."""
    return item_section(
        src,
        {
            "kernel": _kernel,
            "os_release": _os_release,
            "hostname": _file("/proc/sys/kernel/hostname"),
            "machine_id": _file("/etc/machine-id"),
            "dbus_machine_id": _optional_file("/var/lib/dbus/machine-id"),
            "boot_id": _file("/proc/sys/kernel/random/boot_id"),
            "dmi_modalias": _file("/sys/class/dmi/id/modalias"),
            "container": _optional_file("/run/systemd/container"),
            "hypervisor": _hypervisor,
            "clocksource": _clocksource,
            "virtualization": _virtualization,
        },
    )


__all__ = ["read_linux_platform"]
