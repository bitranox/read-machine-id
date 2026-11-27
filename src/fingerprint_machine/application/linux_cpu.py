"""The ``cpu`` section of a Linux reading: every logical CPU as the kernel sees it.

``/proc/cpuinfo`` per logical CPU (vendor, family, model, stepping, microcode, flags, bugs), and
under ``/sys/devices/system/cpu`` each CPU's topology (package, die, core, thread siblings), its
caches (``cache/index*``) and its frequency limits, the system-wide CPU masks and SMT state, and
the kernel's verdict on every hardware vulnerability. A VM shows its virtual topology here, and the
flags it passes through (or hides) are one of the first things to compare.

The current frequency is left out: it changes from one read to the next.

Contents:
    * :func:`read_linux_cpu` - the section.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..domain.procfs import parse_cpuinfo
from .guard import guarded
from .linux_files import file_values, item_section, optional_dir, text

if TYPE_CHECKING:
    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import LinuxSource, LinuxSources

_CPU = "/sys/devices/system/cpu"
_TOPOLOGY = (
    "physical_package_id",
    "die_id",
    "cluster_id",
    "core_id",
    "book_id",
    "drawer_id",
    "core_cpus_list",
    "thread_siblings_list",
    "die_cpus_list",
    "cluster_cpus_list",
    "package_cpus_list",
)
_CACHE = (
    "id",
    "level",
    "type",
    "size",
    "ways_of_associativity",
    "coherency_line_size",
    "number_of_sets",
    "physical_line_partition",
    "shared_cpu_list",
)
_CPUFREQ = (
    "cpuinfo_min_freq",
    "cpuinfo_max_freq",
    "base_frequency",
    "scaling_driver",
    "scaling_governor",
    "scaling_min_freq",
    "scaling_max_freq",
)
_SYSTEM = ("online", "offline", "possible", "present", "isolated", "kernel_max", "nohz_full")


def _is_cpu_dir(name: str) -> bool:
    return name.startswith("cpu") and name[3:].isdigit()


def _cpu_number(name: str) -> int:
    return int(name[3:])


def _caches(src: LinuxSource, cpu: str) -> list[JsonValue]:
    base = f"{_CPU}/{cpu}/cache"
    indexes = sorted((n for n in optional_dir(src, base) if n.startswith("index")), key=lambda n: int(n[5:] or 0))
    return [file_values(src, f"{base}/{index}", _CACHE) for index in indexes]


def _one_cpu(src: LinuxSource, cpu: str) -> JsonObject:
    base = f"{_CPU}/{cpu}"
    record: JsonObject = {
        "cpu": _cpu_number(cpu),
        **file_values(src, base, ("online",)),
        "topology": file_values(src, f"{base}/topology", _TOPOLOGY),
        "cache": _caches(src, cpu),
    }
    if optional_dir(src, f"{base}/cpufreq"):
        record["cpufreq"] = file_values(src, f"{base}/cpufreq", _CPUFREQ)
    return record


def _cpus(src: LinuxSources) -> JsonValue:
    names = sorted((n for n in src.system.list_dir(_CPU) if _is_cpu_dir(n)), key=_cpu_number)
    cpus: list[JsonValue] = [guarded(lambda name=name: _one_cpu(src.system, name)) for name in names]
    return cpus


def _system(src: LinuxSources) -> JsonValue:
    values = file_values(src.system, _CPU, _SYSTEM)
    smt = file_values(src.system, f"{_CPU}/smt", ("active", "control"))
    return {**values, "smt": smt}


def _vulnerabilities(src: LinuxSources) -> JsonValue:
    base = f"{_CPU}/vulnerabilities"
    return file_values(src.system, base, optional_dir(src.system, base))


def _cpuinfo(src: LinuxSources) -> JsonValue:
    cpus: list[JsonValue] = list(parse_cpuinfo(text(src.system, "/proc/cpuinfo")))
    return cpus


def read_linux_cpu(src: LinuxSources) -> JsonValue:
    """Read the ``cpu`` section, each item guarded."""
    return item_section(
        src,
        {"cpuinfo": _cpuinfo, "cpus": _cpus, "system": _system, "vulnerabilities": _vulnerabilities},
    )


__all__ = ["read_linux_cpu"]
