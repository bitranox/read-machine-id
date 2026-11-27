"""The ``services`` section of a Linux reading: which guest agents are installed, enabled, running.

Installed means a systemd unit file of the agent exists in one of systemd's unit directories;
enabled means a ``*.wants`` directory under ``/etc/systemd/system`` links it; running means a
process is the agent (by name, or by script name for an agent run under an interpreter). The
process table is walked one process at a time and only the agents found are kept, so its size
never grows the reading. A process that ends between the listing and the read is passed over.

Contents:
    * :data:`UNIT_DIRS` - the unit directories looked in.
    * :func:`read_linux_services` - the section.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..domain.guest_agents import GUEST_AGENTS, agents_running
from ..domain.machine_errors import SourceError
from .linux_files import item_section, optional_dir, optional_text

if TYPE_CHECKING:
    from ..domain.json_types import JsonObject, JsonValue
    from .machine_ports import LinuxSource, LinuxSources

#: Where systemd looks for unit files (systemd.unit(5), system manager), local first.
UNIT_DIRS = (
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
)
_ETC_UNITS = "/etc/systemd/system"
_CMDLINE_BYTES = 4096
_INTERPRETERS = ("python", "perl", "ruby")


def _installed_units(src: LinuxSource) -> set[str]:
    return {name for directory in UNIT_DIRS for name in optional_dir(src, directory)}


def _enabled_units(src: LinuxSource) -> set[str]:
    wants = [n for n in optional_dir(src, _ETC_UNITS) if n.endswith((".wants", ".requires"))]
    return {unit for w in wants for unit in optional_dir(src, f"{_ETC_UNITS}/{w}")}


def _argv(src: LinuxSource, pid: str, comm: str) -> list[str]:
    # Only an interpreter's command line names the agent; a daemon is known by its process name.
    if not comm.startswith(_INTERPRETERS):
        return []
    raw = src.read_prefix(f"/proc/{pid}/cmdline", size=_CMDLINE_BYTES)
    return [arg.decode("utf-8", errors="replace") for arg in raw.split(b"\0") if arg]


def _process_agents(src: LinuxSource, pid: str) -> list[str]:
    try:
        comm = optional_text(src, f"/proc/{pid}/comm")
        return [] if comm is None else agents_running(comm, _argv(src, pid, comm))
    except SourceError:
        return []  # a kernel thread's cmdline, or a process that ended mid-read


def _running_agents(src: LinuxSource) -> set[str]:
    found: set[str] = set()
    for pid in src.list_dir("/proc"):
        if pid.isdigit():
            found.update(_process_agents(src, pid))
    return found


def _sorted_names(names: set[str] | frozenset[str]) -> list[JsonValue]:
    out: list[JsonValue] = []
    out.extend(sorted(names))
    return out


def _guest_agents(src: LinuxSources) -> JsonValue:
    installed = _installed_units(src.system)
    enabled = _enabled_units(src.system)
    running = _running_agents(src.system)
    agents: JsonObject = {}
    for agent in GUEST_AGENTS:
        units = _sorted_names(agent.units & installed)
        on = _sorted_names(agent.units & enabled)
        agents[agent.name] = {
            "installed": bool(units),
            "units": units,
            "enabled": on,
            "running": agent.name in running,
        }
    return agents


def _cloud_instance(src: LinuxSources) -> JsonValue:
    # cloud-init records the instance id the datasource gave it: a cloud VM's own id.
    return optional_text(src.system, "/var/lib/cloud/data/instance-id")


def read_linux_services(src: LinuxSources) -> JsonValue:
    """Read the ``services`` section, each item guarded."""
    return item_section(src, {"guest_agents": _guest_agents, "cloud_init_instance_id": _cloud_instance})


__all__ = ["UNIT_DIRS", "read_linux_services"]
