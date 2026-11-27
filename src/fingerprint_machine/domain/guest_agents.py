"""The guest agents a hypervisor or cloud installs in a Linux guest, and how to recognise each.

An installed agent shows as its systemd unit files; a running one as a process. A daemon is
recognised by its process name (``/proc/<pid>/comm``, which the kernel cuts to 15 characters); an
agent that runs as a script under an interpreter (``waagent`` under python) by its script name in
the command line. Which agents a guest carries is itself a fingerprint: it names the hypervisor
the image was prepared for.

Contents:
    * :class:`GuestAgent` - one agent's units, process names and script names.
    * :data:`GUEST_AGENTS` - the agents looked for.
    * :func:`agents_running` - which agents a process is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

#: The kernel keeps a process name to this many characters (TASK_COMM_LEN 16, minus the NUL).
COMM_LENGTH = 15


@dataclass(frozen=True)
class GuestAgent:
    """One agent: its unit file names, its daemon process names, its script names."""

    name: str
    units: frozenset[str]
    processes: frozenset[str] = field(default_factory=frozenset[str])
    scripts: frozenset[str] = field(default_factory=frozenset[str])

    def runs_as(self, comm: str, argv: Sequence[str]) -> bool:
        """True when a process with this name and command line is this agent.

        Example:
            >>> agent = GuestAgent("x", frozenset(), scripts=frozenset({"waagent"}))
            >>> agent.runs_as("python3", ["python3", "/usr/sbin/waagent"])
            True
        """
        if comm in {p[:COMM_LENGTH] for p in self.processes}:
            return True
        return any(arg.rsplit("/", 1)[-1] in self.scripts for arg in argv[:2])


def _agent(
    name: str, units: set[str], processes: set[str] | None = None, scripts: set[str] | None = None
) -> GuestAgent:
    return GuestAgent(name, frozenset(units), frozenset(processes or set()), frozenset(scripts or set()))


#: The agents looked for, in the order a reading lists them.
GUEST_AGENTS: tuple[GuestAgent, ...] = (
    _agent(
        "open-vm-tools", {"open-vm-tools.service", "vmtoolsd.service", "vgauth.service"}, {"vmtoolsd", "VGAuthService"}
    ),
    _agent("qemu-guest-agent", {"qemu-guest-agent.service"}, {"qemu-ga"}),
    _agent(
        "hyperv-daemons",
        {
            "hv-kvp-daemon.service",
            "hv_kvp_daemon.service",
            "hv-vss-daemon.service",
            "hv_vss_daemon.service",
            "hv-fcopy-daemon.service",
            "hv_fcopy_daemon.service",
            "hypervkvpd.service",
            "hypervvssd.service",
            "hypervfcopyd.service",
        },
        {"hv_kvp_daemon", "hv_vss_daemon", "hv_fcopy_daemon", "hypervkvpd", "hypervvssd", "hypervfcopyd"},
    ),
    _agent("waagent", {"walinuxagent.service", "waagent.service"}, None, {"waagent"}),
    _agent(
        "cloud-init",
        {"cloud-init.service", "cloud-init-local.service", "cloud-config.service", "cloud-final.service"},
        {"cloud-init"},
        {"cloud-init"},
    ),
    _agent("spice-vdagent", {"spice-vdagentd.service"}, {"spice-vdagentd", "spice-vdagent"}),
    _agent("virtualbox-guest", {"vboxadd-service.service", "vboxadd.service"}, {"VBoxService"}),
    _agent("xen-guest", {"xe-linux-distribution.service", "xe-daemon.service"}, {"xe-daemon"}),
    _agent("google-guest-agent", {"google-guest-agent.service"}, {"google_guest_agent"}),
    _agent("amazon-ssm-agent", {"amazon-ssm-agent.service"}, {"amazon-ssm-agent"}),
)


def agents_running(comm: str, argv: Sequence[str]) -> list[str]:
    """Return the names of the agents a process with this name and command line is.

    Example:
        >>> agents_running("qemu-ga", ["/usr/sbin/qemu-ga"])
        ['qemu-guest-agent']
    """
    return [agent.name for agent in GUEST_AGENTS if agent.runs_as(comm, argv)]


__all__ = ["COMM_LENGTH", "GUEST_AGENTS", "GuestAgent", "agents_running"]
