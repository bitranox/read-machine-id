"""The ports a machine reading is collected through.

A Windows reading asks two sources: :class:`PlatformSource` answers through CIM (WMI) and the
firmware table interfaces, :class:`RegistrySource` reads the registry. A Linux reading asks one,
:class:`LinuxSource`: files under ``/sys``, ``/proc``, ``/etc`` and ``/run``, plus the few kernel
interfaces that are not files (ethtool and netlink sockets, the TPM device). Both OSes also ask
:class:`CpuidSource`, the CPU itself. Production wires the real machine behind them; tests wire a
recorded one.

A source raises :class:`~fingerprint_machine.domain.machine_errors.SourceError` when it cannot
answer one question (a class that does not exist on this build, a key it may not open, a file only
root may read). Collection records that in place of the answer and goes on, so one refused
question never costs the whole reading.

Contents:
    * :data:`RegistryData` - one registry value's data.
    * :class:`PlatformSource` - CIM and firmware tables (Windows).
    * :class:`RegistrySource` - the registry (Windows).
    * :class:`LinuxSource` - files and kernel interfaces (Linux).
    * :class:`NetlinkDump` - the netlink tables :meth:`LinuxSource.netlink_dump` can list.
    * :class:`CpuidSource` - the CPUID instruction (both).
    * :class:`WindowsSources`, :class:`LinuxSources` - the sources one collection takes.
    * :data:`MachineSources` - either bundle.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ..domain.cpuid import CpuidRegs
    from ..domain.json_types import JsonObject

#: One registry value's data, as winreg returns it.
type RegistryData = bytes | int | str | list[str] | None


class PlatformSource(Protocol):
    """CIM classes and the firmware tables of the machine being read."""

    def cim(self, class_name: str, *, namespace: str = "root/cimv2", where: str | None = None) -> list[JsonObject]:
        """Return every instance of a CIM class, each as its properties in JSON.

        Raises:
            SourceError: the class cannot be read here.
        """
        ...

    def smbios_table(self) -> tuple[bytes, str]:
        """Return the raw SMBIOS structure table and the SMBIOS version, e.g. ``"3.1"``.

        Raises:
            SourceError: the firmware table cannot be read.
        """
        ...

    def acpi_tables(self) -> list[bytes]:
        """Return every ACPI table the firmware exposes, each as raw bytes.

        Raises:
            SourceError: the firmware tables cannot be listed.
        """
        ...

    def tbs_device_info(self) -> bytes:
        """Return the TPM_DEVICE_INFO structure the TPM Base Services fill.

        Raises:
            SourceError: there is no TPM, or TBS refused.
        """
        ...

    def firmware_type(self) -> str:
        """Return ``"UEFI"``, ``"BIOS"`` or ``"unknown(<n>)"``.

        Raises:
            SourceError: the firmware type cannot be asked.
        """
        ...


class RegistrySource(Protocol):
    """Read access to the registry of the machine being read."""

    def values(self, key: str) -> Mapping[str, RegistryData]:
        """Return every value of ``key`` by name (``""`` for the default value).

        Raises:
            SourceError: the key does not exist or cannot be opened.
        """
        ...

    def subkeys(self, key: str) -> list[str]:
        """Return the names of the subkeys of ``key``, sorted.

        Raises:
            SourceError: the key does not exist or cannot be opened.
        """
        ...


class CpuidSource(Protocol):
    """The CPUID instruction of the CPU the reading runs on."""

    def cpuid(self, leaf: int, *, subleaf: int = 0) -> CpuidRegs:
        """Return the four registers CPUID gives for ``leaf`` and ``subleaf``.

        Raises:
            SourceError: CPUID cannot be executed here (not x86-64, or executable memory refused).
        """
        ...


class NetlinkDump(StrEnum):
    """The rtnetlink tables a dump request lists."""

    LINKS = "links"
    ADDRESSES = "addresses"
    ROUTES = "routes"
    NEIGHBOURS = "neighbours"


#: Files read whole are capped at this size, so no file (``/proc/kcore``) can exhaust memory.
DEFAULT_MAX_BYTES = 16 * 1024 * 1024


class LinuxSource(Protocol):
    """Files and kernel interfaces of the Linux machine being read.

    Paths are absolute POSIX paths as they are on the machine (``/sys/class/net``).
    """

    def read_bytes(self, path: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
        """Return the content of a file.

        Raises:
            NeedsRootError: only root may read it.
            MissingPathError: it does not exist.
            SourceError: it cannot be read otherwise, or is larger than ``max_bytes``.
        """
        ...

    def read_text(self, path: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
        """Return the content of a text file, decoded as UTF-8 (undecodable bytes replaced).

        Raises:
            NeedsRootError, MissingPathError, SourceError: as :meth:`read_bytes`.
        """
        ...

    def list_dir(self, path: str) -> list[str]:
        """Return the names in a directory, sorted.

        Raises:
            NeedsRootError, MissingPathError, SourceError: as :meth:`read_bytes`.
        """
        ...

    def readlink(self, path: str) -> str:
        """Return the target a symbolic link points at, as written in the link.

        Raises:
            NeedsRootError, MissingPathError, SourceError: as :meth:`read_bytes`; SourceError also
                when ``path`` is not a link.
        """
        ...

    def ethtool(self, ifname: str, *, request: bytes) -> bytes:
        """Run one ``SIOCETHTOOL`` request on an interface and return the buffer it filled.

        ``request`` is the whole ethtool structure, command first; the answer has its size.

        Raises:
            SourceError: the interface or the command is refused.
        """
        ...

    def netlink_dump(self, table: NetlinkDump) -> list[bytes]:
        """Return every message of an rtnetlink dump of ``table``.

        Raises:
            SourceError: the dump is refused.
        """
        ...

    def tpm_nv_read(self, index: int) -> bytes:
        """Return the content of a TPM non-volatile index (e.g. ``0x01C00002``, the RSA EK certificate).

        Raises:
            NeedsRootError: the TPM device may not be opened.
            SourceError: there is no TPM, or the index is not defined.
        """
        ...


@dataclass(frozen=True)
class WindowsSources:
    """The sources one Windows collection reads from."""

    platform: PlatformSource
    registry: RegistrySource
    cpuid: CpuidSource


@dataclass(frozen=True)
class LinuxSources:
    """The sources one Linux collection reads from."""

    system: LinuxSource
    cpuid: CpuidSource


#: The sources of one collection, on either OS.
type MachineSources = WindowsSources | LinuxSources


__all__ = [
    "DEFAULT_MAX_BYTES",
    "CpuidSource",
    "LinuxSource",
    "LinuxSources",
    "MachineSources",
    "NetlinkDump",
    "PlatformSource",
    "RegistryData",
    "RegistrySource",
    "WindowsSources",
]
