"""The ports a machine reading is collected through.

Two sources answer every question a reading asks. :class:`PlatformSource` answers through CIM
(WMI) and the firmware table interfaces; :class:`RegistrySource` reads the registry. Production
wires pwshpy and lib_registry behind them; tests wire a recorded machine.

A source raises :class:`~read_machine_id.domain.errors.SourceError` when it cannot answer one
question (a class that does not exist on this build, a key it may not open). Collection records
that in place of the answer and goes on, so one refused question never costs the whole reading.

Contents:
    * :data:`RegistryData` - one registry value's data.
    * :class:`PlatformSource` - CIM and firmware tables.
    * :class:`RegistrySource` - the registry.
    * :class:`Sources` - both, as collection takes them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, TypeAlias

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ..domain.json_types import JsonObject

#: One registry value's data, as winreg returns it.
RegistryData: TypeAlias = "None | bytes | int | str | list[str]"


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


@dataclass(frozen=True)
class Sources:
    """The two sources one collection reads from."""

    platform: PlatformSource
    registry: RegistrySource


__all__ = ["PlatformSource", "RegistryData", "RegistrySource", "Sources"]
